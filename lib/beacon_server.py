"""
HWP Beacon Server — Temporary HTTP listener for server-side RCE confirmation.

When an XSS→RCE adapter injects a server-side beacon into a dropped PHP
shell, that PHP calls back to this listener when it executes on the target.
A received callback proves the PHP ran on the server (true RCE), not just
that the injected JavaScript fired in a browser.

This mirrors lib/rfi_server.py: a temporary HTTP server on a background
thread, managed entirely by the framework (chain.py).

Usage (by chain.py):
    beacon = BeaconServer(lhost, lport)
    beacon.start()
    # ... chain runs, operator triggers XSS as admin ...
    received = beacon.wait(timeout=300)   # blocks until callback or timeout
    beacon.stop()

The beacon PHP stub posts back a small JSON body (resolved shell path,
whoami output). Whatever it sends is captured in `BeaconServer.received_data`.
"""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from lib import output


class _BeaconHandler(BaseHTTPRequestHandler):
    """Captures a single beacon callback (GET or POST), then signals an event."""

    fired_event = None          # threading.Event, set by BeaconServer
    received_data = None        # parsed dict or raw string from the beacon

    def _capture(self, body):
        # Try JSON first, fall back to raw text
        if body:
            try:
                _BeaconHandler.received_data = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                _BeaconHandler.received_data = {"raw": body}
        else:
            # Even an empty GET is a valid "I fired" signal
            _BeaconHandler.received_data = _BeaconHandler.received_data or {"raw": ""}

        if _BeaconHandler.fired_event is not None:
            _BeaconHandler.fired_event.set()

    def do_GET(self):
        self._capture(self._read_query())
        self._respond_ok()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        self._capture(body)
        self._respond_ok()

    def _read_query(self):
        # Allow beacons that pass data via query string (?d=base64json)
        if "?" in self.path:
            return self.path.split("?", 1)[1]
        return ""

    def _respond_ok(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass  # Suppress default logging


class BeaconServer:
    """Temporary HTTP listener that waits for a server-side beacon callback."""

    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = int(lport)
        self._server = None
        self._thread = None
        self._event = threading.Event()

    def start(self) -> bool:
        """Start the listener on a background thread. Returns True on success."""
        _BeaconHandler.fired_event = self._event
        _BeaconHandler.received_data = None
        self._event.clear()

        try:
            self._server = HTTPServer(("0.0.0.0", self.lport), _BeaconHandler)
        except OSError as e:
            output.error(f"Failed to start beacon listener on port {self.lport}: {e}")
            return False

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        output.info(f"Beacon listener on 0.0.0.0:{self.lport} (awaiting server-side callback)")
        return True

    def wait(self, timeout=300) -> bool:
        """Block until a beacon fires or timeout (seconds) elapses.

        Returns True if a callback was received, False on timeout.
        """
        return self._event.wait(timeout=timeout)

    def stop(self):
        """Shut down the listener."""
        if self._server:
            self._server.shutdown()
            self._thread.join(timeout=5)
            self._server = None
            self._thread = None

    @property
    def fired(self) -> bool:
        """True if a beacon callback was received."""
        return self._event.is_set()

    @property
    def data(self):
        """The data the beacon sent back (dict), or None if nothing received."""
        return _BeaconHandler.received_data
