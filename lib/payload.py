"""
HWP Payload Base Class.

Payloads generate instructions for exploits to deliver.
"""

from lib import output
from lib.http import HTTP

import base64
import hashlib
import random
import string
from urllib.parse import quote, unquote


# Same aliases as exploit
_ALIASES = {
    "RCEp": "RCE",
    "CODEINJp": "CODEINJ",
    "XSSs": "XSS",
}


def resolve_method(method):
    return _ALIASES.get(method, method)


class Payload:
    """Base class for all HWP payloads."""

    # ── Payload author defines these ──────────────────────────────────
    name = None             # Human-readable name
    methods = []            # Capabilities this payload works with
    description = ""        # Short description
    authors = []            # e.g. ["etragardh"]
    credits = []            # Special thanks

    def __init__(self, target=None, domain=None, options=None, verbose=False):
        self.target = target
        self.domain = domain
        self.options = options or {}
        self.verbose = verbose
        self.method = None          # Set by framework before instructions()
        self.http = HTTP()

    def instructions(self):
        """Override: return list of instruction strings. Use self.method."""
        raise NotImplementedError("Implement instructions()")

    def report(self, results):
        """Optional override: called after all instructions executed. Use self.method."""
        pass

    # ── Helpers for students ──────────────────────────────────────────

    def b64e(self, s):
        """Base64 encode a string."""
        if isinstance(s, str):
            s = s.encode()
        return base64.b64encode(s).decode()

    def b64d(self, s):
        """Base64 decode a string."""
        if isinstance(s, str):
            s = s.encode()
        return base64.b64decode(s).decode()

    def url_encode(self, s):
        """URL encode a string."""
        return quote(str(s))

    def url_decode(self, s):
        """URL decode a string."""
        return unquote(str(s))

    def md5(self, s):
        """MD5 hash a string."""
        if isinstance(s, str):
            s = s.encode()
        return hashlib.md5(s).hexdigest()

    def rand(self, n=8):
        """Random alphanumeric string."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

    # Output helpers
    info = staticmethod(output.info)
    warn = staticmethod(output.warn)
    error = staticmethod(output.error)
    success = staticmethod(output.success)

    @classmethod
    def info_str(cls):
        """Return human-readable one-liner."""
        methods = ", ".join(cls.methods) if cls.methods else "?"
        return f"{cls.name} [{methods}]"

    def __repr__(self):
        return f"<{self.__class__.__name__} '{self.name}' [{', '.join(self.methods)}]>"
