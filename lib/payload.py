"""
HWP Payload Base Class.

Payloads generate instructions for exploits to deliver.
"""

from lib import output
from lib.http import HTTP


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

    def __init__(self, options=None, verbose=False):
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
