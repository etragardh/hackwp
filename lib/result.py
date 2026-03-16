class Result:
    """Standardized result from an exploit execution.

    Fields:
        success        (bool) — did the exploit succeed (required)
        output         (str)  — raw response body / command output
        rows_affected  (int)  — SQL rows affected
        insert_id      (int)  — SQL insert ID
        url            (str)  — remote URL (uploaded file, XSS trigger)
        path           (str)  — filesystem path on target
        session        (dict) — session cookies obtained/created/stolen
        credentials    (dict) — {"username": ..., "password": ..., "role": ...}
        message        (str)  — human-readable status message
    """

    _VALID_FIELDS = frozenset({
        "success", "output", "rows_affected", "insert_id",
        "url", "path", "session", "credentials", "message",
    })

    def __init__(self, success=True, **kwargs):
        # Validate — no invented fields
        unknown = set(kwargs.keys()) - self._VALID_FIELDS
        if unknown:
            from lib.output import error as _error
            _error(
                f"Result received unknown field(s): {', '.join(sorted(unknown))}. "
                f"Valid fields: {', '.join(sorted(self._VALID_FIELDS))}"
            )
            raise ValueError(f"Unknown Result field(s): {', '.join(sorted(unknown))}")

        self.success = success
        self.output = kwargs.get("output")
        self.rows_affected = kwargs.get("rows_affected")
        self.insert_id = kwargs.get("insert_id")
        self.url = kwargs.get("url")
        self.path = kwargs.get("path")
        self.session = kwargs.get("session")
        self.credentials = kwargs.get("credentials")
        self.message = kwargs.get("message")

    def __repr__(self):
        fields = [f"{k}={v!r}" for k, v in self.__dict__.items() if v is not None]
        return f"Result({', '.join(fields)})"

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items() if v is not None}
