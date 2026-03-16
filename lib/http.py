"""HTTP wrapper with auth-gated session injection and UA spoofing."""

import random
import requests
from lib.output import debug


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


class AuthRequired(Exception):
    """Raised when auth=True but no session cookies are available."""
    pass


class HTTP:
    """Thin requests wrapper with auth-gated session injection.

    Session cookies are NEVER sent unless the caller passes auth=True.
    This ensures exploit authors explicitly declare when they need auth.

    Usage in exploits:
        self.http.get(url)                         # no cookies sent
        self.http.get(url, auth=True)              # session cookies sent
        self.http.post(url, auth=True, cookies={}) # session + explicit merged
    """

    def __init__(self, session_cookies=None, spoof_ua=True, verbose=False):
        self._session = requests.Session()
        self._auth_cookies = session_cookies or {}
        self._spoof_ua = spoof_ua
        self._verbose = verbose

    def _headers(self, extra_headers=None):
        headers = {}
        if self._spoof_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def _resolve_cookies(self, auth, explicit_cookies):
        """Build the cookie dict for a request.

        auth=False: only explicit_cookies (if any), never session cookies
        auth=True:  session cookies + explicit_cookies merged (explicit wins on conflict)
        """
        if not auth:
            return explicit_cookies or None

        if not self._auth_cookies:
            raise AuthRequired(
                "auth=True but no session cookies available. "
                "Chain with an AUTH exploit, use --cookie, or use --user/--pass."
            )

        merged = dict(self._auth_cookies)
        if explicit_cookies:
            merged.update(explicit_cookies)
        return merged

    def get(self, url, auth=False, **kwargs):
        headers = self._headers(kwargs.pop("headers", None))
        cookies = self._resolve_cookies(auth, kwargs.pop("cookies", None))
        if self._verbose:
            debug(f"GET {url}" + (" [auth]" if auth else ""))
        return self._session.get(url, headers=headers, cookies=cookies, **kwargs)

    def post(self, url, auth=False, **kwargs):
        headers = self._headers(kwargs.pop("headers", None))
        cookies = self._resolve_cookies(auth, kwargs.pop("cookies", None))
        if self._verbose:
            debug(f"POST {url}" + (" [auth]" if auth else ""))
        return self._session.post(url, headers=headers, cookies=cookies, **kwargs)

    def put(self, url, auth=False, **kwargs):
        headers = self._headers(kwargs.pop("headers", None))
        cookies = self._resolve_cookies(auth, kwargs.pop("cookies", None))
        if self._verbose:
            debug(f"PUT {url}" + (" [auth]" if auth else ""))
        return self._session.put(url, headers=headers, cookies=cookies, **kwargs)

    def delete(self, url, auth=False, **kwargs):
        headers = self._headers(kwargs.pop("headers", None))
        cookies = self._resolve_cookies(auth, kwargs.pop("cookies", None))
        if self._verbose:
            debug(f"DELETE {url}" + (" [auth]" if auth else ""))
        return self._session.delete(url, headers=headers, cookies=cookies, **kwargs)

    @property
    def cookies(self):
        return dict(self._auth_cookies)
