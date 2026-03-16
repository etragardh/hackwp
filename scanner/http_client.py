"""
Async HTTP client with concurrency control, caching, and retry logic.
"""

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

import httpx

from lib.output import verbose


@dataclass
class Response:
    """Simplified response object."""
    url: str
    status_code: int
    text: str
    headers: dict
    redirect_url: str | None = None
    original_status_code: int | None = None  # Status before redirects
    was_redirected: bool = False


class HttpClient:
    """Async HTTP client with semaphore-based concurrency control."""

    def __init__(self, args):
        self.args = args
        self.semaphore = asyncio.Semaphore(args.concurrency)
        self.cache: dict[str, Response] = {}
        self._request_count = 0
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.args.timeout),
            follow_redirects=True,
            verify=False,  # Lab environments often use self-signed certs
            headers={"User-Agent": self.args.user_agent},
            limits=httpx.Limits(
                max_connections=self.args.concurrency,
                max_keepalive_connections=self.args.concurrency,
            ),
        )
        return self

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.aclose()

    @property
    def request_count(self) -> int:
        return self._request_count

    def _cache_key(self, url: str, method: str = "GET") -> str:
        return hashlib.md5(f"{method}:{url}".encode()).hexdigest()

    async def get(self, url: str, use_cache: bool = True) -> Response | None:
        """GET request with concurrency control and caching."""
        cache_key = self._cache_key(url)

        if use_cache and cache_key in self.cache:
            return self.cache[cache_key]

        async with self.semaphore:
            try:
                self._request_count += 1
                resp = await self._client.get(url)

                redirect_url = None
                original_status = None
                was_redirected = False
                if resp.history:
                    redirect_url = str(resp.history[0].headers.get("location", ""))
                    original_status = resp.history[0].status_code
                    was_redirected = True

                result = Response(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    text=resp.text,
                    headers=dict(resp.headers),
                    redirect_url=redirect_url,
                    original_status_code=original_status,
                    was_redirected=was_redirected,
                )

                if use_cache:
                    self.cache[cache_key] = result

                return result

            except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
                verbose(f"Request failed: {url} ({e.__class__.__name__})", self.args.verbose)
                return None
            except Exception as e:
                verbose(f"Request error: {url} ({e})", self.args.verbose)
                return None

    async def head(self, url: str) -> Response | None:
        """HEAD request (no caching)."""
        async with self.semaphore:
            try:
                self._request_count += 1
                resp = await self._client.head(url)
                return Response(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    text="",
                    headers=dict(resp.headers),
                )
            except Exception:
                return None

    async def post(self, url: str, data: str = "", content_type: str = "text/xml") -> Response | None:
        """POST request."""
        async with self.semaphore:
            try:
                self._request_count += 1
                resp = await self._client.post(
                    url,
                    content=data,
                    headers={"Content-Type": content_type},
                )
                return Response(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    text=resp.text,
                    headers=dict(resp.headers),
                )
            except Exception:
                return None

    async def get_batch(self, urls: list[str], use_cache: bool = True) -> list[Response | None]:
        """Fetch multiple URLs concurrently."""
        tasks = [self.get(url, use_cache=use_cache) for url in urls]
        return await asyncio.gather(*tasks)

    async def head_batch(self, urls: list[str]) -> list[Response | None]:
        """HEAD multiple URLs concurrently."""
        tasks = [self.head(url) for url in urls]
        return await asyncio.gather(*tasks)

    def grep(self, text: str, pattern: str, group: int = 0) -> list[str]:
        """Extract regex matches from text."""
        matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
        if not matches:
            return []
        if isinstance(matches[0], tuple) and group > 0:
            return [m[group - 1] for m in matches if len(m) >= group]
        if isinstance(matches[0], tuple):
            return [m[0] for m in matches]
        return matches
