"""
Async website crawler for WordPress sites.
Crawls pages within the target domain, extracts URLs, and runs regex patterns.
"""

import re
from urllib.parse import urlparse, urljoin

from scanner.http_client import HttpClient
from lib.output import verbose


class Crawler:
    """Crawls a WordPress site to discover content across all pages."""

    # URLs matching these patterns are skipped during crawling
    EXCLUDE_PATTERN = re.compile(
        r'wp-json|/uploads/|/assets/|\.css|\.js(\?|$)|\.php|\.pdf|\.jpe?g|\.png|'
        r'\.gif|\.svg|\.woff2?|\.ttf|\.ico|\.xml|\.zip|\.gz|#|mailto:|javascript:',
        re.IGNORECASE,
    )

    def __init__(self, client: HttpClient, args):
        self.client = client
        self.args = args
        self.target = args.target
        self.domain = urlparse(args.target).netloc
        self.max_pages = args.max_crawl_pages
        self.visited: set[str] = set()  # Normalized URLs we've visited
        self.page_cache: dict[str, str] = {}  # URL -> response text

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        url = url.split("#")[0]  # Remove fragments
        url = url.rstrip("/")
        return url

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the target domain."""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.domain
        except Exception:
            return False

    def _should_crawl(self, url: str) -> bool:
        """Decide if we should crawl this URL."""
        normalized = self._normalize_url(url)
        if normalized in self.visited:
            return False
        if len(self.visited) >= self.max_pages:
            return False
        if not self._is_same_domain(url):
            return False
        if self.EXCLUDE_PATTERN.search(url):
            return False
        return True

    def _extract_urls(self, text: str) -> list[str]:
        """Extract same-domain URLs from HTML."""
        pattern = rf'(?:href|src|action)=["\']?(https?://(?:{re.escape(self.domain)})[^"\'\s>]*)'
        urls = re.findall(pattern, text, re.IGNORECASE)

        # Also catch relative URLs
        rel_pattern = r'(?:href|src|action)=["\'](/[^"\'\s>]*)'
        for rel in re.findall(rel_pattern, text, re.IGNORECASE):
            urls.append(f"{self.target}{rel}")

        return list(set(urls))

    async def crawl(self, pattern: str, group: int = 0) -> list[str]:
        """
        Crawl the entire site and collect regex matches from all pages.

        Args:
            pattern: Regex pattern to search for on each page
            group: Capture group index (0 = full match, 1+ = specific group)

        Returns:
            List of unique matched strings
        """
        self.visited.clear()
        self.page_cache.clear()
        all_matches: list[str] = []

        # Start with the target URL
        queue = [self.target]

        while queue and len(self.visited) < self.max_pages:
            # Process in batches for concurrency
            batch = []
            while queue and len(batch) < self.args.concurrency:
                url = queue.pop(0)
                if self._should_crawl(url):
                    batch.append(url)
                    self.visited.add(self._normalize_url(url))

            if not batch:
                break

            verbose(f"Crawling batch of {len(batch)} pages ({len(self.visited)} visited)", self.args.verbose)

            # Fetch batch concurrently
            responses = await self.client.get_batch(batch)

            for resp in responses:
                if resp is None or resp.status_code != 200:
                    continue

                # Cache the page text
                self.page_cache[resp.url] = resp.text

                # Extract pattern matches
                matches = self.client.grep(resp.text, pattern, group)
                all_matches.extend(matches)

                # Discover new URLs to crawl
                new_urls = self._extract_urls(resp.text)
                for new_url in new_urls:
                    if self._should_crawl(new_url):
                        queue.append(new_url)

        return list(set(all_matches))

    async def fetch_and_grep(self, url: str, pattern: str, group: int = 0) -> list[str]:
        """Fetch a single URL and extract regex matches."""
        resp = await self.client.get(url)
        if resp is None:
            return []
        return self.client.grep(resp.text, pattern, group)

    async def fetch(self, url: str):
        """Fetch a single URL, return Response."""
        return await self.client.get(url)

    async def check_exists(self, url: str) -> bool | None:
        """Check if a URL exists (returns True/False/None for error)."""
        resp = await self.client.get(url)
        if resp is None:
            return None
        return resp.status_code in (200, 301, 302, 403)
