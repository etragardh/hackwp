"""
WordPress theme detection.

Identifies active theme slug and version.
"""

import re

from scanner.crawler import Crawler
from lib.output import section, found, notfound, info, verbose


class ThemeScanner:
    """Detects the active WordPress theme."""

    def __init__(self, crawler: Crawler, args):
        self.crawler = crawler
        self.args = args

    async def scan(self) -> dict:
        section("Theme")

        result = {
            "slug": None,
            "version": None,
            "parent_theme": None,
        }

        slug = await self._detect_slug()
        result["slug"] = slug

        if slug:
            version = await self._detect_version(slug)
            result["version"] = version

            parent = await self._detect_parent_theme(slug)
            if parent:
                result["parent_theme"] = parent
                info("Parent theme:", parent)
        else:
            notfound("Theme: could not determine")

        return result

    async def _detect_slug(self) -> str | None:
        """Detect theme slug from multiple sources."""

        # Method 1: Regex on index page
        resp = await self.crawler.fetch(self.args.target + "/")
        if resp and resp.status_code == 200:
            # Look for wp-content/themes/{slug}/ in stylesheet/script links
            match = re.search(r'wp-content/themes/([a-zA-Z0-9_-]+)/', resp.text)
            if match:
                return match.group(1)

        # Method 2: Check response body of a 404 page
        import secrets
        resp = await self.crawler.fetch(self.args.target + f"/{secrets.token_hex(8)}/")
        if resp and resp.status_code in (200, 404):
            match = re.search(r'wp-content/themes/([a-zA-Z0-9_-]+)/', resp.text)
            if match:
                return match.group(1)

        return None

    async def _detect_version(self, slug: str) -> str | None:
        """Detect theme version from style.css header."""

        # Method 1: style.css Version header
        url = f"{self.args.target}/wp-content/themes/{slug}/style.css"
        resp = await self.crawler.fetch(url)
        if resp and resp.status_code == 200:
            match = re.search(r'Version:\s*(.+?)[\r\n]', resp.text, re.IGNORECASE)
            if match:
                version = match.group(1).strip()
                if version:
                    return version

        # Method 2: ?ver= parameter on theme CSS/JS from index page
        resp = await self.crawler.fetch(self.args.target + "/")
        if resp and resp.status_code == 200:
            pattern = rf'wp-content/themes/{re.escape(slug)}/[^"\']*\?ver=([0-9]+\.[0-9]+\.?[0-9]*)'
            matches = self.crawler.client.grep(resp.text, pattern, 1)
            if matches:
                return matches[0]

        return None

    async def _detect_parent_theme(self, slug: str) -> str | None:
        """Check if the theme is a child theme by looking for Template: in style.css."""
        url = f"{self.args.target}/wp-content/themes/{slug}/style.css"
        resp = await self.crawler.fetch(url)
        if resp and resp.status_code == 200:
            match = re.search(r'Template:\s*(.+?)[\r\n]', resp.text, re.IGNORECASE)
            if match:
                parent = match.group(1).strip()
                if parent and parent != slug:
                    return parent
        return None
