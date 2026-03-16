"""
WordPress user enumeration.

Multiple discovery methods run concurrently:
  - REST API
  - oEmbed
  - Author archives
  - RSS/Atom feeds
  - Sitemaps
  - Author ID bruteforce
  - Login error messages (aggressive)
"""

import asyncio
import json
import re
from urllib.parse import quote

from scanner.crawler import Crawler
from lib.output import section, found, notfound, info, warn, verbose


class UserScanner:
    """Enumerates WordPress users."""

    def __init__(self, crawler: Crawler, args):
        self.crawler = crawler
        self.args = args

    async def scan(self) -> list[dict]:
        section("Users")
        info("Enumerating users...")

        # Run all methods concurrently
        results = await asyncio.gather(
            self._from_rest_api(),
            self._from_author_links(),
            self._from_feeds(),
            self._from_sitemaps(),
            self._from_oembed(),
            self._from_author_id_bruteforce(),
        )

        # Merge all findings
        users: dict[str, dict] = {}
        for method_results in results:
            for user in method_results:
                slug = user.get("slug", "").lower().strip()
                if not slug or len(slug) < 1:
                    continue

                if slug not in users:
                    users[slug] = {"slug": slug, "sources": [], "id": None, "display_name": None}

                # Merge info
                if user.get("id") and not users[slug]["id"]:
                    users[slug]["id"] = user["id"]
                if user.get("display_name") and not users[slug]["display_name"]:
                    users[slug]["display_name"] = user["display_name"]
                for src in user.get("sources", []):
                    if src not in users[slug]["sources"]:
                        users[slug]["sources"].append(src)

        user_list = list(users.values())

        if user_list:
            for u in sorted(user_list, key=lambda x: x["slug"]):
                detail_parts = []
                if u["id"]:
                    detail_parts.append(f"id:{u['id']}")
                if u["display_name"] and u["display_name"] != u["slug"]:
                    detail_parts.append(f'name:"{u["display_name"]}"')
                detail_parts.append(f"via:{','.join(u['sources'])}")
                found(f"User: {u['slug']}", f"({' | '.join(detail_parts)})")
        else:
            notfound("No users found")

        # Aggressive: login enumeration
        if self.args.aggressive and user_list:
            await self._check_login_enumeration(user_list)

        return user_list

    # ── REST API ───────────────────────────────────────────────────

    async def _from_rest_api(self) -> list[dict]:
        """Fetch users from /wp-json/wp/v2/users (paginated)."""
        users = []
        page = 1
        max_pages = 10

        while page <= max_pages:
            url = f"{self.args.target}/wp-json/wp/v2/users?per_page=100&page={page}"
            resp = await self.crawler.fetch(url)

            if not resp or resp.status_code != 200:
                # Also try the non-pretty-permalink version
                if page == 1:
                    url = f"{self.args.target}/?rest_route=/wp/v2/users&per_page=100"
                    resp = await self.crawler.fetch(url)
                    if not resp or resp.status_code != 200:
                        break
                else:
                    break

            try:
                data = json.loads(resp.text)
            except json.JSONDecodeError:
                break

            if not isinstance(data, list) or len(data) == 0:
                break

            for entry in data:
                if isinstance(entry, dict) and "slug" in entry:
                    users.append({
                        "slug": entry["slug"],
                        "id": entry.get("id"),
                        "display_name": entry.get("name"),
                        "sources": ["rest-api"],
                    })

            # Check if there are more pages
            total_pages = int(resp.headers.get("x-wp-totalpages", 1))
            if page >= total_pages:
                break
            page += 1

        verbose(f"REST API: found {len(users)} user(s)", self.args.verbose)
        return users

    # ── Author archive links ───────────────────────────────────────

    async def _from_author_links(self) -> list[dict]:
        """Find /author/{slug} links by crawling the site."""
        pattern = r'/author/([a-zA-Z0-9_.-]+?)(?:/|"|\'|\?)'
        matches = await self.crawler.crawl(pattern, 1)

        users = []
        for slug in set(matches):
            slug = slug.strip().lower()
            if slug and len(slug) > 0:
                users.append({"slug": slug, "sources": ["author-link"]})

        verbose(f"Author links: found {len(users)} user(s)", self.args.verbose)
        return users

    # ── RSS / Atom feeds ───────────────────────────────────────────

    async def _from_feeds(self) -> list[dict]:
        """Extract author names from RSS and Atom feeds."""
        users = []

        # RSS feed: <dc:creator><![CDATA[username]]></dc:creator>
        rss_url = self.args.target + "/feed/"
        rss_pattern = r'<dc:creator><!\[CDATA\[(.*?)\]\]></dc:creator>'
        matches = await self.crawler.fetch_and_grep(rss_url, rss_pattern, 1)
        for m in set(matches):
            users.append({"slug": m.strip(), "sources": ["rss-feed"]})

        # Atom feed: <author><name>username</name></author>
        atom_url = self.args.target + "/feed/atom/"
        atom_pattern = r'<author>\s*<name>(.*?)</name>'
        matches = await self.crawler.fetch_and_grep(atom_url, atom_pattern, 1)
        for m in set(matches):
            users.append({"slug": m.strip(), "sources": ["atom-feed"]})

        verbose(f"Feeds: found {len(users)} user(s)", self.args.verbose)
        return users

    # ── Sitemaps ───────────────────────────────────────────────────

    async def _from_sitemaps(self) -> list[dict]:
        """Extract users from WordPress and Yoast sitemaps."""
        users = []

        sitemap_sources = [
            # WP core sitemap
            (self.args.target + "/wp-sitemap-users-1.xml",
             r'<loc>[^<]*/author/([a-zA-Z0-9_.-]+?)/?</loc>'),
            # Yoast author sitemap
            (self.args.target + "/author-sitemap.xml",
             r'<loc>[^<]*/author/([a-zA-Z0-9_.-]+?)/?</loc>'),
        ]

        tasks = [self.crawler.fetch_and_grep(url, pat, 1) for url, pat in sitemap_sources]
        results = await asyncio.gather(*tasks)

        for matches in results:
            for m in set(matches):
                users.append({"slug": m.strip(), "sources": ["sitemap"]})

        verbose(f"Sitemaps: found {len(users)} user(s)", self.args.verbose)
        return users

    # ── oEmbed ─────────────────────────────────────────────────────

    async def _from_oembed(self) -> list[dict]:
        """Extract author names from oEmbed responses."""
        users = []

        # Find oEmbed URLs from crawled pages
        pattern = r'<link[^>]+type=["\']application/json\+oembed["\'][^>]+href=["\']([^"\']+)["\']'

        # Check the main page first
        resp = await self.crawler.fetch(self.args.target + "/")
        if not resp:
            return users

        oembed_urls = self.crawler.client.grep(resp.text, pattern, 1)

        # Fetch up to 5 oEmbed URLs
        for url in oembed_urls[:5]:
            resp = await self.crawler.fetch(url)
            if resp and resp.status_code == 200:
                try:
                    data = json.loads(resp.text)
                    author = data.get("author_name", "").strip()
                    if author:
                        users.append({"slug": author, "sources": ["oembed"]})
                except json.JSONDecodeError:
                    pass

        verbose(f"oEmbed: found {len(users)} user(s)", self.args.verbose)
        return users

    # ── Author ID bruteforce ───────────────────────────────────────

    async def _from_author_id_bruteforce(self) -> list[dict]:
        """Enumerate users via /?author=N redirect trick."""
        users = []

        # Start with IDs 1-10, expand range when we find users
        max_id = 10
        current_id = 1
        consecutive_misses = 0

        while current_id <= max_id and current_id <= 1000:
            # Batch requests
            batch_size = min(10, max_id - current_id + 1)
            batch_ids = list(range(current_id, current_id + batch_size))
            urls = [f"{self.args.target}/?author={aid}" for aid in batch_ids]

            responses = await self.crawler.client.get_batch(urls, use_cache=True)

            found_in_batch = False
            for aid, resp in zip(batch_ids, responses):
                if not resp:
                    continue

                slug = None

                if resp.status_code in (200, 301, 302):
                    # Try to extract username from the final URL or body
                    patterns = [
                        (r'/author/([a-zA-Z0-9_.-]+?)/', resp.url),
                        (r'/author/([a-zA-Z0-9_.-]+?)/', resp.text),
                        (r'<body\s+class="[^"]*author-([a-zA-Z0-9_-]+)', resp.text),
                        (r'Posts by (.*?) Feed', resp.text),
                    ]

                    for pat, source in patterns:
                        match = re.search(pat, source, re.IGNORECASE)
                        if match:
                            slug = match.group(1).strip().lower()
                            break

                if slug:
                    users.append({
                        "slug": slug,
                        "id": aid,
                        "sources": ["id-bruteforce"],
                    })
                    found_in_batch = True
                    consecutive_misses = 0

                    # Expand search range
                    if aid >= max_id - 2:
                        max_id = aid + 10
                else:
                    consecutive_misses += 1

            current_id += batch_size

            # Stop if we've had too many consecutive misses
            if consecutive_misses >= 20:
                break

        verbose(f"ID bruteforce: found {len(users)} user(s) (checked up to ID {current_id - 1})", self.args.verbose)
        return users

    # ── Login error message enumeration ────────────────────────────

    async def _check_login_enumeration(self, known_users: list[dict]):
        """Check if wp-login.php reveals whether usernames are valid."""
        info("Checking login error message enumeration...")

        # Test with a known user
        known_slug = known_users[0]["slug"]

        # Test with a definitely-invalid user
        import secrets
        fake_user = f"definitely_not_a_user_{secrets.token_hex(4)}"

        login_url = self.args.target + "/wp-login.php"

        resp_known = await self.crawler.client.post(
            login_url,
            data=f"log={quote(known_slug)}&pwd=wrongpassword&wp-submit=Log+In",
            content_type="application/x-www-form-urlencoded",
        )
        resp_fake = await self.crawler.client.post(
            login_url,
            data=f"log={quote(fake_user)}&pwd=wrongpassword&wp-submit=Log+In",
            content_type="application/x-www-form-urlencoded",
        )

        if resp_known and resp_fake:
            # If the error messages differ, the login form leaks username validity
            if resp_known.text != resp_fake.text:
                warn("Login form reveals valid usernames (different error messages for valid vs invalid)")
            else:
                info("Login form does not differentiate between valid and invalid usernames")
