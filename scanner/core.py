"""
WordPress Core version detection.

Checks multiple sources for the WP version, then picks the most frequent finding.
"""

import re
from collections import Counter

from scanner.crawler import Crawler
from lib.output import section, found, notfound, info, warn, verbose, vuln


VERSION_RE = re.compile(r'^[1-9]\d{0,2}\.\d{1,3}(\.\d{1,3})?$')


def is_valid_version(v: str | None) -> bool:
    if not v or not isinstance(v, str):
        return False
    return bool(VERSION_RE.match(v.strip()))


def best_guess(findings: list[str]) -> str | None:
    valid = [v for v in findings if is_valid_version(v)]
    if not valid:
        return None
    counter = Counter(valid)
    return counter.most_common(1)[0][0]


class CoreScanner:
    """Detects WordPress core version."""

    def __init__(self, crawler: Crawler, args):
        self.crawler = crawler
        self.args = args
        self.findings: list[str] = []

    async def scan(self) -> dict:
        section("WordPress Core")

        result = {
            "version": None,
            "version_sources": [],
            "interesting_files": [],
        }

        # Run all version detection methods concurrently
        checks = [
            self._check_meta_generator(),
            self._check_feeds(),
            self._check_login_page(),
            self._check_install_page(),
            self._check_404_page(),
            self._check_readme_html(),
            self._check_rest_api_root(),
            self._check_link_header(),
            self._check_opml_generator(),
            self._check_wp_includes_ver(),
        ]

        import asyncio
        await asyncio.gather(*checks)

        version = best_guess(self.findings)
        result["version"] = version
        result["version_sources"] = list(set(self.findings))

        # Check interesting files
        interesting = await self._check_interesting_files()
        result["interesting_files"] = interesting

        return result

    async def _add_findings(self, source: str, matches: list[str]):
        for m in matches:
            m = m.strip()
            if is_valid_version(m):
                self.findings.append(m)
        # Log unique findings only
        unique_new = set(m.strip() for m in matches if is_valid_version(m.strip()))
        for v in unique_new:
            verbose(f"Version from {source}: {v}", self.args.verbose)

    # ── Meta generator tag on index ────────────────────────────────

    async def _check_meta_generator(self):
        pattern = r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([0-9]+\.[0-9]+\.?[0-9]*)["\']'
        matches = await self.crawler.fetch_and_grep(self.args.target + "/", pattern, 1)
        await self._add_findings("meta generator", matches)

    # ── RSS / Atom / RDF feeds ─────────────────────────────────────

    async def _check_feeds(self):
        feed_paths = [
            "/feed", "/feed/rss", "/?feed=rss",
            "/feed/rdf", "/?feed=rdf",
            "/feed/atom", "/?feed=atom",
        ]
        # RSS/RDF pattern
        rss_pattern = r'<generator>https?://wordpress\.org/\?v=([0-9]+\.[0-9]+\.?[0-9]*)</generator>'
        # Atom pattern
        atom_pattern = r'<generator[^>]+version=["\']([0-9]+\.[0-9]+\.?[0-9]*)["\']'

        import asyncio
        tasks = []
        for path in feed_paths:
            url = self.args.target + path
            pat = atom_pattern if "atom" in path else rss_pattern
            tasks.append(self.crawler.fetch_and_grep(url, pat, 1))

        results = await asyncio.gather(*tasks)
        for i, matches in enumerate(results):
            source = f"feed ({feed_paths[i]})"
            await self._add_findings(source, matches)

    # ── Login page CSS/JS ver= params ──────────────────────────────

    async def _check_login_page(self):
        pattern = r'wp-(?:includes|admin)/[^"\']+\?ver=([0-9]+\.[0-9]+\.?[0-9]*)'
        matches = await self.crawler.fetch_and_grep(
            self.args.target + "/wp-login.php", pattern, 1
        )
        await self._add_findings("wp-login.php", matches)

    # ── Install page ───────────────────────────────────────────────

    async def _check_install_page(self):
        pattern = r'wp-(?:includes|admin)/[^"\']+\?ver=([0-9]+\.[0-9]+\.?[0-9]*)'
        matches = await self.crawler.fetch_and_grep(
            self.args.target + "/wp-admin/install.php", pattern, 1
        )
        await self._add_findings("install.php", matches)

    # ── 404 page ───────────────────────────────────────────────────

    async def _check_404_page(self):
        import secrets
        random_path = f"/{secrets.token_hex(8)}/{secrets.token_hex(8)}/"
        pattern = r'wp-(?:includes|admin)/[^"\']+\?ver=([0-9]+\.[0-9]+\.?[0-9]*)'
        matches = await self.crawler.fetch_and_grep(
            self.args.target + random_path, pattern, 1
        )
        await self._add_findings("404 page", matches)

    # ── readme.html ────────────────────────────────────────────────

    async def _check_readme_html(self):
        resp = await self.crawler.fetch(self.args.target + "/readme.html")
        if resp and resp.status_code == 200:
            pattern = r'Version\s+([0-9]+\.[0-9]+\.?[0-9]*)'
            matches = self.crawler.client.grep(resp.text, pattern, 1)
            await self._add_findings("readme.html", matches)

    # ── REST API root ──────────────────────────────────────────────

    async def _check_rest_api_root(self):
        resp = await self.crawler.fetch(self.args.target + "/wp-json/")
        if resp and resp.status_code == 200:
            # The root REST response includes WP version in the 'name' or
            # sometimes the response itself reveals capabilities
            # But mostly we look for "namespaces" to discover plugins
            import json
            try:
                data = json.loads(resp.text)
                # Some configs expose version in the description or via oembed
                if "gmt_offset" in data or "namespaces" in data:
                    verbose("REST API root accessible (useful for plugin discovery)", self.args.verbose)
            except (json.JSONDecodeError, KeyError):
                pass

    # ── Link header ────────────────────────────────────────────────

    async def _check_link_header(self):
        resp = await self.crawler.fetch(self.args.target + "/")
        if resp:
            link = resp.headers.get("link", "")
            if "api.w.org" in link:
                verbose("Link header confirms WordPress (api.w.org)", self.args.verbose)

            # X-Redirect-By header
            xrb = resp.headers.get("x-redirect-by", "")
            if "wordpress" in xrb.lower():
                verbose("X-Redirect-By header confirms WordPress", self.args.verbose)

    # ── OPML Generator ──────────────────────────────────────────

    async def _check_opml_generator(self):
        """Check wp-links-opml.php for version in generator attribute."""
        resp = await self.crawler.fetch(self.args.target + "/wp-links-opml.php")
        if resp and resp.status_code == 200:
            pattern = r'generator="[Ww]ord[Pp]ress/([0-9]+\.[0-9]+\.?[0-9]*)"'
            matches = self.crawler.client.grep(resp.text, pattern, 1)
            await self._add_findings("opml generator", matches)

    # ── wp-includes ?ver= parameters ────────────────────────────

    async def _check_wp_includes_ver(self):
        """Extract WP version from ?ver= params on wp-includes CSS/JS in homepage."""
        resp = await self.crawler.fetch(self.args.target + "/")
        if not resp or resp.status_code != 200:
            return

        # Same files WPScan checks for "Most Common Wp Includes Query Parameter"
        wp_includes_files = [
            "wp-includes/js/wp-embed.min.js",
            "wp-includes/css/dist/block-library/style.min.css",
            "wp-includes/css/dist/block-library/style.css",
            "wp-includes/css/dashicons.min.css",
            "wp-includes/js/comment-reply.min.js",
        ]

        for f in wp_includes_files:
            pattern = re.escape(f) + r'\?ver=([0-9]+\.[0-9]+\.?[0-9]*)'
            matches = re.findall(pattern, resp.text)
            for m in matches:
                if is_valid_version(m):
                    self.findings.append(m)
                    verbose(f"Version from wp-includes ver param ({f}): {m}", self.args.verbose)

    # ── Interesting files ──────────────────────────────────────────

    async def _check_interesting_files(self) -> list[dict]:
        """Check for files that shouldn't be publicly accessible."""
        interesting = []

        # We need a baseline 404 response to detect soft 404s
        import secrets
        baseline_url = self.args.target + f"/{secrets.token_hex(16)}.{secrets.token_hex(4)}"
        baseline_resp = await self.crawler.fetch(baseline_url)
        baseline_length = len(baseline_resp.text) if baseline_resp else 0
        baseline_status = baseline_resp.status_code if baseline_resp else 404

        files_to_check = [
            ("readme.html", "WordPress readme - may reveal version", "info"),
            ("license.txt", "WordPress license file", "info"),
            ("wp-content/debug.log", "Debug log - may contain sensitive info", "high"),
            (".git/HEAD", "Git repository exposed", "high"),
            (".svn/entries", "SVN repository exposed", "high"),
            (".env", "Environment file - may contain credentials", "critical"),
            ("wp-admin/install.php", "Installation script accessible", "critical"),
            ("xmlrpc.php", "XML-RPC endpoint", "info"),
            ("wp-content/uploads/", "Uploads directory listing", "medium"),
            ("wp-content/plugins/", "Plugins directory listing", "medium"),
            ("wp-content/themes/", "Themes directory listing", "medium"),
            ("wp-content/mu-plugins/", "Must-Use Plugins directory", "info"),
        ]

        import asyncio
        tasks = []
        for filename, description, severity in files_to_check:
            url = self.args.target + "/" + filename
            tasks.append(self.crawler.fetch(url))

        responses = await asyncio.gather(*tasks)

        for (filename, description, severity), resp in zip(files_to_check, responses):
            result = self._validate_interesting_file(
                filename, description, severity, resp,
                baseline_length, baseline_status
            )
            if result:
                interesting.append(result)

        # Config backups and DB exports only in aggressive mode
        if self.args.aggressive >= 1:
            config_results = await self._check_config_backups(baseline_length, baseline_status)
            interesting.extend(config_results)

            db_results = await self._check_db_exports(baseline_length, baseline_status)
            interesting.extend(db_results)

        return interesting

    def _validate_interesting_file(
        self, filename: str, description: str, severity: str,
        resp, baseline_length: int, baseline_status: int
    ) -> dict | None:
        """Validate a single interesting file response. Returns entry or None."""
        if resp is None:
            return None

        is_interesting = False

        # Skip redirects
        if resp.was_redirected:
            verbose(f"Skipping {filename} (redirected)", self.args.verbose)
            return None

        # Skip non-200 (with exceptions)
        if resp.status_code != 200:
            if filename == "xmlrpc.php" and (
                resp.status_code == 405 or
                "XML-RPC server accepts POST requests only" in resp.text
            ):
                is_interesting = True
                severity = "info"
            else:
                return None

        # Skip soft 404s
        if resp.status_code == 200 and baseline_status == 200:
            length_diff = abs(len(resp.text) - baseline_length)
            if length_diff < 200:
                verbose(f"Skipping {filename} (soft 404)", self.args.verbose)
                return None

        # Content-specific validation
        if resp.status_code == 200:
            if "wp-config" in filename:
                config_indicators = ["DB_NAME", "DB_USER", "DB_PASSWORD", "<?php", "define("]
                if not any(ind in resp.text for ind in config_indicators):
                    verbose(f"Skipping {filename} (no config content)", self.args.verbose)
                    return None

            elif filename == ".git/HEAD":
                if not resp.text.strip().startswith("ref:"):
                    verbose(f"Skipping {filename} (not a git HEAD)", self.args.verbose)
                    return None

            elif filename == ".svn/entries":
                if not resp.text.strip()[:2].isdigit():
                    verbose(f"Skipping {filename} (not SVN entries)", self.args.verbose)
                    return None

            elif filename == ".env":
                env_pattern = r'^[A-Z_]+=.+'
                if not re.search(env_pattern, resp.text, re.MULTILINE):
                    verbose(f"Skipping {filename} (not an env file)", self.args.verbose)
                    return None

            elif filename == "wp-content/debug.log":
                if "PHP" not in resp.text and "Warning" not in resp.text and "Error" not in resp.text:
                    verbose(f"Skipping {filename} (not a debug log)", self.args.verbose)
                    return None

            elif filename.endswith("/"):
                if "Index of" not in resp.text and "<title>Index" not in resp.text:
                    # mu-plugins: even without directory listing, if it returns 200 it exists
                    if filename == "wp-content/mu-plugins/":
                        is_interesting = True
                    else:
                        return None

            elif filename == "wp-admin/install.php":
                text_lower = resp.text.lower()
                if ("already installed" in text_lower or
                        "log in" in text_lower or
                        "wp-login.php" in text_lower):
                    verbose(f"Skipping {filename} (WordPress already installed)", self.args.verbose)
                    return None
                if "setup-config.php" in text_lower or "select a default language" in text_lower:
                    is_interesting = True
                else:
                    return None

            elif filename in ("readme.html", "license.txt"):
                is_interesting = True

            else:
                is_interesting = True

            if not is_interesting and resp.status_code == 200:
                is_interesting = True

        if is_interesting:
            entry = {
                "file": filename,
                "description": description,
                "status_code": resp.status_code,
                "severity": severity,
            }
            printer = {"critical": vuln, "high": vuln, "medium": warn, "low": info, "info": info}
            printer.get(severity, info)(filename, description)
            return entry

        return None

    async def _check_config_backups(self, baseline_length: int, baseline_status: int) -> list[dict]:
        """Check for wp-config backup files using expanded wordlist."""
        from pathlib import Path
        data_dir = Path(__file__).parent.parent / "data"
        wordlist_path = data_dir / "config_backups.txt"

        if not wordlist_path.exists():
            return []

        with open(wordlist_path) as f:
            filenames = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        results = []
        batch_size = self.args.concurrency * 2

        for i in range(0, len(filenames), batch_size):
            batch = filenames[i:i + batch_size]
            urls = [self.args.target + "/" + fn for fn in batch]

            import asyncio
            responses = await self.crawler.client.get_batch(urls, use_cache=True)

            for fn, resp in zip(batch, responses):
                if resp is None or resp.was_redirected or resp.status_code != 200:
                    continue

                # Soft 404 check
                if baseline_status == 200:
                    if abs(len(resp.text) - baseline_length) < 200:
                        continue

                # Must contain actual config content
                config_indicators = ["DB_NAME", "DB_USER", "DB_PASSWORD", "<?php", "define("]
                if any(ind in resp.text for ind in config_indicators):
                    entry = {
                        "file": fn,
                        "description": "Config backup - CREDENTIALS EXPOSED",
                        "status_code": 200,
                        "severity": "critical",
                    }
                    results.append(entry)
                    vuln(f"[CRITICAL] {fn}", "Config backup - CREDENTIALS EXPOSED")

        verbose(f"Config backups: checked {len(filenames)} paths, {len(results)} found", self.args.verbose)
        return results

    async def _check_db_exports(self, baseline_length: int, baseline_status: int) -> list[dict]:
        """Check for database export files left in the webroot."""
        from pathlib import Path
        from urllib.parse import urlparse
        data_dir = Path(__file__).parent.parent / "data"
        wordlist_path = data_dir / "db_exports.txt"

        if not wordlist_path.exists():
            return []

        # Get domain name for {domain_name} substitution
        parsed = urlparse(self.args.target)
        domain = parsed.hostname or ""
        domain_name = domain.split(".")[0] if domain else "wordpress"

        with open(wordlist_path) as f:
            raw_filenames = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        # Substitute {domain_name} and also try with full domain
        filenames = []
        for fn in raw_filenames:
            if "{domain_name}" in fn:
                filenames.append(fn.replace("{domain_name}", domain_name))
                filenames.append(fn.replace("{domain_name}", domain.replace(".", "_")))
            else:
                filenames.append(fn)

        results = []
        batch_size = self.args.concurrency * 2

        for i in range(0, len(filenames), batch_size):
            batch = filenames[i:i + batch_size]
            urls = [self.args.target + "/" + fn for fn in batch]

            import asyncio
            responses = await self.crawler.client.get_batch(urls, use_cache=True)

            for fn, resp in zip(batch, responses):
                if resp is None or resp.was_redirected or resp.status_code != 200:
                    continue

                # Soft 404 check
                if baseline_status == 200:
                    if abs(len(resp.text) - baseline_length) < 200:
                        continue

                # Validate it looks like SQL
                sql_indicators = [
                    "CREATE TABLE", "INSERT INTO", "DROP TABLE",
                    "-- MySQL", "-- Dump", "BEGIN TRANSACTION",
                    "wp_options", "wp_posts", "wp_users",
                ]
                if any(ind in resp.text[:5000] for ind in sql_indicators):
                    entry = {
                        "file": fn,
                        "description": "Database export - FULL DATABASE EXPOSED",
                        "status_code": 200,
                        "severity": "critical",
                    }
                    results.append(entry)
                    vuln(f"[CRITICAL] {fn}", "Database export - FULL DATABASE EXPOSED")

        verbose(f"DB exports: checked {len(filenames)} paths, {len(results)} found", self.args.verbose)
        return results
