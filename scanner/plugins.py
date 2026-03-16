"""
WordPress plugin enumeration.

Two modes:
  - Passive: crawl the site and extract plugin slugs from wp-content/plugins/ references
  - Aggressive: probe known plugin paths from a wordlist
"""

import asyncio
import json
import re
from collections import Counter
from pathlib import Path

from scanner.crawler import Crawler
from scanner.core import is_valid_version
from lib.output import section, found, notfound, info, warn, verbose, console


def _load_wordlist(filename: str) -> list[str]:
    """Load a wordlist from the data directory."""
    data_dir = Path(__file__).parent.parent / "data"
    filepath = data_dir / filename
    if not filepath.exists():
        return []
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# 1500 most popular WordPress plugins (from WPScan metadata)
POPULAR_PLUGINS = _load_wordlist("popular_plugins.txt")


class PluginScanner:
    """Enumerates WordPress plugins and their versions."""

    def __init__(self, crawler: Crawler, args, core_version: str | None = None):
        self.crawler = crawler
        self.args = args
        self.core_version = core_version
        self._head_supported = None  # Will be probed at scan time

    async def _probe_head_support(self) -> bool:
        """Test if HEAD requests work reliably on this server.
        
        Sends HEAD to a known-existing path and a non-existing path,
        checks that the status codes make sense.
        """
        # HEAD a path that should exist (wp-content/plugins/ or wp-login.php)
        existing_url = self.args.target + "/wp-login.php"
        missing_url = self.args.target + "/wp-content/plugins/this-plugin-does-not-exist-xyz123/"

        existing_resp = await self.crawler.client.head(existing_url)
        missing_resp = await self.crawler.client.head(missing_url)

        if not existing_resp:
            verbose("HEAD probe: no response for existing path, falling back to GET", self.args.verbose)
            return False

        # Existing path should return 200 or 302 (login redirect)
        if existing_resp.status_code not in (200, 301, 302, 403):
            verbose(f"HEAD probe: unexpected status {existing_resp.status_code} for existing path", self.args.verbose)
            return False

        # Missing path should return 404 (or at least different from existing)
        if missing_resp and missing_resp.status_code == 404:
            verbose("HEAD probe: HEAD requests working correctly", self.args.verbose)
            return True

        # If both return 200, HEAD is unreliable (soft 404s)
        if missing_resp and missing_resp.status_code == existing_resp.status_code:
            verbose(f"HEAD probe: both paths return {existing_resp.status_code}, falling back to GET", self.args.verbose)
            return False

        verbose("HEAD probe: HEAD requests appear to work", self.args.verbose)
        return True

    async def scan(self, matcher=None) -> dict:
        section("Plugins")
        info("Enumerating plugins (crawling site)...")

        plugins = {}

        # Step 1: Crawl-based discovery
        crawled = await self._crawl_plugins()
        info(f"Found {len(crawled)} plugin(s) via crawling")

        # Get versions concurrently
        if crawled:
            version_tasks = {slug: self._detect_version(slug) for slug in crawled}
            results = await asyncio.gather(*version_tasks.values())
            for slug, version in zip(version_tasks.keys(), results):
                plugins[slug] = version

        # Step 2: REST API namespace discovery
        rest_plugins = await self._discover_from_rest_api()
        new_from_rest = [s for s in rest_plugins if s not in plugins]
        if new_from_rest:
            info(f"Found {len(new_from_rest)} new plugin(s) via REST API")
        for slug in rest_plugins:
            if slug not in plugins:
                version = await self._detect_version(slug)
                plugins[slug] = version

        # Step 3: Aggressive mode - probe plugin directories
        if self.args.aggressive >= 1:
            # Probe HEAD support before sending many requests
            self._head_supported = await self._probe_head_support()
            if self._head_supported:
                info("Using HEAD requests for faster probing")
            else:
                info("HEAD requests not reliable, using GET")

            info("Aggressive scan: probing popular plugin paths...")
            aggressive_plugins = await self._aggressive_probe(set(plugins.keys()))
            new_from_aggressive = {s: v for s, v in aggressive_plugins.items() if s not in plugins}
            if new_from_aggressive:
                info(f"Found {len(new_from_aggressive)} new plugin(s) via aggressive probing")
            for slug, version in aggressive_plugins.items():
                if slug not in plugins:
                    plugins[slug] = version

        if self.args.aggressive >= 2:
            info("Very aggressive scan: probing all vulnerable plugin slugs from DB...")
            info(" -> This will take a while")
            vuln_plugins = await self._aggressive_probe_vuln_db(set(plugins.keys()))
            new_from_vulndb = {s: v for s, v in vuln_plugins.items() if s not in plugins}
            if new_from_vulndb:
                info(f"Found {len(new_from_vulndb)} new plugin(s) via vuln DB probing")
            for slug, version in vuln_plugins.items():
                if slug not in plugins:
                    plugins[slug] = version

        # Print findings with inline vulnerability info
        output = {}
        if plugins:
            for slug, version in sorted(plugins.items()):
                v_str = version if version else "unknown"
                plugin_vulns = []

                if matcher:
                    plugin_vulns = matcher.find_plugin_vulns(slug, version)

                if not version:
                    potential = len(plugin_vulns)
                    if potential:
                        console.print(f"  [yellow]⚠[/yellow]  Plugin: {slug} [yellow](v: unknown)[/yellow] - {potential} potential vulnerabilities")
                    else:
                        console.print(f"  [yellow]⚠[/yellow]  Plugin: {slug} [yellow](v: unknown)[/yellow]")
                elif plugin_vulns:
                    console.print(f"  [bold red]✗[/bold red]  Plugin: {slug} [red](v: {v_str})[/red]")
                    for v in plugin_vulns:
                        console.print(f"      [dim]↳ {v['title']}[/dim]")
                        parts = []
                        if v.get("cve"):
                            parts.append(v["cve"])
                        if v.get("cvss_score"):
                            rating = f' ({v["cvss_rating"]})' if v.get("cvss_rating") else ""
                            parts.append(f"CVSS: {v['cvss_score']}{rating}")
                        if parts:
                            console.print(f"        [dim]{' | '.join(parts)}[/dim]")
                else:
                    found(f"Plugin: {slug}", f"(v: {v_str})")

                output[slug] = {"version": version, "vulns": plugin_vulns}
        else:
            notfound("No plugins found")

        # MU-Plugins detection
        mu_plugins = await self._crawl_mu_plugins()
        if mu_plugins:
            info(f"Must-Use plugins found: {len(mu_plugins)}")
            for slug, version in sorted(mu_plugins.items()):
                v_str = version if version else "unknown"
                if version:
                    found(f"MU-Plugin: {slug}", f"(v: {v_str})")
                else:
                    console.print(f"  [yellow]⚠[/yellow]  MU-Plugin: {slug} [yellow](v: unknown)[/yellow]")
                output[f"mu:{slug}"] = {"version": version, "vulns": [], "mu_plugin": True}

        return output

    async def _crawl_plugins(self) -> set[str]:
        """Crawl the site for wp-content/plugins/{slug}/ references."""
        pattern = r'wp-content/plugins/([a-zA-Z0-9_-]+)/'
        matches = await self.crawler.crawl(pattern, 1)
        return set(matches)

    async def _crawl_mu_plugins(self) -> dict[str, str | None]:
        """Detect must-use plugins from wp-content/mu-plugins/ references in crawled pages."""
        mu_plugins = {}

        # Look for mu-plugins references in already-crawled pages
        pattern = r'wp-content/mu-plugins/([a-zA-Z0-9_-]+)/[^"\']*?(?:\?ver=([0-9]+\.[0-9]+\.?[0-9]*))?["\']'

        for url, text in self.crawler.page_cache.items():
            matches = re.findall(pattern, text)
            for slug, ver in matches:
                if slug not in mu_plugins:
                    # Filter out version if it matches core WP version
                    if ver and ver != self.core_version and is_valid_version(ver):
                        mu_plugins[slug] = ver
                    elif slug not in mu_plugins:
                        mu_plugins[slug] = None

        # Also check for single-file mu-plugins with slug in the filename
        # e.g., mu-plugins/hwp-training-target.css or mu-plugins/my-plugin.js
        pattern2 = r'wp-content/mu-plugins/([a-zA-Z0-9_-]+)\.[a-z]+\?ver=([0-9]+\.[0-9]+\.?[0-9]*)'
        for url, text in self.crawler.page_cache.items():
            matches = re.findall(pattern2, text)
            for slug, ver in matches:
                if slug not in mu_plugins:
                    if ver and ver != self.core_version and is_valid_version(ver):
                        mu_plugins[slug] = ver
                    elif slug not in mu_plugins:
                        mu_plugins[slug] = None

        return mu_plugins

    async def _discover_from_rest_api(self) -> set[str]:
        """Discover plugins via REST API namespaces."""
        discovered = set()
        resp = await self.crawler.fetch(self.args.target + "/wp-json/")
        if not resp or resp.status_code != 200:
            return discovered

        try:
            data = json.loads(resp.text)
            namespaces = data.get("namespaces", [])
        except (json.JSONDecodeError, AttributeError):
            return discovered

        # Explicit mapping of known REST namespaces to plugin slugs
        namespace_map = {
            "wc/": "woocommerce",
            "yoast/": "wordpress-seo",
            "rankmath/": "seo-by-rank-math",
            "jetpack/": "jetpack",
            "contact-form-7/": "contact-form-7",
            "elementor/": "elementor",
            "fluentform/": "fluentform",
            "wordfence/": "wordfence",
            "acf/": "advanced-custom-fields",
            "mailpoet/": "mailpoet",
            "redirection/": "redirection",
            "wpforms/": "wpforms-lite",
            "buddypress/": "buddypress",
            "bbpress/": "bbpress",
            "tribe/": "the-events-calendar",
            "litespeed/": "litespeed-cache",
            "kadence-blocks/": "kadence-blocks",
            "starter-templates/": "starter-templates",
            "regenerate-thumbnails/": "regenerate-thumbnails",
            "updraftplus/": "updraftplus",
            "sucuri/": "sucuri-scanner",
            "tablepress/": "tablepress",
            "learndash/": "sfwd-lms",
            "learnpress/": "learnpress",
            "edd/": "easy-digital-downloads",
            "instant-images/": "instant-images",
        }

        # Namespaces that are NOT plugins (WP core, WooCommerce internals, themes, etc.)
        ignore_prefixes = {
            "wp/", "wp-site-health/", "wp-block-editor/", "oembed/",
            "wc-admin", "wc-analytics", "wc-telemetry", "wc-admin-email",
            "wccom-site", "wc/store", "wc/private",
        }

        for ns in namespaces:
            # Skip known non-plugin namespaces
            if any(ns.startswith(prefix) or ns == prefix.rstrip("/") for prefix in ignore_prefixes):
                continue

            # Check explicit map first
            matched = False
            for prefix, slug in namespace_map.items():
                if ns.startswith(prefix):
                    discovered.add(slug)
                    verbose(f"Plugin from REST namespace '{ns}': {slug}", self.args.verbose)
                    matched = True
                    break

            if matched:
                continue

            # Generic fallback: namespace that looks like a plugin slug
            # Only accept if we can verify the plugin actually exists
            parts = ns.split("/")
            candidate = parts[0]
            if candidate and re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,}$', candidate):
                # Verify by checking for readme.txt with actual plugin content
                found_it = False
                for readme_name in ("readme.txt", "README.txt"):
                    verify_url = f"{self.args.target}/wp-content/plugins/{candidate}/{readme_name}"
                    verify_resp = await self.crawler.fetch(verify_url)
                    status = self._is_valid_readme_resp(verify_resp)
                    if status in ("valid", "exists"):
                        discovered.add(candidate)
                        verbose(f"Verified plugin from namespace '{ns}': {candidate}", self.args.verbose)
                        found_it = True
                        break
                if not found_it:
                    verbose(f"Skipping namespace '{ns}' (no valid readme)", self.args.verbose)

        return discovered

    async def _aggressive_probe(self, already_found: set[str]) -> dict[str, str | None]:
        """Probe known plugin paths that weren't found via crawling.
        
        If HEAD is supported: HEAD plugin dirs first, then GET readme only for hits.
        Otherwise: GET readme directly (old behavior).
        """
        from rich.progress import Progress, BarColumn, TextColumn, MofNCompleteColumn, TimeRemainingColumn

        to_probe = [slug for slug in POPULAR_PLUGINS if slug not in already_found]

        results = {}
        batch_size = self.args.concurrency * 2

        if self._head_supported:
            # Phase 1: HEAD plugin directories to find candidates
            candidates = []

            with Progress(
                TextColumn("[dim]{task.description}[/dim]"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                TextColumn("[cyan]{task.fields[hits]}[/cyan] hits"),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("HEAD probe", total=len(to_probe), hits=0)

                for i in range(0, len(to_probe), batch_size):
                    batch = to_probe[i:i + batch_size]
                    urls = [f"{self.args.target}/wp-content/plugins/{slug}/" for slug in batch]
                    responses = await self.crawler.client.head_batch(urls)

                    for slug, resp in zip(batch, responses):
                        if resp and resp.status_code in (200, 301, 302, 403):
                            candidates.append(slug)

                    progress.update(task, advance=len(batch), hits=len(candidates))

            if not candidates:
                return results

            verbose(f"HEAD probe found {len(candidates)} candidate plugins, verifying with GET...", self.args.verbose)

            # Phase 2: GET readme.txt for each candidate to verify and get version
            with Progress(
                TextColumn("[dim]{task.description}[/dim]"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                TextColumn("[green]{task.fields[found]}[/green] confirmed"),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Verify plugins", total=len(candidates), found=0)

                for i in range(0, len(candidates), batch_size):
                    batch = candidates[i:i + batch_size]
                    urls = [f"{self.args.target}/wp-content/plugins/{slug}/readme.txt" for slug in batch]
                    responses = await self.crawler.client.get_batch(urls, use_cache=True)

                    retry_slugs = []
                    for slug, resp in zip(batch, responses):
                        status = self._is_valid_readme(resp)
                        if status in ("valid", "exists"):
                            version = await self._detect_version(slug)
                            results[slug] = version
                            verbose(f"Confirmed: {slug}", self.args.verbose)
                        else:
                            retry_slugs.append(slug)

                    # Retry with README.txt (uppercase)
                    if retry_slugs:
                        urls = [f"{self.args.target}/wp-content/plugins/{slug}/README.txt" for slug in retry_slugs]
                        responses = await self.crawler.client.get_batch(urls, use_cache=True)
                        for slug, resp in zip(retry_slugs, responses):
                            status = self._is_valid_readme(resp)
                            if status in ("valid", "exists"):
                                version = await self._detect_version(slug)
                                results[slug] = version
                                verbose(f"Confirmed: {slug} (README.txt)", self.args.verbose)

                    progress.update(task, advance=len(batch), found=len(results))
        else:
            # Fallback: GET-only mode (original behavior)
            with Progress(
                TextColumn("[dim]{task.description}[/dim]"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                TextColumn("[green]{task.fields[found]}[/green] found"),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Popular plugins", total=len(to_probe), found=0)

                for i in range(0, len(to_probe), batch_size):
                    batch = to_probe[i:i + batch_size]
                    urls = [f"{self.args.target}/wp-content/plugins/{slug}/readme.txt" for slug in batch]
                    responses = await self.crawler.client.get_batch(urls, use_cache=True)

                    retry_slugs = []
                    for slug, resp in zip(batch, responses):
                        status = self._is_valid_readme(resp)
                        if status in ("valid", "exists"):
                            version = await self._detect_version(slug)
                            results[slug] = version
                            verbose(f"Aggressive probe found: {slug}", self.args.verbose)
                        else:
                            retry_slugs.append(slug)

                    if retry_slugs:
                        urls = [f"{self.args.target}/wp-content/plugins/{slug}/README.txt" for slug in retry_slugs]
                        responses = await self.crawler.client.get_batch(urls, use_cache=True)
                        for slug, resp in zip(retry_slugs, responses):
                            status = self._is_valid_readme(resp)
                            if status in ("valid", "exists"):
                                version = await self._detect_version(slug)
                                results[slug] = version
                                verbose(f"Aggressive probe found: {slug} (README.txt)", self.args.verbose)

                    progress.update(task, advance=len(batch), found=len(results))

        return results

    @staticmethod
    def _is_valid_readme(resp) -> str:
        """Check if a response indicates a real plugin readme.
        
        Returns:
            'valid' - readme with parseable content
            'exists' - file exists but content not readable (403, etc.)
            'none' - no plugin found
        """
        if not resp:
            return "none"
        
        # 403 = file exists but access denied
        if resp.status_code == 403:
            return "exists"
        
        if resp.status_code != 200:
            return "none"
            
        text_lower = resp.text.lower()
        if any(marker in text_lower for marker in [
            "=== ", "stable tag:", "requires at least:",
            "tested up to:", "contributors:", "== description",
            "== changelog", "== installation",
        ]):
            return "valid"
        
        return "none"

    async def _aggressive_probe_vuln_db(self, already_found: set[str]) -> dict[str, str | None]:
        """Probe all plugin slugs from the vulnerability database."""
        from scanner.vulns import CACHE_DIR, VULN_DB_FILE
        from rich.progress import Progress, BarColumn, TextColumn, MofNCompleteColumn, TimeRemainingColumn
        import json

        if not VULN_DB_FILE.exists():
            warn("Vulnerability database not yet downloaded, skipping -aa probe")
            return {}

        try:
            with open(VULN_DB_FILE, 'r') as f:
                vuln_db = json.load(f)
        except (json.JSONDecodeError, IOError):
            warn("Failed to read vulnerability database")
            return {}

        # Collect unique plugin slugs
        vuln_slugs = set()
        # HackWP format: list of entries with software_type and software_slug
        if isinstance(vuln_db, dict) and "data" in vuln_db:
            entries = vuln_db["data"]
        elif isinstance(vuln_db, list):
            entries = vuln_db
        else:
            entries = []

        for entry in entries:
            if entry.get("software_type") == "plugin" and entry.get("software_slug"):
                vuln_slugs.add(entry["software_slug"])

        to_probe = [slug for slug in vuln_slugs if slug not in already_found]
        info(f"  Probing {len(to_probe)} plugin slugs from vulnerability database...")

        results = {}
        batch_size = self.args.concurrency * 2

        if self._head_supported:
            # Phase 1: HEAD to find candidates
            candidates = []
            with Progress(
                TextColumn("[dim]{task.description}[/dim]"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                TextColumn("[cyan]{task.fields[hits]}[/cyan] hits"),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("HEAD probe (vulnDB)", total=len(to_probe), hits=0)

                for i in range(0, len(to_probe), batch_size):
                    batch = to_probe[i:i + batch_size]
                    urls = [f"{self.args.target}/wp-content/plugins/{slug}/" for slug in batch]
                    responses = await self.crawler.client.head_batch(urls)

                    for slug, resp in zip(batch, responses):
                        if resp and resp.status_code in (200, 301, 302, 403):
                            candidates.append(slug)

                    progress.update(task, advance=len(batch), hits=len(candidates))

            if not candidates:
                return results

            verbose(f"HEAD found {len(candidates)} candidates, verifying...", self.args.verbose)

            # Phase 2: GET readme for candidates only
            with Progress(
                TextColumn("[dim]{task.description}[/dim]"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                TextColumn("[green]{task.fields[found]}[/green] confirmed"),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Verify (vulnDB)", total=len(candidates), found=0)

                for i in range(0, len(candidates), batch_size):
                    batch = candidates[i:i + batch_size]
                    urls = [f"{self.args.target}/wp-content/plugins/{slug}/readme.txt" for slug in batch]
                    responses = await self.crawler.client.get_batch(urls, use_cache=True)

                    retry_slugs = []
                    for slug, resp in zip(batch, responses):
                        status = self._is_valid_readme(resp)
                        if status in ("valid", "exists"):
                            version = await self._detect_version(slug)
                            results[slug] = version
                            verbose(f"VulnDB confirmed: {slug}", self.args.verbose)
                        else:
                            retry_slugs.append(slug)

                    if retry_slugs:
                        urls = [f"{self.args.target}/wp-content/plugins/{slug}/README.txt" for slug in retry_slugs]
                        responses = await self.crawler.client.get_batch(urls, use_cache=True)
                        for slug, resp in zip(retry_slugs, responses):
                            status = self._is_valid_readme(resp)
                            if status in ("valid", "exists"):
                                version = await self._detect_version(slug)
                                results[slug] = version
                                verbose(f"VulnDB confirmed: {slug} (README.txt)", self.args.verbose)

                    progress.update(task, advance=len(batch), found=len(results))
        else:
            # Fallback: GET-only mode
            with Progress(
                TextColumn("[dim]{task.description}[/dim]"),
                BarColumn(bar_width=30),
                MofNCompleteColumn(),
                TextColumn("[green]{task.fields[found]}[/green] found"),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Probing", total=len(to_probe), found=0)

                for i in range(0, len(to_probe), batch_size):
                    batch = to_probe[i:i + batch_size]
                    urls = [f"{self.args.target}/wp-content/plugins/{slug}/readme.txt" for slug in batch]
                    responses = await self.crawler.client.get_batch(urls, use_cache=True)

                    retry_slugs = []
                    for slug, resp in zip(batch, responses):
                        status = self._is_valid_readme(resp)
                        if status in ("valid", "exists"):
                            version = await self._detect_version(slug)
                            results[slug] = version
                            verbose(f"VulnDB probe found: {slug}", self.args.verbose)
                        else:
                            retry_slugs.append(slug)

                    if retry_slugs:
                        urls = [f"{self.args.target}/wp-content/plugins/{slug}/README.txt" for slug in retry_slugs]
                        responses = await self.crawler.client.get_batch(urls, use_cache=True)
                        for slug, resp in zip(retry_slugs, responses):
                            status = self._is_valid_readme(resp)
                            if status in ("valid", "exists"):
                                version = await self._detect_version(slug)
                                results[slug] = version
                                verbose(f"VulnDB probe found: {slug} (README.txt)", self.args.verbose)

                    progress.update(task, advance=len(batch), found=len(results))

        return results

    async def _detect_version(self, slug: str) -> str | None:
        """Detect plugin version using multiple methods, return best guess."""
        candidates = []

        # Method 1: readme.txt - Stable tag line (most reliable for .org plugins)
        version = await self._version_from_readme(slug)
        if version:
            candidates.append(("stable_tag", version))

        # Method 2: Main plugin PHP file header (very reliable if accessible)
        version = await self._version_from_plugin_header(slug)
        if version:
            candidates.append(("plugin_header", version))

        # Method 3: changelog.txt
        version = await self._version_from_changelog(slug)
        if version:
            candidates.append(("changelog", version))

        # Method 4: ?ver= parameters from crawled pages
        version = await self._version_from_ver_params(slug)
        if version:
            candidates.append(("ver_param", version))

        if not candidates:
            return None

        # If we have multiple candidates, prefer plugin_header > stable_tag > ver_param > changelog
        priority = {"plugin_header": 0, "stable_tag": 1, "ver_param": 2, "changelog": 3}
        candidates.sort(key=lambda x: priority.get(x[0], 99))

        verbose(f"Version candidates for {slug}: {candidates}", self.args.verbose)
        return candidates[0][1]

    def _is_valid_readme_resp(self, resp) -> str:
        """Check if a response indicates a real plugin readme.
        
        Returns:
            'valid' - readme with parseable content
            'exists' - file exists but content not readable (403, etc.)
            'none' - no plugin found
        """
        if not resp:
            return "none"
        if resp.status_code == 403:
            return "exists"
        if resp.status_code != 200:
            return "none"
        text_lower = resp.text.lower()
        if any(marker in text_lower for marker in [
            "=== ", "stable tag:", "requires at least:",
            "tested up to:", "contributors:",
        ]):
            return "valid"
        return "none"

    async def _version_from_readme(self, slug: str) -> str | None:
        """Extract version from readme.txt Stable tag."""
        resp = None
        for readme_name in ("readme.txt", "README.txt"):
            url = f"{self.args.target}/wp-content/plugins/{slug}/{readme_name}"
            resp = await self.crawler.fetch(url)
            if resp and resp.status_code == 200 and "stable tag:" in resp.text.lower():
                break
        else:
            return None

        # Stable tag is the canonical version indicator
        match = re.search(r'Stable tag:\s*([0-9]+(?:\.[0-9]+){1,3})', resp.text, re.IGNORECASE)
        if match and is_valid_version(match.group(1)):
            return match.group(1)

        # Fallback: changelog heading
        match = re.search(r'=+\s*([0-9]+(?:\.[0-9]+){1,3})\s*=+', resp.text)
        if match and is_valid_version(match.group(1)):
            return match.group(1)

        return None

    async def _version_from_plugin_header(self, slug: str) -> str | None:
        """Try to read the Version: header from the main plugin PHP file.
        
        Some servers serve .php files as downloads or expose headers in
        certain misconfigurations. The main plugin file is typically
        {slug}/{slug}.php or can be found via the readme.txt.
        """
        # Common patterns for main plugin file
        candidates = [
            f"{slug}.php",
            f"class-{slug}.php",
            f"{slug.replace('-', '_')}.php",
        ]

        for filename in candidates:
            url = f"{self.args.target}/wp-content/plugins/{slug}/{filename}"
            resp = await self.crawler.fetch(url)
            if resp and resp.status_code == 200:
                # Look for the standard WP plugin header
                match = re.search(r'\*?\s*Version:\s*([0-9]+(?:\.[0-9]+){1,3})', resp.text)
                if match and is_valid_version(match.group(1)):
                    return match.group(1)

        return None

    async def _version_from_changelog(self, slug: str) -> str | None:
        """Extract version from changelog.txt."""
        url = f"{self.args.target}/wp-content/plugins/{slug}/changelog.txt"
        resp = await self.crawler.fetch(url)
        if not resp or resp.status_code != 200:
            return None

        match = re.search(r'=+\s*([0-9]+\.[0-9]+\.?[0-9]*\.?[0-9]*)\s*=+', resp.text)
        if match and is_valid_version(match.group(1)):
            return match.group(1)

        return None

    async def _version_from_ver_params(self, slug: str) -> str | None:
        """Look for ?ver= parameters on plugin assets found during crawling."""
        # Search through cached pages from the crawl
        pattern = rf'wp-content/plugins/{re.escape(slug)}/[^"\']*\?ver=([0-9]+\.[0-9]+\.?[0-9]*)'

        all_versions = []
        for url, text in self.crawler.page_cache.items():
            matches = self.crawler.client.grep(text, pattern, 1)
            for m in matches:
                if is_valid_version(m) and m != self.core_version:
                    all_versions.append(m)

        if all_versions:
            counter = Counter(all_versions)
            return counter.most_common(1)[0][0]

        return None
