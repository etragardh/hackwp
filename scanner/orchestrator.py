"""
Scan orchestrator - coordinates all scan modules.
"""

import time

from rich.console import Console

from scanner.http_client import HttpClient
from scanner.crawler import Crawler
from scanner.core import CoreScanner
from scanner.themes import ThemeScanner
from scanner.plugins import PluginScanner
from scanner.users import UserScanner
from scanner.security import SecurityScanner
from scanner.vulns import VulnDatabase, VulnMatcher
from lib.output import section, info, found, notfound, warn, console

console_out = Console()


class ScanOrchestrator:
    """Coordinates the full scan pipeline."""

    def __init__(self, args):
        self.args = args

    async def run(self) -> dict:
        start_time = time.time()

        results = {
            "target": self.args.target,
            "scan_time": None,
            "requests_made": 0,
            "core": {},
            "theme": {},
            "plugins": {},
            "users": [],
            "security": {},
            "vulnerabilities": [],
        }

        async with HttpClient(self.args) as client:
            # Verify target is reachable
            if not self.args.json:
                info(f"Target: {self.args.target}")
                info(f"Concurrency: {self.args.concurrency}")
                if self.args.aggressive == 1:
                    warn("Aggressive mode enabled")
                elif self.args.aggressive >= 2:
                    warn("Very aggressive mode enabled (probing all vuln DB slugs)")
                info("")

            resp = await client.get(self.args.target)
            if not resp:
                if not self.args.json:
                    console_out.print("[bold red]  ✗  Target is not reachable![/bold red]")
                return results

            if not self.args.json:
                found(f"Target is up (HTTP {resp.status_code})")

            # Check if it's actually WordPress
            is_wp = self._detect_wordpress(resp)
            if not is_wp:
                if not self.args.json:
                    warn("Target may not be running WordPress")

            # ── Load Vulnerability Database early ─────────
            vuln_db = VulnDatabase(self.args)
            await vuln_db.load(client)
            matcher = VulnMatcher(vuln_db, self.args) if vuln_db.vulnerabilities else None

            crawler = Crawler(client, self.args)
            all_vulns = []

            # ── Core ────────────────────────────────────────
            if "core" in self.args.enums:
                core_scanner = CoreScanner(crawler, self.args)
                results["core"] = await core_scanner.scan()

                core_version = results.get("core", {}).get("version")
                if matcher and core_version:
                    # check_core prints version with color + vulns inline
                    core_vulns = matcher.check_core(core_version)
                    all_vulns.extend(core_vulns)
                elif core_version:
                    found("WordPress version:", core_version)
                else:
                    notfound("WordPress version: could not determine")

            core_version = results.get("core", {}).get("version")

            # ── Theme ───────────────────────────────────────
            if "themes" in self.args.enums:
                theme_scanner = ThemeScanner(crawler, self.args)
                results["theme"] = await theme_scanner.scan()

                theme_slug = results.get("theme", {}).get("slug")
                theme_version = results.get("theme", {}).get("version")
                if matcher and theme_slug:
                    # check_theme prints theme with color + vulns inline
                    theme_vulns = matcher.check_theme(theme_slug, theme_version)
                    all_vulns.extend(theme_vulns)
                elif theme_slug:
                    v_str = theme_version if theme_version else "unknown"
                    found(f"Theme: {theme_slug}", f"(v: {v_str})")

            # ── Plugins ─────────────────────────────────────
            if "plugins" in self.args.enums:
                plugin_scanner = PluginScanner(crawler, self.args, core_version)
                results["plugins"] = await plugin_scanner.scan(matcher=matcher)

                # Collect plugin vulns
                for slug, pdata in results.get("plugins", {}).items():
                    if isinstance(pdata, dict) and pdata.get("vulns"):
                        all_vulns.extend(pdata["vulns"])

            # ── Users ───────────────────────────────────────
            if "users" in self.args.enums:
                user_scanner = UserScanner(crawler, self.args)
                results["users"] = await user_scanner.scan()

            # ── Security ────────────────────────────────────
            if "security" in self.args.enums:
                security_scanner = SecurityScanner(crawler, self.args)
                results["security"] = await security_scanner.scan()

            results["vulnerabilities"] = all_vulns

            # ── Summary ─────────────────────────────────────
            elapsed = time.time() - start_time
            results["scan_time"] = round(elapsed, 2)
            results["requests_made"] = client.request_count

            if not self.args.json:
                section("Summary")
                info(f"Scan completed in {elapsed:.1f}s")
                info(f"Total HTTP requests: {client.request_count}")
                if results.get("plugins"):
                    info(f"Plugins found: {len(results['plugins'])}")
                if results.get("users"):
                    info(f"Users found: {len(results['users'])}")
                vuln_count = len([v for v in all_vulns if v.get("type") != "core_status"])
                if vuln_count:
                    warn(f"Vulnerabilities found:", str(vuln_count))
                else:
                    info("Vulnerabilities found: 0")

        return results

    def _detect_wordpress(self, resp) -> bool:
        """Quick check if the target looks like WordPress."""
        indicators = [
            "wp-content",
            "wp-includes",
            "wp-json",
            "wordpress",
            '/wp-login.php',
            'name="generator" content="WordPress',
        ]
        text_lower = resp.text.lower()
        headers_lower = str(resp.headers).lower()

        for indicator in indicators:
            if indicator.lower() in text_lower or indicator.lower() in headers_lower:
                return True

        # Check Link header for api.w.org
        link = resp.headers.get("link", "")
        if "api.w.org" in link:
            return True

        return False
