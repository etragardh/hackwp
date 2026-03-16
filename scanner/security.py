"""
Security-focused checks for WordPress misconfigurations and exposures.
"""

import asyncio
import re

from scanner.crawler import Crawler
from lib.output import section, found, notfound, info, warn, vuln, verbose


class SecurityScanner:
    """Checks for common WordPress security misconfigurations."""

    def __init__(self, crawler: Crawler, args):
        self.crawler = crawler
        self.args = args

    async def scan(self) -> dict:
        section("Security Checks")

        results = {
            "xmlrpc": None,
            "directory_listing": [],
            "debug_log": False,
            "wp_cron_public": False,
            "user_registration": False,
            "server_headers": {},
            "security_headers": {},
            "robots_txt": None,
        }

        checks = await asyncio.gather(
            self._check_xmlrpc(),
            self._check_directory_listing(),
            self._check_debug_log(),
            self._check_wp_cron(),
            self._check_user_registration(),
            self._check_server_headers(),
            self._check_security_headers(),
            self._check_robots_txt(),
        )

        (
            results["xmlrpc"],
            results["directory_listing"],
            results["debug_log"],
            results["wp_cron_public"],
            results["user_registration"],
            results["server_headers"],
            results["security_headers"],
            results["robots_txt"],
        ) = checks

        return results

    # ── XML-RPC ────────────────────────────────────────────────────

    async def _check_xmlrpc(self) -> dict | None:
        """Check if XML-RPC is enabled and test for dangerous methods."""
        result = {"enabled": False, "methods": []}

        # First check if it responds
        resp = await self.crawler.fetch(self.args.target + "/xmlrpc.php")
        if not resp:
            notfound("XML-RPC: not accessible")
            return None

        if resp.status_code == 405 or "XML-RPC server accepts POST requests only" in resp.text:
            result["enabled"] = True

            # Try to list methods
            xml_payload = '''<?xml version="1.0"?>
<methodCall>
    <methodName>system.listMethods</methodName>
    <params></params>
</methodCall>'''
            resp = await self.crawler.client.post(
                self.args.target + "/xmlrpc.php",
                data=xml_payload,
                content_type="text/xml",
            )

            if resp and resp.status_code == 200:
                methods = re.findall(r'<string>(.*?)</string>', resp.text)
                result["methods"] = methods

                dangerous = [m for m in methods if m in (
                    "wp.getUsersBlogs", "wp.getAuthors",
                    "system.multicall", "pingback.ping",
                )]

                if dangerous:
                    warn(f"XML-RPC enabled with {len(methods)} methods")
                    for m in dangerous:
                        warn(f"  Dangerous method: {m}")
                else:
                    info(f"XML-RPC enabled ({len(methods)} methods)")
            else:
                info("XML-RPC enabled (could not list methods)")
        else:
            info("XML-RPC: disabled or blocked")

        return result

    # ── Directory Listing ──────────────────────────────────────────

    async def _check_directory_listing(self) -> list[str]:
        """Check if directory listing is enabled on common paths."""
        paths = [
            "/wp-content/",
            "/wp-content/plugins/",
            "/wp-content/themes/",
            "/wp-content/uploads/",
            "/wp-includes/",
        ]

        urls = [self.args.target + p for p in paths]
        responses = await self.crawler.client.get_batch(urls)

        exposed = []
        for path, resp in zip(paths, responses):
            if resp and resp.status_code == 200:
                if "Index of" in resp.text or "<title>Index" in resp.text:
                    exposed.append(path)
                    warn(f"Directory listing enabled: {path}")

        if not exposed:
            info("No directory listing found on common paths")

        return exposed

    # ── Debug Log ──────────────────────────────────────────────────

    async def _check_debug_log(self) -> bool:
        """Check if debug.log is publicly accessible."""
        resp = await self.crawler.fetch(self.args.target + "/wp-content/debug.log")
        if resp and resp.status_code == 200 and len(resp.text) > 20:
            vuln("debug.log is publicly accessible!", "May contain sensitive information")
            return True

        notfound("debug.log not accessible")
        return False

    # ── WP Cron ────────────────────────────────────────────────────

    async def _check_wp_cron(self) -> bool:
        """Check if wp-cron.php is publicly accessible."""
        resp = await self.crawler.fetch(self.args.target + "/wp-cron.php")
        if resp and resp.status_code == 200:
            info("wp-cron.php is publicly accessible (potential DoS vector)")
            return True
        return False

    # ── User Registration ──────────────────────────────────────────

    async def _check_user_registration(self) -> bool:
        """Check if user registration is enabled."""
        resp = await self.crawler.fetch(self.args.target + "/wp-login.php?action=register")
        if resp and resp.status_code == 200:
            if "registration" in resp.text.lower() and "register" in resp.text.lower():
                # Check it's not just a "registration disabled" message
                if "not allowed" not in resp.text.lower() and "disabled" not in resp.text.lower():
                    warn("User registration appears to be enabled")
                    return True
        info("User registration: disabled or restricted")
        return False

    # ── Server Headers ─────────────────────────────────────────────

    async def _check_server_headers(self) -> dict:
        """Extract interesting server headers."""
        resp = await self.crawler.fetch(self.args.target + "/")
        if not resp:
            return {}

        interesting_headers = {}
        headers_to_check = [
            "server", "x-powered-by", "x-redirect-by",
            "x-generator", "x-pingback", "x-frame-options",
        ]

        for h in headers_to_check:
            value = resp.headers.get(h)
            if value:
                interesting_headers[h] = value

        # Report findings
        server = interesting_headers.get("server", "")
        if server:
            info(f"Server: {server}")

        powered_by = interesting_headers.get("x-powered-by", "")
        if powered_by:
            warn(f"X-Powered-By: {powered_by}", "(version disclosure)")

        pingback = interesting_headers.get("x-pingback", "")
        if pingback:
            info(f"X-Pingback: {pingback}")

        return interesting_headers

    # ── Security Headers ───────────────────────────────────────────

    async def _check_security_headers(self) -> dict:
        """Check for missing security headers."""
        resp = await self.crawler.fetch(self.args.target + "/")
        if not resp:
            return {}

        results = {}
        headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-Frame-Options": "X-Frame-Options",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy",
        }

        for header, label in headers.items():
            value = resp.headers.get(header.lower())
            if value:
                results[header] = value
                info(f"{label}: present")
            else:
                results[header] = None
                warn(f"{label}: missing")

        return results

    # ── robots.txt ─────────────────────────────────────────────────

    async def _check_robots_txt(self) -> dict | None:
        """Analyze robots.txt for interesting paths."""
        resp = await self.crawler.fetch(self.args.target + "/robots.txt")
        if not resp or resp.status_code != 200:
            notfound("robots.txt not found")
            return None

        result = {
            "exists": True,
            "disallowed": [],
            "sitemaps": [],
        }

        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    result["disallowed"].append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                # Rejoin in case the URL had a colon
                if ":" in line[len("sitemap:"):]:
                    sitemap = line.split(" ", 1)[1].strip() if " " in line else line.split(":", 2)[-1].strip()
                    sitemap = line[line.lower().index("sitemap:") + 8:].strip()
                result["sitemaps"].append(sitemap)

        info(f"robots.txt: {len(result['disallowed'])} disallow rules, {len(result['sitemaps'])} sitemaps")

        # Flag interesting disallowed paths
        for path in result["disallowed"]:
            if any(s in path.lower() for s in ["backup", "secret", "private", "admin", "config"]):
                verbose(f"Interesting disallow: {path}", self.args.verbose)

        return result
