"""
Vulnerability matching using the HackWP vulnerability API.

Downloads the vulnerability database and matches found software
against known vulnerabilities.
"""

import asyncio
import json
import os
import re
import time
from pathlib import Path

from scanner.http_client import HttpClient
from lib.output import section, found, notfound, info, warn, vuln, verbose, console


# Cache directory for vulnerability database
CACHE_DIR = Path.home() / ".hwp_cache"
VULN_DB_FILE = CACHE_DIR / "vulnerabilities.json"
WP_VERSIONS_FILE = CACHE_DIR / "wp_versions.json"
DB_MAX_AGE = 60 * 60 * 24 * 7  # 7 days


def _compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1."""
    def normalize(v):
        return [int(x) for x in re.sub(r'[^0-9.]', '', v).split('.') if x]

    try:
        parts1 = normalize(v1)
        parts2 = normalize(v2)
    except (ValueError, AttributeError):
        return 0

    # Pad to same length
    max_len = max(len(parts1), len(parts2))
    parts1.extend([0] * (max_len - len(parts1)))
    parts2.extend([0] * (max_len - len(parts2)))

    for a, b in zip(parts1, parts2):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0


def _version_lte(version: str, max_version: str) -> bool:
    """Check if version <= max_version."""
    return _compare_versions(version, max_version) <= 0


def _version_gte(version: str, min_version: str) -> bool:
    """Check if version >= min_version."""
    return _compare_versions(version, min_version) >= 0


def _parse_affected_versions(affected_str: str) -> tuple[str, str]:
    """
    Parse the HackWP affected_versions string.

    Formats:
        "* - 3.9.001"   -> from=*, to=3.9.001
        "3.0 - 3.9.001" -> from=3.0, to=3.9.001
        "* - *"          -> from=*, to=*

    Returns (from_version, to_version) with * for wildcards.
    """
    affected_str = affected_str.strip()
    if " - " in affected_str:
        parts = affected_str.split(" - ", 1)
        return parts[0].strip(), parts[1].strip()
    # Fallback: treat as upper bound
    return "*", affected_str


class VulnDatabase:
    """Manages the vulnerability database."""

    def __init__(self, args):
        self.args = args
        self.vulnerabilities = []
        self.wp_versions = {}

    async def load(self, client: HttpClient):
        """Load or update the vulnerability database."""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

        needs_update = False
        if not VULN_DB_FILE.exists() or not WP_VERSIONS_FILE.exists():
            needs_update = True
        else:
            age = time.time() - VULN_DB_FILE.stat().st_mtime
            if age > DB_MAX_AGE:
                needs_update = True

        if needs_update:
            info("Updating vulnerability database...")
            await self._download_db(client)
        else:
            verbose("Vulnerability database is up to date", self.args.verbose)

        # Load databases
        if VULN_DB_FILE.exists():
            try:
                with open(VULN_DB_FILE, 'r') as f:
                    raw = json.load(f)
                # HackWP API wraps data in {"data": [...]}
                if isinstance(raw, dict) and "data" in raw:
                    self.vulnerabilities = raw["data"]
                elif isinstance(raw, list):
                    self.vulnerabilities = raw
                else:
                    self.vulnerabilities = []
                info(f"Loaded {len(self.vulnerabilities)} vulnerabilities from database")
            except (json.JSONDecodeError, IOError) as e:
                warn(f"Failed to load vulnerability database: {e}")
                self.vulnerabilities = []

        if WP_VERSIONS_FILE.exists():
            try:
                with open(WP_VERSIONS_FILE, 'r') as f:
                    self.wp_versions = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.wp_versions = {}

    async def _download_db(self, client: HttpClient):
        """Download vulnerability databases."""
        # HackWP vulnerability feed
        resp = await client.get(
            "https://api.hackwp.io/api/v1/vulnerabilities/download",
            use_cache=False,
        )
        if resp and resp.status_code == 200:
            try:
                with open(VULN_DB_FILE, 'w') as f:
                    f.write(resp.text)
                found("Downloaded HackWP vulnerability database")
            except IOError as e:
                warn(f"Failed to save vulnerability database: {e}")
        else:
            warn("Failed to download HackWP vulnerability database")

        # WordPress core versions
        resp = await client.get(
            "https://api.wordpress.org/core/stable-check/1.0/",
            use_cache=False,
        )
        if resp and resp.status_code == 200:
            try:
                with open(WP_VERSIONS_FILE, 'w') as f:
                    f.write(resp.text)
                verbose("Downloaded WordPress core version database", self.args.verbose)
            except IOError as e:
                warn(f"Failed to save WP versions database: {e}")


class VulnMatcher:
    """Matches scan results against the vulnerability database."""

    def __init__(self, db: VulnDatabase, args):
        self.db = db
        self.args = args
        # Build lookup index: (software_type, slug) -> [vuln entries]
        self._index = {}
        for entry in self.db.vulnerabilities:
            key = (entry.get("software_type", ""), entry.get("software_slug", ""))
            if key not in self._index:
                self._index[key] = []
            self._index[key].append(entry)

    def check_core(self, version: str | None) -> list[dict]:
        """Check WordPress core version status. Returns vulns list."""
        results = []

        if not version:
            return results

        # Check against WP versions database
        status = self.db.wp_versions.get(version, "unknown")
        is_insecure = status == "insecure"

        if is_insecure:
            console.print(f"  [bold red]✗[/bold red]  WordPress version: [red]{version}[/red]")
        elif status == "outdated":
            console.print(f"  [yellow]⚠[/yellow]  WordPress version: [yellow]{version}[/yellow] (outdated)")
        else:
            found("WordPress version:", version)

        results.append({
            "type": "core_status",
            "version": version,
            "status": status,
        })

        # Check for specific core vulnerabilities
        core_vulns = self._find_vulnerabilities("core", "wordpress", version)
        for v in core_vulns:
            results.append(v)
            console.print(f"      [dim]↳ {v['title']}[/dim]")
            parts = []
            if v.get("cve"):
                parts.append(v["cve"])
            if v.get("cvss_score"):
                rating = f' ({v["cvss_rating"]})' if v.get("cvss_rating") else ""
                parts.append(f"CVSS: {v['cvss_score']}{rating}")
            if parts:
                console.print(f"        [dim]{' | '.join(parts)}[/dim]")

        return results

    def check_theme(self, slug: str | None, version: str | None) -> list[dict]:
        """Check theme for known vulnerabilities. Prints inline."""
        if not slug:
            return []

        vulns = self._find_vulnerabilities("theme", slug, version)

        v_str = version if version else "unknown"
        if not version:
            if vulns:
                console.print(f"  [yellow]⚠[/yellow]  Theme: {slug} [yellow](v: unknown)[/yellow] - {len(vulns)} potential vulnerabilities")
            else:
                console.print(f"  [yellow]⚠[/yellow]  Theme: {slug} [yellow](v: unknown)[/yellow]")
        elif vulns:
            console.print(f"  [bold red]✗[/bold red]  Theme: {slug} [red](v: {v_str})[/red]")
            for v in vulns:
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
            found(f"Theme: {slug}", f"(v: {v_str})")

        return vulns

    def find_plugin_vulns(self, slug: str, version: str | None) -> list[dict]:
        """Find vulnerabilities for a plugin. Returns list without printing."""
        return self._find_vulnerabilities("plugin", slug, version)

    def check_plugin(self, slug: str, version: str | None) -> list[dict]:
        """Legacy method - check a plugin for known vulnerabilities."""
        vulns = self._find_vulnerabilities("plugin", slug, version)
        return vulns

    def _print_vuln_detail(self, v: dict):
        """Print CVE, CVSS, and reference link."""
        parts = []
        if v.get("cve"):
            parts.append(v["cve"])
        if v.get("cvss_score"):
            rating = f' ({v["cvss_rating"]})' if v.get("cvss_rating") else ""
            parts.append(f"CVSS: {v['cvss_score']}{rating}")
        if parts:
            verbose("  " + " | ".join(parts), self.args.verbose)

    @staticmethod
    def _highlight_versions(title: str) -> str:
        """Highlight version numbers in vuln titles with blue color."""
        return re.sub(
            r'(\d+\.\d+(?:\.\d+)*)',
            r'[cyan]\1[/cyan]',
            title
        )

    def _find_vulnerabilities(self, software_type: str, slug: str, version: str | None) -> list[dict]:
        """Search the vulnerability database for matching entries."""
        matches = []
        candidates = self._index.get((software_type, slug), [])

        for entry in candidates:
            affected_str = entry.get("affected_versions", "")
            if not affected_str:
                continue

            is_affected = self._is_version_affected(version, affected_str)

            if is_affected is True or is_affected == "maybe":
                result = {
                    "id": entry.get("id"),
                    "title": entry.get("title", "Unknown"),
                    "cve": entry.get("cve") or None,
                    "cve_link": f"https://nvd.nist.gov/vuln/detail/{entry['cve']}" if entry.get("cve") else None,
                    "cvss_score": entry.get("cvss_score"),
                    "cvss_rating": entry.get("cvss_rating", ""),
                    "software_type": software_type,
                    "slug": slug,
                    "installed_version": version,
                    "affected_versions": affected_str,
                    "patched_versions": [],
                    "confirmed": is_affected is True,
                    "capability": entry.get("capability"),
                    "capability_chain": entry.get("capability_chain"),
                    "auth_required": entry.get("auth_required", False),
                    "references": [],
                }
                matches.append(result)

        return matches

    def _is_version_affected(self, version: str | None, affected_str: str) -> bool | str:
        """
        Check if the installed version falls within the affected range.

        Returns:
            True - version is definitely affected
            "maybe" - version is unknown so we can't be sure
            False - version is not affected
        """
        if not version:
            return "maybe"

        from_ver, to_ver = _parse_affected_versions(affected_str)

        # Normalize wildcards
        if from_ver == "*":
            from_ver = "0"

        if to_ver == "*":
            # Unbounded upper range — matches everything
            # (different from Wordfence where we skip these)
            return True

        try:
            if _version_gte(version, from_ver) and _version_lte(version, to_ver):
                return True
        except Exception:
            pass

        return False
