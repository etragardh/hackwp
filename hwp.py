#!/usr/bin/env python3
"""
HWP - HackWP Framework v2
WordPress Security Training Tool

Usage:
    hwp -t <target> --exploit <exploit> [exploit ...] --payload <payload> [options]
    hwp -t <target> --scan [-a | -aa] [--enumerate plugins,users]
    hwp --list-exploits
    hwp --list-payloads
    hwp -i
"""

import argparse
import os
import sys
from urllib.parse import urlparse

# Project root
_ROOT = os.path.dirname(os.path.realpath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from lib.output import banner, section, info, warn, error, success, print_table
from lib.loader import load_exploit, load_payload, list_exploits, list_payloads
from lib.chain import run_chain


EXPLOITS_DIR = os.path.join(_ROOT, "exploits")
PAYLOADS_DIR = os.path.join(_ROOT, "payloads")


def normalize_target(target):
    """Ensure scheme, strip trailing slash, extract domain."""
    if not target:
        return None, None
    target = target.strip().rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target
    domain = urlparse(target).netloc
    return target, domain


def parse_args():
    """Parse known args; unknown args become options dict."""
    parser = argparse.ArgumentParser(
        prog="hwp",
        description="HWP — HackWP Framework v2",
    )
    parser.add_argument("-t", "--target", help="Target URL or domain")
    parser.add_argument("--exploit", nargs="+", metavar="EXPLOIT",
                        help="Exploit(s) to run, e.g. bricks/1.9.6-rce")
    parser.add_argument("--payload", metavar="PAYLOAD",
                        help="Payload to deliver, e.g. shell, admin-user")
    parser.add_argument("--scan", action="store_true", help="Run scanner")
    parser.add_argument("--list-exploits", action="store_true", help="List available exploits")
    parser.add_argument("--list-payloads", action="store_true", help="List available payloads")
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="Interactive mode — TUI exploit builder")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Verbose output (-v verbose, -vv very verbose)")
    parser.add_argument("-a", "--aggressive", action="count", default=0,
                        help="Scanner aggressiveness (-a popular plugins, -aa vuln DB)")
    parser.add_argument("--cookie", help="Inject session cookie string")
    parser.add_argument("--clear-session", action="store_true",
                        help="Clear stored session for target")
    parser.add_argument("--no-banner", action="store_true",
                        help=argparse.SUPPRESS)  # Hidden: used by TUI

    args, extra = parser.parse_known_args()

    # Parse extra args into options dict: --lhost 10.0.0.5 → {"lhost": "10.0.0.5"}
    options = {}
    i = 0
    while i < len(extra):
        arg = extra[i]
        if arg.startswith("--"):
            key = arg.lstrip("-")
            if i + 1 < len(extra) and not extra[i + 1].startswith("--"):
                options[key] = extra[i + 1]
                i += 2
            else:
                options[key] = True
                i += 1
        else:
            i += 1

    return args, options


def cmd_list_exploits():
    refs = list_exploits(EXPLOITS_DIR)
    if not refs:
        warn("No exploits found")
        return
    rows = []
    for ref in refs:
        cls = load_exploit(ref, EXPLOITS_DIR)
        if cls:
            rows.append((ref, cls.info_str()))
        else:
            rows.append((ref, "[dim]load error[/dim]"))
    print_table(f"Available Exploits ({len(refs)})", rows)


def cmd_list_payloads():
    refs = list_payloads(PAYLOADS_DIR)
    if not refs:
        warn("No payloads found")
        return
    rows = []
    for ref in refs:
        cls = load_payload(ref, PAYLOADS_DIR)
        if cls:
            rows.append((ref, cls.info_str()))
        else:
            rows.append((ref, "[dim]load error[/dim]"))
    print_table(f"Available Payloads ({len(refs)})", rows)


def _save_scan_results(target, results):
    """Save scan results to cache for TUI integration."""
    import json
    from pathlib import Path
    from urllib.parse import urlparse

    cache_dir = Path.home() / ".hackwp" / "scans"
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Use hostname as filename
    parsed = urlparse(target)
    host = parsed.hostname or target
    host = host.replace("/", "_").replace(":", "_")

    try:
        with open(cache_dir / f"{host}.json", "w") as f:
            json.dump(results, f, indent=2, default=str)
    except IOError:
        pass


def cmd_scan(args, options):
    """Run the integrated WPScanX scanner."""
    import asyncio
    from scanner.orchestrator import ScanOrchestrator

    target, _ = normalize_target(args.target)

    # Build a scanner args namespace from hwp args + extra options
    scan_args = argparse.Namespace(
        target=target,
        aggressive=args.aggressive,
        concurrency=int(options.get("concurrency", options.get("c", 10))),
        timeout=float(options.get("timeout", 10.0)),
        user_agent=options.get("user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        no_color=bool(options.get("no-color", False)),
        verbose=args.verbose or bool(options.get("verbose", False)),
        json=bool(options.get("json", False)),
        max_crawl_pages=int(options.get("max-crawl-pages", 100)),
        enumerate=options.get("enumerate", "all"),
    )

    # Parse enumerate flags
    enums = [e.strip().lower() for e in scan_args.enumerate.split(",")]
    if "all" in enums:
        enums = ["core", "themes", "plugins", "users", "security"]
    scan_args.enums = enums

    scanner = ScanOrchestrator(scan_args)
    results = asyncio.run(scanner.run())

    # Save scan results for TUI integration
    _save_scan_results(scan_args.target, results)

    if scan_args.json:
        import json
        from lib.output import console as scan_console
        scan_console.print(json.dumps(results, indent=2, default=str))


def cmd_exploit(args, options):
    target, domain = normalize_target(args.target)
    if not target:
        error("No target specified (-t)")
        return

    # Clear session
    if args.clear_session:
        from lib.store import clear
        clear(domain)
        success(f"Cleared stored session for {domain}")
        return

    # Load exploits
    exploit_classes = []
    for ref in args.exploit:
        cls = load_exploit(ref, EXPLOITS_DIR)
        if cls is None:
            return
        exploit_classes.append(cls)
        if args.verbose:
            info(f"Loaded exploit: {cls.info_str()}")

    # Load payload
    payload_class = None
    if args.payload:
        payload_class = load_payload(args.payload, PAYLOADS_DIR)
        if payload_class is None:
            return
        if args.verbose:
            info(f"Loaded payload: {payload_class.info_str()}")

    # Print launch info
    section("Attack Mode")
    info("Target:", target)
    for i, cls in enumerate(exploit_classes):
        label = "Chain:" if i > 0 else "Exploit:"
        info(f"{label:9s}", cls.info_str())
    if payload_class:
        info("Payload:", payload_class.info_str())
    print()

    # Execute
    results = run_chain(
        exploit_classes=exploit_classes,
        payload_class=payload_class,
        target=target,
        domain=domain,
        options=options,
        verbose=args.verbose,
    )

    # Summary
    if results:
        ok = sum(1 for r in results if r.success)
        print()
        if ok == len(results):
            success(f"All {len(results)} instruction(s) executed successfully")
        else:
            warn(f"{ok}/{len(results)} instruction(s) succeeded")


def main():
    args, options = parse_args()

    # Interactive mode: no arguments OR explicit -i
    if len(sys.argv) == 1 or args.interactive:
        from lib.interactive import run_interactive
        run_interactive(EXPLOITS_DIR, PAYLOADS_DIR, verbose=args.verbose)
        return

    if args.list_exploits:
        banner()
        cmd_list_exploits()
        return

    if args.list_payloads:
        banner()
        cmd_list_payloads()
        return

    if not args.no_banner:
        banner()

    if args.scan:
        if not args.target:
            error("--scan requires -t <target>")
            return
        cmd_scan(args, options)
        return

    if args.exploit:
        cmd_exploit(args, options)
        return

    if args.clear_session and args.target:
        _, domain = normalize_target(args.target)
        from lib.store import clear
        clear(domain)
        success(f"Cleared session for {domain}")
        return

    error("Use --exploit, --scan, --list-exploits, --list-payloads, or -i")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  \033[33m⚠\033[0m  Interrupted by user")
        sys.exit(0)
