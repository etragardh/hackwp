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
   g. Identify delivery exploit and transformers
   h. Execute: transformers → delivery → collect results
   i. Call payload.report(results)
```

## Chain Resolution

Given: `--exploit hwp-training/1.0.0-auth hwp-training/1.0.0-objinj hwp-training/1.0.0-pop-rce hwp-training/1.0.0-rce --payload webshell`

The framework:
1. Separates `hwp-training/1.0.0-auth` (capability=AUTH) → runs first
2. Remaining chain: `1.0.0-objinj`, `1.0.0-pop-rce`, `1.0.0-rce`
3. Matches payload `webshell` (methods=["RCE"]) to rightmost RCE exploit
4. Identifies delivery exploit (first with `delivers=None`)
5. Remaining exploits are transformers, processed right-to-left

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

## Project Structure

```
hwp/
├── hwp.py                  # CLI entry point
├── hwp/                    # Public package (from hwp import Exploit, Payload)
│   └── __init__.py
├── lib/                    # Framework internals
│   ├── chain.py            # Chain resolver & executor
│   ├── exploit.py          # Exploit base class
│   ├── http.py             # HTTP wrapper with auth gating
│   ├── interactive.py      # Textual TUI
│   ├── loader.py           # Module discovery
│   ├── output.py           # Colored terminal output
│   ├── payload.py          # Payload base class
│   ├── result.py           # Result class with field validation
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
