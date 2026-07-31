# HWP Backlog

Deferred work — not yet scheduled.

## Sample `SQLIq` (read/extract) payload

**Why:** the capability spec split SQL injection into `SQLI` (write-capable,
statement/stacked) and `SQLIq` (in-query read: UNION or blind). 77 exploits are
now `SQLIq`, but no payload declares `methods = ["SQLIq"]`, so none of them has a
matching payload — they can be selected but not driven. `SQLIq` needs at least
one read/extract payload to be usable again.

**What to build:** `payloads/sql_read/` (`methods = ["SQLIq"]`) that extracts data
through an in-query injection. Options for common targets, e.g.:

- `--dump users` → WP user logins + `user_pass` hashes
- `--dump options` → `siteurl`, secret keys, etc.
- `--select "<expr>"` → an arbitrary scalar/column to read

**The real design question (why it's backlog, not trivial):** the current `SQLIq`
exploits are heterogeneous in *how* they take the injection — some forward the
instruction into a `WHERE`/`search` param (UNION or boolean context), some into
`ORDER BY`/`orderby`, and they just return the raw HTTP response. There is no
common "give me a SELECT, get the value back" contract yet. Two ways forward:

1. **Shallow (start here):** a payload that emits UNION-style `SELECT` fragments
   for the common WP tables. Works only against UNION-based `SQLIq` exploits whose
   response reflects the unioned columns. Document the limitation.
2. **Deep (better, larger):** give `SQLIq` exploits a standard extraction
   interface — the exploit owns the UNION/blind mechanics (cf. the blind
   bit-banging already in `exploits/wordpress/7.0.1-auth` `_getscalar`/`_getint`)
   and the payload just names *what* to read. This makes one `sql_read` payload
   work across all `SQLIq` exploits regardless of injection context, at the cost
   of refactoring the exploits to a shared helper.

Recommended: ship (1) to unblock usage, then evolve toward (2) via a shared
extractor helper on the `Exploit` base class.

## Missing `hwp-training` examples

The training target is where people learn, but 4 canonical capabilities have no
`hwp-training/` example: **`SQLIq`, `AFD`, `FILEDL`, `PRIVESC`**. Each needs a
matching endpoint on the training-target plugin (external to this repo), so add
the plugin endpoint and the exploit together:

- `SQLIq` — an endpoint with a UNION/blind read injection (pairs with the sample
  SQLIq payload above).
- `FILEDL` — an endpoint that streams an arbitrary file by path (pairs with
  `file_read`).
- `AFD` — an endpoint that deletes/modifies a file by path.
- `PRIVESC` — an endpoint that raises the current low-priv user's role (demonstrates
  `requires_role` → `grants_role`, and an `AUTH → PRIVESC → delivery` chain).

Don't add exploits that hit non-existent endpoints — they'd load fine but fail at
runtime and mislead learners.
