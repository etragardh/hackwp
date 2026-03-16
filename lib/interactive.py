"""
HWP Interactive Mode — single-screen TUI using Textual.

Layout (merged from Emil's prototype + Claude's HWP integration):

  ┌─ Plan Box ─────────────────────────────────────────────────────┐
  │  exploit(bricks/1.9.6-rce) > payload(shell) > target(…)       │
  ├─ Exploit List (multi) ─────┬─ Payload List (single) ──────────┤
  │  ☑ bricks/1.9.6-rce       │  ▸ shell                         │
  │  ☐ bricks/1.9.6.1-rce     │    file_read                     │
  ├─ Arguments ────────────────────────────────────────────────────┤
  │  Main         │ bricks/1.9.6-rce │ shell                      │
  │  RHOST: [   ] │ — none —         │ CMD: [whoami]              │
  │  RPORT: [80 ] │                  │ LHOST: [127.0.0.1]         │
  ├─ Bottom Bar ───────────────────────────────────────────────────┤
  │  hwp -t http://localhost --exploit ...        [Go]       │
  └────────────────────────────────────────────────────────────────┘

Launched via: hwp -i
"""

import asyncio
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from rich.text import Text

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button, Footer, Input, Label, RichLog, SelectionList, Static,
)

from lib.loader import load_exploit, load_payload, list_exploits, list_payloads
from lib.exploit import resolve_capability
from lib.payload import resolve_method


# ─── Scan Data ────────────────────────────────────────────────────────

SCAN_CACHE_DIR = Path.home() / ".hwp_cache" / "scans"


def _load_scan_data(target: str) -> Optional[dict]:
    """Load cached scan results for a target host."""
    if not target.strip():
        return None

    parsed = urlparse(target if target.startswith("http") else f"http://{target}")
    host = parsed.hostname or target
    host = host.replace("/", "_").replace(":", "_")

    scan_file = SCAN_CACHE_DIR / f"{host}.json"
    if not scan_file.exists():
        return None

    try:
        with open(scan_file, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def _match_exploit_to_scan(cls, scan_data: dict) -> Optional[str]:
    """
    Check if an exploit matches scan data.

    Returns:
        "confirmed" — slug found, version in affected range
        "possible"  — slug found, version unknown or can't determine
        None        — slug not found on target
    """
    if not scan_data:
        return None

    exploit_slug = getattr(cls, "slug", "")
    exploit_type = getattr(cls, "type", "")
    exploit_versions = getattr(cls, "versions", "")

    if not exploit_slug:
        return None

    # Check plugins
    if exploit_type == "plugin":
        plugins = scan_data.get("plugins", {})
        if exploit_slug in plugins:
            pdata = plugins[exploit_slug]
            installed_version = pdata.get("version") if isinstance(pdata, dict) else pdata
            if installed_version:
                if _version_in_range(installed_version, exploit_versions):
                    return "confirmed"
                else:
                    return None  # installed but patched
            return "possible"

    # Check themes
    elif exploit_type == "theme":
        theme = scan_data.get("theme", {})
        if theme.get("slug") == exploit_slug:
            installed_version = theme.get("version")
            if installed_version:
                if _version_in_range(installed_version, exploit_versions):
                    return "confirmed"
                else:
                    return None
            return "possible"

    # Check core
    elif exploit_type == "core":
        core = scan_data.get("core", {})
        installed_version = core.get("version")
        if installed_version:
            if _version_in_range(installed_version, exploit_versions):
                return "confirmed"
            else:
                return None
        return "possible"

    return None


def _version_in_range(installed: str, version_spec: str) -> bool:
    """Check if installed version matches an exploit's version spec."""
    if not version_spec or not installed:
        return False

    # Exact match
    if installed == version_spec:
        return True

    # Range: "1.0 - 2.0"
    if " - " in version_spec:
        parts = version_spec.split(" - ", 1)
        from_v = parts[0].strip()
        to_v = parts[1].strip()
        if from_v == "*":
            from_v = "0"
        if to_v == "*":
            return True
        return _cmp(installed, from_v) >= 0 and _cmp(installed, to_v) <= 0

    # Comma-separated versions
    if "," in version_spec:
        return installed in [v.strip() for v in version_spec.split(",")]

    # Single version — exact match or lte
    return _cmp(installed, version_spec) <= 0


def _cmp(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1."""
    def normalize(v):
        return [int(x) for x in re.sub(r'[^0-9.]', '', v).split('.') if x]
    try:
        p1, p2 = normalize(v1), normalize(v2)
    except (ValueError, AttributeError):
        return 0
    max_len = max(len(p1), len(p2))
    p1.extend([0] * (max_len - len(p1)))
    p2.extend([0] * (max_len - len(p2)))
    for a, b in zip(p1, p2):
        if a < b: return -1
        if a > b: return 1
    return 0


# ─── CSS ──────────────────────────────────────────────────────────────

APP_CSS = """
Screen {
    background: black;
    color: #cccccc;
    layout: vertical;
}

Header { display: none; }

/* ── Banner (top) ── */
#banner-box {
    height: auto;
    max-height: 11;
    border: round #333333;
    padding: 0 1;
    margin: 0 1;
    background: black;
}

#banner-art {
    height: auto;
    color: cyan;
}

#plan-line {
    height: 1;
}

/* ── Lists section (middle, two columns) ── */
#lists-grid {
    height: 1fr;
    min-height: 8;
    grid-size: 2;
    grid-columns: 2fr 1fr;
    grid-gutter: 0 1;
    padding: 0 1;
}

.list-pane {
    height: 1fr;
    min-height: 0;
    border: round #333333;
    padding: 0 1;
    background: black;
}

.list-pane-title {
    height: 1;
    color: cyan;
    padding: 0;
}

/* ── Filter row (input + toggle) ── */
.filter-row {
    height: 1;
    width: 100%;
    layout: horizontal;
}

.filter-row Input {
    width: 1fr;
}

.scan-toggle {
    height: 1;
    width: 18;
    padding: 0 1;
    background: #1a1a2e;
    color: #888888;
    text-style: none;
    content-align: center middle;
}

.scan-toggle.active {
    color: #00cc00;
    background: #0a1a0a;
}

.scan-toggle:focus {
    background: #2a2a4e;
    text-style: bold;
}

Input {
    height: 1;
    border: none;
    background: #111111;
    color: #999999;
    padding: 0 1;
    margin: 0 0 0 0;
}

Input:focus {
    background: #1a1a2e;
    color: #cccccc;
    border: none;
}

SelectionList {
    height: 1fr;
    min-height: 0;
    border: none;
    background: black;
    color: #cccccc;
    padding: 0;
    scrollbar-size: 1 1;
}

/* ── Checkbox styling ── */
SelectionList > .selection-list--button {
    background: #333333;
    color: #333333;
    text-style: none;
}

SelectionList > .selection-list--button-highlighted {
    background: #444444;
    color: #444444;
    text-style: none;
}

SelectionList > .selection-list--button-selected {
    background: #1a3a1a;
    color: #00cc00;
    text-style: bold;
}

SelectionList > .selection-list--button-selected-highlighted {
    background: #224422;
    color: #00ff00;
    text-style: bold;
}

/* ── Lower section (args + description, two columns) ── */
#lower-grid {
    height: 1fr;
    min-height: 6;
    max-height: 16;
    grid-size: 2;
    grid-columns: 2fr 1fr;
    grid-gutter: 0 1;
    padding: 0 1;
}

#args-box {
    height: 1fr;
    border: round #333333;
    padding: 0 1;
    background: black;
}

#args-title {
    height: 1;
    color: cyan;
}

#args-scroll {
    height: 1fr;
    min-height: 0;
}

#args-grid {
    height: auto;
    grid-gutter: 0 1;
}

.arg-col {
    height: auto;
    border: round #222222;
    padding: 0 1 1 1;
    background: black;
}

.arg-col-title {
    height: 1;
    color: cyan;
}

.arg-row {
    height: auto;
}

.arg-label {
    width: 10;
    color: #888888;
}

/* ── Description pane (right of args) ── */
#desc-box {
    height: 1fr;
    border: round #333333;
    padding: 0 1;
    background: black;
    overflow-y: auto;
}

#desc-content {
    height: auto;
}

.desc-section-title {
    color: cyan;
    text-style: bold;
}

.desc-warning {
    color: #e94560;
}

.desc-credits {
    color: #888888;
}

/* ── Bottom bar ── */
#bottom-bar {
    height: auto;
    padding: 0 1;
    margin: 0 1;
}

#cmd-preview {
    height: 1;
}

Button {
    height: 3;
    border: heavy #333333;
    background: black;
    color: #cccccc;
    padding: 0 2;
    margin: 0 0 0 1;
}

Button:hover {
    border: heavy #555555;
}

/* ── Footer ── */
Footer {
    background: #111111;
}

FooterKey {
    background: #111111;
    color: #666666;
}
"""


# ─── Results Screen ──────────────────────────────────────────────────

RESULTS_CSS = """
Screen {
    background: black;
    color: #cccccc;
}

#results-banner-box {
    height: auto;
    max-height: 11;
    border: round #333333;
    padding: 0 1;
    margin: 0 1;
    background: black;
}

#results-banner-art {
    height: auto;
    color: cyan;
}

#results-status {
    height: 1;
    color: yellow;
}

#results-log {
    height: 1fr;
    margin: 0 1;
    border: round #333333;
    background: black;
    padding: 0 1;
    scrollbar-size: 1 1;
}

#results-controls {
    height: 3;
    padding: 0 1;
    margin: 0 1;
}

#results-controls Button {
    height: 3;
    border: heavy #333333;
    background: black;
    color: #cccccc;
    padding: 0 2;
    margin: 0 1 0 0;
}

#results-controls Button:hover {
    border: heavy #555555;
}

Footer {
    background: #111111;
}

FooterKey {
    background: #111111;
    color: #666666;
}
"""


class ResultsScreen(Screen):
    """Results screen — shows exploit execution output."""

    CSS = RESULTS_CSS

    BINDINGS = [
        Binding("ctrl+q", "quit_app", "Quit", show=True, priority=True),
        Binding("escape", "go_back", "Back", show=True),
    ]

    BANNER_ART = (
        "⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀\n"
        "⣿⡿⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⢿⡵\n"
        "⣿⡇⠀⠀⠉⠛⠛⣿⣿⠛⠛⠉⠀⠀⣿⡇  » hackwp «\n"
        "⣿⣿⣀⠀⢀⣠⣴⡇⠹⣦⣄⡀⠀⣠⣿⡇    by @etragardh\n"
        "⠋⠻⠿⠿⣟⣿⣿⣦⣤⣼⣿⣿⠿⠿⠟⠀\n"
        "⠀   ⠸⡿⣿⣿⢿⡿⢿⠇⠀ v2.0\n"
        "⠀⠀⠀⠀⠀⠀⠈⠁⠈⠁"
    )

    def __init__(self, cmd_parts: list, cmd_display=None):
        super().__init__()
        self.cmd_parts = cmd_parts
        self.cmd_display = cmd_display  # Rich Text object or None
        self._process = None
        self._running = False

    def compose(self) -> ComposeResult:
        with Vertical(id="results-banner-box"):
            yield Static(self.BANNER_ART, id="results-banner-art")
            yield Static("", id="results-status", markup=True)

        yield RichLog(id="results-log", highlight=True, markup=True)

        with Horizontal(id="results-controls"):
            yield Button("◂ Back", id="btn-back")
            yield Button("↻ Re-run", id="btn-rerun")
            yield Button("Quit", id="btn-quit")

        yield Footer()

    def on_mount(self) -> None:
        status = self.query_one("#results-status", Static)
        status.update(Text.from_markup(f"[yellow]Running...[/yellow]"))

        log = self.query_one("#results-log", RichLog)
        # Show the command being run (colored if available)
        if self.cmd_display:
            log.write(self.cmd_display)
        else:
            cmd_text = " ".join(self.cmd_parts[2:]) if len(self.cmd_parts) > 2 else " ".join(self.cmd_parts)
            log.write(Text.from_markup(f"[dim]$ {cmd_text}[/dim]"))
        log.write("")

        self._run_command()

    def _run_command(self):
        """Run the exploit command as a subprocess, stream output to log."""
        self._running = True
        self.run_worker(self._execute(), exclusive=True)

    async def _execute(self):
        """Async worker that runs the subprocess and streams output."""
        log = self.query_one("#results-log", RichLog)
        status = self.query_one("#results-status", Static)

        try:
            self._process = await asyncio.create_subprocess_exec(
                *self.cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, "PYTHONUNBUFFERED": "1", "COLUMNS": "120", "FORCE_COLOR": "1"},
            )

            async for line in self._process.stdout:
                decoded = line.decode("utf-8", errors="replace").rstrip("\n\r")
                # Convert ANSI escape codes to Rich Text for proper color rendering
                log.write(Text.from_ansi(decoded))

            await self._process.wait()
            rc = self._process.returncode

            log.write("")
            if rc == 0:
                log.write(Text.from_markup("[bold green]✓ Completed successfully[/bold green]"))
                status.update("")
            else:
                log.write(Text.from_markup(f"[bold red]✗ Exited with code {rc}[/bold red]"))
                status.update(Text.from_markup(f"[red]✗ Failed (exit {rc})[/red]"))

        except Exception as e:
            log.write(Text.from_markup(f"[bold red]Error: {e}[/bold red]"))
            status.update(Text.from_markup("[red]✗ Error[/red]"))
        finally:
            self._running = False
            self._process = None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.action_go_back()
        elif event.button.id == "btn-rerun":
            log = self.query_one("#results-log", RichLog)
            log.clear()
            self.on_mount()
        elif event.button.id == "btn-quit":
            self.action_quit_app()

    def action_go_back(self):
        """Return to the config screen."""
        self.app.pop_screen()

    def action_quit_app(self):
        """Quit the entire application."""
        self.app.exit()


# ─── Data Loading ─────────────────────────────────────────────────────

def load_catalog(exploits_dir, payloads_dir):
    """Load all exploits and payloads."""
    exploit_catalog = {}
    for ref in sorted(list_exploits(exploits_dir)):
        cls = load_exploit(ref, exploits_dir)
        if cls and not ref.startswith("template"):
            exploit_catalog[ref] = cls

    payload_catalog = {}
    for ref in sorted(list_payloads(payloads_dir)):
        cls = load_payload(ref, payloads_dir)
        if cls and ref != "template":
            payload_catalog[ref] = cls

    return exploit_catalog, payload_catalog


# ─── Main TUI App ────────────────────────────────────────────────────

class HWPApp(App):
    """HWP Interactive — single-screen exploit builder."""

    CSS = APP_CSS
    TITLE = "HWP"
    dark = True

    BINDINGS = [
        Binding("ctrl+r", "run_exploit", "Run", show=True, priority=True),
        Binding("ctrl+q", "quit", "Quit", show=True, priority=True),
        Binding("f2", "toggle_scan_filter", "Scan Filter", show=True),
        Binding("tab", "focus_next", "Next", show=False),
        Binding("shift+tab", "focus_previous", "Prev", show=False),
    ]

    def __init__(self, exploits_dir, payloads_dir, verbose=False):
        super().__init__()
        self.exploits_dir = exploits_dir
        self.payloads_dir = payloads_dir
        self.verbose = verbose

        self.exploit_catalog, self.payload_catalog = load_catalog(
            exploits_dir, payloads_dir
        )

        # State
        self.selected_exploit_refs: Set[str] = set()
        self.selected_payload_ref: Optional[str] = None
        self.exploit_filter = ""
        self.payload_filter = ""
        self.rhost = "localhost"
        self.rport = "80"

        # Scan integration
        self.scan_data: Optional[dict] = None
        self.scan_filter_active = False

        self._last_scan_host = ""
        self._scan_match_cache: Dict[str, Optional[str]] = {}
        self._last_args_key = ""
        self._last_payload_key = ""

        # Dynamic arg values: (scope, scope_id, arg_key) → value
        self.arg_values: Dict[Tuple[str, str, str], str] = {}
        self._arg_gen = 0
        self._input_id_to_argref: Dict[str, Tuple[str, str, str]] = {}

    # ── Scan data helpers ─────────────────────────────────────────────

    def _reload_scan_data(self):
        """Load scan data for the current target host (debounced by hostname)."""
        target = self._get_target_url() or self.rhost.strip()
        if not target.strip():
            if self.scan_data is not None:
                self.scan_data = None
                self._update_scan_toggle_display()
            return

        # Extract hostname to avoid reloading on every keystroke
        parsed = urlparse(target if target.startswith("http") else f"http://{target}")
        host = parsed.hostname or target
        host = host.replace("/", "_").replace(":", "_")

        # Skip if same host as last load
        if hasattr(self, "_last_scan_host") and self._last_scan_host == host:
            return

        self._last_scan_host = host
        self.scan_data = _load_scan_data(target)
        # Rebuild match cache
        self._scan_match_cache = {}
        if self.scan_data:
            for ref, cls in self.exploit_catalog.items():
                self._scan_match_cache[ref] = _match_exploit_to_scan(cls, self.scan_data)
        self._update_scan_toggle_display()

    def _update_scan_toggle_display(self):
        """Update the scan toggle label based on state."""
        try:
            toggle = self.query_one("#scan-toggle", Static)
        except Exception:
            return

        has_data = self.scan_data is not None
        if not has_data:
            toggle.update("Scan filter ─")
            toggle.remove_class("active")
        elif self.scan_filter_active:
            toggle.update("Scan filter ●")
            toggle.add_class("active")
        else:
            toggle.update("Scan filter ○")
            toggle.remove_class("active")

    def action_toggle_scan_filter(self):
        """Toggle scan-only filter on/off."""
        if self.scan_data is None:
            return  # No scan data, do nothing
        self.scan_filter_active = not self.scan_filter_active
        self._update_scan_toggle_display()
        self._populate_exploit_list()

    # ── Selected items helpers ────────────────────────────────────────

    def selected_exploits(self) -> List:
        """Return exploit classes for all selected refs, in order."""
        return [
            (ref, self.exploit_catalog[ref])
            for ref in sorted(self.selected_exploit_refs)
            if ref in self.exploit_catalog
        ]

    def selected_payload(self):
        """Return (ref, cls) for selected payload, or None."""
        if self.selected_payload_ref and self.selected_payload_ref in self.payload_catalog:
            return (self.selected_payload_ref, self.payload_catalog[self.selected_payload_ref])
        return None

    def allowed_payload_caps(self) -> Optional[Set[str]]:
        """Capabilities the selected exploits can deliver to payloads."""
        exploits = self.selected_exploits()
        if not exploits:
            return None
        caps = set()
        for _, cls in exploits:
            cap = resolve_capability(cls.capability)
            caps.add(cap)
            # RFI/SSRF exploits can also use AFU payloads (via server fallback)
            if cap in ("RFI", "SSRF"):
                caps.add("AFU")
        return caps

    def matched_method(self) -> Optional[str]:
        """Resolve which method the payload will use with selected exploits."""
        _, method, _ = self._resolve_match()
        return method

    def needs_rfi_server(self) -> bool:
        """True if the current selection requires the RFI server fallback."""
        _, _, needs_server = self._resolve_match()
        return needs_server

    def _resolve_match(self) -> tuple:
        """Returns (index, method, needs_server) for current selection."""
        p = self.selected_payload()
        if not p:
            return None, None, False
        _, pcls = p
        payload_methods = [resolve_method(m) for m in pcls.methods]

        exploits = self.selected_exploits()
        chain_exploits = [
            (ref, cls) for ref, cls in exploits
            if resolve_capability(cls.capability) != "AUTH"
        ]
        if not chain_exploits:
            return None, None, False

        # Direct match first
        for i in range(len(chain_exploits) - 1, -1, -1):
            cap = resolve_capability(chain_exploits[i][1].capability)
            if cap in payload_methods:
                return i, cap, False

        # RFI/SSRF fallback: exploit needs RFI/SSRF, payload has AFU
        for i in range(len(chain_exploits) - 1, -1, -1):
            cap = resolve_capability(chain_exploits[i][1].capability)
            if cap in ("RFI", "SSRF") and "AFU" in payload_methods:
                return i, "AFU", True

        return None, None, False

    # ── Layout ────────────────────────────────────────────────────────

    BANNER_ART = (
        "⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀\n"
        "⣿⡿⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⢿⡵\n"
        "⣿⡇⠀⠀⠉⠛⠛⣿⣿⠛⠛⠉⠀⠀⣿⡇  » hackwp «\n"
        "⣿⣿⣀⠀⢀⣠⣴⡇⠹⣦⣄⡀⠀⣠⣿⡇    by @etragardh\n"
        "⠋⠻⠿⠿⣟⣿⣿⣦⣤⣼⣿⣿⠿⠿⠟⠀\n"
        "⠀   ⠸⡿⣿⣿⢿⡿⢿⠇⠀ v2.0\n"
        "⠀⠀⠀⠀⠀⠀⠈⠁⠈⠁"
    )

    def compose(self) -> ComposeResult:
        # Banner (top — art + live pipeline status)
        with Vertical(id="banner-box"):
            yield Static(self.BANNER_ART, id="banner-art")
            yield Static("", id="plan-line", markup=True)

        # Selection lists (middle — two columns)
        with Grid(id="lists-grid"):
            # Left: Exploits (multi-select)
            with Vertical(classes="list-pane"):
                yield Label("Exploits (multi-select)", classes="list-pane-title")
                with Horizontal(classes="filter-row"):
                    yield Input(placeholder="filter exploits…", id="filter-exploit")
                    yield Static("Scan filter ─", id="scan-toggle", classes="scan-toggle")
                yield SelectionList(id="exploit-list")

            # Right: Payloads (single-select via SelectionList)
            with Vertical(classes="list-pane"):
                yield Label("Payloads", classes="list-pane-title")
                yield Input(placeholder="filter payloads…", id="filter-payload")
                yield SelectionList(id="payload-list")

        # Lower section (args 2fr + description 1fr)
        with Grid(id="lower-grid"):
            # Left: Arguments
            with Vertical(id="args-box"):
                yield Static("[bold cyan]Arguments[/bold cyan]", id="args-title")
                with VerticalScroll(id="args-scroll"):
                    yield Grid(id="args-grid")

            # Right: Description
            with VerticalScroll(id="desc-box"):
                yield Static("", id="desc-content", markup=True)

        # Bottom bar (command preview + Go button)
        with Horizontal(id="bottom-bar"):
            yield Static("", id="cmd-preview", markup=True)
            yield Button("Go ▸", id="btn-go")

        yield Footer()

    # ── Mount / Initial Population ────────────────────────────────────

    def on_mount(self) -> None:
        self._reload_scan_data()
        self._populate_exploit_list()
        self._populate_payload_list()
        self._rebuild_args()
        self._refresh_plan()
        self._refresh_description()
        self._refresh_cmd_preview()

        # Make scan toggle clickable
        toggle = self.query_one("#scan-toggle", Static)
        toggle.can_focus = True

    def on_click(self, event) -> None:
        """Handle clicks on the scan toggle."""
        try:
            toggle = self.query_one("#scan-toggle", Static)
            # Check if the click target is the toggle or a descendant
            node = event.widget
            while node is not None:
                if node is toggle:
                    self.action_toggle_scan_filter()
                    return
                node = node.parent
        except Exception:
            pass

    def on_key(self, event) -> None:
        """Handle Enter on focused scan toggle."""
        if event.key == "enter":
            try:
                toggle = self.query_one("#scan-toggle", Static)
                if toggle.has_focus:
                    self.action_toggle_scan_filter()
                    event.prevent_default()
                    event.stop()
            except Exception:
                pass

    # ── Exploit List (SelectionList — checkboxes) ─────────────────────

    def _populate_exploit_list(self):
        """Rebuild exploit SelectionList with current filter and scan markers."""
        sl = self.query_one("#exploit-list", SelectionList)
        sl.clear_options()

        visible = []
        query = self.exploit_filter.lower().strip()
        for ref, cls in self.exploit_catalog.items():
            cves = " ".join(getattr(cls, "cves", []) or [])
            authors = " ".join(getattr(cls, "authors", []) or [])
            desc = getattr(cls, "description", "") or ""
            searchable = f"{ref} {cls.type} {cls.slug} {cls.capability} {cves} {authors} {desc}".lower()
            if query and query not in searchable:
                continue

            # Scan match status (from cache)
            scan_status = self._scan_match_cache.get(ref)

            # If scan filter is active, hide non-matching exploits
            if self.scan_filter_active and scan_status is None:
                continue

            visible.append((ref, cls, scan_status))

        if not visible:
            return

        MAX_REF = 50
        max_ref = min(MAX_REF, max(len(ref) for ref, _, _ in visible))
        max_type = max(len(cls.type) for _, cls, _ in visible)

        AUTH_WIDTH = 6

        def _cap_len(cls):
            n = len(cls.capability) + 2
            if cls.delivers:
                n += 3 + len(cls.delivers)
            return n

        max_cap = max(_cap_len(cls) for _, cls, _ in visible)

        # Sort: confirmed first, then possible, then rest
        sort_order = {"confirmed": 0, "possible": 1, None: 2}
        visible.sort(key=lambda x: (sort_order.get(x[2], 2), x[0]))

        for ref, cls, scan_status in visible:
            has_conditions = bool(getattr(cls, "conditions", []))
            display_ref = ref if len(ref) <= MAX_REF else ref[:MAX_REF - 1] + "…"

            label = Text()
            label.append(display_ref.ljust(max_ref + 2), style="bold")
            label.append(cls.type.ljust(max_type + 1), style="dim")

            cap_text = f"[{cls.capability}]"
            label.append(cap_text, style="bold cyan")
            used = len(cap_text)
            if cls.delivers:
                label.append(" > ", style="green")
                label.append(cls.delivers, style="bold cyan")
                used += 3 + len(cls.delivers)
            pad = max_cap - used
            if pad > 0:
                label.append(" " * pad)
            label.append(" ")

            if cls.auth_required:
                label.append("auth".ljust(AUTH_WIDTH), style="#ff8c00")
            else:
                label.append("unauth".ljust(AUTH_WIDTH), style="green")

            if has_conditions:
                label.append(" conditions", style="yellow")

            # Scan status marker
            if scan_status == "confirmed":
                label.append("  « confirmed", style="bold red")
            elif scan_status == "possible":
                label.append("  « possible", style="yellow")

            checked = ref in self.selected_exploit_refs
            sl.add_option((label, ref, checked))

    # ── Payload List (SelectionList — single-select with deselect) ────

    def _populate_payload_list(self):
        """Rebuild payload SelectionList, dimming incompatible ones."""
        allowed_caps = self.allowed_payload_caps()
        payload_key = f"{self.payload_filter}|{allowed_caps}|{self.selected_payload_ref}"
        if payload_key == self._last_payload_key:
            return
        self._last_payload_key = payload_key

        sl = self.query_one("#payload-list", SelectionList)
        sl.clear_options()

        query = self.payload_filter.lower().strip()

        visible = []
        for ref, cls in self.payload_catalog.items():
            searchable = f"{ref} {cls.name}".lower()
            if query and query not in searchable:
                continue
            methods = [resolve_capability(m) for m in cls.methods]
            compatible = True
            if allowed_caps is not None:
                compatible = bool(allowed_caps & set(methods))
            visible.append((ref, cls, methods, compatible))

        if not visible:
            return

        max_ref = max(len(ref) for ref, _, _, _ in visible)
        max_name = max(len(cls.name) for _, cls, _, _ in visible)

        for ref, cls, methods, compatible in visible:
            label = Text()

            if compatible:
                label.append(ref.ljust(max_ref + 2), style="bold")
                label.append(cls.name.ljust(max_name + 2), style="dim")
                label.append(f"[{', '.join(cls.methods)}]", style="bold cyan")
            else:
                label.append(ref.ljust(max_ref + 2), style="dim strike")
                label.append(cls.name.ljust(max_name + 2), style="dim strike")
                label.append(f"[{', '.join(cls.methods)}]", style="dim strike")

            is_selected = (ref == self.selected_payload_ref)
            sl.add_option(
                (label, ref, is_selected)
            )

    # ── Arguments Grid (dynamic columns) ──────────────────────────────

    def _rebuild_args(self):
        """Rebuild the arguments grid with one column per selection."""
        # Build a key representing current args structure to skip unnecessary rebuilds
        method = self.matched_method()
        rfi_server = self.needs_rfi_server()
        exploit_refs = tuple(sorted(self.selected_exploit_refs))
        payload_ref = self.selected_payload_ref or ""
        args_key = f"{exploit_refs}|{payload_ref}|{method}|{rfi_server}"
        if args_key == self._last_args_key:
            return
        self._last_args_key = args_key

        grid = self.query_one("#args-grid", Grid)
        grid.remove_children()

        self._arg_gen += 1
        self._input_id_to_argref = {}

        cols = []
        cols.append(("Main", "main", "main", []))

        for ref, cls in self.selected_exploits():
            opts = getattr(cls, "options", None) or []
            if opts:
                short_ref = ref.split("/")[-1] if "/" in ref else ref
                cols.append((short_ref, "exploit", ref, opts))

        p = self.selected_payload()
        if p:
            ref, cls = p
            all_opts = getattr(cls, "options", None) or []
            visible_opts = []
            for opt in all_opts:
                opt_methods = opt.get("methods", None)
                if opt_methods is None or method is None or method in opt_methods:
                    visible_opts.append(opt)
            if visible_opts:
                cols.append((ref, "payload", ref, visible_opts))

        grid.styles.grid_size_columns = len(cols)
        grid.styles.grid_size_rows = 1

        for title, scope, scope_id, opts in cols:
            col = Vertical(classes="arg-col")
            grid.mount(col)
            col.mount(Static(f"[cyan]{title}[/cyan]", classes="arg-col-title"))

            if scope == "main":
                self._mount_arg_row(col, "RHOST", Input(
                    value=self.rhost,
                    id="inp-rhost",
                    placeholder="localhost",
                ))
                self._mount_arg_row(col, "RPORT", Input(
                    value=self.rport,
                    id="inp-rport",
                    placeholder="80",
                ))

                # LHOST/LPORT for RFI server fallback
                if rfi_server:
                    col.mount(Static("[dim]── afu » rfi server ──[/dim]"))

                    lhost_key = ("main", "main", "lhost")
                    lport_key = ("main", "main", "lport")
                    lhost_wid = f"arg-{self._arg_gen}-main-lhost"
                    lport_wid = f"arg-{self._arg_gen}-main-lport"
                    self._input_id_to_argref[lhost_wid] = lhost_key
                    self._input_id_to_argref[lport_wid] = lport_key

                    self._mount_arg_row(col, "LHOST [red]*[/red]", Input(
                        value=self.arg_values.get(lhost_key, ""),
                        id=lhost_wid,
                        placeholder="Your IP reachable by target",
                    ))
                    self._mount_arg_row(col, "LPORT", Input(
                        value=self.arg_values.get(lport_key, ""),
                        id=lport_wid,
                        placeholder="RFI server port (default: 8888)",
                    ))

                continue

            for opt in opts:
                name = opt["name"]
                default = opt.get("default", "")
                help_text = opt.get("help", "")
                required = opt.get("required", False)

                ref_key = (scope, scope_id, name)
                existing = self.arg_values.get(ref_key, "")

                wid = f"arg-{self._arg_gen}-{scope}-{name}"
                self._input_id_to_argref[wid] = ref_key

                if isinstance(default, bool):
                    placeholder = f"{help_text} (default: {'yes' if default else 'no'})"
                elif default:
                    placeholder = f"{help_text} (default: {default})"
                else:
                    placeholder = help_text

                if required:
                    label = f"{name.upper()} [red]*[/red]"
                else:
                    label = name.upper()

                self._mount_arg_row(col, label, Input(
                    value=existing,
                    id=wid,
                    placeholder=placeholder,
                ))

        valid_refs = set(self._input_id_to_argref.values())
        self.arg_values = {k: v for k, v in self.arg_values.items() if k in valid_refs}

    def _mount_arg_row(self, col, label_text, inp):
        """Mount a label + input row inside a column."""
        row = Horizontal(classes="arg-row")
        col.mount(row)
        row.mount(Static(label_text, classes="arg-label"))
        row.mount(inp)

    # ── Plan Line ─────────────────────────────────────────────────────

    def _refresh_plan(self):
        """Update the pipeline plan line at the top."""
        rhost = self.rhost.strip() or self._get_target_url()
        exploit_refs = sorted(self.selected_exploit_refs)
        payload_ref = self.selected_payload_ref or ""

        t = Text()

        if rhost:
            t.append(rhost, style="yellow")
        else:
            t.append("…", style="dim")

        t.append(" > ", style="green")

        t.append("exploit(", style="cyan")
        if exploit_refs:
            t.append(", ".join(exploit_refs), style="bold red")
        t.append(")", style="cyan")

        t.append(" > ", style="green")

        t.append("payload(", style="cyan")
        if payload_ref:
            t.append(payload_ref, style="bold red")
        t.append(")", style="cyan")

        if self._is_ready():
            t.append("  ", style="")
            t.append("  Ctrl+R  ", style="bold white on dark_green")

        self.query_one("#plan-line", Static).update(t)

    # ── Description Pane ──────────────────────────────────────────────

    def _refresh_description(self):
        """Update the right-side description panel with exploit/payload info."""
        lines = []

        exploits = self.selected_exploits()
        if exploits:
            for ref, cls in exploits:
                lines.append(f"[bold cyan]» {ref}[/bold cyan]")

                desc = getattr(cls, "description", "")
                if desc:
                    lines.append(f"  {desc}")

                cves = getattr(cls, "cves", []) or []
                if cves:
                    lines.append(f"  CVE: [bold]{', '.join(cves)}[/bold]")

                authors = getattr(cls, "authors", []) or []
                if authors:
                    lines.append(f"  Author: {', '.join(authors)}")

                credits = getattr(cls, "credits", []) or []
                if credits:
                    lines.append(f"  [dim]Special thanks: {', '.join(credits)}[/dim]")

                conditions = getattr(cls, "conditions", []) or []
                for cond in conditions:
                    lines.append(f"  [yellow]⚠ {cond}[/yellow]")

                # Show scan match info
                scan_status = _match_exploit_to_scan(cls, self.scan_data)
                if scan_status == "confirmed":
                    lines.append(f"  [bold red]« confirmed by scan[/bold red]")
                elif scan_status == "possible":
                    lines.append(f"  [yellow]« possible (version unknown)[/yellow]")

                lines.append("")

        payload = self.selected_payload()
        if payload:
            ref, cls = payload
            lines.append(f"[bold cyan]» {ref}[/bold cyan]")

            desc = getattr(cls, "description", "")
            if desc:
                lines.append(f"  {desc}")

            authors = getattr(cls, "authors", []) or []
            if authors:
                lines.append(f"  Author: {', '.join(authors)}")

            credits = getattr(cls, "credits", []) or []
            if credits:
                lines.append(f"  [dim]Special thanks: {', '.join(credits)}[/dim]")

        if not lines and not self.scan_data:
            lines.append("[dim]Select an exploit or payload to see details[/dim]")

        # Scan intel section (always shown if scan data exists)
        if self.scan_data:
            lines.append("")
            lines.append("[bold cyan]─── Scan Intel ───[/bold cyan]")

            # Collect vulnerability info for color decisions
            vulns = self.scan_data.get("vulnerabilities", [])

            # Core
            core = self.scan_data.get("core", {})
            if core.get("version"):
                # Check if core_status in vulns says insecure
                core_insecure = False
                for v in vulns:
                    if isinstance(v, dict) and v.get("type") == "core_status" and v.get("status") == "insecure":
                        core_insecure = True
                        break
                # Also check if any core vulns exist
                if not core_insecure:
                    for v in vulns:
                        if isinstance(v, dict) and v.get("software_type") == "core":
                            core_insecure = True
                            break
                if core_insecure:
                    lines.append(f"  WP: [red]{core['version']}[/red]")
                else:
                    lines.append(f"  WP: [green]{core['version']}[/green]")

            # Theme
            theme = self.scan_data.get("theme", {})
            if theme.get("slug"):
                tv = theme.get("version", "?")
                # Check if theme has vulns
                theme_slug = theme.get("slug", "")
                theme_vulnerable = False
                for v in vulns:
                    if isinstance(v, dict) and v.get("software_type") == "theme" and v.get("slug") == theme_slug:
                        theme_vulnerable = True
                        break
                if theme_vulnerable:
                    lines.append(f"  Theme: {theme_slug} ([red]{tv}[/red])")
                else:
                    lines.append(f"  Theme: {theme_slug} ([green]{tv}[/green])")

            # Plugins count
            plugins = self.scan_data.get("plugins", {})
            if plugins:
                lines.append(f"  Plugins: {len(plugins)}")

            # Users
            users = self.scan_data.get("users", [])
            if users:
                lines.append(f"  [bold]Users ({len(users)}):[/bold]")
                for u in users:
                    if isinstance(u, dict):
                        slug = u.get("slug", "")
                        uid = u.get("id", "")
                        display = u.get("display_name", "")
                        parts = []
                        if uid:
                            parts.append(f"id:{uid}")
                        if display and display != slug:
                            parts.append(display)
                        extra = f" [dim]({', '.join(parts)})[/dim]" if parts else ""
                        lines.append(f"    [yellow]{slug}[/yellow]{extra}")
                    else:
                        lines.append(f"    [yellow]{u}[/yellow]")

            # Security highlights
            security = self.scan_data.get("security", {})
            if security:
                sec_items = []
                xmlrpc = security.get("xmlrpc")
                if isinstance(xmlrpc, dict) and xmlrpc.get("enabled"):
                    sec_items.append("[red]XML-RPC enabled[/red]")
                if security.get("debug_log"):
                    sec_items.append("[red]debug.log exposed[/red]")
                if security.get("user_registration"):
                    sec_items.append("[yellow]registration open[/yellow]")
                if security.get("wp_cron_public"):
                    sec_items.append("[dim]wp-cron public[/dim]")
                dir_listing = security.get("directory_listing", [])
                if dir_listing:
                    sec_items.append(f"[yellow]{len(dir_listing)} dir listings[/yellow]")
                if sec_items:
                    lines.append(f"  [bold]Security:[/bold]")
                    for item in sec_items:
                        lines.append(f"    {item}")

        self.query_one("#desc-content", Static).update("\n".join(lines))

    # ── Command Preview ───────────────────────────────────────────────

    def _build_command_parts(self) -> List[str]:
        """Build the CLI command as a list of args."""
        parts = ["hwp"]

        target = self._get_target_url()
        if target:
            parts += ["-t", target]

        exploit_refs = sorted(self.selected_exploit_refs)
        if exploit_refs:
            parts.append("--exploit")
            parts.extend(exploit_refs)

        if self.selected_payload_ref:
            parts += ["--payload", self.selected_payload_ref]

        used_flags = set()
        for wid, ref in self._input_id_to_argref.items():
            scope, scope_id, arg_key = ref
            val = self.arg_values.get(ref, "").strip()
            if not val:
                continue

            flag = f"--{arg_key}"
            if flag not in used_flags:
                parts += [flag, val]
                used_flags.add(flag)

        if self.verbose:
            parts.append("-v")

        return parts

    def _refresh_cmd_preview(self):
        """Update the command preview in the bottom bar."""
        parts = self._build_command_parts()

        multi_value_flags = {"--exploit"}

        t = Text()
        current_flag = None

        for i, p in enumerate(parts):
            if i > 0:
                t.append(" ")

            if p == "hwp":
                t.append(p, style="bold white")
                current_flag = None
            elif p.startswith("-"):
                t.append(p, style="cyan")
                current_flag = p
            elif current_flag:
                t.append(p, style="yellow")
                if current_flag not in multi_value_flags:
                    current_flag = None
            else:
                t.append(p, style="white")

        self.query_one("#cmd-preview", Static).update(t)

    # ── Target URL Builder ────────────────────────────────────────────

    def _get_target_url(self) -> str:
        rhost = self.rhost.strip()
        rport = self.rport.strip() or "80"

        if not rhost:
            return ""

        if not rhost.startswith("http"):
            rhost = f"https://{rhost}" if rport == "443" else f"http://{rhost}"

        if rport not in ("80", "443"):
            parsed = urlparse(rhost)
            rhost = f"{parsed.scheme}://{parsed.hostname}:{rport}"

        return rhost.rstrip("/")

    def _is_ready(self) -> bool:
        return bool(
            self.selected_exploit_refs
            and self.selected_payload_ref
            and self._get_target_url()
        )

    # ── Event Handlers ────────────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed) -> None:
        """Route all input changes by widget ID."""
        wid = event.input.id or ""

        if wid == "filter-exploit":
            self.exploit_filter = event.value
            self._populate_exploit_list()
            return

        if wid == "filter-payload":
            self.payload_filter = event.value
            self._populate_payload_list()
            return

        if wid == "inp-rhost":
            self.rhost = event.value
            self._reload_scan_data()
            self._populate_exploit_list()
            self._refresh_plan()
            self._refresh_description()
            self._refresh_cmd_preview()
            return

        if wid == "inp-rport":
            self.rport = event.value
            self._refresh_plan()
            self._refresh_cmd_preview()
            return

        if wid.startswith("arg-"):
            ref = self._input_id_to_argref.get(wid)
            if ref:
                self.arg_values = {**self.arg_values, ref: event.value}
                self._refresh_cmd_preview()
            return

    def on_selection_list_selected_changed(self, event: SelectionList.SelectedChanged) -> None:
        """Handle both exploit and payload selection changes."""
        list_id = event.selection_list.id

        if list_id == "exploit-list":
            self.selected_exploit_refs = set(event.selection_list.selected)
            # Invalidate payload cache since allowed caps may have changed
            self._last_payload_key = ""
            self._populate_payload_list()
            self._rebuild_args()
            self._refresh_plan()
            self._refresh_description()
            self._refresh_cmd_preview()

        elif list_id == "payload-list":
            sl = event.selection_list
            selected = list(sl.selected)

            if not selected:
                self.selected_payload_ref = None
            elif len(selected) == 1:
                ref = selected[0]
                if ref in self.payload_catalog:
                    self.selected_payload_ref = ref
            else:
                old = self.selected_payload_ref
                new_ref = None
                for ref in selected:
                    if ref != old:
                        new_ref = ref
                        break
                if new_ref is None:
                    new_ref = selected[-1]

                self.selected_payload_ref = new_ref
                for ref in selected:
                    if ref != new_ref:
                        sl.deselect(ref)

            self._rebuild_args()
            self._refresh_plan()
            self._refresh_description()
            self._refresh_cmd_preview()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Go button — validate and run."""
        if event.button.id != "btn-go":
            return
        self.action_run_exploit()

    # ── Run / Exit ────────────────────────────────────────────────────

    def action_run_exploit(self):
        """Validate, build command, exit TUI, run in CLI mode."""
        plan_line = self.query_one("#plan-line", Static)

        if not self.rhost.strip():
            plan_line.update(Text.from_markup("[red]Missing:[/red] RHOST"))
            self.bell()
            return

        if not self.selected_exploit_refs:
            plan_line.update(Text.from_markup("[red]Missing:[/red] select at least one exploit"))
            self.bell()
            return

        if not self.selected_payload_ref:
            plan_line.update(Text.from_markup("[red]Missing:[/red] select a payload"))
            self.bell()
            return

        for ref, cls in self.selected_exploits():
            for opt in getattr(cls, "options", []) or []:
                if not opt.get("required", False):
                    continue
                name = opt["name"]
                val = self.arg_values.get(("exploit", ref, name), "").strip()
                if not val:
                    plan_line.update(Text.from_markup(
                        f"[red]Missing:[/red] {ref} → {name}"
                    ))
                    self.bell()
                    return

        method = self.matched_method()
        p = self.selected_payload()
        if p:
            _, pcls = p
            for opt in getattr(pcls, "options", []) or []:
                if not opt.get("required", False):
                    continue
                opt_methods = opt.get("methods", None)
                if opt_methods is not None and method is not None and method not in opt_methods:
                    continue
                name = opt["name"]
                val = self.arg_values.get(("payload", self.selected_payload_ref, name), "").strip()
                if not val:
                    plan_line.update(Text.from_markup(
                        f"[red]Missing:[/red] {self.selected_payload_ref} → {name}"
                    ))
                    self.bell()
                    return

        target = self._get_target_url()
        cmd_parts = [
            sys.executable, os.path.join(self.exploits_dir, "..", "hwp.py"),
            "-t", target,
            "--exploit",
        ]
        cmd_parts.extend(sorted(self.selected_exploit_refs))
        cmd_parts += ["--payload", self.selected_payload_ref]

        used_flags = set()
        for wid, ref_key in self._input_id_to_argref.items():
            scope, scope_id, arg_key = ref_key
            val = self.arg_values.get(ref_key, "").strip()
            if not val:
                continue
            flag = f"--{arg_key}"
            if flag not in used_flags:
                cmd_parts += [flag, val]
                used_flags.add(flag)

        if self.verbose:
            cmd_parts.append("-v")

        cmd_parts.append("--no-banner")

        # Build colored display version of the command (matching config screen style)
        display_parts = self._build_command_parts()
        cmd_display = Text()
        cmd_display.append("$ ", style="dim")
        multi_value_flags = {"--exploit"}
        current_flag = None
        for i, p in enumerate(display_parts):
            if i > 0:
                cmd_display.append(" ")
            if p == "hwp":
                cmd_display.append(p, style="bold white")
                current_flag = None
            elif p.startswith("-"):
                cmd_display.append(p, style="cyan")
                current_flag = p
            elif current_flag:
                cmd_display.append(p, style="yellow")
                if current_flag not in multi_value_flags:
                    current_flag = None
            else:
                cmd_display.append(p, style="white")

        # Push results screen instead of exiting
        self.push_screen(ResultsScreen(cmd_parts, cmd_display=cmd_display))


# ─── Entry Point ──────────────────────────────────────────────────────

def run_interactive(exploits_dir, payloads_dir, verbose=False):
    """Launch the interactive TUI."""
    app = HWPApp(exploits_dir, payloads_dir, verbose=verbose)
    app.run()
