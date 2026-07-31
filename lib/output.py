"""
Output and display utilities.
Consistent with WPScanX UI style using rich.
"""

import base64
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console(highlight=False)

from lib.version_info import HWP_VERSION

BANNER_ART = """\
  ⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀
  ⣿⡿⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⢿⡵
  ⣿⡇⠀⠀⠉⠛⠛⣿⣿⠛⠛⠉⠀⠀⣿⡇  » hackwp «
  ⣿⣿⣀⠀⢀⣠⣴⡇⠹⣦⣄⡀⠀⣠⣿⡇    by @etragardh
  ⠋⠻⠿⠿⣟⣿⣿⣦⣤⣼⣿⣿⠿⠿⠟⠀
  ⠀   ⠸⡿⣿⣿⢿⡿⢿⠇⠀ v{ver}⠀⠀⠀
  ⠀⠀⠀⠀⠀⠀⠈⠁⠈⠁⠀⠀⠀⠀⠀⠀""".format(ver=HWP_VERSION)


def banner():
    console.print(Panel(
        Text(BANNER_ART, style="bold cyan"),
        subtitle="[dim]For authorized security testing[/dim]",
        border_style="cyan",
    ))


def section(title: str):
    console.print(f"\n[bold cyan]{'━' * 60}[/bold cyan]")
    console.print(f"[bold cyan]  {title}[/bold cyan]")
    console.print(f"[bold cyan]{'━' * 60}[/bold cyan]")


def info(msg: str, detail: str = ""):
    if detail:
        console.print(f"  [dim]ℹ[/dim]  {msg} [bold]{detail}[/bold]")
    else:
        console.print(f"  [dim]ℹ[/dim]  {msg}")


def success(msg: str, detail: str = ""):
    if detail:
        console.print(f"  [green]✓[/green]  {msg} [bold green]{detail}[/bold green]")
    else:
        console.print(f"  [green]✓[/green]  {msg}")


def warn(msg: str, detail: str = ""):
    if detail:
        console.print(f"  [yellow]⚠[/yellow]  {msg} [bold yellow]{detail}[/bold yellow]")
    else:
        console.print(f"  [yellow]⚠[/yellow]  {msg}")


def error(msg: str, detail: str = ""):
    if detail:
        console.print(f"  [bold red]✗[/bold red]  {msg} {detail}")
    else:
        console.print(f"  [bold red]✗[/bold red]  {msg}")


def debug(msg: str, detail: str = ""):
    if detail:
        console.print(f"  [dim]  › {msg} {detail}[/dim]")
    else:
        console.print(f"  [dim]  › {msg}[/dim]")


def chain_info(msg: str, detail: str = ""):
    if detail:
        console.print(f"  [magenta]▶[/magenta]  {msg} [bold magenta]{detail}[/bold magenta]")
    else:
        console.print(f"  [magenta]▶[/magenta]  {msg}")


def copy_to_clipboard(text: str) -> bool:
    """Copy text to the terminal clipboard via the OSC-52 escape sequence.

    Works in most modern terminals (iTerm2, kitty, wezterm, tmux with the
    right setting, …). Returns True if the sequence was emitted; the caller
    always prints the text too, so an unsupported terminal loses nothing.
    """
    try:
        b64 = base64.b64encode(text.encode()).decode()
        sys.stdout.write(f"\033]52;c;{b64}\a")
        sys.stdout.flush()
        return True
    except Exception:
        return False


def xssr_url(url: str, message: str = ""):
    """Display a reflected-XSS crafted URL for the operator to open in a browser.

    Reflected XSS fires in the victim's browser, so the framework never
    requests the URL — it prints it and copies it to the clipboard (OSC-52) for
    the operator to paste into a browser (as the victim). The URL is printed
    unwrapped on its own line so the TUI can capture it for a Copy button.
    """
    console.print()
    console.print("  [bold magenta]⚡ Reflected XSS — paste into a browser as the victim:[/bold magenta]")
    console.print(Text("  " + url, style="bold cyan"), soft_wrap=True)
    if copy_to_clipboard(url):
        console.print("  [dim]ℹ  copied to clipboard[/dim]")
    if message:
        console.print(f"  [dim]ℹ  {message}[/dim]")


def print_table(title: str, rows: list[tuple[str, str]], style: str = "cyan"):
    """Print a two-column table (used for listing exploits/payloads)."""
    if not rows:
        return
    table = Table(title=title, border_style=style, show_lines=False)
    table.add_column("Module", style="bold")
    table.add_column("Details")
    for item, detail in rows:
        table.add_row(item, detail)
    console.print(table)


# ── Scanner-compatible aliases ────────────────────────────────────────
# These allow scanner/ modules to import from lib.output using the
# names they were originally written with, without maintaining a
# separate scanner/output.py.

# found() = success() — green checkmark
found = success

# vuln() = error() — red X
vuln = error

# print_banner() = banner()
print_banner = banner

# print_results_table() = print_table()
print_results_table = print_table


def notfound(msg: str):
    """Dimmed message for items not detected."""
    console.print(f"  [dim]–[/dim]  [dim]{msg}[/dim]")


def verbose(msg: str, is_verbose: bool):
    """Print only when verbose mode is on."""
    if is_verbose:
        console.print(f"  [dim]  › {msg}[/dim]")
