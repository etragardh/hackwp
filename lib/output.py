"""
Output and display utilities.
Consistent with WPScanX UI style using rich.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console(highlight=False)

BANNER_ART = """\
  ⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀
  ⣿⡿⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⢿⡵
  ⣿⡇⠀⠀⠉⠛⠛⣿⣿⠛⠛⠉⠀⠀⣿⡇  » hackwp «
  ⣿⣿⣀⠀⢀⣠⣴⡇⠹⣦⣄⡀⠀⣠⣿⡇    by @etragardh
  ⠋⠻⠿⠿⣟⣿⣿⣦⣤⣼⣿⣿⠿⠿⠟⠀
  ⠀   ⠸⡿⣿⣿⢿⡿⢿⠇⠀ v2.0⠀⠀⠀
  ⠀⠀⠀⠀⠀⠀⠈⠁⠈⠁⠀⠀⠀⠀⠀⠀"""


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
