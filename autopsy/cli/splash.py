"""Autopsy splash screen."""

from rich.text import Text


def print_splash(console, mode: str = "") -> None:
    """Print a minimal Autopsy header."""
    console.print()
    if mode:
        console.print(f"  [bold red] AUTOPSY[/bold red]  [bold]{mode}[/bold]")
    else:
        console.print("  [bold red] AUTOPSY[/bold red]")
    console.print()
