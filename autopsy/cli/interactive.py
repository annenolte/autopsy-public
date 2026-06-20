"""Autopsy interactive terminal UI — launches when `autopsy` is called with no arguments."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from rich.console import Console
from rich.text import Text
from rich.rule import Rule


def _collect_targets(cwd: Path) -> list[tuple[str, str]]:
    """Collect files and functions from parsed repo. Returns list of (name, kind)."""
    targets: list[tuple[str, str]] = []

    # Files
    py_files = sorted(p.name for p in cwd.glob("*.py"))
    py_files += sorted(str(p.relative_to(cwd)) for p in cwd.rglob("*.py") if p.parent != cwd)
    for f in py_files:
        targets.append((f, "file"))

    # Try to get functions from the parser
    try:
        from autopsy.parser import parse_directory
        parsed = parse_directory(cwd)
        for pf in parsed:
            for func in pf.all_functions:
                targets.append((func.qualified_name, "function"))
    except Exception:
        pass

    return targets


def _pick_target(console: Console, cwd: Path) -> str:
    """Arrow-key picker for selecting a target file or function."""
    targets = _collect_targets(cwd)
    if not targets:
        return console.input("  [bold cyan]Target file or function:[/bold cyan] ").strip()

    try:
        import readchar
    except ImportError:
        # Fallback: just list and prompt
        for name, kind in targets[:20]:
            tag = "[blue]file[/blue]" if kind == "file" else "[yellow]func[/yellow]"
            console.print(f"    {tag}  {name}")
        if len(targets) > 20:
            console.print(f"    [dim]... {len(targets) - 20} more[/dim]")
        return console.input("  [bold cyan]Target file or function:[/bold cyan] ").strip()

    selected = 0
    page_size = min(len(targets), 15)

    while True:
        # Calculate scroll window
        scroll_top = max(0, min(selected - page_size // 2, len(targets) - page_size))
        visible = targets[scroll_top:scroll_top + page_size]

        console.clear()
        console.print(Rule(style="dim white"))
        console.print("  [bold cyan]Select a target[/bold cyan]  [dim]↑↓ navigate · Enter select · / search · q back[/dim]")
        console.print(Rule(style="dim white"))

        if scroll_top > 0:
            console.print("    [dim]...[/dim]")

        for i, (name, kind) in enumerate(visible):
            idx = scroll_top + i
            if kind == "file":
                tag = "[blue]file    [/blue]"
            else:
                tag = "[yellow]function[/yellow]"

            if idx == selected:
                console.print(f"  [bold red]>[/bold red] {tag}  [bold white]{name}[/bold white]")
            else:
                console.print(f"    {tag}  [dim]{name}[/dim]")

        if scroll_top + page_size < len(targets):
            console.print("    [dim]...[/dim]")

        console.print(Rule(style="dim white"))
        console.print(f"  [dim]{selected + 1}/{len(targets)}[/dim]")

        key = readchar.readkey()

        if key == readchar.key.UP:
            selected = (selected - 1) % len(targets)
        elif key == readchar.key.DOWN:
            selected = (selected + 1) % len(targets)
        elif key == readchar.key.ENTER:
            return targets[selected][0]
        elif key == "q" or key == readchar.key.CTRL_C:
            return ""
        elif key == "/":
            # Inline search mode
            console.print()
            query = console.input("  [bold cyan]Search:[/bold cyan] ").strip().lower()
            if query:
                matches = [(n, k) for n, k in targets if query in n.lower()]
                if matches:
                    # Jump to first match
                    for j, (n, k) in enumerate(targets):
                        if query in n.lower():
                            selected = j
                            break


MENU_ITEMS = [
    ("d", "DEBUG THIS", "Trace a bug across the dependency graph"),
    ("s", "SCAN THIS", "Find vulnerabilities in AI-generated code"),
    ("o", "ORIENT ME", "Map this repo's architecture"),
    ("g", "GRAPH", "Show dependency graph stats"),
    ("q", "Quit", ""),
]

KEY_TO_INDEX = {item[0]: i for i, item in enumerate(MENU_ITEMS)}


def _is_git_repo(path: Path) -> bool:
    """Check if path is inside a git repository."""
    try:
        subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=path,
            capture_output=True,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _render_screen(console: Console, selected: int) -> None:
    """Render the full interactive screen."""
    cwd = Path.cwd()
    is_git = _is_git_repo(cwd)

    console.clear()

    # Top rule
    console.print(Rule(style="dim white"))

    # Title
    title = Text(justify="center")
    title.append("          ", style="bold red")
    title.append("A U T O P S Y", style="bold red")
    title.append("   v0.1.0", style="bold red")
    console.print(title)

    subtitle = Text("        AI Vulnerability Detective", style="dim italic white", justify="center")
    console.print(subtitle)

    # Middle rule
    console.print(Rule(style="dim white"))

    # Repo path
    repo_line = Text()
    repo_line.append("  Repo: ", style="dim white")
    repo_line.append(str(cwd), style="bold white")
    console.print(repo_line)

    if not is_git:
        console.print(Text("  ⚠  No git repo detected — some features may be limited", style="yellow"))

    # Tips
    console.print(
        Text(
            "  Tips: Use ↑↓ to navigate · Press Enter to select · q to quit",
            style="dim italic white",
        )
    )

    # Rule before menu
    console.print(Rule(style="dim white"))
    console.print()

    # Menu items
    for i, (key, label, desc) in enumerate(MENU_ITEMS):
        line = Text()
        if i == selected:
            line.append("  > ", style="bold red")
            line.append(f"{key}", style="bold cyan")
            line.append("  ", style="bold red")
            line.append(label, style="bold red")
            if desc:
                line.append(f"      {desc}", style="bold red")
        else:
            line.append("    ", style="dim white")
            line.append(f"{key}", style="bold cyan")
            line.append("  ", style="dim white")
            line.append(label, style="dim white")
            if desc:
                line.append(f"      {desc}", style="dim white")
        console.print(line)

    console.print()
    # Bottom rule
    console.print(Rule(style="dim white"))


def _execute_command(key: str, console: Console) -> bool:
    """Execute a menu command. Returns False if should quit."""
    if key == "q":
        return False

    cwd = Path.cwd()
    import sys

    if key == "d":
        from autopsy.cli.main import debug
        console.print()
        target = _pick_target(console, cwd)
        if not target:
            console.print("[yellow]  No target specified.[/yellow]")
            return True
        query = console.input("  [bold cyan]What's the issue? (Enter to auto-analyze):[/bold cyan] ").strip() or None
        try:
            debug(repo=cwd, target=target, query=query, depth=3, no_llm=False)
        except SystemExit:
            pass
    elif key == "s":
        from autopsy.cli.main import scan
        console.print()
        try:
            scan(repo=cwd, base=None, head="HEAD", uncommitted=True, no_llm=False)
        except SystemExit:
            pass
    elif key == "o":
        from autopsy.cli.main import orient
        console.print()
        try:
            orient(repo=cwd, no_llm=False)
        except SystemExit:
            pass
    elif key == "g":
        from autopsy.cli.main import graph
        console.print()
        try:
            graph(repo=cwd, target=None, depth=3)
        except SystemExit:
            pass

    console.print()
    console.input("[dim]Press Enter to return to menu...[/dim]")
    return True


def _run_with_readchar(console: Console) -> None:
    """Run interactive mode with readchar for single-keypress navigation."""
    import readchar

    selected = 0

    while True:
        _render_screen(console, selected)

        key = readchar.readkey()

        if key == readchar.key.UP:
            selected = (selected - 1) % len(MENU_ITEMS)
        elif key == readchar.key.DOWN:
            selected = (selected + 1) % len(MENU_ITEMS)
        elif key == readchar.key.ENTER:
            chosen_key = MENU_ITEMS[selected][0]
            if not _execute_command(chosen_key, console):
                break
        elif key == readchar.key.CTRL_C:
            break
        elif key in KEY_TO_INDEX:
            selected = KEY_TO_INDEX[key]
            if not _execute_command(key, console):
                break


def _run_with_input(console: Console) -> None:
    """Fallback interactive mode using input() when readchar is not available."""
    console.print(
        "[dim italic]Note: Install readchar (pip install readchar) for arrow key navigation.[/dim italic]\n"
    )

    while True:
        _render_screen(console, 0)
        try:
            choice = console.input("\n  [bold]Enter command (d/s/o/g/q): [/bold]").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice in KEY_TO_INDEX:
            if not _execute_command(choice, console):
                break
        else:
            console.print("[yellow]  Invalid choice. Try d, s, o, g, or q.[/yellow]")


def launch_interactive() -> None:
    """Launch the interactive Autopsy REPL."""
    console = Console()

    try:
        try:
            import readchar  # noqa: F401
            _run_with_readchar(console)
        except ImportError:
            _run_with_input(console)
    except KeyboardInterrupt:
        pass

    console.print()
    console.print("  [bold red] Autopsy out. Stay paranoid.[/bold red]")
    console.print()
