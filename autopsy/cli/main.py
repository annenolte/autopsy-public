"""Autopsy CLI — detect vulnerabilities in AI-generated code."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.tree import Tree
from rich.table import Table

from autopsy.parser import parse_directory
from autopsy.graph.builder import build_dependency_graph
from autopsy.graph.subgraph import (
    extract_subgraph_for_file,
    extract_subgraph_for_function,
    subgraph_summary,
)

app = typer.Typer(
    name="autopsy",
    help="Detect vulnerabilities in AI-generated code by reasoning across dependency graphs.",
)
console = Console()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Autopsy — AI Vulnerability Detective."""
    if ctx.invoked_subcommand is None:
        from autopsy.cli.interactive import launch_interactive
        launch_interactive()


def _parse_and_build(repo: Path):
    """Shared: parse repo and build dependency graph."""
    with console.status("[bold blue]Parsing repository..."):
        parsed = parse_directory(repo)
    console.print(f"Parsed [bold]{len(parsed)}[/bold] files")

    with console.status("[bold blue]Building dependency graph..."):
        graph = build_dependency_graph(parsed)
    _print_graph_stats(graph)
    return parsed, graph


def _stream_to_console(stream_iter, title: str = "Autopsy") -> None:
    """Stream LLM output to the console with live markdown rendering."""
    accumulated = ""
    try:
        with Live(console=console, refresh_per_second=8) as live:
            for chunk in stream_iter:
                accumulated += chunk
                # Only render complete lines as markdown to avoid partial
                # markup (e.g. a bare "###") from rendering as plain text.
                last_newline = accumulated.rfind("\n")
                if last_newline >= 0:
                    renderable = accumulated[:last_newline]
                else:
                    renderable = accumulated
                live.update(Panel(Markdown(renderable), title=title, border_style="green"))
            # Final render with everything
            live.update(Panel(Markdown(accumulated), title=title, border_style="green"))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")


@app.command()
def debug(
    repo: Path = typer.Argument(..., help="Path to the repository root"),
    target: str = typer.Option(None, "--target", "-t", help="Target file or function to debug"),
    query: str = typer.Option(None, "--query", "-q", help="Error message or question to investigate"),
    depth: int = typer.Option(3, "--depth", "-d", help="Max graph traversal depth"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM analysis, only show graph"),
):
    """DEBUG THIS: Trace the causal path of an error across the dependency graph."""
    from autopsy.cli.splash import print_splash
    print_splash(console, "DEBUG THIS")

    repo = repo.resolve()
    if not repo.is_dir():
        console.print(f"[red]Error:[/red] {repo} is not a directory")
        raise typer.Exit(1)

    parsed, graph = _parse_and_build(repo)

    if not target:
        from autopsy.cli.interactive import _pick_target
        target = _pick_target(console, repo)
        if not target:
            console.print("[yellow]No target specified.[/yellow]")
            raise typer.Exit(0)

    if not query:
        query_input = console.input("[bold cyan]What's the issue? (Enter to auto-analyze):[/bold cyan] ").strip()
        if query_input:
            query = query_input

    # Show subgraph
    with console.status(f"[bold blue]Extracting subgraph for {target}..."):
        sub = extract_subgraph_for_file(graph, target, max_depth=depth)
        if sub.number_of_nodes() == 0:
            sub = extract_subgraph_for_function(graph, target, max_depth=depth)

    if sub.number_of_nodes() == 0:
        console.print(f"[yellow]No subgraph found for target:[/yellow] {target}")
        raise typer.Exit(1)

    console.print(Panel(subgraph_summary(sub), title="Relevant Subgraph"))

    if no_llm:
        return

    if not query:
        query = f"Analyze the code at {target} for potential bugs, issues, and error-prone patterns."

    from autopsy.llm.pipeline import debug_stream
    _stream_to_console(
        debug_stream(graph, target, query, root_dir=repo),
        title="DEBUG THIS",
    )


@app.command()
def scan(
    repo: Path = typer.Argument(..., help="Path to the repository root"),
    base: str = typer.Option(None, "--base", "-b", help="Base git ref to diff against"),
    head: str = typer.Option("HEAD", "--head", help="Head git ref"),
    uncommitted: bool = typer.Option(False, "--uncommitted", "-u", help="Scan uncommitted changes"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM analysis, only show graph"),
):
    """SCAN THIS: Find vulnerabilities in AI-generated code changes."""
    from autopsy.cli.splash import print_splash
    print_splash(console, "SCAN THIS")

    repo = repo.resolve()

    parsed, graph = _parse_and_build(repo)

    # Get the diff
    from autopsy.git.diff import get_diff, get_changed_files, get_uncommitted_changes

    try:
        if uncommitted:
            diff_text, changed = get_uncommitted_changes(repo)
        else:
            diff_text = get_diff(repo, base=base, head=head)
            changed = get_changed_files(repo, base=base, head=head)
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    if not diff_text.strip():
        console.print("[yellow]No changes found to scan.[/yellow]")
        raise typer.Exit(0)

    console.print(f"Found [bold]{len(changed)}[/bold] changed files:")
    for f in changed:
        console.print(f"  [dim]{f}[/dim]")

    if no_llm:
        console.print(Panel(diff_text[:2000], title="Diff Preview"))
        return

    from autopsy.llm.pipeline import scan_stream
    _stream_to_console(
        scan_stream(graph, diff_text, changed, root_dir=repo),
        title="SCAN THIS",
    )


@app.command()
def orient(
    repo: Path = typer.Argument(..., help="Path to the repository root"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM narrative, only show graph"),
):
    """ORIENT ME: Generate a structured map of the repository."""
    from autopsy.cli.splash import print_splash
    print_splash(console, "ORIENT ME")

    repo = repo.resolve()

    parsed, graph = _parse_and_build(repo)

    # Build file tree string
    tree = Tree(f"[bold]{repo.name}[/bold]")
    files_by_dir: dict[str, list[str]] = {}
    file_tree_lines = []
    for pf in parsed:
        try:
            rel = pf.path.relative_to(repo)
        except ValueError:
            rel = pf.path
        parent = str(rel.parent) if str(rel.parent) != "." else "(root)"
        files_by_dir.setdefault(parent, []).append(rel.name)
        file_tree_lines.append(f"{parent}/{rel.name}")

    for dir_name, files in sorted(files_by_dir.items()):
        branch = tree.add(f"[blue]{dir_name}/[/blue]")
        for f in sorted(files):
            branch.add(f)
    console.print(tree)

    # Complexity hotspots
    hotspot_lines = []
    table = Table(title="Complexity Hotspots (most called functions)")
    table.add_column("Function", style="cyan")
    table.add_column("File", style="dim")
    table.add_column("Callers", justify="right", style="bold")

    in_degrees = []
    for node, data in graph.nodes(data=True):
        if data.get("type") == "function":
            call_edges = [
                e for e in graph.in_edges(node, data=True) if e[2].get("type") == "calls"
            ]
            if call_edges:
                in_degrees.append((data.get("qualified_name", node), data.get("file", "?"), len(call_edges)))

    in_degrees.sort(key=lambda x: x[2], reverse=True)
    for name, file, count in in_degrees[:15]:
        table.add_row(name, file, str(count))
        hotspot_lines.append(f"- {name} ({file}): {count} callers")

    if in_degrees:
        console.print(table)

    if no_llm:
        return

    from autopsy.llm.pipeline import orient_stream
    _stream_to_console(
        orient_stream(
            graph,
            root_dir=repo,
            file_tree="\n".join(file_tree_lines),
            hotspots="\n".join(hotspot_lines),
        ),
        title="ORIENT ME",
    )


@app.command()
def graph(
    repo: Path = typer.Argument(..., help="Path to the repository root"),
    target: str = typer.Option(None, "--target", "-t", help="Show subgraph for a target"),
    depth: int = typer.Option(3, "--depth", "-d", help="Max graph traversal depth"),
    view: bool = typer.Option(False, "--view", "-v", help="Open interactive graph in browser"),
):
    """Show dependency graph statistics for a repository."""
    repo = repo.resolve()

    parsed, g = _parse_and_build(repo)

    display_graph = g
    if target:
        sub = extract_subgraph_for_file(g, target, max_depth=depth)
        if sub.number_of_nodes() == 0:
            sub = extract_subgraph_for_function(g, target, max_depth=depth)
        if sub.number_of_nodes() > 0:
            console.print(Panel(subgraph_summary(sub), title=f"Subgraph: {target}"))
            display_graph = sub
        else:
            console.print(f"[yellow]No subgraph found for:[/yellow] {target}")
            return

    if view:
        from autopsy.graph.visualize import open_graph_in_browser

        path = open_graph_in_browser(display_graph, root_dir=repo, target=target)
        console.print(f"[bold green]Opened interactive graph in browser[/bold green]")
        console.print(f"[dim]{path}[/dim]")


@app.command()
def serve(
    port: int = typer.Option(7891, "--port", "-p", help="Port to run the server on"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
):
    """Start the Autopsy API server for VS Code extension communication."""
    import uvicorn
    console.print(Panel(f"[bold]Autopsy Server[/bold] — http://{host}:{port}", style="blue"))
    console.print("[dim]Press Ctrl+C to stop.[/dim]")
    uvicorn.run("autopsy.server.app:app", host=host, port=port, log_level="info")


def _print_graph_stats(G) -> None:
    """Print graph statistics to console."""
    file_nodes = sum(1 for _, d in G.nodes(data=True) if d.get("type") == "file")
    func_nodes = sum(1 for _, d in G.nodes(data=True) if d.get("type") == "function")
    class_nodes = sum(1 for _, d in G.nodes(data=True) if d.get("type") == "class")

    import_edges = sum(1 for _, _, d in G.edges(data=True) if d.get("type") == "imports")
    call_edges = sum(1 for _, _, d in G.edges(data=True) if d.get("type") == "calls")

    table = Table(title="Dependency Graph")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="bold")

    table.add_row("Files", str(file_nodes))
    table.add_row("Functions", str(func_nodes))
    table.add_row("Classes", str(class_nodes))
    table.add_row("Import edges", str(import_edges))
    table.add_row("Call edges", str(call_edges))
    table.add_row("Total nodes", str(G.number_of_nodes()))
    table.add_row("Total edges", str(G.number_of_edges()))

    console.print(table)
