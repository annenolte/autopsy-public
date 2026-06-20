"""Extract causally relevant subgraphs for LLM context."""

from __future__ import annotations

from pathlib import Path

import networkx as nx


def extract_subgraph(
    G: nx.DiGraph,
    target: str,
    max_depth: int = 3,
    max_nodes: int = 50,
) -> nx.DiGraph:
    """Extract the subgraph relevant to a target node.

    Walks both upstream (what does target depend on?) and downstream
    (what depends on target?) to build the causal context.

    Args:
        G: The full dependency graph.
        target: Node ID (e.g. "file:src/app.py" or "func:src/app.py::handle_request").
        max_depth: Maximum hops in each direction.
        max_nodes: Cap on total nodes to keep context bounded for LLM.

    Returns:
        A subgraph containing the causally relevant neighborhood.
    """
    if target not in G:
        # Try fuzzy match on the target
        target = _fuzzy_find_node(G, target)
        if not target:
            return nx.DiGraph()

    relevant_nodes = {target}

    # Walk upstream: predecessors (things target depends on)
    _collect_neighbors(G, target, relevant_nodes, max_depth, direction="predecessors")

    # Walk downstream: successors (things that depend on target)
    _collect_neighbors(G, target, relevant_nodes, max_depth, direction="successors")

    # If we have function nodes, also include their parent file nodes
    extra_files = set()
    for node in list(relevant_nodes):
        data = G.nodes.get(node, {})
        if data.get("type") in ("function", "class"):
            file_path = data.get("file")
            if file_path:
                file_node = f"file:{file_path}"
                if file_node in G:
                    extra_files.add(file_node)

    relevant_nodes |= extra_files

    # Cap the total
    if len(relevant_nodes) > max_nodes:
        # Prioritize: target first, then by distance
        relevant_nodes = _prioritize_nodes(G, target, relevant_nodes, max_nodes)

    return G.subgraph(relevant_nodes).copy()


def extract_subgraph_for_file(
    G: nx.DiGraph,
    file_path: str,
    max_depth: int = 3,
    max_nodes: int = 50,
) -> nx.DiGraph:
    """Convenience: extract subgraph for a file path."""
    # Try exact match first
    file_node = f"file:{file_path}"
    if file_node not in G:
        # Try matching by suffix
        for node in G.nodes:
            if node.startswith("file:") and node.endswith(file_path):
                file_node = node
                break
    return extract_subgraph(G, file_node, max_depth, max_nodes)


def extract_subgraph_for_function(
    G: nx.DiGraph,
    function_name: str,
    max_depth: int = 3,
    max_nodes: int = 50,
) -> nx.DiGraph:
    """Convenience: extract subgraph for a function by name."""
    for node, data in G.nodes(data=True):
        if data.get("type") == "function":
            if data.get("name") == function_name or data.get("qualified_name") == function_name:
                return extract_subgraph(G, node, max_depth, max_nodes)
    return nx.DiGraph()


def get_file_contents_for_subgraph(
    subgraph: nx.DiGraph,
    root_dir: Path | None = None,
) -> dict[str, str]:
    """Read the source files referenced by a subgraph.

    Returns a dict of {relative_path: file_contents} for LLM context.
    """
    files = {}
    for node, data in subgraph.nodes(data=True):
        if data.get("type") == "file":
            path_str = data.get("path", "")
            path = Path(path_str)
            if not path.is_absolute() and root_dir:
                path = root_dir / path
            try:
                files[path_str] = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                files[path_str] = f"# Could not read: {path_str}"
    return files


def subgraph_summary(subgraph: nx.DiGraph) -> str:
    """Generate a human-readable summary of a subgraph for LLM context."""
    files = []
    functions = []
    classes = []

    for node, data in subgraph.nodes(data=True):
        match data.get("type"):
            case "file":
                files.append(data.get("path", node))
            case "function":
                functions.append(f"{data.get('qualified_name', node)} ({data.get('file', '?')}:{data.get('line_start', '?')})")
            case "class":
                classes.append(f"{data.get('name', node)} ({data.get('file', '?')}:{data.get('line_start', '?')})")

    edges_by_type: dict[str, int] = {}
    for _, _, edata in subgraph.edges(data=True):
        etype = edata.get("type", "unknown")
        edges_by_type[etype] = edges_by_type.get(etype, 0) + 1

    lines = [
        f"Subgraph: {subgraph.number_of_nodes()} nodes, {subgraph.number_of_edges()} edges",
        f"Files ({len(files)}): {', '.join(files)}",
        f"Functions ({len(functions)}): {', '.join(functions[:20])}",
        f"Classes ({len(classes)}): {', '.join(classes[:10])}",
        f"Edge types: {edges_by_type}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _collect_neighbors(
    G: nx.DiGraph,
    start: str,
    collected: set[str],
    max_depth: int,
    direction: str,
) -> None:
    """BFS in the given direction to collect related nodes."""
    frontier = {start}
    for _ in range(max_depth):
        next_frontier = set()
        for node in frontier:
            if direction == "predecessors":
                neighbors = set(G.predecessors(node))
            else:
                neighbors = set(G.successors(node))
            new = neighbors - collected
            next_frontier |= new
            collected |= new
        frontier = next_frontier
        if not frontier:
            break


def _prioritize_nodes(
    G: nx.DiGraph,
    target: str,
    candidates: set[str],
    max_nodes: int,
) -> set[str]:
    """Keep the most relevant nodes up to max_nodes."""
    # BFS distance from target
    distances = {target: 0}
    frontier = {target}
    depth = 0
    while frontier:
        depth += 1
        next_frontier = set()
        for node in frontier:
            for neighbor in set(G.predecessors(node)) | set(G.successors(node)):
                if neighbor in candidates and neighbor not in distances:
                    distances[neighbor] = depth
                    next_frontier.add(neighbor)
        frontier = next_frontier

    # Sort by distance, take closest
    sorted_nodes = sorted(candidates, key=lambda n: distances.get(n, 999))
    return set(sorted_nodes[:max_nodes])


def _fuzzy_find_node(G: nx.DiGraph, target: str) -> str | None:
    """Try to find a node matching the target string."""
    # Direct match
    if target in G:
        return target

    # Try as file path
    for node in G.nodes:
        if node.endswith(target):
            return node

    # Try as function name
    for node, data in G.nodes(data=True):
        if data.get("name") == target or data.get("qualified_name") == target:
            return node

    return None
