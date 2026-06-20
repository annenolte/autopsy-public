"""Blast radius computation via reverse-BFS on the dependency graph."""

from __future__ import annotations

import networkx as nx


def get_blast_radius(
    graph: nx.DiGraph,
    vulnerable_node: str,
    max_depth: int = 5,
) -> list[dict]:
    """Reverse-BFS from vulnerable_node to find all callers that can reach it.

    Returns list of dicts with node, depth, path, and direct_caller flag.
    """
    if vulnerable_node not in graph:
        return []

    try:
        reversed_graph = graph.reverse()
    except Exception:
        return []

    blast_radius: list[dict] = []
    visited = set()
    # queue entries: (node, depth, path_so_far)
    queue: list[tuple[str, int, list[str]]] = [(vulnerable_node, 0, [])]

    while queue:
        node, depth, path = queue.pop(0)
        if depth >= max_depth:
            continue
        for caller in reversed_graph.neighbors(node):
            if caller not in visited:
                visited.add(caller)
                chain = path + [caller]
                blast_radius.append({
                    "node": caller,
                    "depth": depth + 1,
                    "path": chain,
                    "direct_caller": depth == 0,
                })
                queue.append((caller, depth + 1, chain))

    blast_radius.sort(key=lambda x: x["depth"])
    return blast_radius


def format_blast_radius(blast_radius: list[dict], max_display: int = 10) -> tuple[str, str]:
    """Format blast radius for terminal output and Sonnet prompt injection.

    Returns (terminal_output, prompt_context).
    """
    if not blast_radius:
        return "No callers found in dependency graph.", ""

    direct = [b for b in blast_radius if b["direct_caller"]]
    indirect = [b for b in blast_radius if not b["direct_caller"]]

    # Terminal display
    display = blast_radius[:max_display]
    lines: list[str] = []
    for i, b in enumerate(display):
        prefix = "\u251c\u2500\u2500" if i < len(display) - 1 else "\u2514\u2500\u2500"
        depth_label = "direct caller" if b["direct_caller"] else f"depth {b['depth']}"
        lines.append(f"  {prefix} {b['node']}  ({depth_label})")

    if len(blast_radius) > max_display:
        lines.append(f"  \u2514\u2500\u2500 ... {len(blast_radius) - max_display} more")

    terminal_output = "\n".join(lines)

    # Sonnet prompt injection (structured, capped at 15)
    prompt_context = f"COMPUTED BLAST RADIUS ({len(blast_radius)} nodes can reach this vulnerability):\n"
    for b in blast_radius[:15]:
        prompt_context += f"  - {b['node']} (depth {b['depth']})\n"
    prompt_context += f"Direct callers: {len(direct)}, Indirect: {len(indirect)}\n"
    prompt_context += (
        "Use these SPECIFIC file/function names in your blast radius explanation. "
        "Do not guess \u2014 these are computed from the actual dependency graph.\n"
    )

    return terminal_output, prompt_context
