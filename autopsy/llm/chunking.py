"""Map-reduce scanning for codebases too large to fit one LLM context.

The single-shot scan in pipeline.py builds one context with every relevant file
and truncates any file past 500 lines. On a real repository that silently drops
most of the code (e.g. pygoat's introduction/views.py is ~1,240 lines, so
everything after line 500 is never seen). This module fixes that by *mapping*
the scan over line windows that cover every file completely, scanning each
window in its own LLM call, then *reducing* (the caller concatenates the streamed
output and de-duplicates findings).

The deterministic AST/graph layer is scale-invariant and runs once over the
whole repo; only the LLM step is windowed.

`scan_fn` is injectable so the windowing + reduction can be tested offline with
no API calls.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Callable, Optional

import networkx as nx


def iter_line_windows(total_lines: int, window: int = 400, overlap: int = 40):
    """Yield 1-indexed (start, end) line windows covering every line.

    Consecutive windows overlap by `overlap` lines so a vulnerability spanning a
    boundary is fully visible in at least one window.
    """
    if total_lines <= 0:
        return
    if total_lines <= window:
        yield (1, total_lines)
        return
    step = max(1, window - overlap)
    start = 1
    while start <= total_lines:
        end = min(start + window - 1, total_lines)
        yield (start, end)
        if end >= total_lines:
            break
        start += step


def _graph_neighbors_note(graph: Optional[nx.DiGraph], rel: str) -> str:
    """A short note of cross-file calls made by functions defined in `rel`.

    Gives each window the dependency context the single-shot scan would have had,
    without sending the whole graph. Best-effort; never raises.
    """
    if graph is None:
        return ""
    try:
        base = Path(rel).name
        out_calls: set[str] = set()
        for u, v, d in graph.edges(data=True):
            if d.get("type") != "calls":
                continue
            uf = graph.nodes[u].get("file", "")
            if uf.endswith(base):
                callee = v.split("::")[-1] if "::" in v else v
                vf = Path(graph.nodes[v].get("file", "")).name
                if vf and vf != base:
                    out_calls.add(f"{callee} (in {vf})")
        if not out_calls:
            return ""
        items = ", ".join(sorted(out_calls)[:20])
        return f"\n## Cross-file calls from this file\n{items}\n"
    except Exception:  # pragma: no cover — context note is optional
        return ""


def _graph_subgraph_bodies(
    graph: Optional[nx.DiGraph],
    rel: str,
    root_dir: Optional[Path],
    max_depth: int = 2,
    max_lines: int = 250,
) -> str:
    """Inject the actual source bodies of cross-file callees and callers.

    The stronger graph mode (vs the names-only `_graph_neighbors_note`). For each
    function defined in `rel`, walk the call graph up to `max_depth` hops in both
    directions, keep only nodes in *other* files, read their real bodies from
    disk, and return them as labelled code blocks capped at ~`max_lines` total.

    Best-effort; never raises. Returns "" if no cross-file body is available so
    the window prompt is identical to off-mode in that case.
    """
    if graph is None or root_dir is None:
        return ""
    try:
        base = Path(rel).name
        # Function nodes defined in this file.
        seeds = [
            n for n, d in graph.nodes(data=True)
            if d.get("type") == "function"
            and Path(d.get("file", "")).name == base
        ]
        if not seeds:
            return ""
        # BFS in both directions collecting cross-file function nodes.
        collected: dict[str, int] = {}  # node -> depth
        frontier = set(seeds)
        for depth in range(1, max_depth + 1):
            nxt: set[str] = set()
            for node in frontier:
                neighbors = set(graph.successors(node)) | set(graph.predecessors(node))
                for nb in neighbors:
                    nd = graph.nodes.get(nb, {})
                    if nd.get("type") != "function":
                        continue
                    if Path(nd.get("file", "")).name == base:
                        continue  # same file — already in the window
                    if nb not in collected:
                        collected[nb] = depth
                        nxt.add(nb)
            frontier = nxt
            if not frontier:
                break
        if not collected:
            return ""
        # Read bodies, nearest first, until the line budget is spent.
        blocks: list[str] = []
        used = 0
        for node in sorted(collected, key=lambda n: (collected[n], n)):
            nd = graph.nodes[node]
            fpath = Path(root_dir) / nd.get("file", "")
            ls, le = nd.get("line_start"), nd.get("line_end")
            if not fpath.exists() or ls is None or le is None:
                continue
            try:
                src = fpath.read_text(errors="replace").splitlines()
            except OSError:
                continue
            body = src[ls - 1:le]
            if used + len(body) > max_lines:
                body = body[: max(0, max_lines - used)]
            if not body:
                break
            qn = nd.get("qualified_name", node.split("::")[-1])
            fname = Path(nd.get("file", "")).name
            numbered = "\n".join(
                f"{ls + i}: {line}" for i, line in enumerate(body)
            )
            blocks.append(
                f"### `{qn}` (in {fname}, depth {collected[node]})\n"
                f"```\n{numbered}\n```"
            )
            used += len(body)
            if used >= max_lines:
                break
        if not blocks:
            return ""
        header = (
            "\n## Cross-file callee/caller bodies (dependency subgraph)\n"
            "These functions are connected to this file by the call graph; their "
            "real source is included so cross-file data flow is visible.\n"
        )
        return header + "\n".join(blocks) + "\n"
    except Exception:  # pragma: no cover — context injection is optional
        return ""


def scan_stream_chunked(
    graph: Optional[nx.DiGraph],
    diff_text: str,
    changed_files: list[str],
    root_dir: Optional[Path] = None,
    window_lines: int = 400,
    overlap: int = 40,
    scan_fn: Optional[Callable[[str, str], Iterator[str]]] = None,
    graph_mode: str = "note",
) -> Iterator[str]:
    """Map-reduce scan: window every target file and scan each window.

    Yields text chunks (deterministic findings first, then per-window LLM
    output). The caller parses + de-duplicates findings across the whole stream.

    graph_mode selects what dependency context each window carries:
      - "off":      none (equivalent to passing graph=None).
      - "note":     the names-only cross-file call note (current default).
      - "subgraph": the actual source bodies of cross-file callees/callers
                    (depth 1-2, ~250-line cap). Stronger but heavier; intended
                    for the recall test on cross-file-heavy targets.
    """
    from autopsy.llm.client import stream_sonnet
    from autopsy.llm.prompts import SCAN_SYSTEM

    scan_fn = scan_fn or stream_sonnet

    # ── Reduce-once deterministic layer (scale-invariant) ──
    if root_dir is not None:
        try:
            from autopsy.detection.ignored_returns import (
                detect_ignored_security_returns, format_ignored_return_findings,
            )
            from autopsy.detection.static_rules import (
                detect_static_rules, format_static_findings,
            )
            only = changed_files or None
            ig = detect_ignored_security_returns(root_dir, only_files=only)
            if ig:
                yield format_ignored_return_findings(ig) + "\n"
            st = detect_static_rules(root_dir, only_files=only)
            if st:
                yield format_static_findings(st) + "\n"
        except Exception as e:  # pragma: no cover — defensive
            yield f"[note] Static analysis skipped: {e}\n\n"

    # ── Map the LLM scan over line windows of every target file ──
    _exts = (".py", ".js", ".ts", ".tsx", ".jsx")
    targets = [f for f in (changed_files or []) if f.endswith(_exts)]
    if not targets and root_dir is not None:
        targets = [p.relative_to(root_dir).as_posix()
                   for p in sorted(Path(root_dir).rglob("*"))
                   if p.suffix in _exts and p.is_file()]

    for rel in targets:
        if root_dir is None:
            continue
        path = Path(root_dir) / rel
        if not path.exists():
            continue
        lines = path.read_text(errors="replace").splitlines()
        if not lines:
            continue
        if graph_mode == "off":
            neighbor = ""
        elif graph_mode == "subgraph":
            neighbor = _graph_subgraph_bodies(graph, rel, root_dir)
        else:  # "note" (default)
            neighbor = _graph_neighbors_note(graph, rel)
        for start, end in iter_line_windows(len(lines), window_lines, overlap):
            numbered = "\n".join(
                f"{i}: {lines[i - 1]}" for i in range(start, end + 1)
            )
            user_msg = (
                f"## File `{rel}` (lines {start}-{end} of {len(lines)})\n"
                f"```\n{numbered}\n```\n{neighbor}\n"
                f"## Task\nReport security vulnerabilities in this code using the "
                f"## [SEVERITY: ...] format, with **Location:** `{rel}:LINE` using "
                f"the exact line numbers shown."
            )
            yield f"\n[scanning {rel}:{start}-{end}]\n"
            for chunk in scan_fn(SCAN_SYSTEM, user_msg):
                yield chunk
