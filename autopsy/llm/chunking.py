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


def scan_stream_chunked(
    graph: Optional[nx.DiGraph],
    diff_text: str,
    changed_files: list[str],
    root_dir: Optional[Path] = None,
    window_lines: int = 400,
    overlap: int = 40,
    scan_fn: Optional[Callable[[str, str], Iterator[str]]] = None,
) -> Iterator[str]:
    """Map-reduce scan: window every target file and scan each window.

    Yields text chunks (deterministic findings first, then per-window LLM
    output). The caller parses + de-duplicates findings across the whole stream.
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
    targets = [f for f in (changed_files or []) if f.endswith(".py")]
    if not targets and root_dir is not None:
        targets = [p.relative_to(root_dir).as_posix()
                   for p in sorted(Path(root_dir).rglob("*.py"))]

    for rel in targets:
        if root_dir is None:
            continue
        path = Path(root_dir) / rel
        if not path.exists():
            continue
        lines = path.read_text(errors="replace").splitlines()
        if not lines:
            continue
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
