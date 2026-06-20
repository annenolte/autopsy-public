"""Two-model reasoning pipeline: Haiku triage → Sonnet deep analysis."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import networkx as nx

from autopsy.cache import EmbeddingCache, compute_embeddings
from autopsy.graph.subgraph import (
    extract_subgraph,
    extract_subgraph_for_file,
    extract_subgraph_for_function,
    get_file_contents_for_subgraph,
    subgraph_summary,
)
from autopsy.graph.traversal import get_blast_radius, format_blast_radius
from autopsy.llm.client import call_haiku, stream_sonnet
from autopsy.llm.prompts import (
    TRIAGE_SYSTEM,
    DEBUG_SYSTEM,
    SCAN_SYSTEM,
    ORIENT_SYSTEM,
)


def _build_context_message(
    subgraph: nx.DiGraph,
    root_dir: Path | None = None,
    extra: str = "",
) -> str:
    """Build the context message from a subgraph for LLM consumption."""
    summary = subgraph_summary(subgraph)
    files = get_file_contents_for_subgraph(subgraph, root_dir)

    parts = [
        "## Dependency Graph\n" + summary,
        "\n## Source Files\n",
    ]
    for path, content in files.items():
        # Truncate very long files to keep context bounded
        lines = content.split("\n")
        if len(lines) > 500:
            content = "\n".join(lines[:500]) + f"\n\n... ({len(lines) - 500} lines truncated)"
        parts.append(f"### {path}\n```\n{content}\n```\n")

    if extra:
        parts.append(f"\n## Additional Context\n{extra}")

    return "\n".join(parts)


def triage(
    graph: nx.DiGraph,
    target: str,
    query: str,
    root_dir: Path | None = None,
    max_depth: int = 3,
) -> tuple[nx.DiGraph, dict]:
    """Phase 1: Use Haiku to triage which parts of the subgraph matter.

    Returns the refined subgraph and the triage result dict.
    """
    # Get initial broad subgraph
    sub = extract_subgraph_for_file(graph, target, max_depth=max_depth, max_nodes=80)
    if sub.number_of_nodes() == 0:
        sub = extract_subgraph_for_function(graph, target, max_depth=max_depth, max_nodes=80)
    if sub.number_of_nodes() == 0:
        return sub, {"error": f"No subgraph found for target: {target}"}

    context = _build_context_message(sub, root_dir)
    user_msg = f"{context}\n\n## Query\n{query}"

    raw = call_haiku(TRIAGE_SYSTEM, user_msg)

    # Parse triage response
    try:
        # Try to extract JSON from the response
        json_start = raw.find("{")
        json_end = raw.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            triage_result = json.loads(raw[json_start:json_end])
        else:
            triage_result = {"relevant_files": [], "reasoning": raw}
    except json.JSONDecodeError:
        triage_result = {"relevant_files": [], "reasoning": raw}

    # Refine subgraph based on triage — keep only relevant files' nodes
    relevant_files = triage_result.get("relevant_files", [])
    if relevant_files:
        relevant_nodes = set()
        for node, data in sub.nodes(data=True):
            file_path = data.get("path") or data.get("file", "")
            for rf in relevant_files:
                if rf in file_path or file_path.endswith(rf):
                    relevant_nodes.add(node)
                    break
            # Also keep function nodes inside relevant files
            if data.get("type") in ("function", "class"):
                node_file = data.get("file", "")
                for rf in relevant_files:
                    if rf in node_file or node_file.endswith(rf):
                        relevant_nodes.add(node)
                        break

        if relevant_nodes:
            sub = sub.subgraph(relevant_nodes).copy()

    return sub, triage_result


def debug_stream(
    graph: nx.DiGraph,
    target: str,
    query: str,
    root_dir: Path | None = None,
) -> Iterator[str]:
    """DEBUG THIS: Full pipeline — triage then stream causal reasoning.

    Yields text chunks for real-time display.
    """
    yield "🔍 Triaging with Haiku...\n\n"

    try:
        sub, triage_result = triage(graph, target, query, root_dir)
    except RuntimeError as e:
        yield f"[Triage error: {e}]\n"
        return

    if sub.number_of_nodes() == 0:
        yield f"No relevant code found for target: {target}\n"
        return

    reasoning = triage_result.get("reasoning", "")
    severity = triage_result.get("severity", "unknown")
    yield f"Triage: {severity} severity — {reasoning}\n\n"

    # Compute blast radius for relevant functions
    blast_context = ""
    relevant_funcs = triage_result.get("relevant_functions", [])
    for func_name in relevant_funcs:
        node_id = _resolve_function_node(graph, func_name)
        if node_id:
            br = get_blast_radius(graph, node_id)
            if br:
                terminal_out, prompt_ctx = format_blast_radius(br)
                yield f" Blast Radius — {len(br)} nodes can reach {func_name}:\n{terminal_out}\n\n"
                blast_context += f"\n## Blast Radius for {func_name}\n{prompt_ctx}"

    yield "🧠 Deep analysis with Sonnet...\n\n"

    extra = f"Triage notes: {reasoning}"
    if blast_context:
        extra += blast_context
    context = _build_context_message(sub, root_dir, extra=extra)
    user_msg = f"{context}\n\n## Error/Question\n{query}"

    yield from stream_sonnet(DEBUG_SYSTEM, user_msg)


def scan_stream(
    graph: nx.DiGraph,
    diff_text: str,
    changed_files: list[str],
    root_dir: Path | None = None,
    use_triage: bool = True,
) -> Iterator[str]:
    """SCAN THIS: Scan diff for vulnerabilities with graph context.

    Yields text chunks for real-time display.

    use_triage=False skips the Haiku triage step (graph + Sonnet only) — used by
    the eval's "sonnet-only" arm to measure whether Haiku triage adds value
    (reviewer #16). Default True preserves the normal Haiku+Sonnet pipeline.
    """
    # ------------------------------------------------------------------
    # Deletion analysis — runs BEFORE the existing addition/modification
    # scan. Catches zero-footprint activations (comment boundary deletes)
    # and structural deletions (security controls, broken edges) that an
    # addition-only diff scan would miss entirely.
    # ------------------------------------------------------------------
    activated_nodes: list[str] = []
    try:
        from autopsy.detection.deletions import (
            detect_comment_boundary_deletions,
            format_comment_deletion_warning,
            format_security_deletion_warning,
            format_broken_edge_warning,
        )
        from autopsy.graph.builder import build_graph_at_commit, diff_graphs

        # Phase 1: Comment boundary detection on the raw diff text.
        comment_deletions = detect_comment_boundary_deletions(diff_text)
        if comment_deletions:
            yield format_comment_deletion_warning(comment_deletions) + "\n"

        # Phase 2: Pre/post graph diff. Reads file contents from the git
        # object database into a tempdir — never touches the working tree.
        if root_dir is not None:
            try:
                import git as _git

                repo = _git.Repo(str(root_dir))
                # Initial-commit edge case — no parent to diff against.
                parents = repo.head.commit.parents
                if not parents:
                    raise IndexError("initial commit")

                pre_sha = parents[0].hexsha
                post_sha = repo.head.commit.hexsha

                yield "🧬 Building pre/post commit graph snapshots...\n\n"
                pre_graph = build_graph_at_commit(str(root_dir), pre_sha)
                post_graph = build_graph_at_commit(str(root_dir), post_sha)
                graph_diff = diff_graphs(pre_graph, post_graph)

                if graph_diff["security_critical_deletions"]:
                    yield format_security_deletion_warning(graph_diff) + "\n"
                if graph_diff["broken_edges"]:
                    yield format_broken_edge_warning(graph_diff) + "\n"

                activated_nodes = list(graph_diff["activated_nodes"])
                if activated_nodes:
                    yield (
                        f"✨ Graph diff surfaced {len(activated_nodes)} "
                        f"activated node(s) — feeding into the addition scan "
                        f"as extra targets.\n\n"
                    )
            except IndexError:
                yield "[note] Initial commit — skipping graph diff, using diff-only scan.\n\n"
            except Exception as e:  # pragma: no cover — defensive: never break the scan
                yield f"[note] Graph diff skipped: {e}\n\n"
    except Exception as e:  # pragma: no cover — defensive
        yield f"[note] Deletion analysis unavailable: {e}\n\n"

    # ------------------------------------------------------------------
    # Graph-derived static check — security gate whose return value is
    # discarded (e.g. check_permission(...) called but its result ignored).
    # The dependency graph records the cross-file call edge; the AST tells us
    # the return is thrown away. We emit these as standard findings so the
    # result is deterministic and does not depend on the model noticing the
    # pattern. This is a cross-file capability the graph enables that a plain
    # prompt reproduces unreliably.
    # ------------------------------------------------------------------
    deterministic_findings_md = ""
    try:
        from autopsy.detection.ignored_returns import (
            detect_ignored_security_returns,
            format_ignored_return_findings,
        )
        from autopsy.detection.static_rules import (
            detect_static_rules,
            format_static_findings,
        )

        if root_dir is not None:
            only = changed_files or None
            blocks = []
            ignored = detect_ignored_security_returns(root_dir, only_files=only)
            if ignored:
                blocks.append(format_ignored_return_findings(ignored))
            static = detect_static_rules(root_dir, only_files=only)
            if static:
                blocks.append(format_static_findings(static))
            if blocks:
                deterministic_findings_md = "\n".join(blocks)
                yield deterministic_findings_md + "\n"
    except Exception as e:  # pragma: no cover — defensive
        yield f"[note] Static analysis skipped: {e}\n\n"

    # Phase 0: AI-generated code detection
    from autopsy.detection.heuristics import analyze_diff as detect_ai

    yield "🤖 Detecting AI-generated code...\n\n"

    ai_results = []
    file_diffs = _split_diff_by_file(diff_text)
    for file_path, file_diff in file_diffs.items():
        result = detect_ai(file_diff, file_path=file_path)
        ai_results.append(result)

    ai_flagged = [r for r in ai_results if r.likely_ai]
    if ai_flagged:
        yield f"**Found {len(ai_flagged)} file(s) likely AI-generated:**\n\n"
        for r in ai_flagged:
            yield f"- `{r.file_path}` — {r.summary}\n"
            for s in sorted(r.signals, key=lambda s: s.weighted_score, reverse=True)[:3]:
                if s.score > 0.3:
                    yield f"  - {s.name}: {s.detail}\n"
        yield "\n"
    else:
        yield "No strong AI-generation signals detected. Scanning all changes.\n\n"

    # Phase 1: Triage
    yield "🔍 Triaging changed files with Haiku...\n\n"

    # Build a combined subgraph of all changed files
    combined_nodes: set[str] = set()
    for file_path in changed_files:
        sub = extract_subgraph_for_file(graph, file_path, max_depth=2, max_nodes=30)
        combined_nodes |= set(sub.nodes)

    # Activated nodes from the graph diff are treated identically to
    # additions — to the running codebase they ARE additions, just
    # invisible ones. Feed them into the same scan path.
    for node_id in activated_nodes:
        if node_id in graph:
            combined_nodes.add(node_id)

    if not combined_nodes:
        combined_sub = graph
    else:
        combined_sub = graph.subgraph(combined_nodes).copy()

    # Optional: rank files by semantic similarity to the diff using embeddings
    try:
        import voyageai as _voyageai  # noqa: F401 — presence check only

        yield "Ranking files by semantic relevance...\n\n"

        cache = EmbeddingCache(root_dir) if root_dir else EmbeddingCache(Path.cwd())

        # Gather file contents from the subgraph
        candidate_files = get_file_contents_for_subgraph(combined_sub, root_dir)

        if candidate_files and diff_text.strip():
            # Compute embeddings for candidate files
            file_embeddings = compute_embeddings(candidate_files, cache)

            # Compute embedding for the diff itself
            diff_embeddings = compute_embeddings({"__diff__": diff_text}, cache)
            diff_vec = diff_embeddings.get("__diff__")

            if diff_vec and file_embeddings:
                # Rank files by cosine similarity to the diff
                scored: list[tuple[str, float]] = []
                for fpath, fvec in file_embeddings.items():
                    score = _cosine_similarity(diff_vec, fvec)
                    scored.append((fpath, score))
                scored.sort(key=lambda x: x[1], reverse=True)

                # Keep only the top-20 most relevant files
                top_files = {fpath for fpath, _ in scored[:20]}

                # Prune the subgraph to nodes belonging to top files
                keep_nodes: set[str] = set()
                for node, data in combined_sub.nodes(data=True):
                    node_file = data.get("path") or data.get("file", "")
                    for tf in top_files:
                        if tf in node_file or node_file.endswith(tf):
                            keep_nodes.add(node)
                            break
                if keep_nodes:
                    combined_sub = combined_sub.subgraph(keep_nodes).copy()
    except ImportError:
        pass
    except Exception:
        # Embedding enhancement is strictly optional — swallow any errors
        pass

    # Build AI detection summary for LLM context
    ai_context = ""
    if ai_flagged:
        ai_lines = ["## AI-Generated Code Detection Results\n"]
        ai_lines.append("The following files were flagged as likely AI-generated. Pay EXTRA attention to these:\n")
        for r in ai_flagged:
            ai_lines.append(f"- **{r.file_path}** ({r.summary})")
        ai_context = "\n".join(ai_lines) + "\n"

    context = _build_context_message(
        combined_sub, root_dir,
        extra=f"{ai_context}\n## Git Diff\n```diff\n{diff_text}\n```",
    )

    if use_triage:
        try:
            triage_raw = call_haiku(TRIAGE_SYSTEM, f"{context}\n\n## Query\nFind security vulnerabilities in the changed code, especially in AI-generated sections.")
        except RuntimeError as e:
            yield f"[Triage error: {e}]\n"
            return
        yield f"Triage complete.\n\n"
    else:
        triage_raw = ""
        yield "Triage skipped (sonnet-only arm).\n\n"

    # Phase 2: Compute blast radius for functions in changed files
    blast_context = ""
    for file_path in changed_files:
        for node, data in graph.nodes(data=True):
            if data.get("type") == "function" and data.get("file", "").endswith(file_path):
                br = get_blast_radius(graph, node)
                if br:
                    func_name = data.get("qualified_name", data.get("name", node))
                    terminal_out, prompt_ctx = format_blast_radius(br)
                    yield f" Blast Radius — {len(br)} nodes can reach {func_name}:\n{terminal_out}\n\n"
                    blast_context += f"\n## Blast Radius for {func_name}\n{prompt_ctx}"

    yield "🔬 Scanning with Sonnet...\n\n"

    # Phase 3: Deep analysis
    blast_injection = ""
    if blast_context:
        blast_injection = f"\n\n## Computed Blast Radius Data\n{blast_context}\n"
    dedup_note = ""
    if deterministic_findings_md:
        dedup_note = (
            "\n\n## Already-Reported High-Confidence Findings\n"
            "A deterministic graph-based check has ALREADY reported the "
            "following findings. Do NOT repeat them; focus on other "
            "vulnerabilities:\n" + deterministic_findings_md
        )
    user_msg = f"{context}\n\n## Triage Notes\n{triage_raw}{blast_injection}{dedup_note}\n\n## Task\nAnalyze the git diff for security vulnerabilities. Focus especially on code flagged as AI-generated — these are sections developers may have accepted without full understanding."
    yield from stream_sonnet(SCAN_SYSTEM, user_msg)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _split_diff_by_file(diff_text: str) -> dict[str, str]:
    """Split a unified diff into per-file chunks."""
    files: dict[str, str] = {}
    current_file = ""
    current_lines: list[str] = []

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            if current_file and current_lines:
                files[current_file] = "\n".join(current_lines)
            # Extract file path from "diff --git a/foo b/foo"
            parts = line.split(" b/", 1)
            current_file = parts[1] if len(parts) > 1 else ""
            current_lines = [line]
        else:
            current_lines.append(line)

    if current_file and current_lines:
        files[current_file] = "\n".join(current_lines)

    # If no "diff --git" headers found, treat the whole thing as one block
    if not files and diff_text.strip():
        files["unknown"] = diff_text

    return files


def orient_stream(
    graph: nx.DiGraph,
    root_dir: Path,
    file_tree: str = "",
    hotspots: str = "",
) -> Iterator[str]:
    """ORIENT ME: Generate a structured repo map.

    Yields text chunks for real-time display.
    """
    yield "🗺️ Generating repository map with Sonnet...\n\n"

    summary = subgraph_summary(graph)
    files = get_file_contents_for_subgraph(graph, root_dir)

    # For orient, we send file structure + graph stats, not all source
    # Only send first 100 lines of each file to keep context manageable
    file_previews = []
    for path, content in files.items():
        lines = content.split("\n")
        preview = "\n".join(lines[:100])
        if len(lines) > 100:
            preview += f"\n... ({len(lines) - 100} more lines)"
        file_previews.append(f"### {path}\n```\n{preview}\n```\n")

    user_msg = f"""## Dependency Graph
{summary}

## File Tree
{file_tree}

## Complexity Hotspots
{hotspots}

## File Previews
{"".join(file_previews)}"""

    yield from stream_sonnet(ORIENT_SYSTEM, user_msg)


def _resolve_function_node(graph: nx.DiGraph, func_name: str) -> str | None:
    """Resolve a function name to its graph node ID."""
    for node, data in graph.nodes(data=True):
        if data.get("type") == "function":
            if data.get("name") == func_name or data.get("qualified_name") == func_name:
                return node
    return None
