"""Build a directed dependency graph from parsed files using NetworkX."""

from __future__ import annotations

import tempfile
from pathlib import Path

import networkx as nx

from autopsy.parser.models import ParsedFile


# Security-relevant keyword set used by diff_graphs() to flag deletions of
# probable security controls. These are matched as substrings against the
# lower-cased function name.
SECURITY_KEYWORDS: tuple[str, ...] = (
    "auth", "authenticate", "authorise", "authorize",
    "validate", "sanitize", "sanitise", "verify", "check",
    "guard", "protect", "rate_limit", "csrf", "xss", "escape",
    "hash", "encrypt", "permission", "require", "restrict",
)


def build_dependency_graph(parsed_files: list[ParsedFile]) -> nx.DiGraph:
    """Build a dependency graph from a list of parsed files.

    Nodes:
        - File nodes: "file:<relative_path>"
        - Function nodes: "func:<relative_path>::<qualified_name>"

    Edges:
        - Import edges: file A imports module B → A -> B
        - Call edges: function A calls function B → A -> B
    """
    G = nx.DiGraph()

    # Index: map module/function names to their file nodes
    file_by_path: dict[str, ParsedFile] = {}
    module_to_file: dict[str, str] = {}  # "my_module" -> "file:src/my_module.py"
    func_index: dict[str, str] = {}  # "my_func" -> "func:src/foo.py::my_func"

    # Pass 1: Register all nodes
    for pf in parsed_files:
        path_str = str(pf.path)
        file_node = f"file:{path_str}"
        file_by_path[path_str] = pf

        G.add_node(file_node, type="file", path=path_str, language=pf.language, lines=pf.lines)

        # Register module name (stem and dotted path)
        stem = pf.path.stem
        if stem != "__init__":
            module_to_file[stem] = file_node
        # Also register by dotted module path (e.g. "autopsy.parser.core")
        parts = list(pf.path.parts)
        # Try to build a dotted module name
        if pf.language == "python":
            mod_parts = [p for p in parts if p not in (".", "..")]
            mod_parts[-1] = pf.path.stem  # strip extension
            dotted = ".".join(mod_parts)
            module_to_file[dotted] = file_node

        # Register functions
        for func in pf.all_functions:
            func_node = f"func:{path_str}::{func.qualified_name}"
            G.add_node(
                func_node,
                type="function",
                name=func.name,
                qualified_name=func.qualified_name,
                file=path_str,
                line_start=func.line_start,
                line_end=func.line_end,
            )
            # Function belongs to file
            G.add_edge(file_node, func_node, type="contains")

            # Index for call resolution
            func_index[func.name] = func_node
            func_index[func.qualified_name] = func_node

        # Register classes
        for cls in pf.classes:
            cls_node = f"class:{path_str}::{cls.name}"
            G.add_node(
                cls_node,
                type="class",
                name=cls.name,
                file=path_str,
                line_start=cls.line_start,
                line_end=cls.line_end,
                bases=cls.bases,
            )
            G.add_edge(file_node, cls_node, type="contains")

    # Pass 2: Resolve import edges
    for pf in parsed_files:
        file_node = f"file:{str(pf.path)}"

        for imp in pf.imports:
            target = _resolve_import(imp.module, module_to_file)
            if target:
                G.add_edge(file_node, target, type="imports", module=imp.module)

            # Also try individual imported names
            for name in imp.names:
                full = f"{imp.module}.{name}" if imp.module else name
                target = _resolve_import(full, module_to_file) or _resolve_import(name, module_to_file)
                if target:
                    G.add_edge(file_node, target, type="imports", name=name)

    # Pass 3: Resolve call edges
    for pf in parsed_files:
        for func in pf.all_functions:
            caller_node = f"func:{str(pf.path)}::{func.qualified_name}"
            for call in func.calls:
                callee_node = _resolve_call(call.name, func_index)
                if callee_node and callee_node != caller_node:
                    G.add_edge(caller_node, callee_node, type="calls", line=call.line)

    return G


def build_graph_at_commit(repo_path: str, commit_sha: str) -> nx.DiGraph:
    """Build the dependency graph from the repo state at a specific commit.

    Reads file blobs directly from the git object database via GitPython
    into a tempfile.TemporaryDirectory, parses with Tree-sitter, builds
    the NetworkX graph, then cleans up the temp directory.

    Does NOT modify the working directory at any point.
    """
    # Local imports keep the module-level import surface unchanged.
    from git import Repo

    from autopsy.parser.core import parse_directory

    repo = Repo(repo_path)
    commit = repo.commit(commit_sha)

    with tempfile.TemporaryDirectory(prefix="autopsy-snap-") as tmp:
        tmp_root = Path(tmp)
        for item in commit.tree.traverse():
            # Only blobs (files) — skip trees (directories).
            if getattr(item, "type", None) != "blob":
                continue
            rel_path = item.path
            target = tmp_root / rel_path
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                data = item.data_stream.read()
                target.write_bytes(data)
            except (OSError, ValueError):
                # Skip unreadable blobs rather than aborting the snapshot.
                continue

        parsed = parse_directory(tmp_root)
        graph = build_dependency_graph(parsed)

    # Strip the tempdir prefix from node identifiers and file attributes so
    # that pre/post graphs use comparable, repo-relative paths.
    return _normalize_graph_paths(graph, str(tmp_root))


def _normalize_graph_paths(G: nx.DiGraph, tmp_root: str) -> nx.DiGraph:
    """Rewrite node IDs and file attrs to be relative to the snapshot root.

    Without this, two snapshots from two different TemporaryDirectories would
    have entirely different node IDs and diff_graphs() would mis-classify
    every node as activated or deleted.
    """
    tmp_prefix = tmp_root.rstrip("/") + "/"
    mapping: dict[str, str] = {}
    for node in list(G.nodes()):
        new_node = node.replace(tmp_prefix, "")
        if new_node != node:
            mapping[node] = new_node
    if mapping:
        G = nx.relabel_nodes(G, mapping, copy=True)
    for _, data in G.nodes(data=True):
        for key in ("file", "path"):
            val = data.get(key)
            if isinstance(val, str) and val.startswith(tmp_prefix):
                data[key] = val[len(tmp_prefix):]
    return G


def diff_graphs(pre_graph: nx.DiGraph, post_graph: nx.DiGraph) -> dict:
    """Compare two dependency graph snapshots.

    Returns a dict with four keys:

      activated_nodes — nodes present in post but absent from pre. These
        are NEW live functions/files regardless of whether the textual
        diff shows them as additions. This is what catches comment
        boundary activations and other zero-footprint changes.

      deleted_nodes — nodes present in pre but absent from post.

      broken_edges — edges in pre where the caller still exists in post
        but the callee no longer does. These are dangling calls.

      security_critical_deletions — deleted nodes whose names match a
        security-relevant keyword. These are likely removed security
        controls whose callers are now unprotected.
    """
    pre_nodes = set(pre_graph.nodes())
    post_nodes = set(post_graph.nodes())

    activated_nodes = sorted(post_nodes - pre_nodes)
    deleted_nodes = sorted(pre_nodes - post_nodes)

    # Broken edges: caller survives, callee was deleted.
    broken_edges: list[dict] = []
    for u, v, edata in pre_graph.edges(data=True):
        if u in post_nodes and v not in post_nodes:
            broken_edges.append({
                "caller": u,
                "missing_callee": v,
                "edge_type": edata.get("type"),
                "callers_of_caller": list(pre_graph.predecessors(u)),
            })

    # Security-critical deletions: scan deleted node names.
    security_critical: list[dict] = []
    for node in deleted_nodes:
        node_data = pre_graph.nodes[node]
        # Prefer the human "name" attribute, then qualified_name, then derive
        # from the node ID itself (e.g. "func:foo.py::validate_input").
        name = (
            node_data.get("name")
            or node_data.get("qualified_name")
            or (node.rsplit("::", 1)[-1] if "::" in node else node)
        )
        name_lower = str(name).lower()
        matched = [kw for kw in SECURITY_KEYWORDS if kw in name_lower]
        if not matched:
            continue
        security_critical.append({
            "node": node,
            "name": name,
            "matched_keywords": matched,
            "called_by": list(pre_graph.predecessors(node)),
            "in_degree": pre_graph.in_degree(node),
        })

    return {
        "activated_nodes": activated_nodes,
        "deleted_nodes": deleted_nodes,
        "broken_edges": broken_edges,
        "security_critical_deletions": security_critical,
    }


def _resolve_import(module_name: str, module_to_file: dict[str, str]) -> str | None:
    """Try to resolve a module name to a file node."""
    if module_name in module_to_file:
        return module_to_file[module_name]

    # Try progressively shorter prefixes (e.g. "os.path.join" -> "os.path" -> "os")
    parts = module_name.split(".")
    for i in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in module_to_file:
            return module_to_file[prefix]

    return None


def _resolve_call(call_name: str, func_index: dict[str, str]) -> str | None:
    """Try to resolve a call name to a function node."""
    if call_name in func_index:
        return func_index[call_name]

    # Strip object prefix: "self.do_thing" -> "do_thing", "app.route" -> "route"
    if "." in call_name:
        short = call_name.rsplit(".", 1)[-1]
        if short in func_index:
            return func_index[short]

    return None
