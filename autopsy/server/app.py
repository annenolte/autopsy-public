"""FastAPI server — serves streaming SSE responses from the Autopsy LLM pipeline."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from autopsy.parser import parse_directory
from autopsy.graph.builder import build_dependency_graph
from autopsy.graph.subgraph import subgraph_summary, extract_subgraph_for_file, extract_subgraph_for_function
from autopsy.llm.pipeline import debug_stream, scan_stream, orient_stream
from autopsy.git.diff import get_diff, get_changed_files, get_uncommitted_changes

app = FastAPI(title="Autopsy", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["vscode-webview://*", "http://localhost:*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DebugRequest(BaseModel):
    repo: str
    target: str
    query: str = ""
    depth: int = 3

class ScanRequest(BaseModel):
    repo: str
    base: str | None = None
    head: str = "HEAD"
    uncommitted: bool = False

class OrientRequest(BaseModel):
    repo: str

class GraphRequest(BaseModel):
    repo: str
    target: str | None = None
    depth: int = 3

# ---------------------------------------------------------------------------
# In-memory cache for parsed repos
# ---------------------------------------------------------------------------

_SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build", ".next"}

# Maps resolved repo path -> (fingerprint, parsed, graph)
_cache: dict[str, tuple[str, Any, Any]] = {}


def _fingerprint(repo: Path) -> str:
    """Return a hex digest based on (relative_path, mtime_ns) of supported files."""
    entries: list[tuple[str, int]] = []
    for p in repo.rglob("*"):
        if p.is_dir():
            continue
        # Skip excluded directories
        if any(part in _SKIP_DIRS for part in p.relative_to(repo).parts):
            continue
        if p.suffix not in _SUPPORTED_EXTENSIONS:
            continue
        entries.append((str(p.relative_to(repo)), p.stat().st_mtime_ns))
    entries.sort()
    h = hashlib.sha256()
    for rel, mtime in entries:
        h.update(f"{rel}\0{mtime}\n".encode())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Helper: parse + build graph (cached by repo fingerprint)
# ---------------------------------------------------------------------------

def _build(repo_path: str):
    repo = Path(repo_path).resolve()
    if not repo.is_dir():
        raise HTTPException(status_code=400, detail=f"Not a directory: {repo}")

    key = str(repo)
    fp = _fingerprint(repo)

    cached = _cache.get(key)
    if cached is not None and cached[0] == fp:
        return repo, cached[1], cached[2]

    parsed = parse_directory(repo)
    graph = build_dependency_graph(parsed)
    _cache[key] = (fp, parsed, graph)
    return repo, parsed, graph

# ---------------------------------------------------------------------------
# SSE streaming helper
# ---------------------------------------------------------------------------

def _sse_stream(iterator):
    """Wrap a text chunk iterator as Server-Sent Events."""
    import json
    def generate():
        for chunk in iterator:
            # JSON-encode the chunk to preserve exact whitespace/newlines
            encoded = json.dumps(chunk)
            yield f"data: {encoded}\n\n"
        yield "event: done\ndata: \n\n"
    return StreamingResponse(generate(), media_type="text/event-stream")

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/debug")
def api_debug(req: DebugRequest):
    """Stream causal reasoning for a target."""
    repo, parsed, graph = _build(req.repo)
    query = req.query or f"Analyze {req.target} for bugs and error-prone patterns."
    return _sse_stream(debug_stream(graph, req.target, query, root_dir=repo))


@app.post("/api/scan")
def api_scan(req: ScanRequest):
    """Stream vulnerability scan of git diff."""
    repo, parsed, graph = _build(req.repo)
    try:
        if req.uncommitted:
            diff_text, changed = get_uncommitted_changes(repo)
        else:
            diff_text = get_diff(repo, base=req.base, head=req.head)
            changed = get_changed_files(repo, base=req.base, head=req.head)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not diff_text.strip():
        raise HTTPException(status_code=404, detail="No changes found to scan.")

    return _sse_stream(scan_stream(graph, diff_text, changed, root_dir=repo))


@app.post("/api/orient")
def api_orient(req: OrientRequest):
    """Stream repository orientation map."""
    repo, parsed, graph = _build(req.repo)

    file_tree_lines = []
    hotspot_lines = []
    for pf in parsed:
        try:
            rel = pf.path.relative_to(repo)
        except ValueError:
            rel = pf.path
        file_tree_lines.append(str(rel))

    for node, data in graph.nodes(data=True):
        if data.get("type") == "function":
            call_edges = [e for e in graph.in_edges(node, data=True) if e[2].get("type") == "calls"]
            if call_edges:
                hotspot_lines.append(f"- {data.get('qualified_name', node)}: {len(call_edges)} callers")

    hotspot_lines.sort(key=lambda x: int(x.split(": ")[-1].split()[0]), reverse=True)

    return _sse_stream(orient_stream(
        graph, root_dir=repo,
        file_tree="\n".join(file_tree_lines),
        hotspots="\n".join(hotspot_lines[:15]),
    ))


@app.post("/api/graph")
def api_graph(req: GraphRequest):
    """Return graph stats and optional subgraph as JSON."""
    repo, parsed, graph = _build(req.repo)

    stats = {
        "files": sum(1 for _, d in graph.nodes(data=True) if d.get("type") == "file"),
        "functions": sum(1 for _, d in graph.nodes(data=True) if d.get("type") == "function"),
        "classes": sum(1 for _, d in graph.nodes(data=True) if d.get("type") == "class"),
        "import_edges": sum(1 for _, _, d in graph.edges(data=True) if d.get("type") == "imports"),
        "call_edges": sum(1 for _, _, d in graph.edges(data=True) if d.get("type") == "calls"),
        "total_nodes": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
    }

    subgraph_info = None
    if req.target:
        sub = extract_subgraph_for_file(graph, req.target, max_depth=req.depth)
        if sub.number_of_nodes() == 0:
            sub = extract_subgraph_for_function(graph, req.target, max_depth=req.depth)
        if sub.number_of_nodes() > 0:
            subgraph_info = subgraph_summary(sub)

    return {"stats": stats, "subgraph": subgraph_info}


@app.post("/api/graph/visual")
def api_graph_visual(req: GraphRequest):
    """Return graph nodes and edges as JSON for interactive visualization."""
    repo, parsed, graph = _build(req.repo)

    target_graph = graph
    if req.target:
        sub = extract_subgraph_for_file(graph, req.target, max_depth=req.depth)
        if sub.number_of_nodes() == 0:
            sub = extract_subgraph_for_function(graph, req.target, max_depth=req.depth)
        if sub.number_of_nodes() > 0:
            target_graph = sub

    nodes = []
    for node_id, data in target_graph.nodes(data=True):
        label = data.get("name") or data.get("qualified_name") or node_id
        # Shorten file paths
        if data.get("type") == "file":
            path_str = data.get("path", "")
            try:
                label = str(Path(path_str).relative_to(repo))
            except ValueError:
                label = path_str.split("/")[-1]

        nodes.append({
            "id": node_id,
            "label": label,
            "type": data.get("type", "unknown"),
            "file": data.get("file") or data.get("path", ""),
            "line": data.get("line_start", 0),
        })

    edges = []
    for src, dst, data in target_graph.edges(data=True):
        edges.append({
            "source": src,
            "target": dst,
            "type": data.get("type", "unknown"),
        })

    return {"nodes": nodes, "edges": edges, "target": req.target}


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "0.1.0"}
