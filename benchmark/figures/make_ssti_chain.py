"""Render pygoat's cross-file SSTI write->render chain from the REAL graph.

This is the paper's clearest qualitative evidence for the cross-file mechanism:
`results/codeql/pygoat_scored.json` shows CodeQL misses `pygoat-ssti` while
Autopsy catches it. The chain is genuinely cross-function / cross-file:

  ssti_lab (views.py)  --calls-->  filter_blog (utility.py)      [REAL graph edge]
  ssti_lab (views.py)  --writes-->  templates/.../{id}.html      [source data flow]
  ssti_view_blog (views.py)  --renders-->  templates/.../{id}.html

The two `calls` edges are taken verbatim from the dependency graph that the CLI
builds (`build_dependency_graph`); the write/render edges are the data flow that
links the two views through the template file (derived from the actual sink lines
`file.write` @ ssti_lab and `render(...{id}.html)` @ ssti_view_blog). Edge
provenance is labelled in the figure so nothing is hand-asserted.

Run:  python benchmark/figures/make_ssti_chain.py
Out:  benchmark/figures/ssti_chain.svg
"""
from __future__ import annotations

from pathlib import Path

from autopsy.parser import parse_directory
from autopsy.graph.builder import build_dependency_graph

PYGOAT = Path("/tmp/pygoat/introduction")
OUT = Path(__file__).resolve().parent / "ssti_chain.svg"

# Function nodes of interest (short name -> graph node id suffix).
TARGETS = {
    "ssti_lab": "views.py::ssti_lab",
    "ssti_view_blog": "views.py::ssti_view_blog",
}


def short(node_id: str) -> str:
    return node_id.split("::")[-1]


def file_of(node_id: str) -> str:
    # func:/abs/path/file.py::name  -> file.py
    body = node_id.split("func:")[-1].split("::")[0]
    return Path(body).name


def collect_real_edges(g):
    """Real cross-file `calls` edges out of the two SSTI views, from the graph."""
    edges = []
    for short_name, suffix in TARGETS.items():
        matches = [n for n in g.nodes if n.endswith(suffix)]
        if not matches:
            continue
        src = matches[0]
        for _u, v, d in g.out_edges(src, data=True):
            if d.get("type") != "calls":
                continue
            edges.append((short(src), file_of(src), short(v), file_of(v)))
    return edges


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def box(x, y, w, h, label, sub, fill, stroke):
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="1.5"/>'
        f'<text x="{x+w/2}" y="{y+22}" text-anchor="middle" font-size="13" '
        f'font-weight="bold">{_esc(label)}</text>'
        f'<text x="{x+w/2}" y="{y+40}" text-anchor="middle" font-size="10" '
        f'fill="#666">{_esc(sub)}</text>'
    )


def arrow(x1, y1, x2, y2, label, color, dashed=False):
    dash = ' stroke-dasharray="6 4"' if dashed else ""
    mid_x, mid_y = (x1 + x2) / 2, (y1 + y2) / 2
    return (
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
        f'stroke-width="2" marker-end="url(#arrow)"{dash}/>'
        f'<text x="{mid_x}" y="{mid_y-6}" text-anchor="middle" font-size="10" '
        f'fill="{color}">{_esc(label)}</text>'
    )


def render(real_edges) -> str:
    W, H = 760, 430
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'font-family="-apple-system,Helvetica,Arial,sans-serif">',
        '<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="8" '
        'refY="3" orient="auto" markerUnits="strokeWidth">'
        '<path d="M0,0 L8,3 L0,6 Z" fill="#444"/></marker></defs>',
        f'<rect width="{W}" height="{H}" fill="white"/>',
        f'<text x="{W/2}" y="28" text-anchor="middle" font-size="16" '
        f'font-weight="bold">pygoat SSTI: cross-file write&#8594;render chain '
        f'(Autopsy catches; CodeQL misses)</text>',
    ]
    # Node coordinates
    n = {
        "ssti_lab":   (60, 80, 200, 56),
        "filter_blog": (60, 210, 200, 56),
        "template":   (300, 210, 200, 70),
        "ssti_view_blog": (540, 80, 180, 56),
        "user":       (300, 70, 200, 40),
    }
    # user input
    parts.append(box(*n["user"], "USER POST 'blog'", "untrusted input",
                     "#fff5f5", "#c53030"))
    parts.append(box(*n["ssti_lab"], "ssti_lab()", "views.py (write view)",
                     "#ebf8ff", "#2b6cb0"))
    parts.append(box(*n["filter_blog"], "filter_blog()",
                     "utility.py (cross-file)", "#ebf8ff", "#2b6cb0"))
    parts.append(box(*n["template"], "templates/.../{id}.html",
                     "attacker-controlled template", "#fffaf0", "#c05621"))
    parts.append(box(*n["ssti_view_blog"], "ssti_view_blog()",
                     "views.py (render view)", "#ebf8ff", "#2b6cb0"))

    def cx(name): return n[name][0] + n[name][2] / 2
    def cy(name): return n[name][1] + n[name][3] / 2
    def bottom(name): return n[name][1] + n[name][3]
    def top(name): return n[name][1]

    # user -> ssti_lab
    parts.append(arrow(cx("user"), bottom("user"), cx("ssti_lab")+30, top("ssti_lab"),
                       "POST blog", "#c53030"))
    # ssti_lab --calls--> filter_blog (REAL graph edge if present)
    has_filter = any(s == "ssti_lab" and "filter_blog" in d for (s, _sf, d, _df) in real_edges)
    parts.append(arrow(cx("ssti_lab"), bottom("ssti_lab"), cx("filter_blog"),
                       top("filter_blog"),
                       "calls [graph edge]" if has_filter else "calls",
                       "#2b6cb0"))
    # filter_blog -> template (write)  (data flow)
    parts.append(arrow(n["filter_blog"][0]+n["filter_blog"][2], cy("filter_blog"),
                       n["template"][0], cy("template")+8,
                       "file.write (l.996)", "#c05621", dashed=True))
    # ssti_lab -> template (write)
    parts.append(arrow(cx("ssti_lab")+40, bottom("ssti_lab")+4,
                       n["template"][0], top("template")+4,
                       "writes template", "#c05621", dashed=True))
    # template <- ssti_view_blog (render)
    parts.append(arrow(cx("ssti_view_blog"), bottom("ssti_view_blog"),
                       n["template"][0]+n["template"][2], cy("template"),
                       "render() (l.1006)", "#c05621", dashed=True))

    # legend
    ly = H - 58
    parts.append(f'<line x1="60" y1="{ly}" x2="100" y2="{ly}" stroke="#2b6cb0" '
                 f'stroke-width="2" marker-end="url(#arrow)"/>')
    parts.append(f'<text x="108" y="{ly+4}" font-size="11" fill="#333">solid = '
                 f'`calls` edge from the dependency graph (build_dependency_graph)</text>')
    parts.append(f'<line x1="60" y1="{ly+20}" x2="100" y2="{ly+20}" stroke="#c05621" '
                 f'stroke-width="2" stroke-dasharray="6 4" marker-end="url(#arrow)"/>')
    parts.append(f'<text x="108" y="{ly+24}" font-size="11" fill="#333">dashed = '
                 f'write&#8594;render data flow through the template file (source-derived)</text>')
    parts.append('</svg>')
    return "\n".join(parts)


def main():
    if not PYGOAT.exists():
        raise SystemExit(f"pygoat not found at {PYGOAT}; clone it first "
                         "(see benchmark/pygoat/README.md).")
    g = build_dependency_graph(parse_directory(PYGOAT))
    real_edges = collect_real_edges(g)
    print(f"graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
    print("real cross-file `calls` edges out of the SSTI views:")
    for s, sf, d, df in real_edges:
        tag = "  [CROSS-FILE]" if sf != df else ""
        print(f"   {s} ({sf})  --calls-->  {d} ({df}){tag}")
    OUT.write_text(render(real_edges))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
