"""Generate a standalone HTML visualization of the dependency graph and open in browser."""

from __future__ import annotations

import json
import tempfile
import webbrowser
from pathlib import Path

import networkx as nx


def graph_to_json(graph: nx.DiGraph, root_dir: Path | None = None, target: str | None = None) -> dict:
    """Serialize a NetworkX DiGraph to the {nodes, edges, target} format."""
    nodes = []
    for node_id, data in graph.nodes(data=True):
        label = data.get("name") or data.get("qualified_name") or node_id
        if data.get("type") == "file":
            path_str = data.get("path", "")
            if root_dir:
                try:
                    label = str(Path(path_str).relative_to(root_dir))
                except ValueError:
                    label = path_str.split("/")[-1]
            else:
                label = path_str.split("/")[-1]

        nodes.append({
            "id": node_id,
            "label": label,
            "type": data.get("type", "unknown"),
            "file": data.get("file") or data.get("path", ""),
            "line": data.get("line_start", 0),
        })

    edges = []
    for src, dst, data in graph.edges(data=True):
        edges.append({
            "source": src,
            "target": dst,
            "type": data.get("type", "unknown"),
        })

    return {"nodes": nodes, "edges": edges, "target": target}


def open_graph_in_browser(
    graph: nx.DiGraph,
    root_dir: Path | None = None,
    target: str | None = None,
) -> Path:
    """Write an interactive graph HTML file and open it in the default browser.

    Returns the path to the generated HTML file.
    """
    data = graph_to_json(graph, root_dir, target)
    html = _build_standalone_html(data)

    tmp = tempfile.NamedTemporaryFile(
        suffix=".html", prefix="autopsy-graph-", delete=False, mode="w", encoding="utf-8",
    )
    tmp.write(html)
    tmp.close()
    path = Path(tmp.name)

    webbrowser.open(f"file://{path}")
    return path


_LOGO_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
  <circle cx="16" cy="16" r="15" fill="#1a0000" stroke="#ff2222" stroke-width="1.5"/>
  <text x="16" y="21" text-anchor="middle" font-family="monospace" font-weight="bold" font-size="14" fill="#ff2222">A</text>
</svg>'''


def _build_standalone_html(data: dict) -> str:
    graph_json = json.dumps(data)
    node_count = len(data["nodes"])
    edge_count = len(data["edges"])

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Autopsy \u2014 Dependency Graph</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            background: #0a0a0a;
            color: #cccccc;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            font-size: 12px;
            overflow: hidden;
        }}

        #header {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 20px;
            background: #110000;
            border-bottom: 1px solid #441111;
        }}

        #header svg {{ width: 32px; height: 32px; }}
        #header h2 {{ font-size: 14px; font-weight: 600; color: #ff2222; letter-spacing: 1px; }}
        #header .stats {{ margin-left: auto; opacity: 0.6; font-size: 11px; }}

        #controls {{
            display: flex;
            gap: 8px;
            margin-left: 24px;
        }}

        #controls button {{
            background: #1a0808;
            color: #aaa;
            border: 1px solid #441111;
            padding: 4px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
        }}

        #controls button:hover {{ background: #2a1010; color: #fff; }}
        #controls button.active {{ background: #ff2222; color: #0a0a0a; border-color: #ff2222; }}

        #search-box {{
            margin-left: 12px;
            background: #1a0808;
            color: #ccc;
            border: 1px solid #441111;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            width: 180px;
        }}

        #search-box::placeholder {{ color: #666; }}
        #search-box:focus {{ outline: none; border-color: #ff2222; }}

        #canvas-container {{
            width: 100vw;
            height: calc(100vh - 50px);
            position: relative;
        }}

        canvas {{
            width: 100%;
            height: 100%;
            cursor: grab;
        }}

        canvas:active {{ cursor: grabbing; }}

        #tooltip {{
            display: none;
            position: absolute;
            background: #1a0808;
            border: 1px solid #441111;
            border-radius: 6px;
            padding: 8px 12px;
            font-size: 12px;
            max-width: 350px;
            pointer-events: none;
            z-index: 100;
            box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        }}

        #tooltip .type-badge {{
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
            margin-bottom: 4px;
        }}

        .type-file {{ background: #330000; color: #ff4444; }}
        .type-function {{ background: #331a00; color: #ff8844; }}
        .type-class {{ background: #330022; color: #ff4488; }}

        #legend {{
            position: absolute;
            bottom: 12px;
            left: 12px;
            background: #1a0808;
            border: 1px solid #441111;
            border-radius: 6px;
            padding: 8px 12px;
            font-size: 11px;
        }}

        #legend div {{ display: flex; align-items: center; gap: 6px; margin: 3px 0; }}
        #legend .dot {{ width: 10px; height: 10px; border-radius: 50%; }}
    </style>
</head>
<body>
    <div id="header">
        {_LOGO_SVG}
        <h2>AUTOPSY</h2>
        <span style="opacity:0.5; margin: 0 4px;">\u2014</span>
        <span style="font-size:13px;">Dependency Graph</span>
        <div id="controls">
            <button id="btn-all" class="active">All</button>
            <button id="btn-files">Files</button>
            <button id="btn-functions">Functions</button>
            <button id="btn-classes">Classes</button>
        </div>
        <input type="text" id="search-box" placeholder="Search nodes..." />
        <span class="stats">{node_count} nodes, {edge_count} edges</span>
    </div>
    <div id="canvas-container">
        <canvas id="graph"></canvas>
        <div id="tooltip"></div>
        <div id="legend">
            <div><span class="dot" style="background:#ff4444"></span> File</div>
            <div><span class="dot" style="background:#ff8844"></span> Function</div>
            <div><span class="dot" style="background:#ff4488"></span> Class</div>
            <div><span class="dot" style="background:#ff0000"></span> Target</div>
        </div>
    </div>

    <script>
    (function() {{
        const raw = {graph_json};
        const canvas = document.getElementById('graph');
        const ctx = canvas.getContext('2d');
        const tooltip = document.getElementById('tooltip');
        const searchBox = document.getElementById('search-box');

        // Hi-DPI
        const dpr = window.devicePixelRatio || 1;
        function resize() {{
            const rect = canvas.parentElement.getBoundingClientRect();
            canvas.width = rect.width * dpr;
            canvas.height = rect.height * dpr;
            canvas.style.width = rect.width + 'px';
            canvas.style.height = rect.height + 'px';
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        }}
        resize();
        window.addEventListener('resize', resize);

        const W = () => canvas.width / dpr;
        const H = () => canvas.height / dpr;

        const COLORS = {{
            file: '#ff4444',
            function: '#ff8844',
            'class': '#ff4488',
            unknown: '#888888',
        }};
        const EDGE_COLORS = {{
            imports: '#ff444455',
            calls: '#ff884455',
            contains: '#ffffff15',
        }};

        // State
        let filterType = 'all';
        let searchTerm = '';

        // Build nodes
        const nodeMap = {{}};
        const allNodes = raw.nodes.map((n, i) => {{
            const angle = (2 * Math.PI * i) / raw.nodes.length;
            const r = Math.min(W(), H()) * 0.35;
            const node = {{
                ...n,
                x: W() / 2 + r * Math.cos(angle) + (Math.random() - 0.5) * 60,
                y: H() / 2 + r * Math.sin(angle) + (Math.random() - 0.5) * 60,
                vx: 0,
                vy: 0,
                radius: n.type === 'file' ? 20 : n.type === 'class' ? 16 : 12,
                isTarget: raw.target && n.id.includes(raw.target),
                visible: true,
                highlight: false,
            }};
            nodeMap[n.id] = node;
            return node;
        }});

        const allEdges = raw.edges.map(e => ({{
            ...e,
            sourceNode: nodeMap[e.source],
            targetNode: nodeMap[e.target],
        }})).filter(e => e.sourceNode && e.targetNode);

        function getVisible() {{
            const nodes = allNodes.filter(n => {{
                if (!n.visible) return false;
                if (filterType !== 'all' && n.type !== filterType) return false;
                return true;
            }});
            const nodeSet = new Set(nodes.map(n => n.id));
            const edges = allEdges.filter(e => nodeSet.has(e.source) && nodeSet.has(e.target));
            return {{ nodes, edges }};
        }}

        function applySearch() {{
            const term = searchTerm.toLowerCase();
            for (const n of allNodes) {{
                n.highlight = term && (n.label.toLowerCase().includes(term) || n.id.toLowerCase().includes(term));
            }}
        }}

        // Filter buttons
        document.querySelectorAll('#controls button').forEach(btn => {{
            btn.addEventListener('click', () => {{
                document.querySelectorAll('#controls button').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const map = {{ 'btn-all': 'all', 'btn-files': 'file', 'btn-functions': 'function', 'btn-classes': 'class' }};
                filterType = map[btn.id] || 'all';
            }});
        }});

        searchBox.addEventListener('input', () => {{
            searchTerm = searchBox.value;
            applySearch();
        }});

        // Force simulation
        const REPULSION = 3000;
        const ATTRACTION = 0.005;
        const DAMPING = 0.85;
        const CENTER_PULL = 0.01;

        function simulate() {{
            const {{ nodes, edges }} = getVisible();
            for (let i = 0; i < nodes.length; i++) {{
                for (let j = i + 1; j < nodes.length; j++) {{
                    const a = nodes[i], b = nodes[j];
                    let dx = a.x - b.x;
                    let dy = a.y - b.y;
                    let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    let force = REPULSION / (dist * dist);
                    let fx = (dx / dist) * force;
                    let fy = (dy / dist) * force;
                    a.vx += fx; a.vy += fy;
                    b.vx -= fx; b.vy -= fy;
                }}
            }}

            for (const e of edges) {{
                const a = e.sourceNode, b = e.targetNode;
                let dx = b.x - a.x;
                let dy = b.y - a.y;
                let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                let force = dist * ATTRACTION;
                let fx = (dx / dist) * force;
                let fy = (dy / dist) * force;
                a.vx += fx; a.vy += fy;
                b.vx -= fx; b.vy -= fy;
            }}

            for (const n of nodes) {{
                n.vx += (W() / 2 - n.x) * CENTER_PULL;
                n.vy += (H() / 2 - n.y) * CENTER_PULL;
            }}

            for (const n of nodes) {{
                if (n === dragNode) continue;
                n.vx *= DAMPING;
                n.vy *= DAMPING;
                n.x += n.vx;
                n.y += n.vy;
                n.x = Math.max(n.radius, Math.min(W() - n.radius, n.x));
                n.y = Math.max(n.radius, Math.min(H() - n.radius, n.y));
            }}
        }}

        function draw() {{
            const {{ nodes, edges }} = getVisible();
            ctx.clearRect(0, 0, W(), H());

            // Edges
            for (const e of edges) {{
                const a = e.sourceNode, b = e.targetNode;
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(b.x, b.y);
                ctx.strokeStyle = EDGE_COLORS[e.type] || '#ffffff20';
                ctx.lineWidth = e.type === 'calls' ? 1.5 : 1;
                ctx.stroke();

                const angle = Math.atan2(b.y - a.y, b.x - a.x);
                const tipX = b.x - b.radius * Math.cos(angle);
                const tipY = b.y - b.radius * Math.sin(angle);
                const headLen = 8;
                ctx.beginPath();
                ctx.moveTo(tipX, tipY);
                ctx.lineTo(tipX - headLen * Math.cos(angle - 0.4), tipY - headLen * Math.sin(angle - 0.4));
                ctx.lineTo(tipX - headLen * Math.cos(angle + 0.4), tipY - headLen * Math.sin(angle + 0.4));
                ctx.closePath();
                ctx.fillStyle = EDGE_COLORS[e.type] || '#ffffff20';
                ctx.fill();
            }}

            // Nodes
            for (const n of nodes) {{
                // Search highlight ring
                if (n.highlight) {{
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, n.radius + 8, 0, Math.PI * 2);
                    ctx.fillStyle = '#ffcc0040';
                    ctx.fill();
                    ctx.strokeStyle = '#ffcc00';
                    ctx.lineWidth = 2;
                    ctx.stroke();
                }}

                // Target glow
                if (n.isTarget) {{
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, n.radius + 6, 0, Math.PI * 2);
                    ctx.fillStyle = '#ff444440';
                    ctx.fill();
                }}

                ctx.beginPath();
                ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
                ctx.fillStyle = n.isTarget ? '#ff0000' : (COLORS[n.type] || COLORS.unknown);
                ctx.fill();
                ctx.strokeStyle = '#ffffff30';
                ctx.lineWidth = 1;
                ctx.stroke();

                // Icon
                ctx.fillStyle = '#000000aa';
                ctx.font = 'bold ' + (n.radius * 0.8) + 'px monospace';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                const icon = n.type === 'file' ? 'F' : n.type === 'function' ? 'f' : n.type === 'class' ? 'C' : '?';
                ctx.fillText(icon, n.x, n.y);

                // Label
                ctx.fillStyle = '#cccccc';
                ctx.font = '10px sans-serif';
                ctx.textAlign = 'center';
                const label = n.label.length > 28 ? n.label.slice(0, 25) + '...' : n.label;
                ctx.fillText(label, n.x, n.y + n.radius + 12);
            }}

            // Hover ring
            if (hoverNode && nodes.includes(hoverNode)) {{
                ctx.beginPath();
                ctx.arc(hoverNode.x, hoverNode.y, hoverNode.radius + 3, 0, Math.PI * 2);
                ctx.strokeStyle = '#ffffff80';
                ctx.lineWidth = 2;
                ctx.stroke();
            }}
        }}

        // Interaction
        let hoverNode = null;
        let dragNode = null;
        let offsetX = 0, offsetY = 0;

        function getNodeAt(mx, my) {{
            const {{ nodes }} = getVisible();
            for (let i = nodes.length - 1; i >= 0; i--) {{
                const n = nodes[i];
                const dx = mx - n.x, dy = my - n.y;
                if (dx * dx + dy * dy <= (n.radius + 4) * (n.radius + 4)) return n;
            }}
            return null;
        }}

        function getMousePos(e) {{
            const rect = canvas.getBoundingClientRect();
            return {{ x: e.clientX - rect.left, y: e.clientY - rect.top }};
        }}

        canvas.addEventListener('mousemove', (e) => {{
            const pos = getMousePos(e);
            if (dragNode) {{
                dragNode.x = pos.x + offsetX;
                dragNode.y = pos.y + offsetY;
                dragNode.vx = 0;
                dragNode.vy = 0;
                return;
            }}

            const node = getNodeAt(pos.x, pos.y);
            hoverNode = node;
            canvas.style.cursor = node ? 'pointer' : 'grab';

            if (node) {{
                tooltip.style.display = 'block';
                tooltip.style.left = (pos.x + 16) + 'px';
                tooltip.style.top = (pos.y - 10) + 'px';
                const typeCls = 'type-' + node.type;
                tooltip.innerHTML =
                    '<span class="type-badge ' + typeCls + '">' + node.type + '</span><br>' +
                    '<strong>' + node.label + '</strong>' +
                    (node.file ? '<br><span style="opacity:0.6">' + node.file + (node.line ? ':' + node.line : '') + '</span>' : '');
            }} else {{
                tooltip.style.display = 'none';
            }}
        }});

        canvas.addEventListener('mousedown', (e) => {{
            const pos = getMousePos(e);
            const node = getNodeAt(pos.x, pos.y);
            if (node) {{
                dragNode = node;
                offsetX = node.x - pos.x;
                offsetY = node.y - pos.y;
                canvas.style.cursor = 'grabbing';
            }}
        }});

        canvas.addEventListener('mouseup', () => {{ dragNode = null; }});
        canvas.addEventListener('mouseleave', () => {{
            dragNode = null;
            hoverNode = null;
            tooltip.style.display = 'none';
        }});

        // Animation loop
        let frame = 0;
        function loop() {{
            const iterations = frame < 100 ? 3 : 1;
            for (let i = 0; i < iterations; i++) simulate();
            draw();
            frame++;
            requestAnimationFrame(loop);
        }}
        loop();
    }})();
    </script>
</body>
</html>'''
