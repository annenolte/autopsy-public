import * as vscode from 'vscode';

interface GraphNode {
    id: string;
    label: string;
    type: string;
    file: string;
    line: number;
}

interface GraphEdge {
    source: string;
    target: string;
    type: string;
}

interface GraphData {
    nodes: GraphNode[];
    edges: GraphEdge[];
    target?: string;
}

export class GraphPanel {
    public static currentPanel: GraphPanel | undefined;
    private static readonly viewType = 'autopsyGraph';
    public readonly panel: vscode.WebviewPanel;
    private disposed: boolean = false;

    private constructor(panel: vscode.WebviewPanel) {
        this.panel = panel;
        this.panel.onDidDispose(() => {
            this.disposed = true;
            GraphPanel.currentPanel = undefined;
        });
    }

    public static createOrShow(extensionUri: vscode.Uri): GraphPanel {
        if (GraphPanel.currentPanel) {
            GraphPanel.currentPanel.panel.reveal(vscode.ViewColumn.Beside);
            return GraphPanel.currentPanel;
        }

        const panel = vscode.window.createWebviewPanel(
            GraphPanel.viewType,
            'Autopsy: Dependency Graph',
            vscode.ViewColumn.Beside,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')],
            },
        );

        GraphPanel.currentPanel = new GraphPanel(panel);
        return GraphPanel.currentPanel;
    }

    public setGraphData(data: GraphData, _mascotUri?: string): void {
        if (this.disposed) { return; }
        this.panel.webview.html = this.getHtml(data);
    }

    private getHtml(data: GraphData): string {
        const graphJson = JSON.stringify(data);

        return /*html*/`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Autopsy Graph</title>
    <style>
        :root {
            --bg: var(--vscode-editor-background);
            --fg: var(--vscode-editor-foreground);
            --border: var(--vscode-panel-border);
            --accent: var(--vscode-textLink-foreground);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: var(--bg);
            color: var(--fg);
            font-family: var(--vscode-font-family, sans-serif);
            font-size: 12px;
            overflow: hidden;
        }

        #header {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 16px;
            border-bottom: 1px solid var(--border);
        }

        #header h2 { font-size: 14px; font-weight: 600; color: #ff2222; }
        #header .stats { margin-left: auto; opacity: 0.6; font-size: 11px; }

        #canvas-container {
            width: 100vw;
            height: calc(100vh - 50px);
            position: relative;
        }

        canvas {
            width: 100%;
            height: 100%;
            cursor: grab;
        }

        canvas:active { cursor: grabbing; }

        #tooltip {
            display: none;
            position: absolute;
            background: var(--vscode-editorWidget-background, #252526);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px 12px;
            font-size: 12px;
            max-width: 300px;
            pointer-events: none;
            z-index: 100;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }

        #tooltip .type-badge {
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
            margin-bottom: 4px;
        }

        .type-file { background: #330000; color: #ff4444; }
        .type-function { background: #331a00; color: #ff8844; }
        .type-class { background: #330022; color: #ff4488; }

        #legend {
            position: absolute;
            bottom: 12px;
            left: 12px;
            background: var(--vscode-editorWidget-background, #252526);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px 12px;
            font-size: 11px;
        }

        #legend div { display: flex; align-items: center; gap: 6px; margin: 3px 0; }
        #legend .dot { width: 10px; height: 10px; border-radius: 50%; }
    </style>
</head>
<body>
    <div id="header">
        <h2>AUTOPSY</h2>
        <span style="opacity:0.5; margin: 0 4px;">\u2014</span>
        <span style="font-size:13px;">Dependency Graph</span>
        <span class="stats" id="stats"></span>
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
    (function() {
        const data = ${graphJson};
        const canvas = document.getElementById('graph');
        const ctx = canvas.getContext('2d');
        const tooltip = document.getElementById('tooltip');
        const statsEl = document.getElementById('stats');

        statsEl.textContent = data.nodes.length + ' nodes, ' + data.edges.length + ' edges';

        // Hi-DPI
        const dpr = window.devicePixelRatio || 1;
        function resize() {
            const rect = canvas.parentElement.getBoundingClientRect();
            canvas.width = rect.width * dpr;
            canvas.height = rect.height * dpr;
            canvas.style.width = rect.width + 'px';
            canvas.style.height = rect.height + 'px';
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        }
        resize();
        window.addEventListener('resize', resize);

        const W = () => canvas.width / dpr;
        const H = () => canvas.height / dpr;

        // Colors
        const COLORS = {
            file: '#ff4444',
            function: '#ff8844',
            class: '#ff4488',
            unknown: '#888888',
        };
        const EDGE_COLORS = {
            imports: '#ff444455',
            calls: '#ff884455',
            contains: '#ffffff15',
        };

        // Build node index
        const nodeMap = {};
        const nodes = data.nodes.map((n, i) => {
            const angle = (2 * Math.PI * i) / data.nodes.length;
            const r = Math.min(W(), H()) * 0.3;
            const node = {
                ...n,
                x: W() / 2 + r * Math.cos(angle) + (Math.random() - 0.5) * 50,
                y: H() / 2 + r * Math.sin(angle) + (Math.random() - 0.5) * 50,
                vx: 0,
                vy: 0,
                radius: n.type === 'file' ? 20 : n.type === 'class' ? 16 : 12,
                isTarget: data.target && n.id.includes(data.target),
            };
            nodeMap[n.id] = node;
            return node;
        });

        const edges = data.edges.map(e => ({
            ...e,
            sourceNode: nodeMap[e.source],
            targetNode: nodeMap[e.target],
        })).filter(e => e.sourceNode && e.targetNode);

        // Force simulation
        const REPULSION = 3000;
        const ATTRACTION = 0.005;
        const DAMPING = 0.85;
        const CENTER_PULL = 0.01;

        function simulate() {
            // Repulsion between all nodes
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    const a = nodes[i], b = nodes[j];
                    let dx = a.x - b.x;
                    let dy = a.y - b.y;
                    let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    let force = REPULSION / (dist * dist);
                    let fx = (dx / dist) * force;
                    let fy = (dy / dist) * force;
                    a.vx += fx; a.vy += fy;
                    b.vx -= fx; b.vy -= fy;
                }
            }

            // Attraction along edges
            for (const e of edges) {
                const a = e.sourceNode, b = e.targetNode;
                let dx = b.x - a.x;
                let dy = b.y - a.y;
                let dist = Math.sqrt(dx * dx + dy * dy) || 1;
                let force = dist * ATTRACTION;
                let fx = (dx / dist) * force;
                let fy = (dy / dist) * force;
                a.vx += fx; a.vy += fy;
                b.vx -= fx; b.vy -= fy;
            }

            // Center pull
            for (const n of nodes) {
                n.vx += (W() / 2 - n.x) * CENTER_PULL;
                n.vy += (H() / 2 - n.y) * CENTER_PULL;
            }

            // Apply velocity
            for (const n of nodes) {
                if (n === dragNode) continue;
                n.vx *= DAMPING;
                n.vy *= DAMPING;
                n.x += n.vx;
                n.y += n.vy;
                // Keep in bounds
                n.x = Math.max(n.radius, Math.min(W() - n.radius, n.x));
                n.y = Math.max(n.radius, Math.min(H() - n.radius, n.y));
            }
        }

        // Drawing
        function draw() {
            ctx.clearRect(0, 0, W(), H());

            // Edges
            for (const e of edges) {
                const a = e.sourceNode, b = e.targetNode;
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(b.x, b.y);
                ctx.strokeStyle = EDGE_COLORS[e.type] || '#ffffff20';
                ctx.lineWidth = e.type === 'calls' ? 1.5 : 1;
                ctx.stroke();

                // Arrowhead
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
            }

            // Nodes
            for (const n of nodes) {
                // Glow for target
                if (n.isTarget) {
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, n.radius + 6, 0, Math.PI * 2);
                    ctx.fillStyle = '#ff444440';
                    ctx.fill();
                }

                // Node circle
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
                ctx.fillStyle = n.isTarget ? '#ff0000' : (COLORS[n.type] || COLORS.unknown);
                ctx.fill();
                ctx.strokeStyle = '#ffffff30';
                ctx.lineWidth = 1;
                ctx.stroke();

                // Icon inside node
                ctx.fillStyle = '#000000aa';
                ctx.font = 'bold ' + (n.radius * 0.8) + 'px monospace';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                const icon = n.type === 'file' ? '📄' : n.type === 'function' ? 'f' : n.type === 'class' ? 'C' : '?';
                ctx.fillText(icon, n.x, n.y);

                // Label
                ctx.fillStyle = 'var(--fg, #cccccc)';
                ctx.font = '10px sans-serif';
                ctx.textAlign = 'center';
                const label = n.label.length > 25 ? n.label.slice(0, 22) + '...' : n.label;
                ctx.fillText(label, n.x, n.y + n.radius + 12);
            }

            // Hover node
            if (hoverNode) {
                ctx.beginPath();
                ctx.arc(hoverNode.x, hoverNode.y, hoverNode.radius + 3, 0, Math.PI * 2);
                ctx.strokeStyle = '#ffffff80';
                ctx.lineWidth = 2;
                ctx.stroke();
            }
        }

        // Interaction
        let hoverNode = null;
        let dragNode = null;
        let offsetX = 0, offsetY = 0;

        function getNodeAt(mx, my) {
            for (let i = nodes.length - 1; i >= 0; i--) {
                const n = nodes[i];
                const dx = mx - n.x, dy = my - n.y;
                if (dx * dx + dy * dy <= n.radius * n.radius) return n;
            }
            return null;
        }

        function getMousePos(e) {
            const rect = canvas.getBoundingClientRect();
            return { x: e.clientX - rect.left, y: e.clientY - rect.top };
        }

        canvas.addEventListener('mousemove', (e) => {
            const pos = getMousePos(e);

            if (dragNode) {
                dragNode.x = pos.x + offsetX;
                dragNode.y = pos.y + offsetY;
                dragNode.vx = 0;
                dragNode.vy = 0;
                return;
            }

            const node = getNodeAt(pos.x, pos.y);
            hoverNode = node;
            canvas.style.cursor = node ? 'pointer' : 'grab';

            if (node) {
                tooltip.style.display = 'block';
                tooltip.style.left = (e.clientX + 12) + 'px';
                tooltip.style.top = (e.clientY - 10) + 'px';
                const typeCls = 'type-' + node.type;
                tooltip.innerHTML =
                    '<span class="type-badge ' + typeCls + '">' + node.type + '</span><br>' +
                    '<strong>' + node.label + '</strong>' +
                    (node.file ? '<br><span style="opacity:0.6">' + node.file + (node.line ? ':' + node.line : '') + '</span>' : '');
            } else {
                tooltip.style.display = 'none';
            }
        });

        canvas.addEventListener('mousedown', (e) => {
            const pos = getMousePos(e);
            const node = getNodeAt(pos.x, pos.y);
            if (node) {
                dragNode = node;
                offsetX = node.x - pos.x;
                offsetY = node.y - pos.y;
                canvas.style.cursor = 'grabbing';
            }
        });

        canvas.addEventListener('mouseup', () => {
            dragNode = null;
        });

        canvas.addEventListener('mouseleave', () => {
            dragNode = null;
            hoverNode = null;
            tooltip.style.display = 'none';
        });

        // Animation loop
        let frame = 0;
        function loop() {
            // Simulate more aggressively at start, then settle
            const iterations = frame < 100 ? 3 : 1;
            for (let i = 0; i < iterations; i++) simulate();
            draw();
            frame++;
            requestAnimationFrame(loop);
        }
        loop();
    })();
    </script>
</body>
</html>`;
    }
}
