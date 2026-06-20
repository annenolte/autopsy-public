import * as vscode from 'vscode';

/**
 * Webview panel that streams and renders markdown output from Autopsy.
 */
export class AutopsyPanel {
    public static currentPanel: AutopsyPanel | undefined;

    private static readonly viewType = 'autopsyPanel';
    private readonly panel: vscode.WebviewPanel;
    private readonly extensionUri: vscode.Uri;
    private content: string = '';
    private streaming: boolean = false;
    private disposed: boolean = false;
    private mode: string = '';

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this.panel = panel;
        this.extensionUri = extensionUri;
        this.panel.onDidDispose(() => {
            this.disposed = true;
            AutopsyPanel.currentPanel = undefined;
        });
    }

    public static createOrShow(extensionUri: vscode.Uri, title: string): AutopsyPanel {
        const column = vscode.ViewColumn.Beside;

        if (AutopsyPanel.currentPanel) {
            AutopsyPanel.currentPanel.panel.title = `Autopsy: ${title}`;
            AutopsyPanel.currentPanel.panel.reveal(column);
            AutopsyPanel.currentPanel.content = '';
            AutopsyPanel.currentPanel.mode = title;
            AutopsyPanel.currentPanel.updateWebview();
            return AutopsyPanel.currentPanel;
        }

        const panel = vscode.window.createWebviewPanel(
            AutopsyPanel.viewType,
            `Autopsy: ${title}`,
            column,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')],
            },
        );

        AutopsyPanel.currentPanel = new AutopsyPanel(panel, extensionUri);
        AutopsyPanel.currentPanel.mode = title;
        AutopsyPanel.currentPanel.updateWebview();
        return AutopsyPanel.currentPanel;
    }

    public startStreaming(): void {
        this.content = '';
        this.streaming = true;
        this.updateWebview();
    }

    public stopStreaming(): void {
        this.streaming = false;
        this.updateWebview();
    }

    public appendContent(chunk: string): void {
        if (this.disposed) { return; }
        this.content += chunk;
        this.panel.webview.postMessage({
            type: 'append',
            content: this.content,
            streaming: this.streaming,
        });
    }

    private updateWebview(): void {
        if (this.disposed) { return; }
        this.panel.webview.html = this.getHtml();
    }

    private getHtml(): string {
        const mode = this.mode;
        const modeClass = mode === 'DEBUG THIS' ? 'mode-debug' : mode === 'SCAN THIS' ? 'mode-scan' : mode === 'ORIENT ME' ? 'mode-orient' : 'mode-default';

        return /*html*/`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Autopsy</title>
    <style>
        :root {
            --bg: var(--vscode-editor-background);
            --fg: var(--vscode-editor-foreground);
            --border: var(--vscode-panel-border);
            --accent: var(--vscode-textLink-foreground);
            --code-bg: var(--vscode-textCodeBlock-background);
            --critical: #ff2222;
            --high: #ff6644;
            --medium: #ff8844;
            --low: #cc4444;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: var(--vscode-font-family, 'Segoe UI', sans-serif);
            font-size: var(--vscode-font-size, 13px);
            color: var(--fg);
            background: var(--bg);
            padding: 16px;
            line-height: 1.6;
        }

        /* ---- Header ---- */
        #header {
            text-align: center;
            padding: 20px 0 16px;
            border-bottom: 1px solid #441111;
            margin-bottom: 20px;
        }

        #header h1 {
            font-size: 1.5em;
            margin: 0;
            color: #ff2222;
            letter-spacing: 2px;
            font-weight: 700;
        }

        #header .mode-label {
            display: inline-block;
            margin-top: 6px;
            padding: 3px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        .mode-debug { background: #cc2222; color: white; }
        .mode-scan { background: #ff2222; color: white; }
        .mode-orient { background: #ff4444; color: #0a0a0a; }
        .mode-default { background: #ff2222; color: #0a0a0a; }

        /* ---- Content area ---- */
        #content {
            max-width: 800px;
            margin: 0 auto;
        }

        /* Markdown rendering */
        h1, h2, h3 { margin: 1.2em 0 0.4em; color: #ff2222; }
        h1 { font-size: 1.5em; border-bottom: 1px solid var(--border); padding-bottom: 0.3em; }
        h2 { font-size: 1.25em; margin-top: 1.5em; }
        h3 { font-size: 1.1em; }

        p { margin: 0.6em 0; line-height: 1.65; }
        ul, ol { margin: 0.4em 0 0.4em 1.5em; }
        li { margin: 0.2em 0; line-height: 1.5; }

        code {
            font-family: var(--vscode-editor-font-family, 'Consolas', monospace);
            background: var(--code-bg);
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 0.9em;
        }

        pre {
            background: var(--code-bg);
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            margin: 0.5em 0;
        }

        pre code { background: none; padding: 0; }

        /* Severity badges */
        .severity-critical { color: var(--critical); font-weight: bold; }
        .severity-high { color: var(--high); font-weight: bold; }
        .severity-medium { color: var(--medium); font-weight: bold; }
        .severity-low { color: var(--low); font-weight: bold; }

        /* Streaming indicator */
        #streaming-indicator {
            display: none;
            position: fixed;
            top: 8px;
            right: 16px;
            background: #ff2222;
            color: #0a0a0a;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            animation: pulse 1.5s infinite;
        }

        #streaming-indicator.active { display: block; }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

        hr { border: none; border-top: 1px solid var(--border); margin: 1em 0; }
        blockquote {
            border-left: 3px solid #ff2222;
            padding-left: 12px;
            margin: 0.5em 0;
            opacity: 0.85;
        }

        strong { color: #ff4444; }
    </style>
</head>
<body>
    <div id="header">
        <h1>AUTOPSY</h1>
        <span class="mode-label ${modeClass}">${mode || 'Ready'}</span>
    </div>
    <div id="streaming-indicator">INVESTIGATING</div>
    <div id="content"></div>

    <script>
        const contentEl = document.getElementById('content');
        const indicator = document.getElementById('streaming-indicator');

        // Simple markdown to HTML (handles the common cases from Autopsy output)
        function renderMarkdown(md) {
            let html = md
                // Code blocks
                .replace(/\`\`\`(\\w*)?\\n([\\s\\S]*?)\`\`\`/g, '<pre><code class="lang-$1">$2</code></pre>')
                // Inline code
                .replace(/\`([^\`]+)\`/g, '<code>$1</code>')
                // Headers
                .replace(/^### (.*$)/gm, '<h3>$1</h3>')
                .replace(/^## (.*$)/gm, '<h2>$1</h2>')
                .replace(/^# (.*$)/gm, '<h1>$1</h1>')
                // Bold
                .replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>')
                // Italic
                .replace(/\\*([^*]+)\\*/g, '<em>$1</em>')
                // HR
                .replace(/^---$/gm, '<hr>')
                // Unordered list items
                .replace(/^[\\-\\*] (.*$)/gm, '<li>$1</li>')
                // Blockquote
                .replace(/^> (.*$)/gm, '<blockquote>$1</blockquote>')
                // Line breaks to paragraphs
                .replace(/\\n\\n/g, '</p><p>')
                .replace(/\\n/g, '<br>');

            // Wrap in paragraph
            html = '<p>' + html + '</p>';

            // Severity highlighting
            html = html.replace(/\\[SEVERITY: (CRITICAL|HIGH|MEDIUM|LOW)\\]/g, function(_, s) {
                return '<span class="severity-' + s.toLowerCase() + '">' + s + '</span>';
            });
            html = html.replace(/CRITICAL/g, '<span class="severity-critical">CRITICAL</span>');
            html = html.replace(/HIGH/g, '<span class="severity-high">HIGH</span>');
            html = html.replace(/MEDIUM/g, '<span class="severity-medium">MEDIUM</span>');
            html = html.replace(/LOW/g, '<span class="severity-low">LOW</span>');

            return html;
        }

        window.addEventListener('message', (event) => {
            const msg = event.data;
            if (msg.type === 'append') {
                contentEl.innerHTML = renderMarkdown(msg.content);
                indicator.className = msg.streaming ? 'active' : '';

                // Auto-scroll to bottom while streaming
                if (msg.streaming) {
                    window.scrollTo(0, document.body.scrollHeight);
                }
            }
        });
    </script>
</body>
</html>`;
    }
}
