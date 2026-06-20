import * as vscode from 'vscode';
import { AutopsyPanel } from './panel';
import { AutopsyClient } from './client';
import { AutopsyDiagnostics, getFix } from './diagnostics';
import { GraphPanel } from './graphPanel';

let client: AutopsyClient;
let diagnostics: AutopsyDiagnostics;
let serverProcess: any;

export function activate(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('autopsy');
    const serverUrl = config.get<string>('serverUrl', 'http://127.0.0.1:7891');

    client = new AutopsyClient(serverUrl);
    diagnostics = new AutopsyDiagnostics();

    // Auto-start server if configured
    if (config.get<boolean>('autoStartServer', true)) {
        startServer(context);
    }

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('autopsy.debugThis', () => debugThis(context)),
        vscode.commands.registerCommand('autopsy.scanThis', () => scanThis(context)),
        vscode.commands.registerCommand('autopsy.orientMe', () => orientMe(context)),
        vscode.commands.registerCommand('autopsy.showGraph', () => showGraph(context)),
        diagnostics,
    );

    // ---------- TextDocumentContentProvider for diff preview ----------
    const fixContentProvider = new class implements vscode.TextDocumentContentProvider {
        private _onDidChange = new vscode.EventEmitter<vscode.Uri>();
        readonly onDidChange = this._onDidChange.event;

        async provideTextDocumentContent(uri: vscode.Uri): Promise<string> {
            // uri format: autopsy-fix:/path/to/file?line=<0-based-line>
            const sourcePath = uri.path;
            const lineParam = new URLSearchParams(uri.query).get('line');
            const line = lineParam ? parseInt(lineParam, 10) : -1;

            const sourceUri = vscode.Uri.file(sourcePath);
            const fix = getFix(sourceUri, line);

            // Read the document from the workspace — don't rely on visible editors
            const doc = await vscode.workspace.openTextDocument(sourceUri);
            const lines = doc.getText().split('\n');
            if (line >= 0 && line < lines.length && fix) {
                const fixLines = fix.trim().split('\n');
                lines.splice(line, 1, ...fixLines);
            }
            return lines.join('\n');
        }
    };
    context.subscriptions.push(
        vscode.workspace.registerTextDocumentContentProvider('autopsy-fix', fixContentProvider),
    );

    // ---------- CodeActionProvider — "Fix with Autopsy" lightbulb ----------
    const codeActionProvider = vscode.languages.registerCodeActionsProvider(
        { scheme: 'file' },
        {
            provideCodeActions(
                document: vscode.TextDocument,
                _range: vscode.Range,
                ctx: vscode.CodeActionContext,
            ): vscode.CodeAction[] {
                const actions: vscode.CodeAction[] = [];

                for (const diagnostic of ctx.diagnostics) {
                    if (diagnostic.source !== 'Autopsy') { continue; }

                    const line = diagnostic.range.start.line;
                    const fix = getFix(document.uri, line);
                    if (!fix || fix.trim().length === 0) { continue; }

                    const trimmed = fix.trim();
                    const isMultiLine = trimmed.split('\n').length > 1;

                    if (isMultiLine) {
                        // Multi-line fix — show a diff preview instead of applying directly
                        const action = new vscode.CodeAction(
                            '\u{1F480} Preview fix with Autopsy',
                            vscode.CodeActionKind.QuickFix,
                        );
                        action.diagnostics = [diagnostic];
                        action.isPreferred = true;
                        action.command = {
                            title: 'Preview Autopsy Fix',
                            command: 'vscode.diff',
                            arguments: [
                                document.uri,
                                vscode.Uri.parse(
                                    `autopsy-fix:${document.uri.fsPath}?line=${line}`,
                                ),
                                `Autopsy Fix \u2014 ${document.fileName}`,
                            ],
                        };
                        actions.push(action);
                    } else {
                        // Single-line fix — apply directly via WorkspaceEdit
                        const action = new vscode.CodeAction(
                            '\u{1F480} Fix with Autopsy',
                            vscode.CodeActionKind.QuickFix,
                        );
                        action.diagnostics = [diagnostic];
                        action.isPreferred = true;
                        action.edit = new vscode.WorkspaceEdit();
                        action.edit.replace(document.uri, diagnostic.range, trimmed);
                        actions.push(action);
                    }
                }

                return actions;
            },
        },
    );
    context.subscriptions.push(codeActionProvider);
}

async function startServer(context: vscode.ExtensionContext) {
    try {
        // Check if server is already running
        const healthy = await client.health();
        if (healthy) { return; }
    } catch {
        // Server not running, start it
    }

    const terminal = vscode.window.createTerminal({
        name: 'Autopsy Server',
        hideFromUser: true,
    });
    terminal.sendText('autopsy serve');
    context.subscriptions.push(terminal);

    // Wait for server to be ready
    for (let i = 0; i < 20; i++) {
        await sleep(500);
        try {
            const healthy = await client.health();
            if (healthy) {
                vscode.window.setStatusBarMessage('$(shield) Autopsy server running', 3000);
                return;
            }
        } catch {
            // Keep waiting
        }
    }
    vscode.window.showWarningMessage(
        'Autopsy server did not start. Run "autopsy serve" manually.'
    );
}

async function debugThis(context: vscode.ExtensionContext) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('Open a file first.');
        return;
    }

    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showWarningMessage('Open a workspace folder first.');
        return;
    }

    const filePath = editor.document.uri.fsPath;
    const relativePath = vscode.workspace.asRelativePath(filePath);

    // Get function name at cursor if possible
    const line = editor.document.lineAt(editor.selection.active.line).text;
    const funcMatch = line.match(/(?:def|function|const|let|var)\s+(\w+)/);
    const target = funcMatch ? funcMatch[1] : relativePath;

    const query = await vscode.window.showInputBox({
        prompt: 'What error or question do you want to investigate?',
        placeHolder: 'e.g., "TypeError: cannot read property of undefined" or leave blank for general analysis',
        value: '',
    });

    if (query === undefined) { return; } // Cancelled

    const panel = AutopsyPanel.createOrShow(context.extensionUri, 'DEBUG THIS');
    panel.startStreaming();

    try {
        await client.debug(
            workspaceFolder.uri.fsPath,
            target,
            query || '',
            (chunk) => panel.appendContent(chunk),
        );
    } catch (err: any) {
        panel.appendContent(`\n\n**Error:** ${err.message}`);
    }

    panel.stopStreaming();
}

async function scanThis(context: vscode.ExtensionContext) {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showWarningMessage('Open a workspace folder first.');
        return;
    }

    const scanType = await vscode.window.showQuickPick(
        [
            { label: 'Uncommitted Changes', description: 'Scan staged + unstaged changes', value: 'uncommitted' },
            { label: 'Last Commit', description: 'Scan the most recent commit', value: 'last' },
        ],
        { placeHolder: 'What do you want to scan?' },
    );

    if (!scanType) { return; }

    const panel = AutopsyPanel.createOrShow(context.extensionUri, 'SCAN THIS');
    panel.startStreaming();

    const scanContent: string[] = [];

    try {
        await client.scan(
            workspaceFolder.uri.fsPath,
            scanType.value === 'uncommitted',
            (chunk) => {
                panel.appendContent(chunk);
                scanContent.push(chunk);
            },
        );

        // Parse findings and create diagnostics
        const fullOutput = scanContent.join('');
        diagnostics.parseAndApply(fullOutput, workspaceFolder.uri.fsPath);

    } catch (err: any) {
        panel.appendContent(`\n\n**Error:** ${err.message}`);
    }

    panel.stopStreaming();
}

async function orientMe(context: vscode.ExtensionContext) {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showWarningMessage('Open a workspace folder first.');
        return;
    }

    const panel = AutopsyPanel.createOrShow(context.extensionUri, 'ORIENT ME');
    panel.startStreaming();

    try {
        await client.orient(
            workspaceFolder.uri.fsPath,
            (chunk) => panel.appendContent(chunk),
        );
    } catch (err: any) {
        panel.appendContent(`\n\n**Error:** ${err.message}`);
    }

    panel.stopStreaming();
}

async function showGraph(context: vscode.ExtensionContext) {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showWarningMessage('Open a workspace folder first.');
        return;
    }

    // Ask for optional target
    const target = await vscode.window.showInputBox({
        prompt: 'Focus on a specific file or function? (leave blank for full graph)',
        placeHolder: 'e.g., app.py or handle_request',
        value: '',
    });

    if (target === undefined) { return; } // Cancelled

    try {
        const result = await client.graphVisual(
            workspaceFolder.uri.fsPath,
            target || undefined,
        );

        const mascotPath = vscode.Uri.joinPath(context.extensionUri, 'media', 'mascot.svg');
        const graphPanelInstance = GraphPanel.createOrShow(context.extensionUri);
        const mascotUri = graphPanelInstance.panel.webview.asWebviewUri(mascotPath).toString();
        graphPanelInstance.setGraphData(result, mascotUri);
    } catch (err: any) {
        vscode.window.showErrorMessage(`Autopsy: ${err.message}`);
    }
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function deactivate() {
    if (serverProcess) {
        serverProcess.kill();
    }
}
