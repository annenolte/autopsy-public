import * as vscode from 'vscode';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Fix store — maps URI:line keys to fix strings from Sonnet's analysis
// ---------------------------------------------------------------------------
const fixStore = new Map<string, string>();

function fixKey(uri: vscode.Uri, line: number): string {
    return `${uri.toString()}:${line}`;
}

export function storeFix(uri: vscode.Uri, line: number, fix: string): void {
    fixStore.set(fixKey(uri, line), fix);
}

export function getFix(uri: vscode.Uri, line: number): string | undefined {
    return fixStore.get(fixKey(uri, line));
}

export function clearFixes(uri: vscode.Uri): void {
    for (const key of fixStore.keys()) {
        if (key.startsWith(uri.toString())) {
            fixStore.delete(key);
        }
    }
}

/**
 * Parses Autopsy scan output and creates VS Code diagnostics
 * (squiggly underlines, problems panel entries) + gutter decorations.
 */
export class AutopsyDiagnostics implements vscode.Disposable {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private decorationType: vscode.TextEditorDecorationType;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('autopsy');

        this.decorationType = vscode.window.createTextEditorDecorationType({
            gutterIconPath: undefined, // Will use built-in warning/error icons via diagnostics
            overviewRulerColor: '#ff8800',
            overviewRulerLane: vscode.OverviewRulerLane.Right,
            after: {
                margin: '0 0 0 1em',
                color: 'rgba(255, 136, 0, 0.7)',
                fontStyle: 'italic',
            },
        });
    }

    /**
     * Parse scan output and apply diagnostics to matching files.
     *
     * Looks for patterns like:
     *   **Location:** `file.py:42`
     *   ## [SEVERITY: HIGH] Title
     */
    parseAndApply(output: string, workspaceRoot: string): void {
        this.diagnosticCollection.clear();

        const findings = this.parseFindings(output);
        const diagnosticMap = new Map<string, vscode.Diagnostic[]>();

        for (const finding of findings) {
            if (!finding.file || !finding.line) { continue; }

            const filePath = path.isAbsolute(finding.file)
                ? finding.file
                : path.join(workspaceRoot, finding.file);

            const uri = vscode.Uri.file(filePath);
            const key = uri.toString();

            // Clear stale fixes then store new fix if available
            clearFixes(uri);
            if (finding.fix) {
                storeFix(uri, Math.max(0, finding.line - 1), finding.fix);
            }

            if (!diagnosticMap.has(key)) {
                diagnosticMap.set(key, []);
            }

            const line = Math.max(0, finding.line - 1);
            const range = new vscode.Range(line, 0, line, 1000);

            const severity = this.mapSeverity(finding.severity);
            const diagnostic = new vscode.Diagnostic(
                range,
                `[Autopsy] ${finding.title}\n${finding.attack || ''}`,
                severity,
            );
            diagnostic.source = 'Autopsy';
            diagnostic.code = finding.category || 'vulnerability';

            diagnosticMap.get(key)!.push(diagnostic);
        }

        // Apply diagnostics
        for (const [uriStr, diags] of diagnosticMap) {
            this.diagnosticCollection.set(vscode.Uri.parse(uriStr), diags);
        }

        // Apply decorations to visible editors
        this.applyDecorations(findings, workspaceRoot);

        // Show summary
        const count = findings.length;
        if (count > 0) {
            vscode.window.showWarningMessage(
                `Autopsy found ${count} potential vulnerability${count > 1 ? 'ies' : 'y'}. Check the Problems panel.`
            );
        } else {
            vscode.window.showInformationMessage('Autopsy scan complete — no vulnerabilities found.');
        }
    }

    private parseFindings(output: string): Finding[] {
        const findings: Finding[] = [];
        // Split by vulnerability sections (## [SEVERITY: ...])
        const sections = output.split(/^## \[SEVERITY: /gm);

        for (const section of sections) {
            if (!section.trim()) { continue; }

            const severityMatch = section.match(/^(CRITICAL|HIGH|MEDIUM|LOW)\]\s*(.*)/);
            if (!severityMatch) { continue; }

            const severity = severityMatch[1];
            const title = severityMatch[2].trim();

            // Extract location
            const locationMatch = section.match(/\*\*Location:\*\*\s*`([^`]+)`/);
            let file: string | undefined;
            let line: number | undefined;

            if (locationMatch) {
                const parts = locationMatch[1].split(':');
                file = parts[0];
                if (parts[1]) {
                    line = parseInt(parts[1], 10);
                    if (isNaN(line)) { line = undefined; }
                }
            }

            // Extract category
            const categoryMatch = section.match(/\*\*Category:\*\*\s*(.*)/);
            const category = categoryMatch ? categoryMatch[1].trim() : undefined;

            // Extract attack scenario
            const attackMatch = section.match(/\*\*Attack Scenario:\*\*\s*\n([\s\S]*?)(?=\*\*|$)/);
            const attack = attackMatch ? attackMatch[1].trim().slice(0, 2000) : undefined;

            // Extract fix section — text between Fix header and Blast Radius header
            let fix: string | undefined;
            const fixMatch = section.match(
                /(?:^|\n)(?:#{1,3}\s*fix|fix:|\*\*fix)[^\n]*\n([\s\S]*?)(?=(?:^|\n)(?:#{1,3}\s*blast radius|blast radius:|\*\*blast radius)|$)/i,
            );
            if (fixMatch) {
                fix = fixMatch[1].trim();
                if (fix.length === 0) { fix = undefined; }
            }

            findings.push({ severity, title, file, line, category, attack, fix });
        }

        return findings;
    }

    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'CRITICAL':
            case 'HIGH':
                return vscode.DiagnosticSeverity.Error;
            case 'MEDIUM':
                return vscode.DiagnosticSeverity.Warning;
            case 'LOW':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    private applyDecorations(findings: Finding[], workspaceRoot: string): void {
        for (const editor of vscode.window.visibleTextEditors) {
            const editorPath = editor.document.uri.fsPath;
            const decorations: vscode.DecorationOptions[] = [];

            for (const finding of findings) {
                if (!finding.file || !finding.line) { continue; }

                const findingPath = path.isAbsolute(finding.file)
                    ? finding.file
                    : path.join(workspaceRoot, finding.file);

                if (findingPath !== editorPath) { continue; }

                const line = Math.max(0, finding.line - 1);
                const range = new vscode.Range(line, 0, line, 0);

                decorations.push({
                    range,
                    renderOptions: {
                        after: {
                            contentText: ` ⚠ ${finding.severity}: ${finding.title}`,
                        },
                    },
                });
            }

            editor.setDecorations(this.decorationType, decorations);
        }
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
        this.decorationType.dispose();
    }
}

interface Finding {
    severity: string;
    title: string;
    file?: string;
    line?: number;
    category?: string;
    attack?: string;
    fix?: string;
}
