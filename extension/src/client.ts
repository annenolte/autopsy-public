import http from 'http';
import https from 'https';
import { URL } from 'url';

/**
 * Client for the Autopsy FastAPI backend.
 * Uses raw http/https to stream SSE without external dependencies.
 */
export class AutopsyClient {
    constructor(private baseUrl: string) {}

    async health(): Promise<boolean> {
        const data = await this.jsonRequest('GET', '/api/health');
        return data?.status === 'ok';
    }

    async debug(
        repo: string,
        target: string,
        query: string,
        onChunk: (text: string) => void,
    ): Promise<void> {
        await this.sseRequest('/api/debug', { repo, target, query }, onChunk);
    }

    async scan(
        repo: string,
        uncommitted: boolean,
        onChunk: (text: string) => void,
    ): Promise<void> {
        await this.sseRequest('/api/scan', { repo, uncommitted }, onChunk);
    }

    async orient(
        repo: string,
        onChunk: (text: string) => void,
    ): Promise<void> {
        await this.sseRequest('/api/orient', { repo }, onChunk);
    }

    async graph(repo: string, target?: string): Promise<any> {
        return this.jsonRequest('POST', '/api/graph', { repo, target });
    }

    async graphVisual(repo: string, target?: string, depth: number = 3): Promise<any> {
        return this.jsonRequest('POST', '/api/graph/visual', { repo, target, depth });
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    private async jsonRequest(method: string, path: string, body?: any): Promise<any> {
        return new Promise((resolve, reject) => {
            const url = new URL(path, this.baseUrl);
            const mod = url.protocol === 'https:' ? https : http;

            const options: http.RequestOptions = {
                method,
                hostname: url.hostname,
                port: url.port,
                path: url.pathname,
                headers: { 'Content-Type': 'application/json' },
            };

            const req = mod.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch {
                        reject(new Error(`Invalid JSON response: ${data.slice(0, 200)}`));
                    }
                });
            });

            req.on('error', reject);
            req.setTimeout(5000, () => {
                req.destroy(new Error('Request timeout'));
            });

            if (body) {
                req.write(JSON.stringify(body));
            }
            req.end();
        });
    }

    private async sseRequest(
        path: string,
        body: any,
        onChunk: (text: string) => void,
    ): Promise<void> {
        return new Promise((resolve, reject) => {
            const url = new URL(path, this.baseUrl);
            const mod = url.protocol === 'https:' ? https : http;

            const options: http.RequestOptions = {
                method: 'POST',
                hostname: url.hostname,
                port: url.port,
                path: url.pathname,
                headers: { 'Content-Type': 'application/json' },
            };

            const req = mod.request(options, (res) => {
                if (res.statusCode && res.statusCode >= 400) {
                    let data = '';
                    res.on('data', (chunk) => { data += chunk; });
                    res.on('end', () => {
                        try {
                            const err = JSON.parse(data);
                            reject(new Error(err.detail || `HTTP ${res.statusCode}`));
                        } catch {
                            reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
                        }
                    });
                    return;
                }

                let buffer = '';

                res.on('data', (chunk: Buffer) => {
                    buffer += chunk.toString();

                    // Parse SSE lines
                    const lines = buffer.split('\n');
                    buffer = lines.pop() || ''; // Keep incomplete line in buffer

                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const raw = line.slice(6);
                            if (!raw) { continue; }
                            try {
                                // Chunks are JSON-encoded strings
                                const text = JSON.parse(raw);
                                onChunk(text);
                            } catch {
                                // Fallback for non-JSON lines
                                onChunk(raw);
                            }
                        } else if (line.startsWith('event: done')) {
                            // Stream complete
                        }
                    }
                });

                res.on('end', resolve);
                res.on('error', reject);
            });

            req.on('error', reject);
            req.setTimeout(300000); // 5 min timeout for long analyses

            req.write(JSON.stringify(body));
            req.end();
        });
    }
}
