# Multi-language (TypeScript) benchmark (reviewer #3)

The paper claims Python/JS/TS/TSX support, but every benchmark and table was
Python. This is a small **cross-file TypeScript** Express-style app with 8
planted vulnerabilities, used to test the multi-language claim.

| id | file | category | line |
|----|------|----------|------|
| js-sqli-sink | db.ts | SQLi (sink) | 8 |
| js-weak-hash | auth.ts | Weak Crypto (MD5) | 10 |
| js-sqli-search | routes.ts | SQLi (concat → runQuery) | 11 |
| js-auth-ignored | routes.ts | Auth Bypass (ignored isAuthorized) | 18 |
| js-sqli-update | routes.ts | SQLi (concat → runQuery) | 20 |
| js-command-injection | routes.ts | Command Injection (exec) | 27 |
| js-ssrf | routes.ts | SSRF (fetch) | 33 |
| js-code-injection | routes.ts | Code Injection (eval) | 39 |

## What we found (honest)

Building this surfaced a real gap and a real fix:

1. **The TS function extractor was broken.** Exported functions live inside
   `export_statement` AST nodes, but the extractor only looked at direct module
   children — so it extracted **zero** functions from idiomatic TS and the
   dependency graph was empty (just file nodes). **Fixed** (`_unwrapped_children`
   in `autopsy/parser/extractors.py`): exported `function`/`class`/`const`
   declarations are now extracted (`runQuery`, `isAuthorized`, `hashPassword`).
   Locked by `tests/test_js_extraction.py`.

2. **Even after the fix, the graph is much sparser for TS than Python.**
   Idiomatic Express route handlers are *anonymous arrow callbacks*
   (`router.get("/x", (req,res)=>{...})`), which aren't named functions, so they
   don't become graph nodes and their cross-file calls (to `runQuery`,
   `isAuthorized`) aren't captured as call edges. So Autopsy's **graph-guided
   cross-file reasoning — its core novelty — is currently Python-centric** and
   only weakly applies to idiomatic TS. The LLM scan still sees raw TS source,
   so it can still detect these, but without the graph advantage.

   **Honest conclusion for the paper: scope the multi-language claim.** Parsing
   and imports work across languages; the dependency-graph mechanism is
   effective for Python and only partial for idiomatic JS/TS.

## Baselines (token-free)

```bash
python benchmark/compare_tools.py --target benchmark/js_demo \
    --ground-truth benchmark/js_demo/ground_truth_js.json \
    --tools semgrep --semgrep-config p/default
```
Semgrep (`p/default`): **4/8 strict, 6/8 location-only** (caught eval, exec, raw
`conn.query`, MD5; missed the concatenation-based SQLi and the ignored auth gate).

## LLM scan (needs API tokens — not run)
The Autopsy LLM scan on this TS app would measure the full-pipeline number; it is
left for an explicit token decision.
