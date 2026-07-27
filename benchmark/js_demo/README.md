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

CodeQL (`javascript-security-extended`, CodeQL CLI 2.25.6) scored through the same
frozen matcher (`benchmark/run_codeql_baseline.py`):

| Tool | recall (strict) | recall (loc-only) | # findings |
|------|----------------|-------------------|-----------|
| Semgrep (`p/default`) | 50% (4/8) | 75% (6/8) | 5 |
| CodeQL (`security-extended`) | 62% (5/8) | 100% (8/8) | 7 |

CodeQL reaches all 8 vuln lines under loc-only; the two concat-SQLi handlers and
the MD5 hash normalize to a category the strict gate rejects. See
`results/codeql_baseline_report.md`.

## LLM scan result (whole-file, N=5)

| arm | Precision | Recall | F1 |
|-----|-----------|--------|----|
| **Autopsy** (graph + LLM) | 100% | **95%** (8/8 in 4 of 5 runs) | 97% |
| Raw Sonnet (no graph) | 100% | 75% (6/8) | 86% |

~$0.75 (46K in / 41K out, Sonnet 4.5). Despite the partial TS dependency graph
(anonymous handlers / call edges not captured), the full pipeline detects **95%**
of the 8 planted vulns and beats raw single-prompt prompting (75%) — so the
multi-language claim holds at the *detection* level even where the graph is weak.
Run: `python benchmark/eval.py --demo benchmark/js_demo --ground-truth
benchmark/js_demo/ground_truth_js.json --baseline-mode whole-file --arm both --repeat 5`
