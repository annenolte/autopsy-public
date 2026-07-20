# CodeQL static-analysis baseline (reviewer issue #18)

CodeQL run as a third off-the-shelf SAST baseline, alongside Semgrep and Bandit,
scored under the **same frozen matching protocol** (`benchmark/eval.py`, commit
`6da8b87`) against the **same ground truth** with the **same recall definition**
as the other static tools. CodeQL is a pure static analyzer (no model calls), so
it is scored exactly like Semgrep/Bandit — not like the Autopsy LLM pipeline.

**Run date:** 2026-06-22 (local; no SARIF uploaded to GitHub).

## Pinned versions (cite these)

| component | version |
|-----------|---------|
| CodeQL CLI | **2.25.6** (sha `7c492d06b1175b24bf72bfb8e0daba1bb3a21847`) |
| query suite (Python) | `python-security-extended.qls` (standard `security-extended`) |
| query suite (JS/TS) | `javascript-security-extended.qls` (standard `security-extended`) |
| `codeql/python-queries` pack | **1.8.4** |
| `codeql/javascript-queries` pack | **2.3.11** |

Standard suites only — no custom, hand-picked, or bug-tuned queries. Raw
`codeql version --format=json` and `codeql resolve packs` output are saved in
`results/codeql/codeql_version.json` and `results/codeql/resolved_packs.json`.

## Methods

For each benchmark, a CodeQL database was built locally with
`codeql database create --language=<python|javascript>` over the unmodified
source, then analyzed with the standard `*-security-extended.qls` suite via
`codeql database analyze --format=sarif-latest`. No build step was needed (pure
Python / TS source extraction). The SARIF was converted to the matcher's finding
format by `benchmark/codeql_sarif_adapter.py` — `{category, title,
locations:[{file,line}]}`, identical to what the inline Semgrep/Bandit adapters
in `benchmark/compare_tools.py` emit — and scored by the frozen matcher
(`benchmark/run_codeql_baseline.py`): same category normalization, same dedupe,
same one-to-one assignment, same ±5-line fuzz. CodeQL files were scanned 100%:
pygoat 80/80, SecurityEval 121/121, TypeScript 3/3, demo_project 6/6 — no
database build failed and no file was dropped.

Two recall readings per matcher-scored benchmark, in fairness to the baseline:
- **strict** = file basename + normalized category + line within ±5 (how Autopsy
  is scored);
- **loc-only** = file basename + line within ±5, ignoring category (most
  generous: "did the tool flag the vulnerable spot at all?").

SecurityEval uses **file-level detection rate** (fraction of the 121
vulnerable-by-construction files with ≥1 CodeQL finding), computed exactly as
Semgrep/Bandit are scored on that set in `benchmark/eval_securityeval.py`.

## Results

Semgrep/Bandit columns were re-run through the same harness on 2026-06-22 and
reproduce the previously documented numbers.

### pygoat — real third-party app (11 in-scope vulns)

| Tool | recall (strict) | recall (loc-only) | # findings |
|------|----------------|-------------------|-----------|
| Semgrep (`p/python`) | 64% (7/11) | 64% (7/11) | 14 |
| Bandit | 45% (5/11) | 82% (9/11) | 42 |
| **CodeQL (`security-extended`)** | **82% (9/11)** | **82% (9/11)** | 37 |

Per-category recall (strict; loc-only is identical here — the same 9 IDs match
under both modes):

| category | recall | caught |
|----------|--------|--------|
| SQLi | 2/2 | sqli-login, sqli-injection-lab |
| Command Injection | 1/1 | command-injection |
| Code Injection | 1/2 | code-injection-eval (missed `ImageMath.eval`) |
| Insecure Deserialization | 2/2 | pickle, unsafe-yaml |
| SSRF | 1/1 | ssrf |
| XXE | 1/1 | xxe |
| Weak Crypto | 1/1 | weak-hash |
| SSTI | 0/1 | — (cross-function template write→render) |

Missed: `pygoat-imagemath-eval` (PIL `ImageMath.eval` — not a CodeQL code-injection
sink) and `pygoat-ssti` (the hardest of the set: user content written to a
template file in one view and rendered in another).

### SecurityEval — 121 CWE-labeled vulnerable Python files (file-level recall)

| tool | per-file detection (recall) |
|------|-----------------------------|
| Semgrep (`p/python`) | 19% (23/121) |
| Bandit | 40% (49/121) |
| **CodeQL (`security-extended`)** | **42% (51/121)** |

### TypeScript benchmark (8 planted vulns)

| Tool | recall (strict) | recall (loc-only) | # findings |
|------|----------------|-------------------|-----------|
| Semgrep (`p/default`) | 50% (4/8) | 75% (6/8) | 5 |
| **CodeQL (`security-extended`)** | **62% (5/8)** | **100% (8/8)** | 7 |

(Bandit is Python-only, so it has no TypeScript row — same as the existing
table.) CodeQL caught the SQLi sink, auth-bypass (ignored return), command
injection, code injection (`eval`), and SSRF under strict matching; loc-only
reaches all 8 (the two concat-based SQLi handlers and the MD5 hash are flagged on
the right lines but normalize to a category the strict gate rejects).

### demo_project — synthetic Flask app (12 vulns)

| Tool | recall (strict) | recall (loc-only) | # findings |
|------|----------------|-------------------|-----------|
| Semgrep (`p/python`) | 25% (3/12) | 42% (5/12) | 3 |
| Bandit | 42% (5/12) | 67% (8/12) | 5 |
| **CodeQL (`security-extended`)** | **17% (2/12)** | **25% (3/12)** | 3 |

CodeQL caught `weak-hash` and `sqli-execute` (strict); loc-only adds
`auth-bypass-permission`. Reported as-is — see caveats.

## Paste-ready rows for the existing tables

> pygoat comparison table (`benchmark/BASELINES.md`):
```
| CodeQL (`security-extended`) | 82% (9/11) | 82% (9/11) | 37 |
```
> demo_project comparison table (`benchmark/BASELINES.md`):
```
| CodeQL (`security-extended`) | 17% (2/12) | 25% (3/12) | 3 |
```
> SecurityEval table (`benchmark/SECURITYEVAL.md`):
```
| CodeQL (`security-extended`) | 42% (51/121) |
```
> TypeScript benchmark (`benchmark/js_demo/README.md`):
```
| CodeQL (`security-extended`) | 62% (5/8) | 100% (8/8) | 7 |
```

## Caveats (honest reading)

- **Recall, not precision.** As with the other static baselines, only recall is
  comparable here: the pygoat ground truth is intentionally incomplete (it labels
  11 of dozens of real vulns), so a precision ranking would be unfair to any tool
  that emits more findings.
- **CodeQL's dataflow is built for whole applications.** On pygoat (a complete
  Django app) its interprocedural taint tracking works as designed and it reaches
  82% — above both Semgrep (64%) and Bandit (45% strict). On **SecurityEval**,
  each file is an isolated single function with no surrounding application or
  realized taint source, which is the analysis shape CodeQL's whole-program
  dataflow is *least* suited to; 42% there is reported exactly as produced and
  should be read in that light (it still edges Bandit's 40% and roughly doubles
  Semgrep's 19%).
- **demo_project is a tiny synthetic app and is where CodeQL is weakest here**
  (17%/25%, below both Semgrep and Bandit). This is reported with no adjustment.
  It is consistent with the paper's own point that the small synthetic demo is
  not where capability differences are best measured; the real third-party
  pygoat and the external SecurityEval set are the meaningful comparisons.
- **TypeScript via `--language=javascript`** is the standard CodeQL path for TS;
  all 3 `.ts` files extracted and were analyzed.
- **N=1.** CodeQL is deterministic, so a single run is the number — but it is a
  single suite version; pack versions are pinned above so it is reproducible.
- **Two pygoat misses are genuine static-analysis limits**, not configuration:
  `ImageMath.eval` is not modeled as a code-execution sink by the stock suite,
  and the SSTI lab's write-then-render spans two views with a file on the path.
  Autopsy's LLM pipeline catches both (it reaches 11/11 on pygoat).

## Reproduce

```bash
# 1. SARIF (needs CodeQL CLI 2.25.6 + pygoat@19d17cc8 and SecurityEval cloned):
CODEQL=~/codeql-home/codeql/codeql bash benchmark/run_codeql.sh
# 2. Score with the frozen matcher:
python benchmark/run_codeql_baseline.py
```

Raw SARIF and per-benchmark matched/unmatched (caught/missed) lists are under
`results/codeql/` (`*.sarif`, `*_scored.json`, `scores.json`).
