# Established benchmark: SecurityEval (reviewer #2)

[SecurityEval](https://github.com/s2e-lab/SecurityEval) (MSR4P&S '22) is a
published dataset of **121 CWE-labeled vulnerable Python files across 69 CWEs**,
built to evaluate security of ML code-generation. It is one of the established
benchmarks the reviewer asked for, it is Python (Autopsy's strongest language),
and it is on-thesis (AI/code-generation security). Not vendored — clone it.

Each file is vulnerable by construction, so **per-file detection rate** (a tool
reports ≥1 finding in the file) is recall on a real third-party benchmark.

## Token-free baseline results (`benchmark/eval_securityeval.py`)

| tool | per-file detection (recall) |
|------|-----------------------------|
| Autopsy deterministic layer (no LLM) | 3% (4/121) |
| Semgrep (`p/python`) | 19% (23/121) |
| Bandit | 40% (49/121) |
| **Autopsy full LLM scan** | **staged — needs API tokens** |

## Honest reading
- SecurityEval is **hard for static analysis** — 69 diverse CWEs, many subtle or
  not statically decidable. Low SAST numbers (19–40%) are expected and match the
  literature; this is exactly why a tiny easy demo overstates capability.
- The **deterministic Autopsy layer is narrow** (3%) — it covers SQLi / weak
  crypto / ignored-auth-gate only; most of SecurityEval's CWEs are out of its
  rule set. The graph+LLM pipeline is what would carry detection here.
- Detection rate is **file-level** ("did the tool flag *anything* in this
  known-vulnerable file") — generous to all tools, and the fair granularity for
  SecurityEval (one vuln per file, no line-level ground truth).
- ⚠️ The headline **Autopsy LLM number on SecurityEval is not yet measured** (it
  needs tokens). Run:
  ```bash
  python benchmark/eval.py --demo /tmp/SecurityEval/Testcases_Insecure_Code \
    --baseline-mode whole-file --chunked --arm both
  ```
  (file-level CWE ground truth is derivable from the `CWE-*` folder names.)

## Detection on AI-generated subsets (token-free)
The same tools on SecurityEval's **model-generated** files (on-thesis: vulns in
AI-generated code):

| subset | Autopsy det. | Semgrep | Bandit |
|--------|--------------|---------|--------|
| Testcases_Copilot (130) | 1% | 15% | 28% |
| Testcases_InCoder (130) | 2% | 13% | 28% |
| Testcases_Insecure_Code (121, human) | 3% | 19% | 40% |

Static tools detect *less* on AI-generated code (Bandit 28% vs 40% on human) —
motivating better tooling. The Autopsy LLM number on these is staged (tokens).

## CodeQL
Not run: no `brew`/`gh` in this environment and the CodeQL CLI is a ~700MB
download plus a per-target database build. Semgrep + Bandit serve as the SAST
baselines; CodeQL commands are documented in `compare_tools.py`.
