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
| CodeQL (`security-extended`) | 42% (51/121) |
| **Autopsy (full LLM pipeline, chunked)** | **95% (115/121)** |

Run: `python benchmark/eval_securityeval.py --autopsy-llm` — 121 files scanned
individually (one per call); ~$1.80 (142K input / 91K output tokens, 121 calls),
Sonnet 4.5. N=1.

## Honest reading
- **Autopsy's LLM pipeline detects 95%**, far above Semgrep (19%) and Bandit
  (40%) on this named external benchmark — the central result for reviewer #2.
- ⚠️ This is **file-level detection** ("did Autopsy flag *something* in this
  known-vulnerable file"), i.e. recall. It does **not** verify the finding names
  the file's *exact* CWE — only that the vulnerable file was flagged. Report it
  as detection/recall, not CWE-accurate classification.
- ⚠️ **N=1** (one pass, nondeterministic) — repeat for a confidence interval.
- SecurityEval is **hard for static analysis** — 69 diverse CWEs, many subtle or
  not statically decidable. Low SAST numbers (19–40%) are expected and match the
  literature; this is exactly why a tiny easy demo overstates capability.
- The **deterministic Autopsy layer is narrow** (3%) — it covers SQLi / weak
  crypto / ignored-auth-gate only; most of SecurityEval's CWEs are out of its
  rule set. The graph+LLM pipeline is what would carry detection here.
- Detection rate is **file-level** ("did the tool flag *anything* in this
  known-vulnerable file") — generous to all tools, and the fair granularity for
  SecurityEval (one vuln per file, no line-level ground truth).

## Detection on AI-generated subsets (token-free)
The same tools on SecurityEval's **model-generated** files (on-thesis: vulns in
AI-generated code):

| subset | Autopsy det. | Semgrep | Bandit |
|--------|--------------|---------|--------|
| Testcases_Copilot (130) | 1% | 15% | 28% |
| Testcases_InCoder (130) | 2% | 13% | 28% |
| Testcases_Insecure_Code (121, human) | 3% | 19% | 40% |

Static tools detect *less* on AI-generated code (Bandit 28% vs 40% on human) —
motivating better tooling. (Autopsy's LLM on the human Insecure_Code set: 95%.)

## CodeQL
Run as a third SAST baseline (CodeQL CLI 2.25.6, `python-security-extended.qls`,
`codeql/python-queries` 1.8.4), scored file-level exactly as Semgrep/Bandit:
**42% (51/121)** — above Bandit (40%) and roughly double Semgrep (19%), but far
below Autopsy's 95%. SecurityEval is the analysis shape CodeQL's whole-program
dataflow is least suited to (each file is an isolated function with no realized
taint source); reported as-is. See `results/codeql_baseline_report.md`.

## Also used for #9
SecurityEval's `Testcases_Copilot` + `Testcases_InCoder` (model-generated) vs
`Testcases_Insecure_Code` (human-authored) provided the labeled AI-vs-human set
for the authorship-classifier validation — see `AUTHORSHIP.md` (ROC-AUC 0.42).
