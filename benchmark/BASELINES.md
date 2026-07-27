# Baseline comparison (reviewer issue #18)

Established SAST tools run on the **same** benchmarks, scored against the **same**
ground truth with the **same** matcher (`benchmark/compare_tools.py`). This tests
whether Autopsy's architecture adds anything over off-the-shelf static analysis,
and replaces the paper's untested capability claims with measured numbers.

All numbers are **recall** (did the tool find the labeled vulns?). Two readings
are given because the baselines don't use Autopsy's category taxonomy:
- **strict** = file + (normalized) category + line within ±5 (how Autopsy is scored);
- **loc-only** = file + line within ±5, ignoring category (most generous to the baseline).

## pygoat — real third-party app (11 in-scope vulns)

| Tool | recall (strict) | recall (loc-only) | # findings |
|------|----------------|-------------------|-----------|
| Semgrep (`p/python`) | 64% (7/11) | 64% (7/11) | 14 |
| Bandit | 45% (5/11) | 82% (9/11) | 42 |
| CodeQL (`security-extended`) | 82% (9/11) | 82% (9/11) | 37 |
| Raw Sonnet (no graph, single prompt) | **68% (mean of 2: 7/11, 8/11)** | — | ~19 |
| Autopsy (chunked, graph note OFF) | **100% (11/11), 2/2 runs** | — | ~108 |
| **Autopsy** (full, chunked, graph note ON) | **100% (11/11), 2/2 runs** | — | ~110 |

> Raw single-prompt reconciled this session: measured **68%** (not 45%/57%);
> graph-on vs graph-off both reach 11/11 (Δ = 0.0 ± 0.0 pp) — the gain over raw is
> **windowing**, not the dependency-graph note. Autopsy emits ~110 deduped findings
> (recall, not precision — see README). Full analysis: `results/phaseA/interpretation.md`.

> Bandit finding count corrected 36 → **42**: re-measured this build (Bandit
> 1.9.4) via `compare_tools.py` on `pygoat/introduction`. CodeQL row from
> `results/codeql_baseline_report.md` (CodeQL CLI 2.25.6, packs pinned there).

## demo_project — synthetic app (12 vulns)

| Tool | recall (strict) | recall (loc-only) | # findings |
|------|----------------|-------------------|-----------|
| Semgrep (`p/python`) | 25% (3/12) | 42% (5/12) | 3 |
| Bandit | 42% (5/12) | 67% (8/12) | 5 |
| CodeQL (`security-extended`) | 17% (2/12) | 25% (3/12) | 3 |
| **Autopsy** (full) | ~92% (best run) / high-80s mean | — | ~10–14 |

## Honest reading
- **On recall, Autopsy beats both SAST baselines and the raw-LLM baseline** on
  both benchmarks. That is the central, defensible result.
- **This is recall, not precision.** Bandit emitted 42 findings on pygoat (noisy);
  Autopsy ~60; precision is not fairly comparable here because the pygoat ground
  truth is incomplete (see benchmark/pygoat/README.md). Do not report a precision
  ranking from these runs.
- **Bandit's loc-only (82%) >> its strict (45%)**: it often flags the right line
  with a generic category our matcher rejects. Reported honestly so the baseline
  isn't unfairly understated.
- **Semgrep with `p/python` is a standard config**, not its maximum. Semgrep
  Pro / Code has interfile taint that `p/python` does not exercise — a fairer
  "max Semgrep" comparison would need the paid tier.
- **CodeQL was run** as a third off-the-shelf baseline (CodeQL CLI 2.25.6,
  standard `security-extended` suites), scored through the same frozen matcher by
  `benchmark/run_codeql_baseline.py`. Full results, per-category breakdown, and
  caveats: `results/codeql_baseline_report.md`; raw SARIF + scored JSON under
  `results/codeql/`. On pygoat it reaches 82% (9/11) — above Semgrep (64%) and
  Bandit (45% strict) — but still misses the cross-function SSTI and the
  `ImageMath.eval` sink that Autopsy's LLM pipeline catches (11/11).

## Reproduce
```bash
pip install semgrep bandit
python benchmark/compare_tools.py --target demo_project \
    --ground-truth benchmark/ground_truth.json
python benchmark/compare_tools.py --target /path/to/pygoat/introduction \
    --ground-truth benchmark/pygoat/ground_truth_pygoat.json
```

> Note: installing `semgrep` downgrades `click`, which conflicts with `typer`
> (used by the `autopsy` CLI). The benchmark harness (argparse + rich) is
> unaffected and all tests pass, but if you need the `autopsy` CLI, install
> semgrep in a separate virtualenv.
