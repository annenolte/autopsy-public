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
| Bandit | 45% (5/11) | 82% (9/11) | 36 |
| Raw Sonnet (no graph, single prompt) | ~57% (4-run mean) | — | — |
| **Autopsy** (full, chunked) | **100% (11/11), 4/4 runs** | — | ~60 |

## demo_project — synthetic app (12 vulns)

| Tool | recall (strict) | recall (loc-only) | # findings |
|------|----------------|-------------------|-----------|
| Semgrep (`p/python`) | 25% (3/12) | 42% (5/12) | 3 |
| Bandit | 42% (5/12) | 67% (8/12) | 5 |
| **Autopsy** (full) | ~92% (best run) / high-80s mean | — | ~10–14 |

## Honest reading
- **On recall, Autopsy beats both SAST baselines and the raw-LLM baseline** on
  both benchmarks. That is the central, defensible result.
- **This is recall, not precision.** Bandit emitted 36 findings on pygoat (noisy);
  Autopsy ~60; precision is not fairly comparable here because the pygoat ground
  truth is incomplete (see benchmark/pygoat/README.md). Do not report a precision
  ranking from these runs.
- **Bandit's loc-only (82%) >> its strict (45%)**: it often flags the right line
  with a generic category our matcher rejects. Reported honestly so the baseline
  isn't unfairly understated.
- **Semgrep with `p/python` is a standard config**, not its maximum. Semgrep
  Pro / Code has interfile taint that `p/python` does not exercise — a fairer
  "max Semgrep" comparison would need the paid tier.
- **CodeQL was not run** (needs the CLI + a built database). Commands to add it
  are in `compare_tools.py`.

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
