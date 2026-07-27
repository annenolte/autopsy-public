# Test B — Positional mechanism test (FREE, no API calls)

**Pre-registered reading rule:** see `benchmark/preregistration_matched_budget.md` §5,
committed before the data was arranged.

**Question.** If windowing helps because a single whole-file pass cannot effectively
reach code deep in a long file, the vulns the single-prompt baseline MISSES should sit
systematically DEEPER (higher `vuln_line` / `depth_ratio`) than the ones it CATCHES. If the
recall gap is instead just "more shots," the misses should be positionally random.

**Data source.** The two existing single-prompt (`raw`) runs on
`/tmp/pygoat/introduction` (pygoat @ `19d17cc`), scored by the frozen matcher. The stored
findings in `benchmark/results/phaseA/eval_raw_20260622_145235.json` were **re-scored with
`eval.match()` and reproduce the ledger `matched_ids` exactly** (cross-check printed by the
script). Line numbers are `line_start` from `ground_truth_pygoat.json`.

**Constant to disclose up front:** all 11 in-scope vulns live in one file,
`introduction/views.py` (**1238 lines**, `wc -l`). So `file_total_lines` is identical for
every vuln and the CAUGHT-vs-MISSED comparison collapses to `vuln_line` / `depth_ratio`.
The two runs also disagree on which vulns they catch, so catch status is shown per-run and
as the union, with group means for each.

---

## The raw 11-row table

`depth_ratio = vuln_line / 1238`. `r0` = caught by run 0 (7/11); `r1` = caught by run 1
(8/11); `union` = caught by at least one of the two single-prompt runs; windowed arm caught
all 11 in both of its runs.

| vuln_id | file | vuln_line | file_total_lines | depth_ratio | caught r0 | caught r1 | caught (union) | caught windowed |
|---|---|---:|---:|---:|:--:|:--:|:--:|:--:|
| pygoat-sqli-login | introduction/views.py | 147 | 1238 | 0.119 | ✅ | ✅ | ✅ | ✅ |
| pygoat-insecure-deser-pickle | introduction/views.py | 205 | 1238 | 0.166 | ✅ | ✅ | ✅ | ✅ |
| pygoat-xxe | introduction/views.py | 256 | 1238 | 0.207 | ✅ | ✅ | ✅ | ✅ |
| pygoat-command-injection | introduction/views.py | 415 | 1238 | 0.335 | ✅ | ✅ | ✅ | ✅ |
| pygoat-code-injection-eval | introduction/views.py | 453 | 1238 | 0.366 | ✅ | ❌ | ✅ | ✅ |
| pygoat-unsafe-yaml | introduction/views.py | 551 | 1238 | 0.445 | ✅ | ✅ | ✅ | ✅ |
| pygoat-imagemath-eval | introduction/views.py | 574 | 1238 | 0.464 | ❌ | ❌ | ❌ | ✅ |
| pygoat-sqli-injection-lab | introduction/views.py | 855 | 1238 | 0.691 | ✅ | ❌ | ✅ | ✅ |
| pygoat-ssrf | introduction/views.py | 956 | 1238 | 0.772 | ❌ | ✅ | ✅ | ✅ |
| pygoat-ssti | introduction/views.py | 975 | 1238 | 0.788 | ❌ | ✅ | ✅ | ✅ |
| pygoat-weak-hash | introduction/views.py | 1018 | 1238 | 0.822 | ❌ | ✅ | ✅ | ✅ |

## Group means (CAUGHT vs MISSED, single-prompt)

| grouping | group | n | mean vuln_line | mean depth_ratio |
|---|---|---:|---:|---:|
| **run 0 (7/11)** | caught | 7 | 411.7 | 0.333 |
| | missed | 4 | 880.8 | 0.712 |
| **run 1 (8/11)** | caught | 8 | 565.4 | 0.457 |
| | missed | 3 | 627.3 | 0.507 |
| **union (10/11)** | caught | 10 | 583.1 | 0.471 |
| | missed | 1 | 574.0 | 0.464 |

(n = 11 total; per the pre-registration, no significance test is run — the rows and means
are shown for the reader to judge.)

---

## Reading (against the pre-registered rule)

**Outcome: INCONCLUSIVE / MIXED — and it refutes the *strong* positional-truncation version
of the windowing mechanism.**

- **Run 0, taken alone, looks like it supports windowing:** its misses average
  `depth_ratio` 0.712 vs 0.333 for its catches — the misses are deeper.
- **Run 1 contradicts that cleanly.** Its caught/missed depth means are almost identical
  (0.457 vs 0.507), and critically it **caught the three *deepest* vulns in the file**
  (ssrf @ 956, ssti @ 975, weak-hash @ 1018, depths 0.77–0.82) while **missing a *shallow*
  one** (code-injection-eval @ 453, depth 0.366). A single pass that literally could not
  reach deep code could not have produced run 1.
- **The two runs disagree on which vulns they miss.** Run 0 misses {imagemath, ssrf, ssti,
  weak-hash}; run 1 misses {code-injection-eval, imagemath, sqli-injection-lab}. Only
  `imagemath-eval` is missed by both. The set of misses is therefore substantially
  **stochastic**, not a fixed positional cutoff.
- **The one persistent miss is mid-file, not deepest.** `imagemath-eval` sits at line 574
  (`depth_ratio` 0.464) — the middle of the file. If depth drove the misses, the persistent
  miss would be the deepest vuln (weak-hash @ 1018); instead the deepest three are all
  recovered by the union and a mid-file vuln is the survivor.

**Mechanism note (verified in source, not assumed).** The `raw` arm (`run_raw_llm_scan`,
`eval.py:481`) sends the **whole** file to Sonnet — it does NOT truncate the input (the
500-line truncation in `pipeline.py:45` is on the *subgraph/context-builder* path, not this
one). Both raw runs terminate at **exactly `sonnet_out = 8192` output tokens** — the output
cap. So the binding constraint on the single pass is its **finite output budget**: it reads
the entire file but can only emit ~18–20 findings before being cut off, and *which* ~18–20 it
emits varies run to run. That is a real limitation windowing removes (each ~400-line window
gets its own read and its own output budget), but it is an **output-budget / stochastic-
emission** mechanism, **not** the "deep code is invisible to a single pass" mechanism this
depth test was designed to detect. The depth prediction is only weakly and inconsistently
supported, so Test B does **not** by itself vindicate windowing.

**Consequence for the paper.** Test B cannot be used to claim "the baseline misses deep
vulns because a single pass can't read that far." The data don't support that clean story.
The better-supported and more honest mechanism is: a single pass is output-budget-limited and
emits a variable subset of findings; whether repeated single passes can pool their way to the
windowed arm's recall is exactly what **Test A** decides. This outcome was written before
running Test A, as required.
