# Pre-registration — Matched-Budget + Positional Mechanism Test

**Written and committed BEFORE any new API call.** Date: 2026-07-12.
Branch: `measure/cost-runtime`.

Purpose: close the last open objection to Autopsy's surviving pygoat result — that
Autopsy's 11/11 recall beats the single-prompt baseline (7–8/11) only because Autopsy
emits ~110 findings vs ~19 and simply takes more shots at an 11-item label set (the
**volume hypothesis**), rather than because **windowing** lets the model actually read
code a single pass never effectively processes (the **windowing hypothesis**).

Nothing below may be changed after the first new API call. The matcher, ground truth,
prompt, model, and dedup rule are frozen and unmodified; the ONLY thing that varies is
the number of single-prompt baseline runs.

---

## 1. The two hypotheses and their predictions

### Volume hypothesis
The recall gap is just "more shots." Autopsy emits ~110 findings, the baseline ~19, so
Autopsy hits more of an 11-item set by sheer count. **Prediction:** the vulnerabilities
the single-prompt baseline misses are positionally random within their files, and
pooling enough independent single-prompt runs (whose unions grow toward ~110 findings)
should eventually recover the same recall Autopsy reaches in one windowed pass.

### Windowing hypothesis
Windowing (map-reduce over ~400-line windows so no file is truncated and no single
context has to hold/emit findings for the whole file at once) works because a single
whole-file pass cannot effectively process/emit findings across the entire file — it is
bounded by its finite output budget and degrading attention over a long input.
**Prediction:** the vulnerabilities the single-prompt baseline MISSES sit systematically
DEEPER in LONGER files than the ones it CATCHES; and repeated single-prompt runs keep
re-discovering the same (mostly early/prominent) findings, so their pooled union
**plateaus** well below both ~110 findings and 11/11 recall.

---

## 2. Primary metric

Recall on the **11 in-scope pygoat vulnerabilities** (`benchmark/pygoat/ground_truth_pygoat.json`),
scored with the **frozen matcher** (`benchmark/eval.py` `match()`, fuzz = 5 lines,
category-gated one-to-one matching) and the **frozen dedup rule** (`dedupe_findings`,
same file / within 3 lines / same category → merge). Unmodified.

Model: `claude-sonnet-4-5-20250929`. Prompt: `SCAN_SYSTEM` via `run_raw_llm_scan`
(whole files, one pass, no windowing, no dependency graph). Target:
`/tmp/pygoat/introduction` @ pygoat commit `19d17cc8874861142b330636d068bbde54e86b85`.

---

## 3. Number of new baseline runs

**3** new single-prompt runs (committed in advance). Combined with the **2** single-prompt
runs already on disk (`benchmark/results/phaseA/eval_raw_20260622_145235.json`, runs 0 and 1)
this gives **5** independent single-prompt runs at ~$1.70 total, ≈1.5× the windowed arm's
$1.13/run budget. Hard stop at **$3 total**.

---

## 4. Decision rule for Test A (matched budget), fixed in advance

Pool the **union** of findings across the first k single-prompt runs (k = 1..5, runs
taken in chronological order, no cherry-picking), dedupe with the frozen rule, and score
once with the frozen matcher.

- **Pooled single-prompt recall ≥ 11/11** at ≥ the windowed arm's cost → the windowing
  *recall* advantage IS confounded with budget. Report that the recall claim reduces to an
  **efficiency** claim (windowing reaches in one pass what repeated sampling reaches in five).
- **Pooled single-prompt recall ≤ 9/11** at ≥ the windowed arm's cost → windowing
  **survives** the matched-budget test (the pooled baseline, given more money, still loses).
- **Pooled single-prompt recall = 10/11** → **inconclusive**; report as inconclusive.

Report whichever of these three actually occurs. A result weakening the windowing claim is
publishable and will be reported.

---

## 5. Test B reading rule (positional mechanism), written down BEFORE looking at the arranged data

For each of the 11 in-scope vulns record: `vuln_line`, `file_total_lines`,
`depth_ratio = vuln_line / file_total_lines`, and caught/missed by the single-prompt
baseline (per the frozen matcher) and by the windowed arm. Report mean `vuln_line`, mean
`file_total_lines`, and mean `depth_ratio` for CAUGHT vs MISSED (single-prompt), plus the
raw 11-row table. With n = 11, **no significance test** — show the rows and the group means.

- **Supports windowing:** missed vulns sit deeper (higher `vuln_line`, higher `depth_ratio`)
  and/or in longer files than caught vulns; strongest if every miss is past the point where a
  single pass's effective output/attention degrades and every catch is before it.
- **Undercuts windowing:** misses are positionally indistinguishable from catches; then the
  volume explanation gains ground and the paper must say so.
- **Inconclusive:** mixed / no clear pattern — report as inconclusive.

Note (disclosed honestly): all 11 in-scope vulns live in one file
(`introduction/views.py`, 1238 lines), so `file_total_lines` is constant across the set and
the CAUGHT-vs-MISSED comparison reduces to `vuln_line` / `depth_ratio` only. The two
existing single-prompt runs disagree on which vulns they catch, so the per-vuln caught
status is reported per-run AND as the union of the two runs, and group means are computed
for each, so run-to-run stochasticity is visible rather than hidden.

---

## 6. Guardrails (binding)

- Do not modify the matcher, ground truth, prompt, model, or dedup rule.
- Do not cherry-pick which runs to pool; pool all, in chronological order.
- Do not stop early because the result is going badly for windowing; run all 3 and report.
- Print a running cost total after each run. Hard stop at $3.
- If a run errors, note it, retry once, disclose the retry.
