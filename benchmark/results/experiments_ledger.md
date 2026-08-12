# Experiments ledger — replication & precision extension (Aug 2026)

Pre-registration: `benchmark/prereg_addendum_20260811.md` (committed 2026-08-11,
before any API call for these phases; pushed to autopsy-public main as `9bf3551`).

Hard stop: **$18.00 cumulative**. Prices are Anthropic list prices, computed from the
API-reported `usage` token counts by the same `usd()` helper the original runs used
(Sonnet 4.5 $3/$15 per Mtok; Haiku 4.5 $1/$5 per Mtok).

Phase caps: P1 $2.50 / P2 $9.00 / P3 $5.00 / P4 $1.50 / P5 $1.00.

| # | phase | run | arm / config | recall | dedup findings | in tok | out tok | cost $ | cum $ |
|---|-------|-----|--------------|--------|----------------|--------|---------|--------|-------|
| 1 | P1 | seq2_1 | raw single-prompt, whole-file, pygoat | 6/11 | 21 | 72,010 | 8,192 | 0.3389 | 0.3389 |
| 2 | P1 | seq2_2 | raw single-prompt, whole-file, pygoat | 9/11 | 22 | 72,010 | 8,192 | 0.3389 | 0.6778 |
| 3 | P1 | seq2_3 | raw single-prompt, whole-file, pygoat | 4/11 | 21 | 72,010 | 8,192 | 0.3389 | 1.0167 |
| — | P1 | seq2_4 attempt 1 | **FAILED** — HTTP 400, credit exhausted | — | — | 0 | 0 | 0.0000 | 1.0167 |
| — | P1 | seq2_5 attempt 1 | **FAILED** — HTTP 400, credit exhausted | — | — | 0 | 0 | 0.0000 | 1.0167 |
| 4 | P1 | seq2_4 (retry) | raw single-prompt, whole-file, pygoat | 6/11 | 29 | 72,010 | 8,192 | 0.3389 | 1.3556 |
| 5 | P1 | seq2_5 (retry) | raw single-prompt, whole-file, pygoat | 6/11 | 22 | 72,010 | 8,192 | 0.3389 | 1.6945 |

**Phase 1 subtotal: $1.6945** (cap $2.50 — within).

| # | phase | run | arm / config | recall | dedup findings | cost $ | cum $ |
|---|-------|-----|--------------|--------|----------------|--------|-------|
| 6 | P2 | autopsy new 1 | windowed, graph note ON, pygoat | 11/11 | 102 | 1.0826 | 2.7771 |
| 7 | P2 | autopsy new 2 | windowed, graph note ON, pygoat | 11/11 | 103 | 1.1335 | 3.9106 |
| 8 | P2 | autopsy new 3 | windowed, graph note ON, pygoat | 11/11 | 109 | 1.0910 | 5.0016 |
| 9 | P2 | nograph new 1 | windowed, graph note OFF, pygoat | 11/11 | 110 | 1.1674 | 6.1690 |
| 10 | P2 | nograph new 2 | windowed, graph note OFF, pygoat | 11/11 | 113 | 1.1609 | 7.3299 |
| 11 | P2 | nograph new 3 | windowed, graph note OFF, pygoat | 11/11 | 108 | 1.1131 | 8.4430 |

**Phase 2 subtotal: $6.7485** (cap $9.00 — within).

| # | phase | run | arm / config | recall | dedup findings | cost $ | cum $ |
|---|-------|-----|--------------|--------|----------------|--------|-------|
| — | P3 | pass 2, attempt 1 | **LOST** — tooling bug after a fully paid pass | — | — | ~1.79 (est) | ~10.23 |

**Lost pass — disclosure.** The Phase 3 wrapper resolved `_all_files()` through the
`/tmp` → `/private/tmp` symlink but compared against an unresolved `target`, so
`Path.relative_to()` raised **after** all 121 API calls had completed and before the
result JSON was written. The scan was billed; the record was lost, including its
`usage` counts. The $1.79 figure is therefore an estimate taken from
`SECURITYEVAL.md` (142K in / 91K out at Sonnet 4.5 list prices = $1.79), not a
measurement — it is the only unmeasured number in this ledger.

The wrapper now (a) resolves the target and (b) persists the raw hit set and usage to
`_raw_pass_<n>.json` the moment the scan returns, before any post-processing, so a
downstream bug can never again discard a paid pass.

**Pre-registered deviation (approved by the author before proceeding):** the lost pass
leaves Phase 3 unable to reach its pre-registered N=3 inside the $5.00 phase cap. Two
further passes were authorised, putting Phase 3 at roughly $5.37 — about $0.37 over its
phase cap, while remaining far inside the binding $18.00 hard stop. The overrun is
attributable to a tooling failure, not to experimental spend.

| # | phase | run | arm / config | recall | files detected | cost $ | cum $ |
|---|-------|-----|--------------|--------|----------------|--------|-------|
| 12 | P3 | pass 2 | SecurityEval LLM, 121 files | 95% | 115/121 | 1.7755 | 12.0085 |
| 13 | P3 | pass 3 | SecurityEval LLM, 121 files | 96% | 116/121 | 1.7989 | 13.8074 |

**Phase 3 subtotal: $5.3644** — $3.5744 measured plus the ~$1.79 estimated lost pass.
Measured spend alone is inside the $5.00 cap; the total is $0.36 over, as authorised.

| # | phase | run | arm / config | recall | findings | cost $ | cum $ |
|---|-------|-----|--------------|--------|----------|--------|-------|
| 14 | P4 | exploratory 1 | windowed, **deep=Haiku 4.5**, pygoat | 11/11 | 80 | 0.2944 | 14.1018 |
| 15 | P4 | exploratory 2 | windowed, **deep=Haiku 4.5**, pygoat | 11/11 | 86 | 0.3082 | 14.4100 |

**Phase 4 subtotal: $0.6026** (cap $1.50 — within).

| # | phase | run | arm / config | recall | findings | cost $ | cum $ |
|---|-------|-----|--------------|--------|----------|--------|-------|
| 16 | P5 | demo wf 1 | raw single-prompt, whole-file, demo_project | 11/12 | 15 | 0.1424 | 14.5524 |
| 17 | P5 | demo wf 2 | raw single-prompt, whole-file, demo_project | 12/12 | 15 | 0.1198 | 14.6722 |
| 18 | P5 | demo wf 3 | raw single-prompt, whole-file, demo_project | 10/12 | 15 | 0.1251 | 14.7972 |

**Phase 5 subtotal: $0.3872** (cap $1.00 — within). Precondition satisfied: cumulative
after Phase 4 was $14.41 ≤ $16.

## Cumulative total — FINAL

**$14.7972** of the $18.00 hard stop.

- **$13.0072 measured** from API-reported `usage` token counts.
- **~$1.79 estimated** for the lost Phase 3 pass (the only unmeasured figure here).

18 paid runs completed; 3 further paid attempts failed or were lost (2 to the credit
exhaustion, 1 to the tooling bug). All five phases ran to completion. Per-phase: P1
$1.6945 / P2 $6.7485 / P3 $5.3644 / P4 $0.6026 / P5 $0.3872. Every phase is inside its
cap except P3, which is $0.36 over solely because of the lost pass, as authorised.

## Interruption and retry (disclosed per prereg §6)

Runs 4 and 5 failed on first attempt with:

```
400 invalid_request_error: Your credit balance is too low to access the Anthropic API.
request_id: req_011CdwW2YDkQiKTAN3NdvToY / req_011CdwW2bFKSiHr91JRNYHkN
```

The account was topped up and each was retried **once**, which is what
`preregistration_matched_budget.md` §6 provides for ("If a run errors, note it, retry
once, disclose the retry"). Failed first attempts are preserved verbatim as
`raw_seq2_run_{4,5}_FAILED_attempt1.json` with `VALID_RUN: false`. No run was retried
for any reason other than an API error, and no run was retried because its number was
unfavourable — seq2_3 returned 4/11, the worst single result in either sequence, and
stands as measured.

## Harness defect found (affects how any future run must be read)

`autopsy/llm/client.py::stream_sonnet()` catches `APIError`, `RateLimitError`, and
`APIConnectionError` and **yields an error string into the scan output instead of
raising**. Consequently:

- a failed API call is parsed as a scan that legitimately found nothing;
- `run_single` returns normally, so the runner's retry/`except` path never fires;
- the run is recorded as `recall=0/11, findings=0, usage=0, cost=$0.00` — visually a
  real result row.

Had this not been caught, seq2 would have been published as a 5-run sequence whose last
two runs found nothing, and the resulting flat k=3→k=5 curve would have read as a
genuine plateau rather than two dead API calls.

The signature of a swallowed failure is **`usage_total == 0` AND `findings == 0`**.
An audit of every artifact under `benchmark/results/` found this signature in exactly
four runs: the two above, plus `eval_20260618_152241.json` run[0] and
`eval_20260618_152405.json` run[0] (early June dev runs, outside the frozen protocol set
and not cited in the paper).

**The paper's frozen artifacts are clean.** All 19 runs in `results/phaseA/` and
`results/matched_budget/` carry non-zero usage and non-zero findings. The many
June 18–19 artifacts showing `usage_total == 0` predate the token-accounting patch
(added for reviewer #14) and have real finding counts — they are not failures.

Recommendation: make `stream_sonnet` re-raise, or have `run_single` treat a zero-token
scan as an error. Until then, any run reporting 0 findings must be checked against its
usage counts before being read as a result.
