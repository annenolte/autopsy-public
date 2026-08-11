# Pre-registration addendum: replication and precision extension
Date committed: 2026-08-11. No API calls for these phases have been made
before this commit.

Purpose: increase run counts on already-reported experiments and replicate the
matched-budget pooling result with an independent sequence. No new hypotheses are
introduced; Phase 4 is exploratory and labeled as such. All analysis is estimation
(per-run values, means, ranges). Every outcome will be reported in the paper
regardless of direction, including any run in which the windowed pipeline recalls
fewer than 11/11.

- Phase 1: five (5) new single-prompt pygoat runs, config identical to the original
  pre-registration's raw arm. Pooled chronologically as an INDEPENDENT sequence under
  the original frozen dedupe and matcher rules (preregistration_matched_budget.md §5);
  the original pooling artifacts are not touched. Outputs: raw_seq2_run_{1..5}.json,
  pooling_summary_seq2.json. Reading rule: report the full k=1..5 curve as measured.
- Phase 2: three (3) additional runs per arm (graph-on "note", graph-off) of the
  central ablation, configs identical to the original phaseA runs, bringing each arm
  to N=5. Report per-run recall and finding counts, and per-arm mean and range.
- Phase 3: two (2) additional full SecurityEval passes (config identical to the
  reported pass), bringing N=3. Report per-run file-level recall and the mean.
- Phase 4 (exploratory): two (2) windowed pygoat runs with the deep-analysis model
  swapped to the current Claude Haiku model, all else identical, scored with the
  frozen matcher. Reported as an exploratory cost/capability observation, not a
  confirmatory result.
- Phase 5 (conditional, only if cumulative spend ≤ $16 after Phase 4): three (3)
  single-prompt runs on the synthetic demo in the whole-file scenario, to make the
  demo comparison scenario-matched. Outputs: raw_demo_wholefile_run{1..3}.json.

Budget caps per phase: $2.50 / $9.00 / $5.00 / $1.50 / $1.00. Hard stop at $18.00
cumulative. Any deviation from this plan will be recorded in the results summary.

---

## Execution environment pinned at commit time

Recorded here because neither target was present on disk when these phases began,
and neither is vendored into the repo. Both were cloned fresh before any API call.

- pygoat: `github.com/adeyosemanputra/pygoat` @ `19d17cc8874861142b330636d068bbde54e86b85`
  (the commit named in `preregistration_matched_budget.md` §2), cloned to
  `/tmp/pygoat`. `introduction/views.py` = 1238 lines, matching the line count
  recorded in the original pre-registration §5.
- SecurityEval: `github.com/s2e-lab/SecurityEval` @ `6f4fb70f782c6d47b02ea24341e8ef8c1eb04a6a`
  (repository HEAD as of 2026-08-11; last upstream commit 2023-11-04), cloned to
  `/tmp/SecurityEval`. Subset `Testcases_Insecure_Code` = 121 files, matching the
  count in the originally reported pass. The original SecurityEval pass did not
  record a dataset commit; this pin is recorded now so the N=3 set is internally
  consistent and re-runnable, and the file count agreeing at 121 is the evidence
  that the subset is unchanged from the original pass.
