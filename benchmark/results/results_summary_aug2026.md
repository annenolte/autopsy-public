# Replication & precision extension — results summary (Aug 2026)

Pre-registration: `benchmark/prereg_addendum_20260811.md`, committed and pushed to
autopsy-public main (`9bf3551`) **before any API call for these phases**.

**All five phases complete.** Total spend **$14.7972** of the $18.00 hard stop
($13.0072 measured from API-reported token counts, plus ~$1.79 estimated for one lost
pass). Full per-run accounting in `benchmark/results/experiments_ledger.md`.

### Headline results

| phase | outcome |
|---|---|
| 1 — pooling replication | **The two sequences reach opposite pre-registered verdicts.** Test A is underpowered at N=5; the outcome hinges on one run in ten. |
| 2 — ablation to N=5/arm | **11/11 in all 10 windowed runs.** Graph note contributes nothing to recall — clean null result. |
| 3 — SecurityEval to N=3 | **95.3% mean** (95/95/96%), 4 stable misses. The 95% claim reproduces. |
| 4 — Haiku deep (exploratory) | **11/11 at 3.7× lower cost, 2.8× faster.** N=2, exploratory. |
| 5 — demo whole-file | Raw arm **91.7% recall** in whole-file vs 67% reported in `safe` — baseline mode moves the number ~25 points. |

---

## Phase 1 — independent pooling sequence (seq2). COMPLETE, 5/5 runs.

Config identical to the original pre-registration's raw arm: single-prompt Sonnet 4.5
(`claude-sonnet-4-5-20250929`), whole files, no windowing, no dependency graph, target
`/tmp/pygoat/introduction` @ pygoat `19d17cc`, frozen dedupe (window 3), frozen matcher
(fuzz 5). The original sequence's artifacts were neither read nor modified.

### Per-run

| run | recall | dedup findings | input tok | output tok | hit 8192 cap | cost $ |
|---|---|---|---|---|---|---|
| seq2_1 | 6/11 | 21 | 72,010 | 8,192 | yes | 0.3389 |
| seq2_2 | 9/11 | 22 | 72,010 | 8,192 | yes | 0.3389 |
| seq2_3 | **4/11** | 21 | 72,010 | 8,192 | yes | 0.3389 |
| seq2_4 | 6/11 | 29 | 72,010 | 8,192 | yes | 0.3389 |
| seq2_5 | 6/11 | 22 | 72,010 | 8,192 | yes | 0.3389 |

Mean **6.2/11**, range 4/11 – 9/11. The 4/11 run is the worst single result in either
sequence and stands as measured; it was not re-run.

Runs 4 and 5 failed on first attempt (HTTP 400, credit exhausted) and were retried once
each after the account was topped up — the retry `preregistration_matched_budget.md` §6
provides for. Failed attempts preserved as `raw_seq2_run_{4,5}_FAILED_attempt1.json`.

### Pooled curve, and the §4 verdict

| k | dedup findings | recall | cumulative cost | missed |
|---|---|---|---|---|
| 1 | 21 | 6/11 | $0.3389 | imagemath-eval, insecure-deser-pickle, ssrf, ssti, weak-hash |
| 2 | 34 | 9/11 | $0.6778 | ssti, weak-hash |
| 3 | 47 | 9/11 | $1.0167 | ssti, weak-hash |
| 4 | 67 | 9/11 | $1.3556 | ssti, weak-hash |
| 5 | 77 | 9/11 | $1.6945 | ssti, weak-hash |

seq2's pooled cost ($1.6945) exceeds the windowed arm's ($1.1261), so the §4 rule fires:

> **Pooled single-prompt recall ≤ 9/11 at ≥ the windowed arm's cost → windowing
> survives the matched-budget test.**

## The headline: the two sequences reach OPPOSITE pre-registered verdicts

| | seq1 (original) | seq2 (this replication) |
|---|---|---|
| curve | 7 → 10 → 10 → **11** → 11 | 6 → 9 → 9 → 9 → 9 |
| union findings | 18 → 66 | 21 → 77 |
| pooled cost | $1.6935 | $1.6945 |
| §4 verdict | ≥11/11 → **recall advantage IS confounded with budget** | ≤9/11 → **windowing SURVIVES** |

Same frozen protocol, same target, same matcher, near-identical cost, opposite
conclusions. **The Test A result is not stable across independent sequences.**

### Why they diverge — it comes down to one run in ten

Across **all 10** single-prompt runs now on record (5 seq1 + 5 seq2), the two labels that
separate the verdicts were caught like this:

| label | runs catching it |
|---|---|
| `pygoat-ssti` | **1 of 10** — `existing_1` only |
| `pygoat-weak-hash` | **1 of 10** — `existing_1` only |

Both are caught by the *same single run*, and that run is in seq1. seq1 reaches 11/11
only because `existing_1` is in its pool; remove it and seq1 plateaus at 9/11 exactly as
seq2 does. No seq2 run caught either label, and seq2's union grew from 47 to 77 findings
across k=3→k=5 while recall did not move at all.

That growth-without-recall is the pattern §1 predicted for the **windowing** hypothesis:
"repeated single-prompt runs keep re-discovering the same (mostly early/prominent)
findings, so their pooled union plateaus well below both ~110 findings and 11/11 recall."
seq2's union plateaued at 77 findings against the windowed arm's ~112, with recall stuck
at 9/11.

### Recommended reading for the paper

The original Test A conclusion — that Autopsy's recall advantage reduces to an efficiency
claim — **should not be reported as established**. It rests on a single run out of ten
catching two labels that the other nine never caught. The defensible statement is:

> Two independent five-run pooled sequences under the frozen protocol reached opposite
> pre-registered verdicts ($1.69 each). The matched-budget test is underpowered at N=5:
> its outcome is determined by whether one unusually productive single-prompt run happens
> to land in the pool. We report both sequences and draw no verdict.

This is a stronger and more honest result than either sequence alone, and it is exactly
what raising N was supposed to expose.

### Output-cap evidence (clean gain)

All 5 seq2 runs emitted **exactly 8,192** output tokens — the `max_tokens` ceiling in
`stream_sonnet`. With the 5 prior single-prompt runs (4 at exactly 8192, 1 at 8123), the
single-prompt arm now hits its output ceiling in **9 of 10 recorded runs**. This extends
the paper's output-cap evidence from 5 runs to 10 as planned.

---

## Phase 2 — ablation replication to N=5 per arm. COMPLETE.

Three additional runs per arm, configs identical to the original phaseA runs
(`--baseline-mode whole-file --chunked`, window 400, frozen dedupe and matcher),
bringing each arm from N=2 to N=5. Cost $6.7485 against a $9.00 cap.

| arm | N | recall per run | mean | range | findings per run | mean | range |
|---|---|---|---|---|---|---|---|
| autopsy (graph note **ON**) | 5 | 11, 11, 11, 11, 11 | **11/11** | 11–11 | 112, 107, 102, 103, 109 | 106.6 | 102–112 |
| chunked-nograph (graph **OFF**) | 5 | 11, 11, 11, 11, 11 | **11/11** | 11–11 | 109, 108, 110, 113, 108 | 109.6 | 108–113 |

### Reading

**The windowed arm's 11/11 is completely stable.** Ten windowed runs are now on record
across the two arms and every single one recalls 11/11, with zero variance. The paper's
headline pygoat result reproduces without qualification at N=5.

**The dependency-graph note contributes nothing to recall.** Both arms hit 11/11 in every
run; the graph-off arm even produces marginally *more* findings on average (109.6 vs
106.6), though the ranges overlap heavily and the difference is not meaningful at N=5.
This confirms at N=5 what the original N=2 suggested: the recall comes from **windowing**,
not from the cross-file graph note. The ablation should be reported as a null result for
the graph note, stated positively — it is evidence about the mechanism, not a failure.

### How this interacts with Phase 1

The two phases together sharpen the picture considerably. The windowed arm is the *stable*
side of the comparison — 10 runs, 11/11 every time, no variance at all. The single-prompt
baseline it is measured against swings between 4/11 and 9/11 run-to-run, and its pooled
verdict flips depending on whether one unusually productive run lands in the pool.

So the fragility exposed in Phase 1 belongs to the **matched-budget comparison**, not to
the windowing result itself. That is a materially different claim from "the windowing
result is fragile", and the paper should say so explicitly.

## Phase 3 — SecurityEval N=3. COMPLETE.

Two additional full 121-file passes over `Testcases_Insecure_Code`, config identical to
the reported pass (`eval_securityeval.run_autopsy_llm`, chunked LLM scan, one call per
file), bringing the benchmark to N=3.

| pass | detected | recall | input tok | output tok | cost $ |
|---|---|---|---|---|---|
| 1 (originally reported) | 115/121 | 95% | ~142K | ~91K | ~1.80 |
| 2 (new) | 115/121 | 95% | 142,498 | 89,866 | 1.7755 |
| 3 (new) | 116/121 | 96% | 142,498 | 91,426 | 1.7989 |

**Mean 115.3/121 = 95.3%**, range 95–96%. Input token counts are identical across the
two new passes (142,498), which confirms the two runs saw byte-identical inputs.

### Union / intersection

The addendum asked for per-file TP lists so union and intersection could be reported.
This is available for passes 2 and 3 only — **the originally reported pass recorded no
per-file list** (that limitation is precisely why the recording wrapper was written), so
only its aggregate 95% is on record. Across passes 2 and 3:

| | files | rate |
|---|---|---|
| union | 117/121 | 97% |
| intersection | 114/121 | 94% |
| stable misses (missed by both) | 4 | — |
| disagreements (caught by exactly one) | 3 | — |

**Stable misses** — the four files neither pass detected:
`CWE-462/mitre_1.py`, `CWE-477/author_1.py`, `CWE-703/author_1.py`, `CWE-835/author_1.py`.

**Disagreements** — caught by one pass but not the other:
`CWE-193/author_1.py` (pass 3), `CWE-703/author_2.py` (pass 2), `CWE-730/author_1.py`
(pass 3).

### Reading

The 95% headline reproduces cleanly. Run-to-run variance is ±1 file out of 121, and the
detection set is highly stable — 114 of the ~115 detections are common to both passes,
with only 3 files flipping. The paper's "N=1, repeat for a confidence interval" caveat in
`SECURITYEVAL.md` can now be replaced with **95.3% mean over N=3, range 95–96%**.

The four stable misses are a more useful object than the aggregate: they are the same
files every time, so they characterise a genuine capability boundary rather than sampling
noise, and are worth a sentence in the paper.

## Phase 4 — Haiku deep model. EXPLORATORY, COMPLETE.

**Labelled exploratory in the addendum and reported as such. This is a cost/capability
observation, not a confirmatory result.**

Two windowed pygoat runs with the deep-analysis model swapped from Sonnet 4.5 to
`claude-haiku-4-5-20251001`, everything else identical to the Phase 2 `autopsy` arm
(whole-file baseline, chunked at 400 lines, graph note ON), scored with the frozen
matcher. The model id was resolved from the API's live model list, not from memory.

| | deep model | recall | findings | deep tok (in/out) | cost $ | time |
|---|---|---|---|---|---|---|
| exploratory run 1 | Haiku 4.5 | **11/11** | 80 | 87,462 / 41,389 | 0.2944 | 396s |
| exploratory run 2 | Haiku 4.5 | **11/11** | 86 | 87,462 / 44,153 | 0.3082 | 414s |
| baseline (Phase 2, N=5) | Sonnet 4.5 | 11/11 ×5 | mean 106.6 | — | mean ~1.1250 | ~1150s |

### Reading

**Recall holds completely.** Both Haiku runs recall 11/11 with nothing missed — identical
to the Sonnet-deep arm across all five of its runs.

**At 27% of the cost and 35% of the runtime.** $0.30/run vs $1.125/run is a **3.7×**
cost reduction, and 405s vs ~1150s is a **2.8×** speedup. Findings drop about 22%
(mean ~83 vs 106.6), which on pygoat is not a quality signal in either direction —
precision is explicitly not claimed on this target because the labels are incomplete.

### Correction to the phase's premise

The addendum anticipated "holds at a tenth the cost". That framing should not be used:

- There is **no Haiku 5**. The newest Haiku on the API's model list is
  `claude-haiku-4-5-20251001` — the same model the pipeline already uses for triage.
- Haiku 4.5 is **$1/$5 per Mtok** against Sonnet 4.5's **$3/$15** — a 3× list-price
  ratio, not 10×. The measured end-to-end ratio is 3.7×, slightly better than list
  because Haiku also emitted fewer output tokens.

So the honest headline is **"same 11/11 recall at roughly a quarter of the cost and a
third of the runtime, N=2, exploratory."**

### Caveats that must travel with this number

- **N=2.** The Sonnet arm needed N=5 before its stability was credible; this has two runs.
- **pygoat only**, and pygoat is the target the matcher was partly developed against.
- Recall on 11 labels is a coarse instrument — it cannot detect quality loss that shows
  up as worse explanations, worse localisation, or more false positives.
- This is not evidence that Haiku should replace Sonnet in the pipeline; it is evidence
  that the question is worth a proper confirmatory experiment.

## Phase 5 — demo whole-file baseline. COMPLETE.

Precondition satisfied (cumulative $14.41 ≤ $16 after Phase 4). Three single-prompt
raw-arm runs on `demo_project` with `--baseline-mode whole-file` (flag verified against
`run_phaseA.py`'s own `choices=["safe", "whole-file"]`), 12 scored vulns, frozen dedupe
and matcher. Cost $0.3872 against a $1.00 cap.

| run | recall | precision | F1 | findings | missed |
|---|---|---|---|---|---|
| 1 | 11/12 (92%) | 79% | 85% | 15 | auth-ignored-return |
| 2 | 12/12 (100%) | 86% | 92% | 15 | — |
| 3 | 10/12 (83%) | 71% | 77% | 15 | auth-ignored-return, sqli-admin-delete |

**Mean recall 91.7%** (range 83–100%), **mean F1 84.6%** (range 77–92%), mean precision
78.6%.

### What this does establish

The single-prompt arm's demo figure is strongly sensitive to baseline mode. The paper
reports the raw demo arm at **67% recall / 76% F1** from a single `safe`-mode run
(`FROZEN_PROTOCOL.md`). Run in the whole-file scenario instead, the same arm averages
**91.7% recall / 84.6% F1** over three runs. Baseline-mode choice moves the raw arm's
demo recall by roughly 25 points — larger than most of the between-arm gaps the paper
reports on this target. That is worth stating plainly.

It also gives the raw arm a scenario-matched figure across targets for the first time:
raw single-prompt is now measured in **whole-file** mode on both demo_project (91.7%
recall) and pygoat (mean 6.2/11 = 56%), so the two are finally comparable to each other.

### What this does NOT establish — important

**This is not a scenario-matched Autopsy-vs-raw comparison on demo_project.** Every
existing Autopsy demo run — the frozen single run and the phaseA N=3 set — was executed
with `--baseline-mode safe`. There are no whole-file Autopsy runs on demo_project, and
the addendum did not schedule any. So the 91.7% raw figure must **not** be set against
the 83% (frozen) or 79.2% (phaseA N=3) Autopsy demo F1: those are a different scenario.

Closing that gap needs three whole-file Autopsy runs on demo_project (~$0.55). That is
outside this addendum and should be pre-registered separately rather than folded in here.

### Incidental finding: the demo Autopsy numbers are themselves unstable

While establishing the comparison baseline, the frozen single run and the phaseA N=3 set
disagree substantially on the *same* arm and *same* `safe` scenario:

| source | N | recall | precision | F1 |
|---|---|---|---|---|
| `FROZEN_PROTOCOL.md` frozen run | 1 | 83% | 83% | 83% |
| phaseA `eval_autopsy-demo` | 3 | 100% | 65.6% | 79.2% |

Recall differs by 17 points and precision by 17 points between the two records. This is
the demo-target fragility reviewer #2 flagged, and it is an argument for reporting the
demo distribution rather than any single run — consistent with what `FROZEN_PROTOCOL.md`
already says about not cherry-picking the 91.67% figure.

---

## Deviations from the addendum

1. **Phase 1 was interrupted mid-sequence** by an external billing stop (account out of
   credit) and resumed after top-up. Runs 4 and 5 each consumed their one permitted §6
   retry. Disclosed above; failed attempts preserved as artifacts.
2. **The addendum carries an added section** pinning the two evaluation targets. Neither
   was present on disk; pygoat was cloned at the commit the original prereg names
   (`19d17cc`, `views.py` = 1238 lines as recorded), and SecurityEval at repository HEAD
   (`6f4fb70`, 121 files in `Testcases_Insecure_Code` as recorded) because the original
   pass recorded no dataset commit. Additive disclosure below a separator; the plan text
   itself is verbatim.
3. **A new ledger file** `results/phaseA/ledger_aug2026.jsonl` is used instead of
   appending to the published `results/phaseA/ledger.jsonl`, via the shim
   `benchmark/run_phaseA_aug2026.py`, to honour the no-modify rule. Only the ledger path
   differs; all experiment logic is run_phaseA's own code.
4. **`testA_seq2.py` gained `--start-index`** so the sequence could be resumed after the
   billing failure, and its pooling step now reads the run files back from disk by index
   rather than pooling only in-process runs. The `E.run_single(...)` call, the dedupe, and
   the matcher are byte-identical to `testA_runner.py`.
5. **Phase 3 needs a recording wrapper.** `eval_securityeval.py --autopsy-llm` prints an
   aggregate percentage only, so the per-file union/intersection the addendum asks for is
   not recoverable from it. `run_securityeval_repeats.py` calls that module's own
   `run_autopsy_llm()` unchanged and records the hit list. The token-free SAST baselines
   are deliberately not re-run (deterministic, unchanged, not part of the N=3 question).
6. **Phase 4's premise needs correcting.** The API model list contains no Haiku 5; the
   newest Haiku is `claude-haiku-4-5-20251001` — the model the pipeline already uses for
   triage. At $1/$5 vs Sonnet 4.5's $3/$15 it is **~3× cheaper, not "a tenth the cost"**.
   The `--model` override is implemented by rebinding the module global
   `autopsy.llm.client.SONNET_MODEL` from the Phase 4 driver, which leaves every frozen
   file byte-identical.

## Harness defect (reportable finding in its own right)

`stream_sonnet()` swallows `APIError` / `RateLimitError` / `APIConnectionError` and yields
an error string into the scan text instead of raising. A failed call is therefore scored
as a legitimate zero-finding scan, and the runner's retry path never fires. The failure
signature is `usage_total == 0 AND findings == 0`.

Had this not been caught, seq2's two dead API calls would have been published as runs
that found nothing, and the flat k=3→k=5 curve would have read as a genuine plateau.

An audit of every artifact under `benchmark/results/` found four runs with this
signature: the two above, plus `eval_20260618_152241.json` run[0] and
`eval_20260618_152405.json` run[0] (early June dev runs, outside the frozen protocol set
and not cited in the paper). **All 19 runs in the paper's frozen set (`phaseA/`,
`matched_budget/`) are clean.** The many June 18–19 artifacts with `usage_total == 0`
predate the token-accounting patch and carry real finding counts; they are not failures.

Recommendation: make `stream_sonnet` re-raise, or have `run_single` treat a zero-token
scan as an error.

## Integrity check

A SHA-256 comparison against the pre-run baseline confirms **no pre-existing artifact was
modified or removed**; all 50 prior files hash identically.
`benchmark/results/matched_budget/pooling_summary.json` (original sequence) is
byte-identical to autopsy-public HEAD.

---

# Correction (2026-08-12)

**Append-only. Nothing above this rule has been altered.**

## The original claim

The Phase 5 section above, under *"What this does NOT establish — important"*, states:

> There are no whole-file Autopsy runs on demo_project, and the addendum did not
> schedule any.

## Why it is wrong

Four whole-file Autopsy-arm demo artifacts exist in `benchmark/results/`:

- `eval_autopsy_20260618_161028.json` — `baseline_mode: whole-file`, N=3
- `eval_autopsy_20260618_210426.json` — `baseline_mode: whole-file`, N=3
- `eval_autopsy_20260618_212208.json` — `baseline_mode: whole-file`, N=3
- `eval_autopsy_20260619_233900.json` — `baseline_mode: whole-file`, `chunked: false`, N=5

The claim was reached by checking only the frozen single run and the phaseA N=3 set —
both of which are `safe`-mode — and generalising from them without enumerating the full
artifact set.

## The accurate claim

**There are no whole-file _chunked_ Autopsy demo runs.** Every chunked demo run in the
repository is `safe`-mode (`phaseA/eval_autopsy-demo_*.json`,
`phaseA/eval_chunked-nograph-demo_*.json`). The whole-file Autopsy demo runs above are
all unchunked, so a whole-file **windowed** Autopsy demo arm genuinely does not exist —
but whole-file Autopsy demo runs do.

## What follows: the config-matched comparison that does exist

Because those artifacts exist, a config-matched demo comparison is available at
**whole-file + unchunked**, which is exactly the configuration of the Phase 5 runs:

| arm (whole-file, unchunked) | N | recall | precision | F1 |
|---|---|---|---|---|
| autopsy | 5 | 91.7% | 81.9% | **86.4** |
| raw single-prompt | 5 | 91.7% | 79.4% | 84.7 |
| sonnet-only | 5 | **95.0%** | 82.7% | **88.3** |
| raw single-prompt — Phase 5 (new) | 3 | 91.7% | 78.6% | 84.6 |

Two consequences.

**Autopsy and the raw single-prompt baseline are indistinguishable on recall** (both
91.7%) in this matched configuration, Autopsy leads on F1 by ~1.7 points, and the
sonnet-only arm outperforms both. This is a materially weaker picture for the demo target
than the frozen `safe` comparison (Autopsy 83% F1 vs raw 76% F1) implies.

**The Phase 5 runs are an unplanned but clean reproduction of the archived raw figures.**
Same arm, same baseline mode, same chunking as `eval_raw_20260619_233900.json`: 91.7%
recall in both, F1 84.6 vs 84.7. This was not a pre-registered goal and is reported as an
incidental replication.

## Manuscript changes made in consequence

The manuscript's **Table 4**, **Table 9**, and **Section VI-A** were corrected
accordingly.

## Provenance of this correction

The error was found by enumerating every `demo_project` run artifact under
`benchmark/results/` and reading `config.baseline_mode` and `config.chunked` from each,
rather than relying on the subset originally consulted.

An earlier fix to this claim was applied **in place** to the Phase 5 section and pushed as
`bb957c8` on 2026-08-11. That edit violated the append-only rule for published reports.
The body above has since been restored byte-for-byte to its as-published state
(`b66e945`), and the correction now lives here, dated and below the rule. No measured
value was altered by either step.
