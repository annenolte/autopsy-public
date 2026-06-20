# Frozen evaluation protocol (reviewer #2 / #5)

This protocol is **frozen as of this commit**. The reruns reported below were
executed *after* this file was committed, and the matcher, ground truth, and
config were **not** changed afterward regardless of the results. This is the
discipline the reviewer asked for ("fix the protocol, then rerun").

**Honesty caveat:** this is a *frozen-protocol reproduction*, not a blind test.
The matcher was developed partly by inspecting these same targets (demo_project
and pygoat), so this confirms the numbers are *stable under a locked protocol* —
it does not establish performance on unseen data. A genuinely blind number
requires a fresh target the protocol never saw (e.g. the TypeScript LLM run,
not yet executed).

## CODE FROZEN for the one-time paid evaluation
As of the commit that adds this note, the **detection code and the scoring/eval
harness are frozen**. No further changes will be made that could alter results.
This means a single paid evaluation run produces the numbers to report — the
spend does not need to be repeated because the code changed afterward.
(Deliberately NOT done, to avoid teaching-to-the-test / false-positive risk:
broadening the deterministic detectors. The LLM already covers those cases.)

## Frozen components
- **Matcher** (`benchmark/eval.py`): a finding matches a ground-truth entry iff
  file basename matches AND normalized category matches (with the generic
  "injection" bridge and per-entry `accepted_categories`) AND the reported line
  is within **fuzz = 5** of `[line_start, line_end]`. One-to-one assignment,
  ties broken by smallest line distance.
- **Dedupe**: findings at the same file + within 3 lines with overlapping
  category are merged before scoring (on by default).
- **Provisional** ground-truth entries excluded from scoring.
- **Models**: `claude-haiku-4-5-20251001` (triage), `claude-sonnet-4-5-20250929`
  (analysis).
- **Configs**:
  - demo_project: `--baseline-mode safe` (reconstructed clean baseline), single-shot.
  - pygoat: `--baseline-mode whole-file --chunked`, 11 in-scope vulns.
- **Reporting**: whole-number percentages; mean ± std over repeats; recall is the
  headline (precision not claimed on pygoat — incomplete labels).

## Results (frozen rerun, single run each — reported as produced)

No matcher or ground-truth edits were made after seeing these.

**demo_project** (safe baseline, 12 vulns):
| arm | P | R | F1 |
|-----|----|----|----|
| Autopsy | 83% | 83% | 83% |
| Raw Sonnet (no graph) | 89% | 67% | 76% |
Autopsy missed `auth-bypass-permission`, `sqli-export-service`.

**pygoat** (whole-file, chunked, 11 in-scope vulns):
| arm | recall | precision |
|-----|--------|-----------|
| Autopsy | **100% (11/11)** | 18% — NOT meaningful (incomplete GT; ~50 "FPs" are mostly real unlabeled pygoat vulns) |
| Raw Sonnet (no graph) | 45% (5/11) | 38% |

Notes:
- This is **N=1**. For the paper, report mean ± std over repeats (prior
  multi-run data: demo F1 ~84% mean; pygoat recall 11/11 across 4 recovered
  runs). The frozen single run is consistent with those.
- The demo Autopsy F1 of 83% is a normal single-run draw and is **lower** than
  the paper's cherry-picked 91.67% — which is exactly the fragility the reviewer
  flagged. Report the distribution, not a best run.
- On pygoat, precision is intentionally not claimed (see above); recall is the
  headline, and Autopsy's 100% reproduced under the frozen protocol.
