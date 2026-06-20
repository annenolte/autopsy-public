# Autopsy evaluation benchmark

Frozen artifacts for reproducing the paper's evaluation. See the
"Reproduce the evaluation" section of the top-level `readme.md` for setup and
run commands. This file documents the artifacts and, importantly, what is
reconstructed.

## Contents

| Path | What it is |
|------|------------|
| `ground_truth.json` | Authoritative list of planted vulnerabilities with line ranges read directly from `demo_project/`. |
| `baseline/` | **Reconstructed** clean ("before") version of the demo module. |
| `make_diff.py` | Builds a 2-commit temp git repo (baseline → vulnerable) and emits the unified diff, mirroring `autopsy scan`. |
| `eval.py` | Runs the scan against the diff, parses findings, matches them to ground truth, and reports precision / recall / F1. |
| `results/` | Per-run JSON output (gitignored). |
| `heldout/` + `validate_heldout.py` | A separate orders project (vulnerable + safe) used to prove the deterministic detectors generalize and don't false-positive. Not scored. |

## Deterministic detector layer

Autopsy now has two layers: deterministic AST/graph rules
(`autopsy/detection/ignored_returns.py`, `autopsy/detection/static_rules.py`)
and the LLM scan. The deterministic layer is **scale-invariant** — it fires
identically on a 200-line demo and a huge repo, in linear time, with no
context-window limit — so it is what keeps recall up as a codebase grows.
Current rules: ignored cross-file authorization-gate returns, SQL strings built
from interpolated parameters that reach a sink, and weak hashing (md5/sha1).

> **Evaluation honesty — read this before reporting numbers.** Findings from the
> deterministic layer are static analysis, *not* evidence of LLM reasoning. They
> will catch several planted bugs on their own and push F1 up. When you report
> results, **attribute the static layer and the LLM layer separately**, and do
> not tune rules to `demo_project` — `benchmark/heldout/` exists to show the
> rules were validated on code they were not written against
> (`python benchmark/validate_heldout.py`).

The scan target itself is `demo_project/` at the repository root (the
"after"/vulnerable state).

## Evaluation scenarios (`--baseline-mode`)

The "before" commit defines *what scenario you are measuring*, and it materially
affects the score. Choose the one that matches what the paper claims, and state
it explicitly:

- **`whole-file`** (empty-stub baseline) — every vulnerable file appears as
  net-new code. This models *"this file is freshly AI-generated"*, which is
  Autopsy's headline use case, and is how the original development eval was run.
  The scanner sees each file as 100% new, so it attends to every function and
  recall is higher and steadier.
- **`safe`** (reconstructed clean baseline; the default here) — the diff is only
  the change from safe code to vulnerable code. This models *"an AI edited
  already-safe code and introduced a vulnerability"* — a stricter, more
  conservative test. Recall is lower because the scanner focuses on the changed
  hunks.

Neither is "more correct" in the abstract; they answer different questions. Use
`whole-file` if the paper's claim is about scanning AI-generated code, `safe` if
it is about catching regressions introduced into existing code. Whichever you
report, name the scenario in the paper. Do **not** report one scenario's number
while having run the other.

## Ablation: does the graph actually help? (`--arm`)

The central claim of the tool is that a dependency graph enables cross-file
reasoning a plain LLM cannot do. The harness can test that claim directly:

```bash
python benchmark/eval.py --arm both --repeat 5      # side-by-side comparison
python benchmark/eval.py --arm raw                   # control only
```

- **`autopsy`** — the full pipeline (graph summary + Haiku triage + blast radius
  + diff, then Sonnet).
- **`raw`** — the **same** analysis model and the **same** `SCAN_SYSTEM` prompt,
  handed the same raw material (full source of the files + the diff) but **none**
  of the graph-derived context. Findings are parsed and matched identically.

Because model, prompt, and scorer are held constant, any score difference is
attributable to the graph pipeline. `--arm both` prints a Δ table. Watch the
cross-file finding `auth-ignored-return` in particular: that is exactly the case
the graph is supposed to win, so it is the most informative single data point for
whether the architecture earns its keep. **This comparison — not the absolute
F1 — is what makes the evaluation a research result rather than a demo.**

## Matching rule

A streamed finding matches a ground-truth entry when **all** hold:

1. file basename matches,
2. category matches — the finding's category overlaps the entry's
   `accepted_categories` after normalization (e.g. ground-truth `Weak Crypto` ↔
   the scanner's `Secrets Exposure` wording — see `category_tokens` /
   `categories_match` in `eval.py`),
3. the reported line is within `--fuzz-lines` (default **5**) of
   `[line_start, line_end]`.

Most entries accept a single category. `sqli-admin-run` accepts **both** `SQLi`
and `Auth Bypass`: `/api/admin/run-query` executes arbitrary client SQL on an
unauthenticated privileged route, so it is genuinely both, and the scanner is
correct whichever label it emits. `accepted_categories` only relaxes the
category check — the file and line gates are unchanged.

Matching is one-to-one (a finding can satisfy at most one entry and vice versa);
ties break by smallest line distance. `--fuzz-lines 25` reproduces the looser
tolerance used during development.

Before matching, findings are **deduplicated**: two findings at the same
location (same file, within 3 lines) with overlapping categories are merged, so
a single issue reported twice (e.g. by both the deterministic layer and the LLM)
is not counted as two false positives. The window is tight enough that distinct
nearby findings (e.g. `execute_query` vs `execute_read`) are preserved. Disable
with `--no-dedupe`.

## ⚠️ Reconstruction notice (please confirm)

- **`baseline/` is a reconstruction, not recovered source.** No
  pre-vulnerability version of `demo_project/` was ever committed, so the safe
  baseline was rebuilt from the vulnerable files: same module structure and
  function signatures, vulnerabilities removed. Each baseline file says so in
  its header. `baseline/routes.py` is byte-identical to the demo (it has no
  planted vulnerability), so it produces no diff.

- **`sqli-search-service` is a provisional 13th entry (please confirm).**
  `demo_project/user_service.py` `search_users` (lines 10–14) forwards the
  unvalidated `query` argument into `build_search_query` → `execute_read` — a
  genuine SQL-injection forwarding sink that the labeled set omitted, and one
  Autopsy flagged repeatedly in development runs. It is marked
  `"provisional": true` in `ground_truth.json` and is **excluded from scoring by
  default**; pass `--include-provisional` to score it. The headline metric stays
  on the 12 authoritative planted vulnerabilities until this is confirmed.

## Determinism

The scan uses Claude's default sampling — the current client
(`autopsy/llm/client.py`) exposes no temperature parameter, and the harness does
not change the tool's detection path to add one. Results therefore vary slightly
between runs; use `--repeat N` to report mean ± standard deviation.

**Model substitution (2026-06-18).** The analysis model used when the paper was
written, `claude-sonnet-4-20250514`, has been retired by Anthropic and now
returns a 404, which broke the live benchmark. The client is pinned to its
date-stamped successor, `claude-sonnet-4-5-20250929` (see the note in
`autopsy/llm/client.py`); the triage model `claude-haiku-4-5-20251001` is
unchanged and still available. Absolute precision/recall therefore differ from
the original model — confirm whether you want this successor pinned for the
camera-ready, or a different available model.

> Install Autopsy editable from this repo (`pip install -e .`) before running the
> benchmark, so `import autopsy` resolves to this code and not another local
> checkout.
