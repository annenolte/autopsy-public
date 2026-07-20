# Cost and runtime (reviewer Major comment #14)

Run date: **2026-06-21** · frozen matcher commit **6da8b87** · triage **claude-haiku-4-5-20251001** · analysis **claude-sonnet-4-5-20250929**

List prices used (USD per MTok, verified 2026-06-21):
- claude-haiku-4-5-20251001: $1.00 in / $5.00 out
- claude-sonnet-4-5-20250929: $3.00 in / $15.00 out

Line counting: physical newline count (`cloc` unavailable). Cache tokens: none recorded (caching not requested). Total fresh API spend for these measurements: ~$3.01.

## Headline table

| Benchmark | Runs | Files | KLOC | Time (s) | Cost ($) | TP | s/KLOC | s/file | $/KLOC | $/file | $/vuln |
|---|---|---|---|---|---|---|---|---|---|---|---|
| pygoat | 1 | 10 | 1.945 | 598.8 | 0.6114 | 11 | 307.9 | 59.9 | 0.3143 | 0.0611 | 0.0556 |
| securityeval | 1 | 121 | 1.699 | 1872.7 | 1.7896 | 114 | 1102.2 | 15.5 | 1.0533 | 0.0148 | 0.0157 |
| typescript | 5 | 3 | 0.061 | 62.3 | 0.0747 | 8 | 1022.0 | 20.8 | 1.2238 | 0.0249 | 0.0098 |
| flask_demo | 5 | 6 | 0.254 | 92.8 | 0.1404 | 11 | 365.3 | 15.5 | 0.5529 | 0.0234 | 0.0128 |
| Aggregate | 12 | 140 | 3.959 | 2626.6 | 2.6160 | 144 | 663.5 | 18.8 | 0.6608 | 0.0187 | 0.0182 |

_Time = per-scan wall-clock (mean over repeats for TS/Flask). Cost = real input+output `usage` tokens x list price. TP = confirmed true positives via the frozen matcher; SecurityEval TP = files detected (each file vulnerable by construction)._

## Per-model token totals & variance

| Benchmark | Runs | haiku in/out | sonnet in/out | Cost $ (±std) | Time s (±std) |
|---|---|---|---|---|---|
| pygoat | 1 | 0/0 | 41684/32423 | 0.6114 ± 0.0000 | 598.8 ± 0.0 |
| securityeval | 1 | 0/0 | 142498/90804 | 1.7896 ± 0.0000 | 1872.7 ± 0.0 |
| typescript | 5 | 2375/612 | 4132/3788 | 0.0747 ± 0.0058 | 62.3 ± 7.9 |
| flask_demo | 5 | 7505/1285 | 15121/5410 | 0.1404 ± 0.0086 | 92.8 ± 9.7 |
| Aggregate | 12 | 9881/1896 | 203435/132425 | 2.6160 ± 0.0000 | 2626.6 ± 0.0 |

## Haiku triage — per-stage breakdown (single-shot path)

Fresh stage-instrumented re-runs of the two benchmarks whose paper config uses the single-shot pipeline (Haiku triage -> Sonnet); mean over 3 runs each. The chunked path used for pygoat / SecurityEval has no triage step, so Haiku is genuinely $0 / 0 s there.

| Benchmark | graph s | detectors s | **Haiku triage s** | Sonnet s | total wall s | Haiku % of time |
|---|---|---|---|---|---|---|
| typescript_singleshot | 0.00 | 0.00 | **5.12** | 52.83 | 58.2 | 8.8% |
| flask_demo_singleshot | 0.00 | 0.01 | **9.71** | 78.63 | 88.6 | 11.0% |

| Benchmark | Haiku in/out | Haiku $ | Sonnet in/out | Sonnet $ | Total $ | Haiku % of cost |
|---|---|---|---|---|---|---|
| typescript_singleshot | 2382/567 | 0.00522 | 4096/3367 | 0.06279 | 0.0680 | 7.7% |
| flask_demo_singleshot | 7472/1026 | 0.01260 | 14757/5392 | 0.12515 | 0.1378 | 9.1% |

Takeaway: Haiku triage is ~5-10 s (**~9-11% of wall-clock**) but only **~8-9% of dollar cost** — a cheap gate in front of the Sonnet analysis. Graph build + deterministic detectors are negligible (<=0.01 s) at these sizes.

## Sanity checks (per-file throughput; cost/KLOC outliers)

| Benchmark | tokens/file | sec/file | $/KLOC |
|---|---|---|---|
| pygoat | 7411 | 59.9 | 0.3143 |
| securityeval | 1928 | 15.5 | 1.0533 |
| typescript | 3636 | 20.8 | 1.2238 |
| flask_demo | 4887 | 15.5 | 0.5529 |

Median cost/KLOC = $0.8031. Flagging any > 3x median ($2.4093): **none**.

## Provenance (reused vs. fresh)

- **typescript**, **flask_demo** (headline table): reused from stored frozen-protocol artifacts that already held real per-model token usage (no extra API spend). flask_demo = mean over 5 runs (not 9).
- **securityeval**: fresh full 121-file pass, single run.
- **pygoat**: fresh single representative run (N=1).
- **Haiku stage breakdown**: fresh single-shot re-runs of TS + Flask, 3 runs each, stage-instrumented.
- Graph build measured 0.022-0.025 s (confirmed offline); chunked benchmarks (pygoat, securityeval) spend $0 on Haiku (detectors + Sonnet only).

---

## Cost and runtime — methods

Cost is computed from the **real `usage` token counts** returned by every
Anthropic API response (`input_tokens` / `output_tokens`, summed per model), not
estimated from text length, and priced at the published list rates as of
2026-06-21: Claude Haiku 4.5 (triage) $1.00/$5.00 per million input/output
tokens and Claude Sonnet 4.5 (deep analysis) $3.00/$15.00 per million input/
output tokens. Source lines of code were counted with a physical newline count
(Python str.splitlines() over .py/.js/.ts/.tsx) because `cloc` was not installed on the run host; this is the
"lines" used for the per-KLOC normalization. Wall-clock time is broken out by
stage (dependency-graph build, deterministic detectors, Haiku triage, Sonnet deep
analysis) for the freshly run benchmarks and includes live API latency, so it
depends on network and hardware and is reported as **indicative** rather than a
hardware-independent constant. The TypeScript and synthetic Flask-demo figures
are reused from stored frozen-protocol run artifacts that already recorded real
per-model token usage (so they cost no additional API spend), and the synthetic
Flask-demo numbers are the **mean over 5 runs**; SecurityEval (121
files) and pygoat were run fresh, pygoat as a **single representative run**.
All figures use the frozen matcher (commit 6da8b87) and the pinned models
(Haiku claude-haiku-4-5-20251001, Sonnet claude-sonnet-4-5-20250929).

### Caveats
- **Wall-clock is network/hardware-dependent** (it includes live API round-trip
  latency); treat seconds-per-KLOC/-file as indicative, not a fixed constant.
  Token counts and dollar cost are hardware-independent and are the durable
  numbers.
- **pygoat is N=1** (a single representative run); its per-run cost/time has no
  variance estimate. TypeScript and the Flask demo are means over 5 runs each
  (std reported in the CSV); the Flask demo is 5 runs here, not 9.
- **Chunked benchmarks (pygoat, SecurityEval) skip Haiku triage by design** — the
  map-reduce scanner runs the deterministic detectors then Sonnet over line
  windows, so their Haiku token cost is genuinely $0. The single-shot benchmarks
  (TypeScript, Flask demo) do use Haiku triage.
- **Per-stage timing is only available for the freshly run benchmarks.** The
  reused artifacts recorded only aggregate scan time (which excludes the
  sub-second graph build); their stage breakdown is therefore null.
- **SecurityEval "confirmed vulnerabilities" = files detected**, since every file
  in the set is vulnerable by construction (per-file detection rate = recall);
  it is not a precision-matched count like pygoat/TypeScript.
- **Cache tokens were not billed/applied.** The client does not request prompt
  caching and recorded no `cache_creation_input_tokens` / `cache_read_input_tokens`
  in these runs, so cost is input+output only; the documented cache rates were not
  needed.
- **Per-benchmark "total" is per single scan** (mean for repeated benchmarks); the
  Aggregate row sums one representative scan per benchmark.
- List prices may change; they are pinned to 2026-06-21 and printed in the run
  output so the paper can cite them with a date.

## Source files
- CSV: `results/cost_runtime_per_kloc.csv`
- Raw per-run JSONL (no scanned source): `results/cost_runtime_raw.jsonl` (18 records)
- Machine summary: `results/cost_runtime_summary.json`
- Scripts: `benchmark/measure_cost_runtime.py`, `benchmark/measure_haiku_stages.py`
