# Scan time / cost normalization (reviewer #14)

The paper reported only aggregate scan time (~51s) and total API cost ($4–6).
The reviewer asked for time/cost **per KLOC, per file, per vulnerability**, and a
larger-codebase data point. The harness now records `target_loc`,
`scan_time_per_kloc`, and `scan_time_per_vuln` per run (in the results JSON and
the run report).

## Measured (frozen-protocol runs)

| target | LOC | scan time | time / KLOC | time / vuln |
|--------|-----|-----------|-------------|-------------|
| demo_project (single-shot) | 254 | 69.4 s | **273 s/KLOC** | 5.8 s/vuln |
| pygoat (chunked, ~8× larger) | 1,939 | 533 s | **275 s/KLOC** | 48.5 s/vuln |

Time per KLOC is essentially flat (~273–275 s/KLOC) from the 254-line demo to the
~8× larger pygoat app — a useful scaling data point: the chunked scanner keeps
throughput roughly linear in code size rather than blowing up.

## Token accounting (added — enables cost/KLOC)
`autopsy/llm/client.py` now records input/output tokens per model
(`get_usage()` / `reset_usage()`), and the harness reports **tokens (in/out)**
and **tokens/KLOC** per run (in the run report + results JSON). Dollar cost is
then `tokens × the model's published per-token price` — left as `tokens` rather
than a hardcoded dollar figure so it doesn't bake in a price that may change.
(Token numbers populate on a live run; the deterministic/offline paths make no
API calls so report zero.)
