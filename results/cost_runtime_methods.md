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
