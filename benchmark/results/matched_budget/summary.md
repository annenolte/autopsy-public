# Matched-Budget + Positional Mechanism Test — Summary

Pre-registration: `benchmark/preregistration_matched_budget.md` (committed `6ef8f32`,
**before** any new API call). Model `claude-sonnet-4-5-20250929`; frozen matcher (fuzz 5),
frozen dedup (same file / ±3 lines / same category → merge), unmodified `SCAN_SYSTEM`
prompt, `ground_truth_pygoat.json` (11 in-scope vulns), target
`/tmp/pygoat/introduction` @ pygoat `19d17cc`.

**Headline:** on pygoat, the single-prompt baseline's recall deficit **does not survive**
a matched (actually 1.5×) budget. Pooling five independent single-prompt runs reaches
**11/11**, the same recall the windowed arm reaches in one pass. Per the pre-registered
decision rule this means **the windowing *recall* advantage is confounded with budget**;
the surviving honest claim is an **efficiency** claim, not a unique-capability claim.
Test B (positional) was inconclusive/mixed and independently refuted the strong
"single pass can't read deep code" mechanism. Both tests point the same way.

---

## Costs (actual)

| item | value |
|---|---|
| New single-prompt runs | 3 (runs new_1, new_2, new_3), no errors, no retries |
| Cost per new run | $0.3389 |
| **New API spend (this task)** | **$1.0167** |
| 2 existing runs (reused, already on disk) | $0.6768 |
| **5-run pooled total** | **$1.6935** (≈1.5× the windowed arm's $1.13/run) |
| Windowed arm reference (1 run, on disk) | $1.1261, ~112 findings, 11/11 |
| Hard-stop cap | $3.00 (never approached) |

Test B: **$0.00** (pure re-analysis of data on disk).

---

## Test A

### Per-run recall (single-prompt, independent runs)

| run | source | findings | recall |
|---|---|---:|---:|
| existing_0 | phaseA (on disk) | 18 | 7/11 |
| existing_1 | phaseA (on disk) | 20 | 8/11 |
| new_1 | this task | 20 | 6/11 |
| new_2 | this task | 21 | 7/11 |
| new_3 | this task | 25 | 8/11 |

No single run exceeds 8/11; each run misses a *different* subset (run-to-run stochastic).

### Table M1 — matched budget

| Arm | Runs | Total cost | Findings (union, deduped) | Recall |
|---|---:|---:|---:|---:|
| Single-prompt, pooled | 5 | $1.6935 | 66 | **11/11** |
| Windowed (existing) | 1 | $1.1261 | ~112 | 11/11 |

### Table M2 — recall vs finding volume (the curve that answers the objection)

Runs pooled in chronological order (existing_0, existing_1, new_1, new_2, new_3); union
deduped with the frozen rule; scored once with the frozen matcher at each k.

| Arm | Cumulative cost | Cumulative findings (deduped) | Recall | Still missed |
|---|---:|---:|---:|---|
| single-prompt, 1 run | $0.3389 | 18 | 7/11 | imagemath, ssrf, ssti, weak-hash |
| single-prompt, 2 runs (union) | $0.6768 | 33 | 10/11 | imagemath-eval |
| single-prompt, 3 runs (union) | $1.0157 | 46 | 10/11 | imagemath-eval |
| single-prompt, 4 runs (union) | $1.3546 | 55 | **11/11** | — |
| single-prompt, 5 runs (union) | $1.6935 | 66 | 11/11 | — |
| windowed, 1 run | $1.1261 | ~112 | 11/11 | — |

### Does the union plateau?

**Recall does NOT plateau below the windowed arm** — it climbs to 11/11 by the 4th pooled
run (at $1.35, already above the windowed arm's $1.13). The windowing hypothesis's
prediction that repeated single passes would plateau *in recall* below 11/11 is
**falsified**: the vuln missed by the first two runs (`imagemath-eval`, mid-file @ line 574)
is picked up by new_2, so it is catchable by a single pass — just infrequently.

**Finding *count* does plateau, well below the windowed arm** (66 deduped after 5 runs vs
~112 in one windowed run) — repeated single passes keep re-discovering the same ~13-per-run
findings. So the pooled baseline reaches full recall **without** its finding count
approaching the windowed arm's. That cuts against a naive "recall is bought by raw finding
volume" reading too: on an 11-item label set, ~55–66 unique findings already saturate it,
and the windowed arm's extra ~50 findings are not what earns its recall.

### Which pre-registered outcome occurred (Test A)

> **Pooled single-prompt recall = 11/11 at $1.35–$1.69, i.e. ≥ the windowed arm's $1.13
> cost.** Per the fixed decision rule, this is the first branch: **the windowing recall
> advantage IS confounded with budget.** The recall claim reduces to an **efficiency**
> claim — windowing reaches 11/11 in ONE pass ($1.13, ~20 min), whereas repeated
> single-prompt sampling reaches 11/11 only after ~4 pooled passes ($1.35). Windowing is
> not buying recall the baseline categorically cannot reach; it is buying it in one shot
> instead of several.

---

## Test B (positional mechanism) — outcome

Full analysis: `positional_analysis.md`. **Outcome: inconclusive / mixed**, and it refutes
the *strong* positional-truncation version of the windowing mechanism.

- Run 0 alone looked supportive (missed vulns deeper: mean depth 0.712 vs 0.333 for
  catches). **Run 1 contradicted it**, catching the three *deepest* vulns (ssrf/ssti/
  weak-hash, depths 0.77–0.82) while missing a *shallow* one (code-injection-eval, 0.366).
- The two runs miss *different* vulns; only `imagemath-eval` (mid-file, line 574) is missed
  by both — and even it is caught by a later single run (new_2). The persistent miss is
  mid-file, not deepest — the opposite of the truncation prediction.
- Verified mechanism (not assumed): the `raw` arm sends the **whole** file (no input
  truncation); both original runs stop at exactly `sonnet_out = 8192` (the output cap). The
  binding constraint is **output budget** — the single pass reads everything but can only
  emit ~18–25 findings before being cut off, and *which* ones varies. That is a real thing
  windowing removes (per-window output budget), but it is a stochastic-emission /
  output-budget mechanism, **not** "deep code is invisible to a single pass."

---

## Combined conclusion (honest, both directions reported)

On pygoat, Autopsy's windowed 11/11 vs single-prompt 7–8/11 is **not** evidence that
windowing sees code repeated single passes cannot. Given ~1.5× the budget, a pooled
single-prompt baseline also reaches 11/11 (Test A), and the misses are positionally
stochastic rather than systematically deep (Test B). The defensible surviving claim is
**efficiency**: windowing achieves in a single pass the recall that single-prompt sampling
reaches only across several pooled passes. The paper should state the recall edge as an
efficiency/one-shot advantage on this target, and must **not** claim windowing uniquely
recovers deep or otherwise-unreachable vulnerabilities — the matched-budget data do not
support that. This weakens the earlier framing and is reported as such, per pre-registration.

---

## Exact commands (reproducible)

```bash
# 0. pygoat at the pinned commit (no API cost)
cd /tmp && git clone https://github.com/adeyosemanputra/pygoat.git
cd /tmp/pygoat && git checkout 19d17cc8874861142b330636d068bbde54e86b85
wc -l introduction/views.py            # -> 1238

# 1. Pre-registration committed BEFORE any API call
git add benchmark/preregistration_matched_budget.md && git commit   # -> 6ef8f32

# 2. Test B (FREE): positional analysis from the 2 existing raw runs + ground truth
python3 benchmark/results/matched_budget/testB_positional.py

# 3. Test A (~$1.02): 3 new single-prompt runs + pooled union scoring, hard stop $3
python3 <scratchpad>/testA_runner.py --new-runs 3 --cap 3.00
#   -> raw_new_run_{1,2,3}.json, pooling_summary.json
```

Artifacts in `benchmark/results/matched_budget/`: `positional_analysis.{md,json}`,
`raw_new_run_{1,2,3}.json`, `pooling_summary.json`, `testB_positional.py`, this file.
