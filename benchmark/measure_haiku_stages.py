"""Re-run the single-shot benchmarks (TypeScript, Flask demo) with per-stage
timing so the Haiku triage stage is captured explicitly (seconds + tokens),
alongside graph build / deterministic detectors / Sonnet analysis.

These are the two benchmarks whose paper config uses the single-shot pipeline
(scan_stream = Haiku triage -> Sonnet); the chunked path used for pygoat /
SecurityEval has no triage step, so Haiku is genuinely absent there.

Run:  python benchmark/measure_haiku_stages.py
Appends raw records to results/cost_runtime_raw.jsonl (tagged *_singleshot) and
writes results/cost_runtime_haiku_stages.md.
"""
from __future__ import annotations

import json
import statistics
import tempfile
import time
from pathlib import Path

import measure_cost_runtime as M  # installs nothing yet; provides helpers
import eval as E

REPEATS = 3
BASELINE = M._BENCH / "baseline"
RAW_JSONL = M.RAW_JSONL
OUT_MD = M._ROOT / "results" / "cost_runtime_haiku_stages.md"

BENCHES = [
    # name, demo dir, ground-truth path, source dir (for file count)
    ("typescript_singleshot", M._BENCH / "js_demo",
     M._BENCH / "js_demo" / "ground_truth_js.json", M._BENCH / "js_demo"),
    ("flask_demo_singleshot", M._ROOT / "demo_project",
     M._BENCH / "ground_truth.json", M._ROOT / "demo_project"),
]


def one_run(demo, gt_path):
    from autopsy.llm.client import reset_usage, get_usage
    all_truth, scored = E.load_ground_truth(gt_path, include_provisional=False)
    scored_ids = {t["id"] for t in scored}

    M._reset_instr()
    reset_usage()
    t0 = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = Path(tmp) / "eval_repo"
        graph, diff_text, changed_files = E.build_graph_and_diff(
            demo, BASELINE, repo_dir, mode="whole-file")
        # single-shot pipeline with Haiku triage (arm="autopsy"): chunked=False,
        # use_triage=True are the run_scan defaults.
        output, scan_elapsed = E.run_scan(
            graph, diff_text, changed_files, repo_dir, temperature=None,
            chunked=False)
    wall = time.time() - t0
    usage = get_usage()
    findings = E.dedupe_findings(E.parse_findings(output))
    m = E.match(findings, all_truth, scored_ids, M.FUZZ)
    return {
        "wall": wall, "scan_elapsed": scan_elapsed,
        "stages": dict(M.STAGE), "cache": dict(M.CACHE), "usage": usage,
        "findings": len(findings), "tp": m["tp"],
    }


def main():
    M.install_instrumentation()
    print("Re-running single-shot benchmarks with per-stage timing "
          f"({REPEATS} runs each). Haiku triage IS exercised on this path.\n")

    records = []
    summary = {}
    for name, demo, gt, src in BENCHES:
        loc = E.count_loc(demo)
        files = M.count_source_files(src)
        runs = []
        for i in range(REPEATS):
            r = one_run(demo, gt)
            hi = r["usage"].get("haiku_in", 0); ho = r["usage"].get("haiku_out", 0)
            si = r["usage"].get("sonnet_in", 0); so = r["usage"].get("sonnet_out", 0)
            rec = {
                "benchmark": name, "run_index": i,
                "source": "fresh-run single-shot (Haiku triage -> Sonnet), stage-instrumented",
                "wall_clock_s": round(r["wall"], 1),
                "scan_elapsed_s": round(r["scan_elapsed"], 1),
                "stages_s": {k: round(v, 2) for k, v in r["stages"].items()},
                "loc": loc, "files": files,
                "loc_method": "physical-line-count (eval.count_loc; cloc unavailable)",
                "haiku_in": hi, "haiku_out": ho, "sonnet_in": si, "sonnet_out": so,
                "cache": r["cache"],
                "findings": r["findings"], "confirmed_tp": r["tp"],
                "cost_usd": M.cost_in_out(hi, ho, si, so),
            }
            records.append(rec)
            runs.append(rec)
            print(f"  [{name} run {i}] wall {rec['wall_clock_s']}s  "
                  f"stages={rec['stages_s']}  haiku {hi}/{ho}  "
                  f"sonnet {si}/{so}  ${rec['cost_usd']:.4f}  TP={rec['confirmed_tp']}")

        def mean(k): return statistics.mean(r[k] for r in runs)
        def smean(stage): return statistics.mean(r["stages_s"][stage] for r in runs)
        hi, ho = mean("haiku_in"), mean("haiku_out")
        si, so = mean("sonnet_in"), mean("sonnet_out")
        haiku_cost = hi / 1e6 * 1.0 + ho / 1e6 * 5.0
        sonnet_cost = si / 1e6 * 3.0 + so / 1e6 * 15.0
        summary[name] = {
            "runs": REPEATS, "files": files, "loc": loc, "kloc": loc / 1000.0,
            "graph_s": smean("graph_s"), "detectors_s": smean("detectors_s"),
            "haiku_s": smean("haiku_s"), "sonnet_s": smean("sonnet_s"),
            "wall_s": mean("wall_clock_s"),
            "haiku_in": hi, "haiku_out": ho, "sonnet_in": si, "sonnet_out": so,
            "haiku_cost": haiku_cost, "sonnet_cost": sonnet_cost,
            "total_cost": haiku_cost + sonnet_cost,
            "tp": mean("confirmed_tp"),
        }

    with open(RAW_JSONL, "a") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # ── markdown ──
    L = ["# Haiku triage — per-stage breakdown (single-shot path)", "",
         f"Mean over {REPEATS} runs each. Prices: Haiku $1/$5, Sonnet $3/$15 per MTok "
         f"(verified {M.RUN_DATE}). Stage seconds include live API latency (indicative).",
         "",
         "## Wall-clock by stage (seconds, mean)", "",
         "| Benchmark | graph | detectors | **Haiku triage** | Sonnet | total wall | Haiku % of time |",
         "|---|---|---|---|---|---|---|"]
    for n, d in summary.items():
        stage_sum = d["graph_s"] + d["detectors_s"] + d["haiku_s"] + d["sonnet_s"]
        pct = 100 * d["haiku_s"] / stage_sum if stage_sum else 0
        L.append(f"| {n} | {d['graph_s']:.2f} | {d['detectors_s']:.2f} | "
                 f"**{d['haiku_s']:.2f}** | {d['sonnet_s']:.2f} | {d['wall_s']:.1f} | "
                 f"{pct:.1f}% |")
    L += ["", "## Tokens & cost by model (mean)", "",
          "| Benchmark | Haiku in/out | Haiku $ | Sonnet in/out | Sonnet $ | Total $ | Haiku % of cost |",
          "|---|---|---|---|---|---|---|"]
    for n, d in summary.items():
        pct = 100 * d["haiku_cost"] / d["total_cost"] if d["total_cost"] else 0
        L.append(f"| {n} | {d['haiku_in']:.0f}/{d['haiku_out']:.0f} | "
                 f"{d['haiku_cost']:.5f} | {d['sonnet_in']:.0f}/{d['sonnet_out']:.0f} | "
                 f"{d['sonnet_cost']:.5f} | {d['total_cost']:.4f} | {pct:.1f}% |")
    L += ["",
          "_The chunked scanner used for pygoat / SecurityEval has no triage step, "
          "so Haiku cost/time there is genuinely $0 / 0 s — see the main report._", ""]
    OUT_MD.write_text("\n".join(L) + "\n")

    print("\n" + "\n".join(L))
    print(f"\nAppended {len(records)} records -> {RAW_JSONL}")
    print(f"Wrote -> {OUT_MD}")


if __name__ == "__main__":
    main()
