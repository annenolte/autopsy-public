"""Part 2 paid-run driver with a hard budget ledger.

Runs ONE scan at a time, computes the REAL USD cost from the Anthropic `usage`
token counts (pinned list prices, same as measure_cost_runtime.py), appends to a
persistent ledger, and refuses to start a run that would breach the cap. Writes
per-arm aggregate JSON compatible with eval.summarize (so stats.py /
make_run_distribution.py read it directly).

Arms:
  autopsy          graph-ON chunked (deterministic + graph note + Sonnet windows)
  chunked-nograph  graph-OFF chunked (same windowing, graph note disabled)
  raw              single-prompt Sonnet, whole files, no graph

Usage:
  python benchmark/run_phaseA.py --arm autopsy --target /tmp/pygoat/introduction \
     --ground-truth benchmark/pygoat/ground_truth_pygoat.json \
     --baseline-mode whole-file --chunked --repeat 1 --cap 7.50
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

_BENCH = Path(__file__).resolve().parent
_ROOT = _BENCH.parent
for p in (str(_BENCH), str(_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from dotenv import load_dotenv  # noqa: E402
load_dotenv(_ROOT / ".env")

import eval as E  # noqa: E402

PRICES = {
    "claude-haiku-4-5-20251001":  {"in": 1.00, "out": 5.00},
    "claude-sonnet-4-5-20250929": {"in": 3.00, "out": 15.00},
}
HAIKU, SONNET = "claude-haiku-4-5-20251001", "claude-sonnet-4-5-20250929"
PHASE_DIR = _BENCH / "results" / "phaseA"
LEDGER = PHASE_DIR / "ledger.jsonl"
FUZZ = 5


def usd(usage: dict) -> float:
    h, s = PRICES[HAIKU], PRICES[SONNET]
    return (usage.get("haiku_in", 0) / 1e6 * h["in"]
            + usage.get("haiku_out", 0) / 1e6 * h["out"]
            + usage.get("sonnet_in", 0) / 1e6 * s["in"]
            + usage.get("sonnet_out", 0) / 1e6 * s["out"])


def cumulative() -> float:
    if not LEDGER.exists():
        return 0.0
    return sum(json.loads(l)["cost_usd"]
               for l in LEDGER.read_text().splitlines() if l.strip())


def append_ledger(rec: dict):
    PHASE_DIR.mkdir(parents=True, exist_ok=True)
    with open(LEDGER, "a") as f:
        f.write(json.dumps(rec) + "\n")


def run_one(args, all_truth, scored, label, arm, chunked, use_graph) -> dict:
    """One paid scan -> a run dict (eval.run_single shape) + cost."""
    run = E.run_single(
        Path(args.target), Path(args.baseline), all_truth, scored, FUZZ,
        temperature=None, mode=args.baseline_mode, arm=arm,
        dedupe=True, chunked=chunked, window=args.window_lines,
        use_graph=use_graph)
    run["cost_usd"] = usd(run.get("usage", {}))
    return run


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True,
                    choices=["autopsy", "chunked-nograph", "raw"])
    ap.add_argument("--target", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--baseline", default=str(_BENCH / "baseline"))
    ap.add_argument("--baseline-mode", default="whole-file",
                    choices=["safe", "whole-file"])
    ap.add_argument("--chunked", action="store_true")
    ap.add_argument("--window-lines", type=int, default=400)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--cap", type=float, default=7.50)
    ap.add_argument("--est-unit", type=float, default=None,
                    help="estimated USD per run for the pre-run cap check")
    ap.add_argument("--label", default=None, help="output label (defaults to arm)")
    args = ap.parse_args()

    label = args.label or args.arm
    chunked = args.chunked or args.arm == "chunked-nograph"
    use_graph = args.arm not in ("chunked-nograph", "raw")
    # raw arm: arm passed to run_single must be "raw"; chunked arms -> "autopsy".
    inner_arm = "raw" if args.arm == "raw" else "autopsy"

    all_truth, scored = E.load_ground_truth(Path(args.ground_truth))

    runs = []
    for i in range(args.repeat):
        cum = cumulative()
        remaining = args.cap - cum
        est = args.est_unit if args.est_unit is not None else 0.0
        if args.est_unit is not None and remaining - est < 0.30:
            print(f"[STOP] remaining ${remaining:.2f} - est ${est:.2f} < $0.30 "
                  f"buffer; skipping {label} run {i+1}.")
            break
        print(f"\n=== {label} run {i+1}/{args.repeat} "
              f"(cumulative ${cum:.2f}/{args.cap:.2f}) ===")
        t0 = time.time()
        run = run_one(args, all_truth, scored, label, inner_arm, chunked, use_graph)
        cost = run["cost_usd"]
        append_ledger({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "phase": "2", "label": label, "arm": args.arm, "run_index": i,
            "target": args.target, "chunked": chunked, "use_graph": use_graph,
            "recall": round(run["metrics"]["recall"], 4),
            "tp": run["counts"]["tp"], "fp": run["counts"]["fp"],
            "total_findings": run["counts"]["total_findings"],
            "matched_ids": run["matched_ids"], "missed_ids": run["missed_ids"],
            "usage": run.get("usage", {}), "cost_usd": round(cost, 4),
            "scan_time_s": run["scan_time_seconds"],
        })
        new_cum = cumulative()
        print(f"  recall={run['metrics']['recall']*100:.0f}% "
              f"tp={run['counts']['tp']} findings={run['counts']['total_findings']} "
              f"time={run['scan_time_seconds']}s")
        print(f"LEDGER: this run ${cost:.4f}, cumulative ${new_cum:.4f} of ${args.cap:.2f}")
        runs.append(run)

    if not runs:
        print("no runs completed.")
        return

    # Write an eval.summarize-compatible aggregate for Part 3 tooling.
    sargs = SimpleNamespace(
        demo=args.target, baseline=args.baseline,
        baseline_mode=args.baseline_mode, no_dedupe=False, chunked=chunked,
        window_lines=args.window_lines, fuzz_lines=FUZZ, repeat=len(runs),
        include_provisional=False, no_graph=not use_graph, arm=label)
    summary = E.summarize(runs, sargs, scored, all_truth,
                          "temperature: model default (no knob)", arm=label)
    summary["cost_usd_total"] = round(sum(r["cost_usd"] for r in runs), 4)
    summary["cost_usd_per_run"] = round(
        statistics.mean(r["cost_usd"] for r in runs), 4)
    summary["finding_counts"] = [r["counts"]["total_findings"] for r in runs]
    PHASE_DIR.mkdir(parents=True, exist_ok=True)
    out = PHASE_DIR / f"eval_{label}_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps(summary, indent=2))
    print(f"\nwrote {out}")
    print(f"arm {label}: recall mean {summary['aggregate']['recall']['mean_pct']}% "
          f"std {summary['aggregate']['recall']['std_pct']}pp; "
          f"mean findings {statistics.mean(summary['finding_counts']):.1f}; "
          f"${summary['cost_usd_per_run']:.4f}/run")


if __name__ == "__main__":
    main()
