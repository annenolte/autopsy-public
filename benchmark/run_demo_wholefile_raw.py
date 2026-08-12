"""Phase 5 (Aug 2026, conditional) — single-prompt raw arm on demo_project, whole-file.

The paper's demo single-prompt figure is an N=1 run in the `safe` baseline scenario,
while the pygoat single-prompt arm runs in `whole-file`. This adds three whole-file
raw-arm runs on demo_project so the demo comparison is scenario-matched.

Config is the raw arm exactly as `run_phaseA.py --arm raw` builds it (single-prompt
Sonnet over whole files, no windowing, no dependency graph), with
`--baseline-mode whole-file` — the flag verified against run_phaseA's own
`choices=["safe", "whole-file"]`. Frozen dedupe and frozen matcher at fuzz=5.

Usage:
  python benchmark/run_demo_wholefile_raw.py --repeat 3 --cap 1.00
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

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
FUZZ = 5
OUTPUT_CAP = 8192
OUT = _ROOT / "benchmark" / "results" / "demo_wholefile_aug2026"


def usd(u: dict) -> float:
    h, s = PRICES["claude-haiku-4-5-20251001"], PRICES["claude-sonnet-4-5-20250929"]
    return (u.get("haiku_in", 0) / 1e6 * h["in"] + u.get("haiku_out", 0) / 1e6 * h["out"]
            + u.get("sonnet_in", 0) / 1e6 * s["in"] + u.get("sonnet_out", 0) / 1e6 * s["out"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=str(_ROOT / "demo_project"))
    ap.add_argument("--ground-truth", default=str(_BENCH / "ground_truth.json"))
    ap.add_argument("--baseline", default=str(_BENCH / "baseline"))
    ap.add_argument("--baseline-mode", default="whole-file",
                    choices=["safe", "whole-file"])
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--cap", type=float, default=1.00)
    ap.add_argument("--est-unit", type=float, default=0.20)
    args = ap.parse_args()

    all_truth, scored = E.load_ground_truth(Path(args.ground_truth))
    print(f"demo_project ground truth: {len(scored)} scored vulns "
          f"(baseline-mode={args.baseline_mode})")
    OUT.mkdir(parents=True, exist_ok=True)

    spend, recs = 0.0, []
    for i in range(args.repeat):
        if spend + args.est_unit > args.cap:
            print(f"[STOP] would breach ${args.cap:.2f} cap (spent ${spend:.4f}); "
                  f"skipping run {i+1}.")
            break
        print(f"\n=== demo whole-file raw run {i+1}/{args.repeat} "
              f"(spend so far ${spend:.4f}/{args.cap:.2f}) ===")
        run = E.run_single(
            Path(args.target), Path(args.baseline), all_truth, scored, FUZZ,
            temperature=None, mode=args.baseline_mode, arm="raw",
            dedupe=True, chunked=False)
        usage = run.get("usage", {})
        cost = usd(usage)
        spend += cost
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "run_label": f"raw_demo_wholefile_run{i+1}",
            "target": "demo_project", "baseline_mode": args.baseline_mode,
            "arm": "raw (single-prompt, whole files, no graph, no windowing)",
            "recall": round(run["metrics"]["recall"], 4),
            "precision": round(run["metrics"].get("precision", 0.0), 4),
            "f1": round(run["metrics"].get("f1", 0.0), 4),
            "tp": run["counts"]["tp"], "fp": run["counts"]["fp"],
            "total_findings": run["counts"]["total_findings"],
            "n_scored": len(scored),
            "matched_ids": run["matched_ids"], "missed_ids": run["missed_ids"],
            "usage": usage, "cost_usd": round(cost, 4),
            "output_tokens": usage.get("sonnet_out", 0) + usage.get("haiku_out", 0),
            "hit_output_cap_8192": (usage.get("sonnet_out", 0) == OUTPUT_CAP),
            "scan_time_s": run["scan_time_seconds"],
            "findings": run["findings"],
        }
        out = OUT / f"raw_demo_wholefile_run{i+1}.json"
        out.write_text(json.dumps(rec, indent=2))
        recs.append(rec)
        print(f"  recall={rec['recall']*100:.0f}% ({rec['tp']}/{len(scored)}) "
              f"P={rec['precision']*100:.0f}% F1={rec['f1']*100:.0f}% "
              f"findings={rec['total_findings']} time={rec['scan_time_s']}s")
        print(f"  missed={rec['missed_ids']}")
        print(f"COST: this run ${cost:.4f} | phase spend ${spend:.4f} of ${args.cap:.2f}")
        print(f"  wrote {out}")

    if recs:
        r = [x["recall"] for x in recs]
        f = [x["f1"] for x in recs]
        print(f"\nrecall mean {statistics.mean(r)*100:.1f}% "
              f"range [{min(r)*100:.0f}%, {max(r)*100:.0f}%]")
        print(f"F1     mean {statistics.mean(f)*100:.1f}% "
              f"range [{min(f)*100:.0f}%, {max(f)*100:.0f}%]")
    print(f"\nPhase 5 spend total: ${spend:.4f}")


if __name__ == "__main__":
    main()
