"""Phase 4 (Aug 2026) — EXPLORATORY: windowed pygoat with the deep-analysis model swapped.

Pre-registered as exploratory in `benchmark/prereg_addendum_20260811.md`. NOT a
confirmatory result.

The deep-analysis model is the module global `SONNET_MODEL` in
`autopsy/llm/client.py`, read by `stream_sonnet()` at call time. There was no
override flag, so the addendum allows adding `--model`. It is added HERE, on the
experiment branch, rather than by editing the frozen client: rebinding the module
global from the driver is the smallest possible patch and leaves every frozen file
byte-identical.

Everything else is the phaseA `autopsy` arm, unchanged: whole-file baseline mode,
chunked windowing at 400 lines, dependency-graph note ON, frozen dedupe, frozen
matcher at fuzz=5, same ground truth, same target.

Cost accounting note: `_record()` in the client buckets deep-analysis usage under
the `sonnet_*` keys regardless of which model actually served the request. When
--model names a Haiku model, those tokens are therefore priced at HAIKU list rates
here, and the run record states explicitly which model produced them.

Usage:
  python benchmark/run_haiku_deep_exploratory.py --repeat 2 --cap 1.50 \
     --model claude-haiku-4-5-20251001
"""
from __future__ import annotations

import argparse
import json
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
from autopsy.llm import client as LLM  # noqa: E402

PRICES = {
    "claude-haiku-4-5-20251001":  {"in": 1.00, "out": 5.00},
    "claude-sonnet-4-5-20250929": {"in": 3.00, "out": 15.00},
}
FUZZ = 5
OUT = _ROOT / "benchmark" / "results" / "haiku_exploratory"


def usd(usage: dict, deep_model: str, triage_model: str) -> float:
    """Price each bucket at the list rate of the model that actually served it."""
    deep = PRICES[deep_model]
    triage = PRICES[triage_model]
    return (usage.get("sonnet_in", 0) / 1e6 * deep["in"]
            + usage.get("sonnet_out", 0) / 1e6 * deep["out"]
            + usage.get("haiku_in", 0) / 1e6 * triage["in"]
            + usage.get("haiku_out", 0) / 1e6 * triage["out"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True,
                    help="deep-analysis model id; resolve from the API model list")
    ap.add_argument("--target", default="/tmp/pygoat/introduction")
    ap.add_argument("--ground-truth",
                    default=str(_ROOT / "benchmark/pygoat/ground_truth_pygoat.json"))
    ap.add_argument("--baseline", default=str(_BENCH / "baseline"))
    ap.add_argument("--baseline-mode", default="whole-file")
    ap.add_argument("--window-lines", type=int, default=400)
    ap.add_argument("--repeat", type=int, default=2)
    ap.add_argument("--cap", type=float, default=1.50)
    ap.add_argument("--est-unit", type=float, default=0.55)
    args = ap.parse_args()

    if args.model not in PRICES:
        sys.exit(f"No pinned list price for {args.model!r}; add it before running.")

    baseline_deep = LLM.SONNET_MODEL
    triage_model = LLM.HAIKU_MODEL
    # The --model override. stream_sonnet() resolves SONNET_MODEL as a module
    # global at call time, so this redirects the deep-analysis calls only.
    LLM.SONNET_MODEL = args.model
    print(f"[exploratory] deep-analysis model: {baseline_deep} -> {LLM.SONNET_MODEL}")
    print(f"[exploratory] triage model (unchanged): {triage_model}")

    all_truth, scored = E.load_ground_truth(Path(args.ground_truth))
    OUT.mkdir(parents=True, exist_ok=True)

    spend = 0.0
    for i in range(args.repeat):
        if spend + args.est_unit > args.cap:
            print(f"[STOP] would breach ${args.cap:.2f} cap (spent ${spend:.4f}); "
                  f"skipping run {i+1}.")
            break
        print(f"\n=== haiku-deep exploratory run {i+1}/{args.repeat} "
              f"(spend so far ${spend:.4f}/{args.cap:.2f}) ===")
        run = E.run_single(
            Path(args.target), Path(args.baseline), all_truth, scored, FUZZ,
            temperature=None, mode=args.baseline_mode, arm="autopsy",
            dedupe=True, chunked=True, window=args.window_lines, use_graph=True)
        usage = run.get("usage", {})
        cost = usd(usage, args.model, triage_model)
        spend += cost
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "run_label": f"haiku_exploratory_run{i+1}",
            "exploratory": True,
            "deep_analysis_model": args.model,
            "deep_analysis_model_baseline": baseline_deep,
            "triage_model": triage_model,
            "arm": "autopsy (chunked, graph note ON)",
            "recall": round(run["metrics"]["recall"], 4),
            "tp": run["counts"]["tp"], "fp": run["counts"]["fp"],
            "total_findings": run["counts"]["total_findings"],
            "matched_ids": run["matched_ids"], "missed_ids": run["missed_ids"],
            "usage": usage,
            "usage_note": ("sonnet_* keys carry DEEP-ANALYSIS tokens served by "
                           f"{args.model}; priced at that model's list rate."),
            "cost_usd": round(cost, 4),
            "scan_time_s": run["scan_time_seconds"],
            "findings": run["findings"],
        }
        out = OUT / f"haiku_exploratory_run{i+1}.json"
        out.write_text(json.dumps(rec, indent=2))
        print(f"  recall={run['metrics']['recall']*100:.0f}% tp={run['counts']['tp']}/11 "
              f"findings={run['counts']['total_findings']} time={run['scan_time_seconds']}s")
        print(f"  missed={run['missed_ids']}")
        print(f"COST: this run ${cost:.4f} | phase spend ${spend:.4f} of ${args.cap:.2f}")
        print(f"  wrote {out}")

    print(f"\nPhase 4 spend total: ${spend:.4f}")


if __name__ == "__main__":
    main()
