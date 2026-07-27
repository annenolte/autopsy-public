"""Test A: matched-budget pooled single-prompt baseline.

Runs the raw (single-prompt, whole-file, no graph, no windowing) arm N times via the
UNMODIFIED eval.run_single, saving each run's parsed findings. Then pools k=1..5 runs
(2 existing on disk + the new ones, chronological order), dedupes with the frozen
dedupe_findings, and scores each union once with the frozen match(). Hard stop at $3
of NEW spend.

Usage: python testA_runner.py --new-runs 3 --cap 3.00
"""
import argparse, json, sys, time
from pathlib import Path

# Repo root, derived from this file's location
# (<root>/benchmark/results/matched_budget/testA_runner.py) so the script runs from
# a fresh clone rather than one hard-coded working copy.
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "benchmark"))
sys.path.insert(0, str(ROOT))
from dotenv import load_dotenv
load_dotenv(ROOT / ".env")
import eval as E

PRICES = {"claude-sonnet-4-5-20250929": {"in": 3.00, "out": 15.00},
          "claude-haiku-4-5-20251001": {"in": 1.00, "out": 5.00}}

def usd(u):
    s, h = PRICES["claude-sonnet-4-5-20250929"], PRICES["claude-haiku-4-5-20251001"]
    return (u.get("sonnet_in", 0)/1e6*s["in"] + u.get("sonnet_out", 0)/1e6*s["out"]
            + u.get("haiku_in", 0)/1e6*h["in"] + u.get("haiku_out", 0)/1e6*h["out"])

TARGET = "/tmp/pygoat/introduction"
BASELINE = str(ROOT / "benchmark" / "baseline")
GT = ROOT / "benchmark/pygoat/ground_truth_pygoat.json"
FUZZ = 5
OUT = ROOT / "benchmark/results/matched_budget"
OUT.mkdir(parents=True, exist_ok=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new-runs", type=int, default=3)
    ap.add_argument("--cap", type=float, default=3.00)
    args = ap.parse_args()

    all_truth, scored = E.load_ground_truth(GT)
    scored_ids = {t["id"] for t in scored}

    new_spend = 0.0
    new_runs = []
    for i in range(args.new_runs):
        # pre-run cap check (~$0.34/run expected)
        if new_spend + 0.40 > args.cap:
            print(f"[STOP] would breach ${args.cap:.2f} cap (spent ${new_spend:.4f}); "
                  f"skipping run {i+1}.")
            break
        print(f"\n=== NEW single-prompt run {i+1}/{args.new_runs} "
              f"(new spend so far ${new_spend:.4f}/{args.cap:.2f}) ===")
        attempt, run = 0, None
        while attempt < 2:
            attempt += 1
            try:
                run = E.run_single(
                    Path(TARGET), Path(BASELINE), all_truth, scored, FUZZ,
                    temperature=None, mode="whole-file", arm="raw",
                    dedupe=True, chunked=False)
                break
            except Exception as e:
                print(f"  [run {i+1} attempt {attempt}] ERROR: {e!r}")
                if attempt >= 2:
                    raise
                print("  retrying once...")
                time.sleep(3)
        cost = usd(run.get("usage", {}))
        if attempt > 1:
            run["_retried"] = True
        new_spend += cost
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "run_label": f"new_{i+1}", "attempts": attempt,
            "recall": round(run["metrics"]["recall"], 4),
            "tp": run["counts"]["tp"], "fp": run["counts"]["fp"],
            "total_findings": run["counts"]["total_findings"],
            "matched_ids": run["matched_ids"], "missed_ids": run["missed_ids"],
            "usage": run.get("usage", {}), "cost_usd": round(cost, 4),
            "scan_time_s": run["scan_time_seconds"],
            "findings": run["findings"],
        }
        (OUT / f"raw_new_run_{i+1}.json").write_text(json.dumps(rec, indent=2))
        new_runs.append(rec)
        print(f"  recall={run['metrics']['recall']*100:.0f}% tp={run['counts']['tp']} "
              f"findings={run['counts']['total_findings']} time={run['scan_time_seconds']}s")
        print(f"COST: this run ${cost:.4f} | NEW spend ${new_spend:.4f} of ${args.cap:.2f}")

    # ---- Load the 2 existing runs' findings (chronological) ----
    stored = json.load(open(ROOT / "benchmark/results/phaseA/eval_raw_20260622_145235.json"))
    existing = []
    for i, r in enumerate(stored["runs"]):
        existing.append({"run_label": f"existing_{i}", "findings": r["findings"],
                         "total_findings": len(r["findings"])})

    # Chronological pool: existing_0, existing_1, new_1, new_2, new_3
    ordered = existing + new_runs
    print(f"\n=== POOLING {len(ordered)} single-prompt runs (chronological) ===")

    curve = []
    pooled = []
    for k, r in enumerate(ordered, start=1):
        pooled = pooled + r["findings"]                 # union of first k runs' findings
        deduped = E.dedupe_findings(pooled)             # frozen dedup rule (window=3)
        m = E.match(deduped, all_truth, scored_ids, FUZZ)  # frozen matcher, fuzz=5
        recall = len(m["matched_scored"])
        curve.append({
            "k": k, "runs_included": [x["run_label"] for x in ordered[:k]],
            "cumulative_findings_deduped": len(deduped),
            "recall": recall, "recall_str": f"{recall}/11",
            "matched_ids": sorted(m["matched_scored"]),
            "missed_ids": sorted(scored_ids - set(m["matched_scored"])),
        })
        print(f"  k={k}: union deduped findings={len(deduped):>3}  recall={recall}/11  "
              f"missed={sorted(scored_ids - set(m['matched_scored']))}")

    total_new_cost = round(new_spend, 4)
    # 5-run pooled cost = 2 existing (~0.339+0.338) + new
    existing_cost = 0.3389 + 0.3379
    summary = {
        "new_runs": [{k: v for k, v in r.items() if k != "findings"} for r in new_runs],
        "new_spend_usd": total_new_cost,
        "existing_runs_cost_usd": round(existing_cost, 4),
        "pooled_5run_total_cost_usd": round(existing_cost + total_new_cost, 4),
        "curve": curve,
        "windowed_ref": {"runs": 1, "cost_usd": 1.1261, "findings": 112, "recall": "11/11"},
    }
    (OUT / "pooling_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nNEW spend total: ${total_new_cost:.4f}")
    print(f"5-run pooled total cost (2 existing + new): "
          f"${existing_cost + total_new_cost:.4f}")
    print(f"wrote {OUT/'pooling_summary.json'}")

if __name__ == "__main__":
    main()
