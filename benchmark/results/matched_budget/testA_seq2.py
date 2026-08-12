"""Test A, sequence 2: INDEPENDENT matched-budget pooled single-prompt baseline.

Identical to testA_runner.py except for (a) the output paths and (b) the pooled
set: this pools ONLY the five NEW runs produced by this script, in chronological
order. The original sequence's runs and artifacts are not read and not touched.

Runs the raw (single-prompt, whole-file, no graph, no windowing) arm N times via the
UNMODIFIED eval.run_single, saving each run's parsed findings. Then pools k=1..5 runs
(the new ones, chronological order), dedupes with the frozen dedupe_findings, and
scores each union once with the frozen match(). Hard stop at $2.50 of NEW spend.

Usage: python testA_seq2.py --new-runs 5 --cap 2.50
"""
import argparse, json, sys, time
from pathlib import Path

# Repo root, derived from this file's location
# (<root>/benchmark/results/matched_budget/testA_seq2.py) so the script runs from
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
OUTPUT_CAP = 8192  # autopsy.llm.client scan max_tokens; recorded, not enforced here

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new-runs", type=int, default=5)
    ap.add_argument("--cap", type=float, default=2.50)
    ap.add_argument("--start-index", type=int, default=1,
                    help="1-based index of the first run to execute; used to resume "
                         "the sequence after a failure (see §6 retry rule)")
    args = ap.parse_args()

    all_truth, scored = E.load_ground_truth(GT)
    scored_ids = {t["id"] for t in scored}

    new_spend = 0.0
    new_runs = []
    for i in range(args.start_index - 1, args.new_runs):
        # pre-run cap check (~$0.34/run expected)
        if new_spend + 0.40 > args.cap:
            print(f"[STOP] would breach ${args.cap:.2f} cap (spent ${new_spend:.4f}); "
                  f"skipping run {i+1}.")
            break
        print(f"\n=== SEQ2 single-prompt run {i+1}/{args.new_runs} "
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
        usage = run.get("usage", {})
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "run_label": f"seq2_{i+1}", "attempts": attempt,
            "recall": round(run["metrics"]["recall"], 4),
            "tp": run["counts"]["tp"], "fp": run["counts"]["fp"],
            "total_findings": run["counts"]["total_findings"],
            "matched_ids": run["matched_ids"], "missed_ids": run["missed_ids"],
            "usage": usage, "cost_usd": round(cost, 4),
            "output_tokens": usage.get("sonnet_out", 0) + usage.get("haiku_out", 0),
            "hit_output_cap_8192": (usage.get("sonnet_out", 0) == OUTPUT_CAP),
            "scan_time_s": run["scan_time_seconds"],
            "findings": run["findings"],
        }
        (OUT / f"raw_seq2_run_{i+1}.json").write_text(json.dumps(rec, indent=2))
        new_runs.append(rec)
        print(f"  recall={run['metrics']['recall']*100:.0f}% tp={run['counts']['tp']} "
              f"findings={run['counts']['total_findings']} time={run['scan_time_seconds']}s "
              f"out_tokens={rec['output_tokens']} cap_hit={rec['hit_output_cap_8192']}")
        print(f"COST: this run ${cost:.4f} | NEW spend ${new_spend:.4f} of ${args.cap:.2f}")

    # ---- Pool ONLY this sequence's runs (chronological). Sequence 1 is not read.
    # Read back from disk by run index so a resumed sequence pools all of its runs,
    # not just the ones this process executed. Files named *_FAILED_* are ignored.
    ordered = []
    for n in range(1, args.new_runs + 1):
        p = OUT / f"raw_seq2_run_{n}.json"
        if p.exists():
            ordered.append(json.load(open(p)))
    print(f"\n=== POOLING {len(ordered)} single-prompt runs (seq2, chronological) ===")

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
            "cumulative_cost_usd": round(sum(x["cost_usd"] for x in ordered[:k]), 4),
            "matched_ids": sorted(m["matched_scored"]),
            "missed_ids": sorted(scored_ids - set(m["matched_scored"])),
        })
        print(f"  k={k}: union deduped findings={len(deduped):>3}  recall={recall}/11  "
              f"missed={sorted(scored_ids - set(m['matched_scored']))}")

    total_new_cost = round(new_spend, 4)
    pooled_cost = round(sum(r["cost_usd"] for r in ordered), 4)
    summary = {
        "sequence": "seq2 (independent replication of Test A pooling)",
        "runs_pooled": len(ordered),
        "new_runs": [{k: v for k, v in r.items() if k != "findings"} for r in ordered],
        "this_process_spend_usd": total_new_cost,
        "new_spend_usd": pooled_cost,
        "pooled_5run_total_cost_usd": pooled_cost,
        "curve": curve,
        "windowed_ref": {"runs": 1, "cost_usd": 1.1261, "findings": 112, "recall": "11/11"},
        "retry_disclosure": (
            "Runs 4 and 5 failed on their first attempt with HTTP 400 "
            "(credit balance exhausted) and were retried once, as allowed by "
            "preregistration_matched_budget.md §6. The failed first attempts are "
            "preserved as raw_seq2_run_{4,5}_FAILED_attempt1.json. No run was "
            "retried for any reason other than an API error."),
    }
    (OUT / "pooling_summary_seq2.json").write_text(json.dumps(summary, indent=2))
    print(f"\nNEW spend total: ${total_new_cost:.4f}")
    print(f"5-run pooled total cost (seq2 only): ${total_new_cost:.4f}")
    print(f"wrote {OUT/'pooling_summary_seq2.json'}")

if __name__ == "__main__":
    main()
