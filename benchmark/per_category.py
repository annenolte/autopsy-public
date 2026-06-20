"""Per-category recall breakdown for a saved eval run (reviewer #13).

The harness reports overall TP/FP/FN; the reviewer wants to see whether the tool
is strong on some categories (e.g. SQLi) and weak on others (e.g. weak crypto).
This re-scores a saved results JSON's raw output against a ground truth and
breaks recall down by category. Offline, no API.

    python benchmark/per_category.py --results benchmark/results/eval_autopsy_X.json \
        --ground-truth benchmark/pygoat/ground_truth_pygoat.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

_THIS = Path(__file__).resolve().parent
if str(_THIS) not in sys.path:
    sys.path.insert(0, str(_THIS))

import eval as E  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--results", type=Path, required=True)
    p.add_argument("--ground-truth", type=Path, required=True)
    p.add_argument("--fuzz-lines", type=int, default=5)
    args = p.parse_args()

    all_truth, scored = E.load_ground_truth(args.ground_truth)
    by_cat_truth = defaultdict(list)
    for t in scored:
        by_cat_truth[t["category"]].append(t["id"])

    d = json.loads(args.results.read_text())
    runs = d.get("runs", [])
    sids = {t["id"] for t in scored}

    # Aggregate caught-IDs across runs: a category-vuln counts as caught if it
    # was matched in any run (and we also report per-run consistency).
    caught_counts = defaultdict(int)
    for run in runs:
        findings = E.dedupe_findings(E.parse_findings(run["raw_output"]))
        m = E.match(findings, all_truth, sids, args.fuzz_lines)
        for tid in m["matched_scored"]:
            caught_counts[tid] += 1

    n_runs = len(runs)
    print(f"per-category recall over {n_runs} run(s) — {args.results.name}\n")
    print(f"{'category':<26}{'recall':>8}   detail (id: runs-caught/N)")
    for cat in sorted(by_cat_truth):
        ids = by_cat_truth[cat]
        # category recall = mean over its vulns of (caught in any run)
        any_caught = sum(1 for tid in ids if caught_counts[tid] > 0)
        print(f"{cat:<26}{any_caught}/{len(ids):<6}", end="   ")
        print(", ".join(f"{tid}:{caught_counts[tid]}/{n_runs}" for tid in ids))


if __name__ == "__main__":
    main()
