"""Test B: positional mechanism analysis. FREE — no API calls.

Uses the two existing single-prompt (raw) runs on pygoat, scored by the frozen
matcher (matched_ids / missed_ids taken from benchmark/results/phaseA/ledger.jsonl,
cross-checked against the stored findings in eval_raw_20260622_145235.json), and the
ground-truth line numbers. All 11 in-scope vulns are in introduction/views.py (1238 lines).
"""
import json
from pathlib import Path
from statistics import mean

# Repo root, derived from this file's location
# (<root>/benchmark/results/matched_budget/testB_positional.py) so the script runs
# from a fresh clone rather than one hard-coded working copy.
ROOT = Path(__file__).resolve().parents[3]
FILE_TOTAL_LINES = 1238  # introduction/views.py @ 19d17cc, verified with wc -l

gt = json.load(open(ROOT / "benchmark/pygoat/ground_truth_pygoat.json"))
vulns = {v["id"]: v for v in gt["vulnerabilities"]}

# The two existing single-prompt runs, from ledger.jsonl (frozen-matcher output).
raw_runs = []
for line in (ROOT / "benchmark/results/phaseA/ledger.jsonl").read_text().splitlines():
    r = json.loads(line)
    if r.get("arm") == "raw" and r.get("target", "").endswith("introduction"):
        raw_runs.append(r)
raw_runs.sort(key=lambda r: r["ts"])
assert len(raw_runs) == 2, f"expected 2 raw runs, got {len(raw_runs)}"

# Cross-check matched_ids against stored findings via the frozen matcher.
import sys
sys.path.insert(0, str(ROOT / "benchmark"))
sys.path.insert(0, str(ROOT))
import eval as E
all_truth, scored = E.load_ground_truth(ROOT / "benchmark/pygoat/ground_truth_pygoat.json")
scored_ids = {t["id"] for t in scored}
stored = json.load(open(ROOT / "benchmark/results/phaseA/eval_raw_20260622_145235.json"))
for i, run in enumerate(stored["runs"]):
    m = E.match(run["findings"], all_truth, scored_ids, 5)
    assert set(m["matched_scored"]) == set(raw_runs[i]["matched_ids"]), (
        f"run {i} mismatch: {m['matched_scored']} vs {raw_runs[i]['matched_ids']}")
print("cross-check OK: stored findings re-scored == ledger matched_ids\n")

run0_caught = set(raw_runs[0]["matched_ids"])
run1_caught = set(raw_runs[1]["matched_ids"])
union_caught = run0_caught | run1_caught

order = sorted(vulns.values(), key=lambda v: v["line_start"])

rows = []
for v in order:
    vid = v["id"]
    line = v["line_start"]
    depth = line / FILE_TOTAL_LINES
    rows.append({
        "vuln_id": vid,
        "file": v["file"],
        "file_total_lines": FILE_TOTAL_LINES,
        "vuln_line": line,
        "depth_ratio": round(depth, 3),
        "caught_run0": vid in run0_caught,
        "caught_run1": vid in run1_caught,
        "caught_single_union": vid in union_caught,
        "caught_windowed": True,  # windowed arm = 11/11 in both ledger runs
    })

def group_means(rows, key):
    caught = [r for r in rows if r[key]]
    missed = [r for r in rows if not r[key]]
    def summ(g):
        if not g:
            return {"n": 0, "mean_vuln_line": None, "mean_depth_ratio": None,
                    "mean_file_lines": None}
        return {"n": len(g),
                "mean_vuln_line": round(mean(r["vuln_line"] for r in g), 1),
                "mean_depth_ratio": round(mean(r["depth_ratio"] for r in g), 3),
                "mean_file_lines": round(mean(r["file_total_lines"] for r in g), 1)}
    return {"caught": summ(caught), "missed": summ(missed)}

result = {
    "file_total_lines": FILE_TOTAL_LINES,
    "rows": rows,
    "means_run0": group_means(rows, "caught_run0"),
    "means_run1": group_means(rows, "caught_run1"),
    "means_union": group_means(rows, "caught_single_union"),
    "run0_recall": f"{len(run0_caught)}/11",
    "run1_recall": f"{len(run1_caught)}/11",
    "union_recall": f"{len(union_caught)}/11",
}

out = ROOT / "benchmark/results/matched_budget"
out.mkdir(parents=True, exist_ok=True)
(out / "positional_analysis.json").write_text(json.dumps(result, indent=2))

# Pretty print
print(f"{'vuln_id':<28}{'line':>6}{'depth':>7}  r0  r1  union")
for r in rows:
    print(f"{r['vuln_id']:<28}{r['vuln_line']:>6}{r['depth_ratio']:>7}  "
          f"{'Y' if r['caught_run0'] else '.':>2}  {'Y' if r['caught_run1'] else '.':>2}  "
          f"{'Y' if r['caught_single_union'] else '.':>4}")
print()
for lbl, key in [("run0 (7/11)", "means_run0"), ("run1 (8/11)", "means_run1"),
                 ("union (10/11)", "means_union")]:
    g = result[key]
    print(f"{lbl}:")
    print(f"   CAUGHT  n={g['caught']['n']:>2}  mean_line={g['caught']['mean_vuln_line']}  "
          f"mean_depth={g['caught']['mean_depth_ratio']}")
    print(f"   MISSED  n={g['missed']['n']:>2}  mean_line={g['missed']['mean_vuln_line']}  "
          f"mean_depth={g['missed']['mean_depth_ratio']}")
print(f"\nwrote {out/'positional_analysis.json'}")
