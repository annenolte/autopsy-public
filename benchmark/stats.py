"""Significance tests for the Autopsy benchmark (reviewer: statistical rigor).

Pure-Python (no scipy/numpy — not installed on the run host). Runs for FREE on
the JSON that Part 2 writes:

  * McNemar's exact test  — Autopsy vs each SAST baseline on pygoat's 11 paired
                            per-vulnerability outcomes (the correct paired test
                            when the same 11 items are scored by both tools).
  * Fisher's exact test   — a cross-check on the 2x2 caught/missed table.
  * Bootstrap 95% CIs     — for the demo ablation arms' per-run recall (and the
                            arm-vs-arm difference), 10k resamples.

Inputs (all produced for free once the Part 2 runs exist):
  --pygoat-caught   JSON: {"all_ids":[...], "tools":{"autopsy":[caught_ids],
                          "semgrep":[...], "bandit":[...], "codeql":[...]}}
                    Default: benchmark/results/phaseA/pygoat_caught.json
  --demo-arms       one or more eval_<arm>_*.json files (uses
                    aggregate.recall.raw_values per arm). Repeatable.

Usage:
  python benchmark/stats.py \
     --pygoat-caught benchmark/results/phaseA/pygoat_caught.json \
     --demo-arms benchmark/results/phaseA/eval_autopsy_*.json \
                 benchmark/results/phaseA/eval_chunked-nograph_*.json
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import random
from pathlib import Path


# ── McNemar's exact test (paired binary outcomes) ────────────────────────────
def mcnemar_exact(b: int, c: int) -> dict:
    """Exact two-sided McNemar test on the discordant pair counts.

    b = items caught by tool A but NOT B; c = caught by B but NOT A.
    Under H0 each discordant item is a fair coin, so the exact p-value is the
    two-sided binomial tail with n=b+c, p=0.5.
    """
    n = b + c
    if n == 0:
        return {"b": b, "c": c, "n_discordant": 0, "p_value": 1.0,
                "note": "no discordant pairs — tools agree on every item"}
    k = min(b, c)
    # two-sided exact binomial p = 2 * sum_{i=0}^{k} C(n,i) 0.5^n, capped at 1.
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) * (0.5 ** n)
    p = min(1.0, 2.0 * tail)
    return {"b": b, "c": c, "n_discordant": n, "p_value": p}


# ── Fisher's exact test (2x2) ────────────────────────────────────────────────
def fisher_exact(a: int, b: int, c: int, d: int) -> dict:
    """Two-sided Fisher exact p-value for the 2x2 table [[a,b],[c,d]].

    Sums hypergeometric probabilities of all tables (with the same margins) no
    more probable than the observed one.
    """
    row1, row2 = a + b, c + d
    col1, col2 = a + c, b + d
    total = a + b + c + d
    if total == 0:
        return {"table": [[a, b], [c, d]], "p_value": 1.0}

    def hypergeom(x):
        # P(top-left = x) given fixed margins.
        return (math.comb(col1, x) * math.comb(col2, row1 - x)
                / math.comb(total, row1))

    p_obs = hypergeom(a)
    lo = max(0, row1 - col2)
    hi = min(row1, col1)
    p = sum(hypergeom(x) for x in range(lo, hi + 1)
            if hypergeom(x) <= p_obs + 1e-12)
    return {"table": [[a, b], [c, d]], "p_value": min(1.0, p)}


# ── Bootstrap CI ─────────────────────────────────────────────────────────────
def bootstrap_ci(values, n_resamples=10000, alpha=0.05, seed=12345) -> dict:
    """Percentile bootstrap CI for the mean of `values`."""
    if not values:
        return {"n": 0, "mean": None, "ci": [None, None]}
    rng = random.Random(seed)
    k = len(values)
    means = []
    for _ in range(n_resamples):
        sample = [values[rng.randrange(k)] for _ in range(k)]
        means.append(sum(sample) / k)
    means.sort()
    lo = means[int((alpha / 2) * n_resamples)]
    hi = means[min(n_resamples - 1, int((1 - alpha / 2) * n_resamples))]
    return {"n": k, "mean": sum(values) / k, "ci": [lo, hi],
            "n_resamples": n_resamples}


def bootstrap_diff_ci(a_values, b_values, n_resamples=10000, alpha=0.05,
                      seed=999) -> dict:
    """Percentile bootstrap CI for mean(a) - mean(b) (independent resampling)."""
    if not a_values or not b_values:
        return {"diff": None, "ci": [None, None]}
    rng = random.Random(seed)
    ka, kb = len(a_values), len(b_values)
    diffs = []
    for _ in range(n_resamples):
        ma = sum(a_values[rng.randrange(ka)] for _ in range(ka)) / ka
        mb = sum(b_values[rng.randrange(kb)] for _ in range(kb)) / kb
        diffs.append(ma - mb)
    diffs.sort()
    lo = diffs[int((alpha / 2) * n_resamples)]
    hi = diffs[min(n_resamples - 1, int((1 - alpha / 2) * n_resamples))]
    return {"diff": sum(a_values) / ka - sum(b_values) / kb, "ci": [lo, hi],
            "n_resamples": n_resamples}


# ── pygoat paired tests ──────────────────────────────────────────────────────
def paired_pygoat(caught_path: Path) -> dict:
    data = json.loads(Path(caught_path).read_text())
    all_ids = list(data["all_ids"])
    tools = data["tools"]
    autopsy = set(tools["autopsy"])
    out = {"all_ids": all_ids, "n_items": len(all_ids),
           "autopsy_caught": sorted(autopsy), "comparisons": {}}
    print(f"pygoat paired tests over {len(all_ids)} vulnerabilities")
    print(f"  Autopsy caught {len(autopsy)}/{len(all_ids)}: {sorted(autopsy)}\n")
    for name, ids in tools.items():
        if name == "autopsy":
            continue
        base = set(ids)
        # 2x2 over the all_ids universe
        a = sum(1 for i in all_ids if i in autopsy and i in base)      # both
        b = sum(1 for i in all_ids if i in autopsy and i not in base)  # A only
        c = sum(1 for i in all_ids if i not in autopsy and i in base)  # B only
        d = sum(1 for i in all_ids if i not in autopsy and i not in base)
        mc = mcnemar_exact(b, c)
        fi = fisher_exact(a, b, c, d)
        out["comparisons"][name] = {
            "baseline_caught": sorted(base), "table_both_Aonly_Bonly_neither":
            [a, b, c, d], "mcnemar": mc, "fisher": fi}
        sig = "SIGNIFICANT" if mc["p_value"] < 0.05 else "n.s."
        print(f"  Autopsy vs {name}:")
        print(f"    both={a} autopsy_only={b} {name}_only={c} neither={d}")
        print(f"    McNemar exact p = {mc['p_value']:.4f}  ({sig}) "
              f"[discordant b={b}, c={c}]")
        print(f"    Fisher  exact p = {fi['p_value']:.4f}\n")
    return out


# ── demo arm bootstrap ───────────────────────────────────────────────────────
def _recall_values(eval_json: Path):
    d = json.loads(Path(eval_json).read_text())
    arm = d.get("arm") or d.get("config", {}).get("arm", "?")
    vals = d.get("aggregate", {}).get("recall", {}).get("raw_values", [])
    return arm, vals


def demo_bootstrap(arm_files) -> dict:
    arms = {}
    for f in arm_files:
        arm, vals = _recall_values(Path(f))
        arms.setdefault(arm, [])
        arms[arm].extend(vals)
    out = {"arms": {}, "differences": {}}
    print(f"demo-arm bootstrap CIs (10k resamples) over {len(arms)} arm(s)")
    for arm, vals in arms.items():
        ci = bootstrap_ci(vals, 10000)
        out["arms"][arm] = ci
        if ci["mean"] is not None:
            print(f"  {arm:<18} recall mean={ci['mean']*100:.1f}%  "
                  f"95% CI [{ci['ci'][0]*100:.1f}, {ci['ci'][1]*100:.1f}]  "
                  f"(n={ci['n']})")
    names = list(arms)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            dc = bootstrap_diff_ci(arms[a], arms[b], 10000)
            key = f"{a}__minus__{b}"
            out["differences"][key] = dc
            if dc["diff"] is not None:
                inc0 = dc["ci"][0] <= 0 <= dc["ci"][1]
                print(f"  Δ {a} − {b} = {dc['diff']*100:+.1f} pp  "
                      f"95% CI [{dc['ci'][0]*100:+.1f}, {dc['ci'][1]*100:+.1f}]"
                      f"  {'(includes 0 → within noise)' if inc0 else '(excludes 0)'}")
    return out


def main():
    ap = argparse.ArgumentParser(description="Significance tests for Autopsy benchmark")
    ap.add_argument("--pygoat-caught", type=Path,
                    default=Path("benchmark/results/phaseA/pygoat_caught.json"))
    ap.add_argument("--demo-arms", nargs="*", default=[])
    ap.add_argument("--out", type=Path,
                    default=Path("benchmark/results/phaseA/stats.json"))
    args = ap.parse_args()

    result = {}
    if args.pygoat_caught.exists():
        result["pygoat_paired"] = paired_pygoat(args.pygoat_caught)
    else:
        print(f"[skip] pygoat caught file not found: {args.pygoat_caught}")

    arm_files = []
    for pat in args.demo_arms:
        arm_files.extend(sorted(glob.glob(pat)))
    if arm_files:
        print()
        result["demo_bootstrap"] = demo_bootstrap(arm_files)

    if result:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        print(f"\nwrote {args.out}")
    return result


if __name__ == "__main__":
    main()
