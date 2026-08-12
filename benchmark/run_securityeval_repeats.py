"""Phase 3 (Aug 2026 replication) — additional full SecurityEval LLM passes.

Config-identical to `eval_securityeval.py --autopsy-llm`: it calls that module's
own `run_autopsy_llm()` on the same subset (`Testcases_Insecure_Code`, 121 files),
which is the entire LLM-touching path of the original pass. Nothing about the
scan, the model, the chunking, or the detection criterion is redefined here.

What this adds, per the addendum, is *recording*: the original script only prints
an aggregate percentage, so the per-file hit list needed for the union/intersection
across the N=3 set is captured to JSON. The token-free SAST baselines
(deterministic layer / Semgrep / Bandit) are deliberately not re-run — they are
deterministic and unchanged, and they are not part of what N=3 is measuring.

Usage:
  python benchmark/run_securityeval_repeats.py --repeats 2 --cap 5.00
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

import eval_securityeval as SE  # noqa: E402
from autopsy.llm.client import reset_usage, get_usage  # noqa: E402

PRICES = {
    "claude-haiku-4-5-20251001":  {"in": 1.00, "out": 5.00},
    "claude-sonnet-4-5-20250929": {"in": 3.00, "out": 15.00},
}
OUT = _ROOT / "benchmark" / "results" / "securityeval_aug2026"


def usd(u: dict) -> float:
    h, s = PRICES["claude-haiku-4-5-20251001"], PRICES["claude-sonnet-4-5-20250929"]
    return (u.get("haiku_in", 0) / 1e6 * h["in"] + u.get("haiku_out", 0) / 1e6 * h["out"]
            + u.get("sonnet_in", 0) / 1e6 * s["in"] + u.get("sonnet_out", 0) / 1e6 * s["out"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--securityeval", type=Path, default=Path("/tmp/SecurityEval"))
    ap.add_argument("--subset", default="Testcases_Insecure_Code")
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--cap", type=float, default=5.00)
    ap.add_argument("--est-unit", type=float, default=1.85)
    ap.add_argument("--start-index", type=int, default=2,
                    help="label offset; the originally reported pass is run 1")
    args = ap.parse_args()

    # .resolve() matters: SE._all_files() resolves symlinks, and on macOS /tmp is a
    # symlink to /private/tmp. An unresolved target makes the later relative_to()
    # raise AFTER the whole paid pass has run.
    target = (args.securityeval / args.subset).resolve()
    all_files = SE._all_files(target)
    print(f"SecurityEval subset: {args.subset} ({len(all_files)} vulnerable files)")
    OUT.mkdir(parents=True, exist_ok=True)

    spend = 0.0
    for n in range(args.repeats):
        label = args.start_index + n
        if spend + args.est_unit > args.cap:
            print(f"[STOP] would breach ${args.cap:.2f} cap (spent ${spend:.4f}); "
                  f"skipping pass {label}.")
            break
        print(f"\n=== SecurityEval LLM pass {label} "
              f"(spend so far ${spend:.4f}/{args.cap:.2f}) ===")
        reset_usage()
        t0 = time.time()
        hit = SE.run_autopsy_llm(target)
        elapsed = round(time.time() - t0, 1)
        u = get_usage()
        # Crash-insurance: a paid pass costs ~$1.80, so persist the raw result the
        # instant it exists, before any post-processing that could raise.
        (OUT / f"_raw_pass_{label}.json").write_text(json.dumps(
            {"hit_abs": sorted(str(p) for p in hit), "usage": u,
             "target": str(target), "elapsed_s": elapsed}, indent=2))
        cost = usd(u)
        spend += cost
        hit_rel = sorted(p.relative_to(target).as_posix() for p in (hit & all_files))
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "pass_label": f"securityeval_pass_{label}",
            "subset": args.subset,
            "n_files": len(all_files),
            "n_detected": len(hit_rel),
            "recall": round(len(hit_rel) / len(all_files), 4),
            "recall_pct": round(100 * len(hit_rel) / len(all_files)),
            "detected_files": hit_rel,
            "missed_files": sorted(
                p.relative_to(target).as_posix() for p in (all_files - hit)),
            "usage": u,
            "cost_usd": round(cost, 4),
            "scan_time_s": elapsed,
        }
        out = OUT / f"securityeval_pass_{label}.json"
        out.write_text(json.dumps(rec, indent=2))
        print(f"  detected {len(hit_rel)}/{len(all_files)} = {rec['recall_pct']}% "
              f"in {elapsed}s")
        print(f"  tokens: {u.get('sonnet_in',0)+u.get('haiku_in',0)} in / "
              f"{u.get('sonnet_out',0)+u.get('haiku_out',0)} out "
              f"({u.get('calls',0)} calls)")
        print(f"COST: this pass ${cost:.4f} | phase spend ${spend:.4f} of ${args.cap:.2f}")
        print(f"  wrote {out}")

    print(f"\nPhase 3 spend total: ${spend:.4f}")


if __name__ == "__main__":
    main()
