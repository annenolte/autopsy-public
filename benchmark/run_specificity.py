"""Specificity on clean code: scan a target with Autopsy and count how many
vulnerability findings it emits (ideally ~0 on audited/safe code). Also reports
false-vulns-per-KLOC. Uses the same cost ledger as run_phaseA.

Usage:
  python benchmark/run_specificity.py --target benchmark/heldout/safe --label heldout-safe
  python benchmark/run_specificity.py --target /tmp/requests-src --label requests --cap 7.50 --est-unit 0.40
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
from run_phaseA import usd, cumulative, append_ledger, PHASE_DIR  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--window-lines", type=int, default=400)
    ap.add_argument("--cap", type=float, default=7.50)
    ap.add_argument("--est-unit", type=float, default=None)
    args = ap.parse_args()

    target = Path(args.target)
    rels = sorted(p.relative_to(target).as_posix()
                  for p in target.rglob("*")
                  if p.suffix in (".py", ".js", ".ts", ".tsx", ".jsx") and p.is_file())
    loc = E.count_loc(target)

    cum = cumulative()
    remaining = args.cap - cum
    if args.est_unit is not None and remaining - args.est_unit < 0.30:
        print(f"[STOP] remaining ${remaining:.2f} - est ${args.est_unit:.2f} < $0.30; "
              f"skipping {args.label}.")
        return

    from autopsy.parser import parse_directory
    from autopsy.graph.builder import build_dependency_graph
    from autopsy.llm.chunking import scan_stream_chunked
    from autopsy.llm.client import reset_usage, get_usage

    print(f"=== specificity: {args.label} ({len(rels)} files, {loc} LOC) "
          f"(cumulative ${cum:.2f}/{args.cap:.2f}) ===")
    reset_usage()
    graph = build_dependency_graph(parse_directory(target))
    t0 = time.time()
    out = "".join(scan_stream_chunked(graph, "", rels, root_dir=target,
                                      window_lines=args.window_lines))
    elapsed = time.time() - t0
    findings = E.dedupe_findings(E.parse_findings(out))
    usage = get_usage()
    cost = usd(usage)

    fp_per_kloc = round(len(findings) / (loc / 1000.0), 2) if loc else 0.0
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "phase": "2C-specificity",
        "label": args.label, "target": str(target), "files_scanned": len(rels),
        "loc_scanned": loc, "n_findings": len(findings),
        "false_vulns_per_kloc": fp_per_kloc,
        "finding_titles": [f["title"] for f in findings],
        "usage": usage, "cost_usd": round(cost, 4), "scan_time_s": round(elapsed, 1),
    }
    append_ledger(rec)
    PHASE_DIR.mkdir(parents=True, exist_ok=True)
    (PHASE_DIR / f"specificity_{args.label}.json").write_text(json.dumps(rec, indent=2))
    print(f"  findings={len(findings)}  false-vulns/KLOC={fp_per_kloc}  "
          f"files={len(rels)} loc={loc}")
    for f in findings:
        locs = ",".join(f"{Path(l['file']).name}:{l['line']}" for l in f["locations"])
        print(f"    - {f['title']!r} [{f['category']}] @ {locs}")
    print(f"LEDGER: this run ${cost:.4f}, cumulative ${cumulative():.4f} of ${args.cap:.2f}")


if __name__ == "__main__":
    main()
