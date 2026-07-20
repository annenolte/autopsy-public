"""Score CodeQL SARIF output with the SAME frozen matcher as Semgrep/Bandit.

This is the CodeQL analogue of `benchmark/compare_tools.py`. It does NOT run
CodeQL (that is a separate, heavy step — see `run_codeql.sh` / the report); it
takes the SARIF files CodeQL already produced, converts them with
`codeql_sarif_adapter.sarif_to_findings`, and scores them through
`benchmark/eval.py` exactly as the other static baselines are scored:

  * pygoat / demo_project / typescript -> recall under the frozen matcher
      - strict       : file basename + normalized category + line within ±5
      - location-only: file basename + line within ±5, ignoring category
    plus per-category recall (pygoat), reusing E.dedupe_findings + E.match.
  * SecurityEval -> file-level detection rate (fraction of the 121 vulnerable
    files with >=1 CodeQL finding), computed exactly as eval_securityeval.py
    does for Semgrep/Bandit (by resolved absolute path).

No new matching logic is introduced; the strict/loc-only helpers are lifted
verbatim from compare_tools.py so CodeQL and Semgrep/Bandit go through identical
code. Matched/unmatched lists are written under results/codeql/ for transparency.

Usage:
    python benchmark/run_codeql_baseline.py            # score everything found
    python benchmark/run_codeql_baseline.py --only pygoat
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
from codeql_sarif_adapter import sarif_to_findings, query_pack_versions  # noqa: E402

_REPO = _THIS.parent
_RESULTS = _REPO / "results" / "codeql"

# Per-benchmark wiring. source_root is where CodeQL's database was built (so
# SARIF relative URIs resolve to real files); ground_truth is the same file the
# other tools are scored against.
BENCH = {
    "pygoat": {
        "sarif": _RESULTS / "pygoat.sarif",
        "ground_truth": _THIS / "pygoat" / "ground_truth_pygoat.json",
        "source_root": Path("/tmp/pygoat"),
        "kind": "matcher",  # strict + loc-only + per-category
    },
    "demo_project": {
        "sarif": _RESULTS / "demo_project.sarif",
        "ground_truth": _THIS / "ground_truth.json",
        "source_root": _REPO / "demo_project",
        "kind": "matcher",
    },
    "typescript": {
        "sarif": _RESULTS / "typescript.sarif",
        "ground_truth": _THIS / "js_demo" / "ground_truth_js.json",
        "source_root": _THIS / "js_demo",
        "kind": "matcher",
    },
    "securityeval": {
        "sarif": _RESULTS / "securityeval.sarif",
        "source_root": Path("/tmp/SecurityEval/Testcases_Insecure_Code"),
        "kind": "file_level",
    },
}


# ── strict / location-only helpers (verbatim from compare_tools.py) ───────────
def _location_only_recall(findings, scored, fuzz):
    """Recall ignoring category: a truth is hit if any finding is in-file within fuzz."""
    hits = []
    for t in scored:
        tb = Path(t["file"]).name.lower()
        ok = any(
            Path(loc["file"]).name.lower() == tb
            and E._line_distance(loc["line"], t["line_start"], t["line_end"]) <= fuzz
            for f in findings for loc in f["locations"]
        )
        if ok:
            hits.append(t["id"])
    return hits


def score_matcher(name, cfg, fuzz):
    """Strict + location-only recall (+ per-category) via the frozen matcher."""
    all_truth, scored = E.load_ground_truth(cfg["ground_truth"])
    raw = sarif_to_findings(cfg["sarif"], cfg["source_root"])
    findings = E.dedupe_findings(raw)
    sids = {t["id"] for t in scored}
    m = E.match(findings, all_truth, sids, fuzz)
    loc_hits = _location_only_recall(findings, scored, fuzz)
    n = len(scored)

    # per-category recall (mirrors per_category.py)
    by_cat = defaultdict(list)
    for t in scored:
        by_cat[t["category"]].append(t["id"])
    matched = set(m["matched_scored"])
    per_cat = {}
    for cat in sorted(by_cat):
        ids = by_cat[cat]
        per_cat[cat] = {
            "recall_n": sum(1 for tid in ids if tid in matched),
            "total": len(ids),
            "ids": ids,
            "caught": [tid for tid in ids if tid in matched],
        }

    res = {
        "benchmark": name,
        "kind": "matcher",
        "n_truth": n,
        "n_findings_raw": len(raw),
        "n_findings_deduped": len(findings),
        "strict_tp": m["tp"],
        "strict_recall_pct": round(100 * m["tp"] / n) if n else 0,
        "loc_tp": len(loc_hits),
        "loc_recall_pct": round(100 * len(loc_hits) / n) if n else 0,
        "caught_strict": sorted(matched),
        "caught_loc_only": sorted(loc_hits),
        "missed_strict": sorted(sids - matched),
        "missed_loc_only": sorted(sids - set(loc_hits)),
        "per_category": per_cat,
        "pack_versions": query_pack_versions(cfg["sarif"]),
    }
    print(f"\n[{name}] {len(raw)} raw -> {len(findings)} deduped CodeQL findings, "
          f"{n} in-scope vulns")
    print(f"   strict recall (file+category+line): {m['tp']}/{n} = {res['strict_recall_pct']}%")
    print(f"   location-only recall (file+line)  : {len(loc_hits)}/{n} = {res['loc_recall_pct']}%")
    print(f"   caught (strict): {sorted(matched)}")
    print("   per-category (strict):")
    for cat, d in per_cat.items():
        print(f"      {cat:<26} {d['recall_n']}/{d['total']}  caught={d['caught']}")
    return res


def score_file_level(name, cfg):
    """SecurityEval-style detection rate (fraction of files with >=1 finding).

    Identical metric to eval_securityeval.py's Semgrep/Bandit scoring: resolve
    each finding's file to an absolute path and count distinct hit files over the
    full vulnerable-file set.
    """
    root = cfg["source_root"].resolve()  # resolve symlinks (/tmp -> /private/tmp on macOS)
    all_files = {p.resolve() for p in root.rglob("*.py")}
    raw = sarif_to_findings(cfg["sarif"], root)
    hit_files = set()
    for f in raw:
        for loc in f["locations"]:
            ap = loc.get("abspath")
            if ap:
                hit_files.add(Path(ap).resolve())
    detected = hit_files & all_files
    n = len(all_files)
    h = len(detected)
    res = {
        "benchmark": name,
        "kind": "file_level",
        "n_files": n,
        "n_findings": len(raw),
        "detected": h,
        "recall_pct": round(100 * h / n) if n else 0,
        "detected_files": sorted(str(p.relative_to(root)) for p in detected),
        "missed_files": sorted(str(p.relative_to(root)) for p in (all_files - detected)),
        "pack_versions": query_pack_versions(cfg["sarif"]),
    }
    print(f"\n[{name}] {len(raw)} CodeQL findings over {n} vulnerable files")
    print(f"   file-level detection (recall): {h}/{n} = {res['recall_pct']}%")
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="score a single benchmark")
    ap.add_argument("--fuzz-lines", type=int, default=5)
    ap.add_argument("--out", type=Path, default=_RESULTS / "scores.json")
    args = ap.parse_args()

    targets = [args.only] if args.only else list(BENCH)
    out = {}
    for name in targets:
        cfg = BENCH[name]
        if not cfg["sarif"].exists():
            print(f"[skip] {name}: missing SARIF {cfg['sarif']}")
            continue
        if cfg["kind"] == "matcher":
            res = score_matcher(name, cfg, args.fuzz_lines)
        else:
            res = score_file_level(name, cfg)
        out[name] = res
        (_RESULTS / f"{name}_scored.json").write_text(json.dumps(res, indent=2))

    args.out.write_text(json.dumps(out, indent=2))
    print(f"\nwrote {args.out}")
    return out


if __name__ == "__main__":
    main()
