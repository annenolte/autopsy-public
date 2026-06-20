"""Baseline comparison: run established SAST tools on the same benchmark.

Addresses reviewer issue #18 ("run Semgrep/CodeQL on the same benchmark") by
running Semgrep and Bandit over a target directory, scoring their findings
against the same ground_truth.json with the same matcher used for Autopsy, and
reporting recall. This is what lets the paper claim — with evidence — whether
Autopsy's architecture adds anything over off-the-shelf static analysis.

Tools are static analyzers (no API tokens). CodeQL is intentionally not run
here: it needs the CodeQL CLI plus a built database, which is a heavy,
environment-specific setup. The exact commands are documented at the bottom so
it can be added; this harness focuses on the two tools that run out of the box.

Two recall numbers are reported per tool, in fairness to the baselines:
  - strict : file basename + (normalized) category + line within fuzz, the same
             rule Autopsy is scored by;
  - location-only : file + line within fuzz, ignoring category — the most
             generous reading ("did the tool flag the vulnerable spot at all?").

Usage:
    python benchmark/compare_tools.py --target demo_project \
        --ground-truth benchmark/ground_truth.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_THIS = Path(__file__).resolve().parent
if str(_THIS) not in sys.path:
    sys.path.insert(0, str(_THIS))

import eval as E  # noqa: E402


def _venv_bin(name: str) -> str:
    """Prefer the tool from this project's venv if present."""
    cand = _THIS.parent / ".venv" / "bin" / name
    return str(cand) if cand.exists() else name


def run_semgrep(target: Path, config: str = "p/python") -> list[dict]:
    """Run Semgrep with the given ruleset config; return findings."""
    proc = subprocess.run(
        [_venv_bin("semgrep"), "scan", f"--config={config}", "--json",
         "--quiet", str(target)],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"[semgrep] could not parse output: {proc.stderr[:300]}", file=sys.stderr)
        return []
    findings = []
    for r in data.get("results", []):
        check = r.get("check_id", "")
        meta = r.get("extra", {}).get("metadata", {})
        cwe = " ".join(meta.get("cwe", []) if isinstance(meta.get("cwe"), list)
                       else [str(meta.get("cwe", ""))])
        cat = f"{check} {cwe} {r.get('extra', {}).get('message', '')}"
        findings.append({
            "category": cat,
            "title": check.split(".")[-1],
            "locations": [{"file": r.get("path", ""), "line": r.get("start", {}).get("line", 0)}],
        })
    return findings


def run_bandit(target: Path) -> list[dict]:
    """Run Bandit (Python security linter); return findings."""
    proc = subprocess.run(
        [_venv_bin("bandit"), "-q", "-r", "-f", "json", str(target)],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(proc.stdout[proc.stdout.find("{"):])  # strip progress-bar prefix
    except json.JSONDecodeError:
        print(f"[bandit] could not parse output: {proc.stderr[:300]}", file=sys.stderr)
        return []
    findings = []
    for r in data.get("results", []):
        cat = f"{r.get('test_id','')} {r.get('test_name','')} {r.get('issue_text','')}"
        findings.append({
            "category": cat,
            "title": r.get("test_name", ""),
            "locations": [{"file": r.get("filename", ""), "line": r.get("line_number", 0)}],
        })
    return findings


def _location_only_recall(findings, scored, fuzz):
    """Recall ignoring category: a truth is hit if any finding is in-file within fuzz."""
    hit = 0
    for t in scored:
        tb = Path(t["file"]).name.lower()
        ok = any(
            Path(loc["file"]).name.lower() == tb
            and E._line_distance(loc["line"], t["line_start"], t["line_end"]) <= fuzz
            for f in findings for loc in f["locations"]
        )
        hit += 1 if ok else 0
    return hit


def score(tool_name, findings, all_truth, scored, fuzz):
    findings = E.dedupe_findings(findings)
    sids = {t["id"] for t in scored}
    m = E.match(findings, all_truth, sids, fuzz)
    loc_hits = _location_only_recall(findings, scored, fuzz)
    n = len(scored)
    print(f"\n[{tool_name}] {len(findings)} findings")
    print(f"   strict recall (file+category+line): {m['tp']}/{n} = {round(100*m['tp']/n)}%")
    print(f"   location-only recall (file+line)  : {loc_hits}/{n} = {round(100*loc_hits/n)}%")
    print(f"   caught (strict): {sorted(m['matched_scored'])}")
    return {"tool": tool_name, "n_findings": len(findings),
            "strict_tp": m["tp"], "loc_tp": loc_hits, "n_truth": n,
            "caught": sorted(m["matched_scored"])}


def main():
    p = argparse.ArgumentParser(description="Run SAST baselines against a benchmark")
    p.add_argument("--target", type=Path, required=True, help="Source directory to scan")
    p.add_argument("--ground-truth", type=Path, default=E.GROUND_TRUTH_PATH)
    p.add_argument("--fuzz-lines", type=int, default=5)
    p.add_argument("--tools", default="semgrep,bandit",
                   help="Comma-separated subset of: semgrep,bandit")
    p.add_argument("--semgrep-config", default="p/python",
                   help="Semgrep ruleset (e.g. p/python, p/default for JS/TS)")
    args = p.parse_args()

    all_truth, scored = E.load_ground_truth(args.ground_truth)
    print(f"target       : {args.target}")
    print(f"ground truth : {len(scored)} in-scope vulns")

    runners = {
        "semgrep": lambda t: run_semgrep(t, args.semgrep_config),
        "bandit": run_bandit,
    }
    results = []
    for tool in [t.strip() for t in args.tools.split(",") if t.strip()]:
        if tool not in runners:
            print(f"[skip] unknown tool {tool}")
            continue
        results.append(score(tool, runners[tool](args.target), all_truth, scored, args.fuzz_lines))
    return results


if __name__ == "__main__":
    main()

# ── CodeQL (not run here; documented for completeness) ─────────────────────────
# CodeQL needs the CLI + a built database:
#   codeql database create cqdb --language=python --source-root=<target>
#   codeql database analyze cqdb codeql/python-queries \
#       --format=sarifv2.1.0 --output=codeql.sarif
# then parse codeql.sarif results[].locations[].physicalLocation for file:line
# and map ruleId -> category, scoring with the same matcher as above.
