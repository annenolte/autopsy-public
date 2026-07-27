"""Evaluate on the SecurityEval established benchmark (reviewer #2).

SecurityEval (MSR4P&S '22) is a published dataset of 121 CWE-labeled vulnerable
Python files (69 CWEs). Each file is vulnerable by construction, so per-file
**detection rate** (fraction of files where a tool reports at least one finding)
is the recall on a real, third-party, established benchmark.

This runs the token-free tools now — Autopsy's deterministic layer, Semgrep,
Bandit — and reports detection rate. The full Autopsy LLM scan over these files
needs API tokens and is staged (command at the bottom).

    python benchmark/eval_securityeval.py --securityeval /tmp/SecurityEval
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from autopsy.detection.static_rules import detect_static_rules
from autopsy.detection.ignored_returns import detect_ignored_security_returns

_VENV = Path(__file__).resolve().parent.parent / ".venv" / "bin"


def _bin(name):
    p = _VENV / name
    return str(p) if p.exists() else name


def _all_files(d: Path):
    return {p.resolve() for p in d.rglob("*.py")}


def detection_rate(label, hit_files, all_files):
    n = len(all_files)
    h = len(hit_files & all_files)
    print(f"  {label:<28} {h}/{n} = {round(100*h/n)}%")
    return h, n


def run_autopsy_llm(target: Path, scan_fn=None):
    """Run Autopsy's chunked LLM scan on each file individually; return the set of
    files (resolved paths) whose own scan produced at least one finding.

    Scanning per-file avoids ambiguity: SecurityEval reuses filenames across CWE
    folders, so mapping pooled findings back to files by name is unreliable.
    scan_fn is injectable for an offline (no-API) dry run.
    """
    import sys as _sys
    _b = str(Path(__file__).resolve().parent)
    if _b not in _sys.path:
        _sys.path.insert(0, _b)
    import eval as E
    from autopsy.parser import parse_directory
    from autopsy.graph.builder import build_dependency_graph
    from autopsy.llm.chunking import scan_stream_chunked

    graph = build_dependency_graph(parse_directory(target))
    rels = [p.relative_to(target).as_posix() for p in sorted(target.rglob("*.py"))]
    hit = set()
    for rel in rels:
        out = "".join(scan_stream_chunked(graph, "", [rel], root_dir=target,
                                          scan_fn=scan_fn))
        if E.parse_findings(out):
            hit.add((target / rel).resolve())
    return hit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--securityeval", type=Path, default=Path("/tmp/SecurityEval"))
    ap.add_argument("--subset", default="Testcases_Insecure_Code")
    ap.add_argument("--autopsy-llm", action="store_true",
                    help="Also run Autopsy's chunked LLM scan (COSTS API tokens)")
    args = ap.parse_args()
    target = args.securityeval / args.subset
    files = _all_files(target)
    print(f"SecurityEval subset: {args.subset}  ({len(files)} vulnerable files)\n")
    print("Per-file detection rate (each file is vulnerable -> this is recall):")

    # Autopsy deterministic layer (token-free)
    det = detect_static_rules(target) + detect_ignored_security_returns(target)
    det_files = {(target / f["caller_file"]).resolve() for f in det if "caller_file" in f}
    # caller_file is relative to target root; re-resolve robustly by basename match
    det_files = set()
    by_name = {p.name: p for p in files}
    for f in det:
        nm = Path(f.get("caller_file", "")).name
        if nm in by_name:
            det_files.add(by_name[nm])
    detection_rate("Autopsy deterministic layer", det_files, files)

    # Semgrep (token-free)
    try:
        proc = subprocess.run([_bin("semgrep"), "scan", "--config=p/python",
                               "--json", "--quiet", str(target)],
                              capture_output=True, text=True)
        sg = {Path(r["path"]).resolve() for r in json.loads(proc.stdout).get("results", [])}
        detection_rate("Semgrep (p/python)", sg, files)
    except Exception as e:
        print(f"  Semgrep failed: {e}")

    # Bandit (token-free)
    try:
        proc = subprocess.run([_bin("bandit"), "-q", "-r", "-f", "json", str(target)],
                              capture_output=True, text=True)
        out = proc.stdout[proc.stdout.find("{"):]  # strip any progress-bar prefix
        bd = {Path(r["filename"]).resolve() for r in json.loads(out).get("results", [])}
        detection_rate("Bandit", bd, files)
    except Exception as e:
        print(f"  Bandit failed: {e}")

    if args.autopsy_llm:
        try:
            from autopsy.llm.client import reset_usage, get_usage
            reset_usage()
        except Exception:
            get_usage = None
        hit = run_autopsy_llm(target)
        detection_rate("Autopsy (LLM, chunked)", hit, files)
        if get_usage:
            u = get_usage()
            tin = u.get("haiku_in", 0) + u.get("sonnet_in", 0)
            tout = u.get("haiku_out", 0) + u.get("sonnet_out", 0)
            print(f"  tokens used: {tin} in / {tout} out  ({u.get('calls',0)} calls)")
    else:
        print("\n[staged, needs API tokens] Autopsy full LLM scan: pass --autopsy-llm")


if __name__ == "__main__":
    main()
