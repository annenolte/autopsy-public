"""Autopsy evaluation harness (frozen benchmark).

Measures precision / recall / F1 of Autopsy's `scan_stream` against the planted
vulnerabilities in demo_project/, recorded in benchmark/ground_truth.json.

Pipeline (mirrors the production `autopsy scan` path):
  1. benchmark/make_diff.py builds a throwaway git repo with two commits —
     the clean baseline (benchmark/baseline/) then the vulnerable demo project —
     and emits the baseline->vulnerable unified diff.
  2. We parse the vulnerable working tree and build the dependency graph with
     the same parser/graph code the CLI uses.
  3. We invoke scan_stream(graph, diff, changed_files, root_dir=repo).
  4. Streamed findings are parsed using the severity-header format from
     autopsy/llm/prompts.py (## [SEVERITY: ...]).
  5. Findings are matched one-to-one to ground_truth.json: same file basename
     AND matching (normalized) category AND reported line within +/- fuzz lines
     (default 5) of the labeled range; ties broken by smallest line distance.
  6. Precision / recall / F1 are computed and written to
     benchmark/results/eval_<timestamp>.json.

This evolved from eval/eval.py (commit "Add eval harness..."). Changes: loads
ground truth from JSON, uses a real safe baseline (not empty stubs), gates
matches on category, defaults fuzz to 5 (--fuzz-lines to loosen), supports
--repeat for mean/std, rounds reported percentages to whole numbers, and runs
end-to-end offline (graph + diff + matcher wiring) when no API key is present —
without fabricating metric values.

Model IDs are whatever autopsy/llm/client.py defines
(claude-haiku-4-5-20251001 triage, claude-sonnet-4-20250514 analysis); this
harness does not change them.

Usage:
    export ANTHROPIC_API_KEY=sk-...
    python benchmark/eval.py                 # one live run, default fuzz=5
    python benchmark/eval.py --repeat 5       # 5 runs, report mean +/- std
    python benchmark/eval.py --fuzz-lines 25  # looser legacy matching
    python benchmark/eval.py --dry-run        # offline: graph+diff+wiring only
    python benchmark/eval.py --include-provisional   # also score provisional GT
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

import networkx as nx
from rich.console import Console
from rich.table import Table

# Make `import make_diff` work no matter the current working directory, and make
# `import autopsy` resolve to THIS repo rather than to whatever tree an editable
# install happens to point at (running `python benchmark/eval.py` puts only the
# script's own directory on sys.path, so without _REPO_ROOT the import silently
# falls through to site-packages).
_THIS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _THIS_DIR.parent
for _p in (str(_THIS_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from make_diff import make_diff  # noqa: E402

console = Console()

GROUND_TRUTH_PATH = _THIS_DIR / "ground_truth.json"
DEFAULT_DEMO = _REPO_ROOT / "demo_project"
DEFAULT_BASELINE = _THIS_DIR / "baseline"
RESULTS_DIR = _THIS_DIR / "results"

DEFAULT_FUZZ_LINES = 5  # +/- lines a reported location may be off and still match


# ─── Ground truth ─────────────────────────────────────────────────────────────

def load_ground_truth(
    path: Path = GROUND_TRUTH_PATH, include_provisional: bool = False
) -> tuple[list[dict], list[dict]]:
    """Load ground truth.

    Returns (all_truth, scored_truth):
      - all_truth: every entry, including provisional ones (used for matching so
        a genuine-but-unconfirmed detection is not mislabeled as a false
        positive).
      - scored_truth: the entries that count toward precision/recall. Provisional
        entries are excluded unless include_provisional is True.
    """
    data = json.loads(Path(path).read_text())
    entries = data["vulnerabilities"]
    all_truth = []
    for e in entries:
        all_truth.append({
            "id": e["id"],
            "file": e["file"],
            "category": e["category"],
            "line_start": int(e["line_start"]),
            "line_end": int(e["line_end"]),
            # accepted_categories: the category label(s) a finding may carry and
            # still match this entry. Defaults to [category]; an entry may list
            # more than one when the planted vulnerability genuinely spans
            # categories (e.g. an unauthenticated arbitrary-SQL endpoint is both
            # SQLi and Auth Bypass). It never widens the line/file gate.
            "accepted_categories": list(
                e.get("accepted_categories", [e["category"]])
            ),
            "provisional": bool(e.get("provisional", False)),
            "description": e.get("description", ""),
        })
    scored = [
        t for t in all_truth if include_provisional or not t["provisional"]
    ]
    return all_truth, scored


# ─── Category normalization ─────────────────────────────────────────────────
# Ground truth stores authoritative human labels (SQLi / Auth Bypass /
# Weak Crypto). The scanner emits its own category strings from prompts.py
# (SQLi / Auth Bypass / Secrets Exposure / ...). We normalize both sides to a
# small set of canonical tokens before comparing, so e.g. "Weak Crypto" matches
# the tool's "Secrets Exposure" / "weak password hashing" wording.

_CATEGORY_RULES = [
    # Order does not matter: category_tokens() returns the set of ALL matching
    # tokens, and a match needs only a non-empty overlap. Keep needles specific
    # so distinct injection classes don't collapse into one another (e.g.
    # "command injection" must NOT read as SQL).
    ("sql", ("sql injection", "sqli", "sql")),
    ("command", ("command injection", "os command", "shell injection",
                 "command execution", "rce")),
    ("codeexec", ("code injection", "arbitrary code", "code execution",
                  "eval(", "remote code")),
    ("deserial", ("deserial", "pickle", "unsafe yaml", "yaml.load",
                  "insecure deserialization", "object injection")),
    # Generic umbrella token: the LLM often labels a specific injection bug just
    # "Injection". This token lets such a label bridge to any injection-family
    # ground-truth category (see categories_match) without collapsing the
    # specific classes into each other.
    ("injection", ("injection",)),
    ("auth", ("auth", "authz", "authn", "permission", "access control",
              "privilege", "authoriz")),
    ("crypto", ("crypto", "secret", "weak hash", "md5", "sha1",
                "password storage", "weak cipher")),
    ("xxe", ("xxe", "xml external", "external entit")),
    ("ssti", ("ssti", "template injection", "server-side template")),
    ("ssrf", ("ssrf", "server-side request")),
    ("xss", ("xss", "cross-site script")),
    ("path", ("path traversal", "directory traversal")),
    ("race", ("race condition",)),
]


def category_tokens(raw: str) -> set[str]:
    """All canonical tokens a free-text category string maps to.

    Returns a set (not a single token) so a dual-labeled finding like
    "SQLi / Auth Bypass" matches an SQLi *or* an Auth Bypass entry.
    """
    s = (raw or "").lower()
    return {token for token, needles in _CATEGORY_RULES if any(n in s for n in needles)}


_INJECTION_FAMILY = {"sql", "command", "codeexec", "deserial", "xxe", "ssti"}


def categories_match(finding_category: str, accepted: list[str]) -> bool:
    """True if the finding's category overlaps any accepted ground-truth category.

    A generic "injection" label on one side bridges to any specific
    injection-family class on the other (e.g. the model reporting a pickle bug as
    "Injection" still matches a "Insecure Deserialization" ground-truth entry).
    The specific classes do not bridge to each other — only via the generic
    token — so e.g. SQLi and command injection stay distinct.
    """
    f = category_tokens(finding_category)
    a = set().union(*(category_tokens(c) for c in accepted)) if accepted else set()
    if f & a:
        return True
    if "injection" in f and (a & _INJECTION_FAMILY):
        return True
    if "injection" in a and (f & _INJECTION_FAMILY):
        return True
    return False


# ─── Finding parser ─────────────────────────────────────────────────────────

def parse_findings(output: str) -> list[dict]:
    """Parse Autopsy's streaming markdown into structured findings.

    Expected per-finding block (from prompts.py SCAN_SYSTEM):
        ## [SEVERITY: CRITICAL] Title
        **Category:** SQLi
        **Location:** `file.py:42`
        ...
        ---
    """
    findings: list[dict] = []
    blocks = re.split(r'(?=##\s*\[SEVERITY:)', output, flags=re.IGNORECASE)
    blocks = [b for b in blocks if b.strip()]

    severity_count = len(re.findall(r'##\s*\[SEVERITY:', output, re.IGNORECASE))
    if len(blocks) <= 1 and severity_count > 1:
        blocks = re.findall(
            r'(##\s*\[SEVERITY:.*?)(?=##\s*\[SEVERITY:|\Z)',
            output, flags=re.IGNORECASE | re.DOTALL,
        )

    for block in blocks:
        sev_match = re.search(
            r'##\s*\[SEVERITY:\s*(\w+)\]\s*(.+)', block, re.IGNORECASE
        )
        if not sev_match:
            continue
        severity = sev_match.group(1).upper()
        title = sev_match.group(2).strip()

        cat_match = re.search(r'\*\*Category:\*\*\s*(.+)', block, re.IGNORECASE)
        category = cat_match.group(1).strip() if cat_match else ""

        locations = []
        for f, ln in re.findall(
            r'\*\*Location:\*\*\s*`?([^\n:`]+):(\d+)', block, re.IGNORECASE
        ):
            locations.append({"file": f.strip(), "line": int(ln)})
        for f, ln in re.findall(r'([\w/._-]+\.(?:py|js|ts|tsx)):(\d+)', block):
            entry = {"file": f.strip(), "line": int(ln)}
            if entry not in locations:
                locations.append(entry)

        findings.append({
            "severity": severity,
            "title": title,
            "category": category,
            "locations": locations,
            "raw": block[:500],
        })

    return findings


# ─── Matching ─────────────────────────────────────────────────────────────────

def _line_distance(line: int, t_start: int, t_end: int) -> int:
    if line < t_start:
        return t_start - line
    if line > t_end:
        return line - t_end
    return 0


def finding_truth_distance(
    finding: dict, truth: dict, fuzz: int
) -> Optional[int]:
    """Smallest in-file line distance within fuzz, or None if no qualifying loc."""
    tb = Path(truth["file"]).name.lower()
    best: Optional[int] = None
    for loc in finding["locations"]:
        if Path(loc["file"]).name.lower() != tb:
            continue
        d = _line_distance(loc["line"], truth["line_start"], truth["line_end"])
        if d <= fuzz and (best is None or d < best):
            best = d
    return best


def match(
    findings: list[dict], all_truth: list[dict], scored_ids: set[str], fuzz: int
) -> dict:
    """One-to-one match findings -> truth (gated on category + file + line).

    Matching uses ALL truth entries (provisional included). Scoring (TP/FP/FN)
    uses only scored_ids; a finding matched solely to a provisional entry is set
    aside (neither TP nor FP) so an unconfirmed-but-real detection neither
    inflates recall nor deflates precision.
    """
    truth_by_id = {t["id"]: t for t in all_truth}

    # Build candidate (finding, truth) pairs that pass the category gate.
    candidates = []  # (distance, finding_idx, truth_order, truth_id)
    for fi, finding in enumerate(findings):
        for ti, truth in enumerate(all_truth):
            if not categories_match(finding["category"], truth["accepted_categories"]):
                continue
            d = finding_truth_distance(finding, truth, fuzz)
            if d is not None:
                candidates.append((d, fi, ti, truth["id"]))

    candidates.sort(key=lambda c: (c[0], c[1], c[2]))

    matched_truth: dict[str, int] = {}   # truth_id -> finding_idx
    matched_findings: dict[int, str] = {}  # finding_idx -> truth_id
    for d, fi, _ti, tid in candidates:
        if tid in matched_truth or fi in matched_findings:
            continue
        matched_truth[tid] = fi
        matched_findings[fi] = tid

    matched_scored = {tid for tid in matched_truth if tid in scored_ids}
    matched_provisional = {tid for tid in matched_truth if tid not in scored_ids}

    tp = len(matched_scored)
    fn = len(scored_ids) - tp

    # False positives: findings matched to nothing. Findings matched only to a
    # provisional entry are excluded from the FP pool.
    fp_indices = [
        fi for fi in range(len(findings))
        if fi not in matched_findings
    ]
    provisional_finding_indices = [
        fi for fi, tid in matched_findings.items() if tid not in scored_ids
    ]
    fp = len(fp_indices)

    # Diagnostics: findings that hit a truth's file+line but with a mismatched
    # category (these remain false positives, but explain "near misses").
    category_mismatches = []
    for fi in fp_indices:
        f = findings[fi]
        for t in all_truth:
            if finding_truth_distance(f, t, fuzz) is not None and \
               not categories_match(f["category"], t["accepted_categories"]):
                category_mismatches.append({
                    "finding_index": fi,
                    "finding_title": f["title"],
                    "finding_category": f["category"],
                    "truth_id": t["id"],
                    "truth_category": t["category"],
                })
                break

    return {
        "matched_truth": matched_truth,
        "matched_findings": matched_findings,
        "matched_scored": sorted(matched_scored),
        "matched_provisional": sorted(matched_provisional),
        "missed_ids": sorted(scored_ids - matched_scored),
        "fp_indices": fp_indices,
        "provisional_finding_indices": sorted(provisional_finding_indices),
        "category_mismatches": category_mismatches,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "truth_by_id": truth_by_id,
    }


def metrics_from_counts(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return {"precision": precision, "recall": recall, "f1": f1}


def _pct(x: float) -> int:
    """Round a 0..1 fraction to a whole-number percentage."""
    return round(x * 100)


def dedupe_findings(findings: list[dict], window: int = 3) -> list[dict]:
    """Collapse findings that describe the same vulnerability.

    Two findings are duplicates when their categories overlap (after
    normalization) and each has a location in the same file within `window`
    lines of the other. This happens because the deterministic layer emits a
    finding and the LLM occasionally re-reports the same one despite being told
    not to. Counting one real issue twice as two false positives is a
    measurement artifact, not a real precision loss — so we merge them before
    scoring. The window is intentionally tight (default 3) so genuinely distinct
    nearby findings (e.g. execute_query vs execute_read) are NOT merged.
    """
    kept: list[dict] = []
    for f in findings:
        f_tokens = category_tokens(f["category"])
        is_dup = False
        for k in kept:
            if not (f_tokens & category_tokens(k["category"])):
                continue
            for lf in f["locations"]:
                for lk in k["locations"]:
                    if (Path(lf["file"]).name.lower() == Path(lk["file"]).name.lower()
                            and abs(lf["line"] - lk["line"]) <= window):
                        is_dup = True
                        break
                if is_dup:
                    break
            if is_dup:
                break
        if not is_dup:
            kept.append(f)
    return kept


# ─── Scan invocation ─────────────────────────────────────────────────────────

def _import_autopsy():
    try:
        from autopsy.parser import parse_directory
        from autopsy.graph.builder import build_dependency_graph
        from autopsy.llm.pipeline import scan_stream
    except ImportError as e:
        console.print(f"[red]Import error: {e}[/red]")
        console.print("Run from the autopsy repo root with autopsy installed (pip install -e .).")
        sys.exit(1)
    return parse_directory, build_dependency_graph, scan_stream


def _resolve_temperature(scan_stream) -> tuple[Optional[float], str]:
    """Set temperature=0 only if the scan path actually exposes the knob.

    The current client (autopsy/llm/client.py) does not accept a temperature
    argument, and threading one through scan_stream would alter the tool's
    detection path — which this benchmark must not do. So this returns
    (None, note) today and would return (0.0, ...) automatically if a
    `temperature` parameter is ever added to scan_stream.
    """
    if "temperature" in inspect.signature(scan_stream).parameters:
        return 0.0, "temperature=0 (scan_stream supports it)"
    return None, ("temperature not configurable in the current client; using "
                  "model default (results vary slightly across runs)")


def count_loc(demo_dir: Path) -> int:
    """Total source lines of the scan target (.py/.js/.ts/.tsx). For #14 cost/time
    normalization."""
    exts = (".py", ".js", ".ts", ".tsx")
    total = 0
    for p in Path(demo_dir).rglob("*"):
        if p.suffix in exts and p.is_file():
            total += len(p.read_text(errors="replace").splitlines())
    return total


def build_graph_and_diff(demo_dir: Path, baseline_dir: Path, repo_dir: Path,
                         mode: str = "safe"):
    """Build the eval repo, dependency graph, and diff. Returns (graph, diff, changed)."""
    parse_directory, build_dependency_graph, _ = _import_autopsy()
    diff_text, changed_files = make_diff(baseline_dir, demo_dir, repo_dir, mode=mode)
    parsed = parse_directory(repo_dir)
    graph = build_dependency_graph(parsed)
    return graph, diff_text, changed_files


def run_scan(graph, diff_text, changed_files, repo_dir, temperature,
             chunked=False, window=400, use_triage=True, use_graph=True,
             graph_mode="note"):
    """Invoke the scan and return the concatenated streamed output + elapsed.

    chunked=True uses the map-reduce scanner (windows every file so large files
    aren't truncated); otherwise the single-shot scan_stream.
    use_triage=False skips the Haiku triage step (sonnet-only arm, #16).
    use_graph=False (chunked only) passes graph=None to scan_stream_chunked,
    which disables the cross-file `_graph_neighbors_note` while keeping identical
    windowing + the deterministic layer — the single-variable graph ablation.
    """
    t0 = time.time()
    chunks = []
    if chunked:
        from autopsy.llm.chunking import scan_stream_chunked
        stream = scan_stream_chunked(graph if use_graph else None,
                                     diff_text, changed_files,
                                     root_dir=repo_dir, window_lines=window,
                                     graph_mode=graph_mode)
    else:
        _, _, scan_stream = _import_autopsy()
        kwargs = {}
        if temperature is not None:
            kwargs["temperature"] = temperature
        stream = scan_stream(graph, diff_text, changed_files, root_dir=repo_dir,
                             use_triage=use_triage, **kwargs)
    for chunk in stream:
        chunks.append(chunk)
        console.print(chunk, end="", highlight=False)
    return "".join(chunks), time.time() - t0


def run_raw_llm_scan(repo_dir, diff_text, changed_files, temperature):
    """Ablation baseline: ask Sonnet directly, with NO graph machinery.

    This is the control for "does Autopsy's dependency graph / triage / blast
    radius actually help?". It uses the *same* analysis model and the *same*
    SCAN_SYSTEM prompt as Autopsy, and is handed the same raw material (full
    source of the changed files + the diff) — but none of the graph-derived
    context (no dependency summary, no triage, no blast radius). Findings are
    parsed and matched identically, so any score difference is attributable to
    the graph pipeline, not to the model or the scorer.
    """
    from autopsy.llm.client import stream_sonnet
    from autopsy.llm.prompts import SCAN_SYSTEM

    repo_dir = Path(repo_dir)
    _exts = (".py", ".js", ".ts", ".tsx", ".jsx")
    parts = ["## Source Files\n"]
    for p in sorted(q for q in repo_dir.rglob("*") if q.suffix in _exts and q.is_file()):
        rel = p.relative_to(repo_dir)
        parts.append(f"### {rel}\n```\n{p.read_text(errors='replace')}\n```\n")
    parts.append(f"\n## Git Diff\n```diff\n{diff_text}\n```")
    user_msg = (
        "\n".join(parts)
        + "\n\n## Task\nAnalyze the git diff for security vulnerabilities. "
        "Report each finding using the ## [SEVERITY: ...] format above."
    )
    # stream_sonnet exposes no temperature knob today (see _resolve_temperature);
    # the parameter is accepted for symmetry and forwarded only if supported.
    if temperature is not None and "temperature" in inspect.signature(stream_sonnet).parameters:
        gen = stream_sonnet(SCAN_SYSTEM, user_msg, temperature=temperature)
    else:
        gen = stream_sonnet(SCAN_SYSTEM, user_msg)
    t0 = time.time()
    chunks = []
    for chunk in gen:
        chunks.append(chunk)
        console.print(chunk, end="", highlight=False)
    return "".join(chunks), time.time() - t0


# ─── Single run ────────────────────────────────────────────────────────────────

def run_single(
    demo_dir: Path, baseline_dir: Path, all_truth, scored, fuzz, temperature,
    mode="safe", arm="autopsy", dedupe=True, chunked=False, window=400,
    use_graph=True
) -> dict:
    """Run one scan with the given arm ('autopsy' = full pipeline, 'raw' = no graph).

    use_graph=False (only meaningful with chunked=True) runs the same windowed
    scan but with the dependency-graph cross-file note disabled — the Part 2
    graph ablation (chunked-nograph arm).
    """
    scored_ids = {t["id"] for t in scored}
    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = Path(tmp) / "eval_repo"
        graph, diff_text, changed_files = build_graph_and_diff(
            demo_dir, baseline_dir, repo_dir, mode=mode
        )
        console.print(
            f"  [{arm}] Graph: {graph.number_of_nodes()} nodes, "
            f"{graph.number_of_edges()} edges | "
            f"Diff: {len(diff_text.splitlines())} lines, "
            f"{len(changed_files)} changed files"
        )
        try:
            from autopsy.llm.client import reset_usage, get_usage
            reset_usage()
        except Exception:
            get_usage = None
        if arm == "raw":
            output, elapsed = run_raw_llm_scan(repo_dir, diff_text, changed_files, temperature)
        else:
            # "sonnet-only" = full graph pipeline but no Haiku triage (#16)
            output, elapsed = run_scan(graph, diff_text, changed_files, repo_dir,
                                       temperature, chunked=chunked, window=window,
                                       use_triage=(arm != "sonnet-only"),
                                       use_graph=use_graph)
        usage = get_usage() if get_usage else {}

    findings = parse_findings(output)
    if dedupe:
        findings = dedupe_findings(findings)
    m = match(findings, all_truth, scored_ids, fuzz)
    metrics = metrics_from_counts(m["tp"], m["fp"], m["fn"])

    loc = count_loc(demo_dir)
    n_scored = len(scored) or 1
    total_tokens = sum(v for k, v in usage.items() if k.endswith(("_in", "_out")))

    return {
        "arm": arm,
        "metrics": metrics,
        "counts": {"tp": m["tp"], "fp": m["fp"], "fn": m["fn"],
                   "total_findings": len(findings)},
        "usage": usage,
        "tokens_per_kloc": round(total_tokens / (loc / 1000)) if loc else 0,
        "target_loc": loc,
        "scan_time_per_kloc": round(elapsed / (loc / 1000), 1) if loc else 0,
        "scan_time_per_vuln": round(elapsed / n_scored, 1),
        "matched_ids": m["matched_scored"],
        "missed_ids": m["missed_ids"],
        "provisional_matched_ids": m["matched_provisional"],
        "category_mismatches": m["category_mismatches"],
        "scan_time_seconds": round(elapsed, 1),
        "findings": findings,
        "raw_output": output,
        "_match": m,
    }


def print_run_report(run: dict, fuzz: int):
    m = run["_match"]
    c = run["counts"]
    metrics = run["metrics"]

    table = Table(title="Autopsy Eval Results", show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("True Positives", str(c["tp"]))
    table.add_row("False Negatives (missed)", str(c["fn"]))
    table.add_row("False Positives (noise)", str(c["fp"]))
    table.add_row("Total Findings", str(c["total_findings"]))
    if run["provisional_matched_ids"]:
        table.add_row("Provisional matches (uncounted)",
                      str(len(run["provisional_matched_ids"])))
    table.add_row("─" * 22, "─" * 8)
    table.add_row("Precision", f"{_pct(metrics['precision'])}%")
    table.add_row("Recall", f"{_pct(metrics['recall'])}%")
    table.add_row("F1 Score", f"{_pct(metrics['f1'])}%")
    table.add_row("Scan Time", f"{run['scan_time_seconds']}s")
    table.add_row("Target LOC", str(run.get("target_loc", 0)))
    table.add_row("Time / KLOC", f"{run.get('scan_time_per_kloc', 0)}s")
    table.add_row("Time / vuln", f"{run.get('scan_time_per_vuln', 0)}s")
    u = run.get("usage") or {}
    if u:
        tin = u.get("haiku_in", 0) + u.get("sonnet_in", 0)
        tout = u.get("haiku_out", 0) + u.get("sonnet_out", 0)
        table.add_row("Tokens (in/out)", f"{tin}/{tout}")
        table.add_row("Tokens / KLOC", str(run.get("tokens_per_kloc", 0)))
    table.add_row("Fuzz (+/- lines)", str(fuzz))
    console.print(table)

    if run["matched_ids"]:
        console.print("\n[green]True positives:[/green] " + ", ".join(run["matched_ids"]))
    if run["provisional_matched_ids"]:
        console.print("[cyan]Provisional matches (not scored):[/cyan] "
                      + ", ".join(run["provisional_matched_ids"]))
    if run["missed_ids"]:
        console.print("\n[yellow]False negatives (missed):[/yellow]")
        for tid in run["missed_ids"]:
            t = m["truth_by_id"][tid]
            console.print(f"  - [{tid}] {t['description']} ({t['file']}:{t['line_start']}-{t['line_end']})")
    if m["fp_indices"]:
        console.print("\n[red]False positives:[/red]")
        for fi in m["fp_indices"]:
            f = run["findings"][fi]
            locs = ", ".join(f"{Path(l['file']).name}:{l['line']}" for l in f["locations"]) or "(no loc)"
            console.print(f"  - {f['title']!r} [{f['category'] or 'no category'}] @ {locs}")
    if run["category_mismatches"]:
        console.print("\n[yellow]Category mismatches (file+line hit, category differed):[/yellow]")
        for cm in run["category_mismatches"]:
            console.print(
                f"  - finding {cm['finding_title']!r} category="
                f"[magenta]{cm['finding_category'] or '(none)'}[/magenta] vs "
                f"truth [bold]{cm['truth_id']}[/bold] category=[cyan]{cm['truth_category']}[/cyan]"
            )


# ─── Orchestration ─────────────────────────────────────────────────────────────

def run_eval(args):
    all_truth, scored = load_ground_truth(
        args.ground_truth, include_provisional=args.include_provisional
    )
    parse_directory, build_dependency_graph, scan_stream = _import_autopsy()
    temperature, temp_note = _resolve_temperature(scan_stream)

    console.rule("[bold]Autopsy Evaluation Harness[/bold]")
    console.print(f"Demo project   : {args.demo}")
    console.print(f"Baseline       : {args.baseline}")
    console.print(f"Baseline mode  : {args.baseline_mode}")
    console.print(f"Ground truth   : {len(scored)} scored "
                  f"({len(all_truth) - len(scored)} provisional excluded)")
    console.print(f"Fuzz lines     : {args.fuzz_lines}")
    console.print(f"Temperature    : {temp_note}")
    if args.arm == "both":
        arms = ["autopsy", "raw"]
    elif args.arm == "all":
        arms = ["autopsy", "sonnet-only", "raw"]
    elif args.arm == "graph-ablation":
        # Part 2 core experiment: graph-on vs graph-off (both chunked) vs raw.
        arms = ["autopsy", "chunked-nograph", "raw"]
    else:
        arms = [args.arm]
    if args.no_graph and not (args.chunked or "chunked-nograph" in arms):
        console.print("[yellow]--no-graph is only honored with --chunked "
                      "(or the chunked-nograph arm); ignoring it.[/yellow]")
    console.print(f"Arm(s)         : {', '.join(arms)} "
                  f"(autopsy=graph+Haiku+Sonnet, sonnet-only=graph+Sonnet no triage, "
                  f"raw=Sonnet no graph, chunked-nograph=chunked windows, graph note OFF)")
    console.print(f"Repeat         : {args.repeat}\n")

    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    offline = args.dry_run or not has_key
    if offline and not args.dry_run:
        console.print("[yellow]ANTHROPIC_API_KEY not set — running offline "
                      "(graph + diff + matcher wiring only, no metrics).[/yellow]\n")

    if offline:
        return run_offline(args, all_truth, scored)

    # ── Live run(s) ── one paired iteration per repeat, each arm on its own repo
    runs_by_arm: dict[str, list] = {a: [] for a in arms}
    for i in range(args.repeat):
        for arm in arms:
            if args.repeat > 1 or len(arms) > 1:
                console.rule(f"[bold]Run {i + 1}/{args.repeat} — arm: {arm}[/bold]")
            # A transient API/network error in one run should not discard the
            # whole batch. Retry once, then skip just that run and continue so
            # the remaining repeats still produce a confidence interval.
            # Per-arm chunked / graph settings. The chunked-nograph arm forces the
            # windowed scanner with the graph note OFF regardless of flags; for
            # other arms --no-graph (honored only with --chunked) flips the note.
            arm_chunked = args.chunked or arm == "chunked-nograph"
            arm_use_graph = not (arm == "chunked-nograph"
                                 or (args.no_graph and arm_chunked))
            run = None
            for attempt in (1, 2):
                try:
                    run = run_single(args.demo, args.baseline, all_truth, scored,
                                     args.fuzz_lines, temperature,
                                     mode=args.baseline_mode, arm=arm,
                                     dedupe=not args.no_dedupe,
                                     chunked=arm_chunked, window=args.window_lines,
                                     use_graph=arm_use_graph)
                    break
                except Exception as e:
                    console.print(f"\n[red]Run {i + 1} ({arm}) attempt {attempt} "
                                  f"failed: {e}[/red]")
            if run is None:
                console.print(f"[yellow]Skipping run {i + 1} ({arm}) after retry.[/yellow]")
                continue
            print_run_report(run, args.fuzz_lines)
            runs_by_arm[arm].append(run)

    summaries = {}
    for arm in arms:
        if not runs_by_arm[arm]:
            console.print(f"[red]No successful runs for arm '{arm}'.[/red]")
            continue
        summaries[arm] = summarize(runs_by_arm[arm], args, scored, all_truth,
                                   temp_note, arm=arm)
        write_results(summaries[arm], args, arm=arm)

    if len(arms) > 1:
        print_comparison(summaries)

    return summaries if len(arms) > 1 else summaries[arms[0]]


def print_comparison(summaries: dict):
    """Side-by-side Autopsy vs raw-LLM comparison — the headline ablation."""
    console.rule("[bold]Ablation: Autopsy (graph pipeline) vs raw Sonnet (no graph)[/bold]")
    table = Table(show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column("Autopsy", justify="right")
    table.add_column("raw Sonnet", justify="right")
    table.add_column("Δ (Autopsy − raw)", justify="right")
    a = summaries.get("autopsy", {}).get("aggregate", {})
    r = summaries.get("raw", {}).get("aggregate", {})
    for name in ("precision", "recall", "f1"):
        av = a.get(name, {}).get("mean_pct", 0)
        rv = r.get(name, {}).get("mean_pct", 0)
        delta = av - rv
        sign = "+" if delta >= 0 else ""
        table.add_row(name.capitalize(), f"{av}%", f"{rv}%", f"{sign}{delta} pp")
    console.print(table)
    console.print(
        "[dim]Same model, same prompt, same scorer — the only difference is the "
        "dependency-graph pipeline. A positive Δ is evidence the graph adds value; "
        "look especially at the cross-file finding auth-ignored-return.[/dim]"
    )


def summarize(runs, args, scored, all_truth, temp_note, arm="autopsy") -> dict:
    precisions = [r["metrics"]["precision"] for r in runs]
    recalls = [r["metrics"]["recall"] for r in runs]
    f1s = [r["metrics"]["f1"] for r in runs]

    def agg(vals):
        mean = statistics.mean(vals)
        std = statistics.stdev(vals) if len(vals) > 1 else 0.0
        return {
            "mean_pct": _pct(mean),
            "std_pct": round(std * 100, 1),
            "raw_values": [round(v, 4) for v in vals],
        }

    aggregate = {
        "precision": agg(precisions),
        "recall": agg(recalls),
        "f1": agg(f1s),
    }

    if args.repeat > 1:
        table = Table(title=f"[{arm}] Aggregate over {args.repeat} runs (mean +/- std)")
        table.add_column("Metric", style="bold")
        table.add_column("Mean", justify="right")
        table.add_column("Std (pp)", justify="right")
        for name in ("precision", "recall", "f1"):
            a = aggregate[name]
            table.add_row(name.capitalize(), f"{a['mean_pct']}%", f"{a['std_pct']}")
        console.print(table)

    return {
        "mode": "live",
        "arm": arm,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "config": {
            "arm": arm,
            "demo": str(args.demo),
            "baseline": str(args.baseline),
            "baseline_mode": args.baseline_mode,
            "dedupe": not args.no_dedupe,
            "chunked": args.chunked or arm == "chunked-nograph",
            "use_graph": not (arm == "chunked-nograph"
                              or (args.no_graph
                                  and (args.chunked or arm == "chunked-nograph"))),
            "window_lines": args.window_lines,
            "fuzz_lines": args.fuzz_lines,
            "repeat": args.repeat,
            "include_provisional": args.include_provisional,
            "temperature_note": temp_note,
            "haiku_model": _model_ids()[0],
            "sonnet_model": _model_ids()[1],
        },
        "ground_truth": {
            "scored_count": len(scored),
            "scored_ids": [t["id"] for t in scored],
            "all_count": len(all_truth),
        },
        "aggregate": aggregate,
        "runs": [{
            "metrics": {
                "precision": round(r["metrics"]["precision"], 4),
                "recall": round(r["metrics"]["recall"], 4),
                "f1": round(r["metrics"]["f1"], 4),
                "precision_pct": _pct(r["metrics"]["precision"]),
                "recall_pct": _pct(r["metrics"]["recall"]),
                "f1_pct": _pct(r["metrics"]["f1"]),
            },
            "counts": r["counts"],
            "matched_ids": r["matched_ids"],
            "missed_ids": r["missed_ids"],
            "provisional_matched_ids": r["provisional_matched_ids"],
            "category_mismatches": r["category_mismatches"],
            "scan_time_seconds": r["scan_time_seconds"],
            "target_loc": r.get("target_loc", 0),
            "scan_time_per_kloc": r.get("scan_time_per_kloc", 0),
            "scan_time_per_vuln": r.get("scan_time_per_vuln", 0),
            "usage": r.get("usage", {}),
            "tokens_per_kloc": r.get("tokens_per_kloc", 0),
            "findings": r["findings"],
            "raw_output": r["raw_output"],
        } for r in runs],
    }


def _model_ids():
    from autopsy.llm.client import HAIKU_MODEL, SONNET_MODEL
    return HAIKU_MODEL, SONNET_MODEL


def write_results(summary: dict, args, arm="autopsy"):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = RESULTS_DIR / f"eval_{arm}_{ts}.json"
    out.write_text(json.dumps(summary, indent=2))
    console.print(f"\n[green]Results written to {out}[/green]")


# ─── Offline / dry-run path ─────────────────────────────────────────────────

def run_offline(args, all_truth, scored) -> dict:
    """Exercise the full wiring offline: build graph + diff, reach the scan
    boundary, and self-test the parser+matcher. No live LLM call, no fabricated
    metrics."""
    scored_ids = {t["id"] for t in scored}
    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = Path(tmp) / "eval_repo"
        graph, diff_text, changed_files = build_graph_and_diff(
            args.demo, args.baseline, repo_dir, mode=args.baseline_mode
        )
        console.print(f"[bold]Graph[/bold]: {graph.number_of_nodes()} nodes, "
                      f"{graph.number_of_edges()} edges")
        console.print(f"[bold]Diff[/bold]: {len(diff_text.splitlines())} lines, "
                      f"changed files = {changed_files}")
        console.print("[bold]Reached scan_stream boundary[/bold] — live LLM call "
                      "skipped (offline).")

    # Matcher self-test: a synthetic findings list keyed to the real ground
    # truth proves the parse->normalize->match path works end to end. This is a
    # WIRING CHECK, not an evaluation result — the metrics below are over
    # synthetic input and are labeled as such.
    sample = "\n".join(
        f"## [SEVERITY: CRITICAL] {t['id']}\n"
        f"**Category:** {t['category']}\n"
        f"**Location:** `{t['file']}:{t['line_start']}`\n---\n"
        for t in scored
    )
    findings = parse_findings(sample)
    m = match(findings, all_truth, scored_ids, args.fuzz_lines)
    ok = (m["tp"] == len(scored) and m["fp"] == 0 and m["fn"] == 0)
    console.print(
        f"\n[bold]Matcher self-test (synthetic input, NOT a result)[/bold]: "
        f"parsed {len(findings)} findings, "
        f"matched {m['tp']}/{len(scored)} scored truths, fp={m['fp']} "
        f"-> {'[green]WIRING OK[/green]' if ok else '[red]WIRING BROKEN[/red]'}"
    )
    if not ok:
        console.print("[red]Self-test did not fully match — investigate parser/matcher.[/red]")

    return {
        "mode": "offline",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "metrics": None,  # never fabricate metrics offline
        "wiring": {
            "graph_nodes": graph.number_of_nodes(),
            "graph_edges": graph.number_of_edges(),
            "diff_lines": len(diff_text.splitlines()),
            "changed_files": changed_files,
            "matcher_self_test_ok": ok,
        },
    }


# ─── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Autopsy evaluation harness")
    p.add_argument("--demo", type=Path, default=DEFAULT_DEMO,
                   help="Path to the vulnerable demo_project directory")
    p.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE,
                   help="Path to the clean baseline directory")
    p.add_argument("--ground-truth", type=Path, default=GROUND_TRUTH_PATH,
                   help="Path to a ground_truth.json (default: the demo's). "
                        "Use benchmark/pygoat/ground_truth_pygoat.json for pygoat.")
    p.add_argument("--baseline-mode", choices=["safe", "whole-file"], default="safe",
                   help="Scenario: 'safe' diffs against the clean baseline; "
                        "'whole-file' treats each vulnerable file as net-new "
                        "AI-generated code (empty-stub baseline)")
    p.add_argument("--fuzz-lines", type=int, default=DEFAULT_FUZZ_LINES,
                   help="Line-distance tolerance for a match (default 5)")
    p.add_argument("--repeat", type=int, default=1,
                   help="Number of live runs; reports mean +/- std when > 1")
    p.add_argument("--arm",
                   choices=["autopsy", "sonnet-only", "raw", "both", "all",
                            "chunked-nograph", "graph-ablation"],
                   default="autopsy",
                   help="autopsy=graph+Haiku triage+Sonnet; sonnet-only=graph+Sonnet "
                        "(no Haiku triage, #16); raw=Sonnet no graph (#11); "
                        "chunked-nograph=windowed scan with the graph note OFF "
                        "(graph ablation); both=autopsy+raw; all=autopsy+sonnet-only+raw; "
                        "graph-ablation=autopsy+chunked-nograph+raw")
    p.add_argument("--no-graph", action="store_true",
                   help="Disable the dependency-graph cross-file note (honored only "
                        "with --chunked; isolates the graph's marginal contribution)")
    p.add_argument("--include-provisional", action="store_true",
                   help="Score provisional ground-truth entries as well")
    p.add_argument("--no-dedupe", action="store_true",
                   help="Disable merging of duplicate findings at the same "
                        "location+category (dedupe is on by default)")
    p.add_argument("--chunked", action="store_true",
                   help="Use the map-reduce scanner (windows every file so large "
                        "files are not truncated). Recommended for large repos.")
    p.add_argument("--window-lines", type=int, default=400,
                   help="Line-window size for --chunked scanning (default 400)")
    p.add_argument("--graph-mode", choices=["off", "note", "subgraph"],
                   default="note",
                   help="Dependency context per --chunked window: off=none, "
                        "note=cross-file call names (default), subgraph=actual "
                        "cross-file callee/caller bodies (depth 1-2, ~250-line "
                        "cap). 'subgraph' is the stronger, untested recall mode.")
    p.add_argument("--dry-run", action="store_true",
                   help="Offline: build graph + diff + matcher wiring, no LLM call")
    return p


def main():
    args = build_parser().parse_args()
    if not args.demo.exists():
        console.print(f"[red]Demo project not found: {args.demo}[/red]")
        sys.exit(1)
    if not args.baseline.exists():
        console.print(f"[red]Baseline not found: {args.baseline}[/red]")
        sys.exit(1)
    run_eval(args)


if __name__ == "__main__":
    main()
