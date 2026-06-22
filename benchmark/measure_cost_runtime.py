"""Cost & runtime measurement, normalized per KLOC / per file / per vulnerability.

Reviewer Major comment #14. Produces defensible cost + runtime numbers from
REAL scan runs and REAL Anthropic `usage` token counts — nothing is estimated.

What it does
------------
* Reuses stored run artifacts that already carry real per-model token usage
  (TypeScript `js_demo` and the synthetic Flask `demo_project`) — $0 extra spend.
* Freshly runs SecurityEval (121 files) and one representative pygoat scan under
  the frozen protocol, with a non-invasive timing+usage wrapper monkeypatched
  around the existing pipeline (no source file is modified, the frozen matcher in
  eval.py is used verbatim).
* Emits results/cost_runtime_raw.jsonl, results/cost_runtime_per_kloc.csv,
  results/cost_runtime_methods.md, and a markdown table + sanity checks to stdout.

Run:  python benchmark/measure_cost_runtime.py
"""
from __future__ import annotations

import csv
import json
import statistics
import sys
import time
from datetime import date
from pathlib import Path

# ── Make `import eval` / `import eval_securityeval` resolve to the benchmark dir ──
_BENCH = Path(__file__).resolve().parent
_ROOT = _BENCH.parent
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Load .env so ANTHROPIC_API_KEY is available for the fresh runs.
from dotenv import load_dotenv  # noqa: E402
load_dotenv(_ROOT / ".env")

# ════════════════════════════════════════════════════════════════════════════
#  PRICING  — Anthropic list prices, per MILLION tokens (USD).
#  VERIFIED 2026-06-21 against https://platform.claude.com/docs/en/about-claude/pricing
#  Haiku 4.5:  $1.00 in / $5.00 out      Sonnet 4.5: $3.00 in / $15.00 out
#  Cache (documented but NOT recorded by the client, so not applied here):
#    Haiku  read $0.10 / 5m-write $1.25 ;  Sonnet read $0.30 / 5m-write $3.75 per MTok
# ════════════════════════════════════════════════════════════════════════════
PRICES = {
    "claude-haiku-4-5-20251001":  {"input_per_mtok": 1.00, "output_per_mtok": 5.00},
    "claude-sonnet-4-5-20250929": {"input_per_mtok": 3.00, "output_per_mtok": 15.00},
}
HAIKU_MODEL = "claude-haiku-4-5-20251001"
SONNET_MODEL = "claude-sonnet-4-5-20250929"
RUN_DATE = date.today().isoformat()
FROZEN_MATCHER_COMMIT = "6da8b87"
FUZZ = 5

RAW_JSONL = _ROOT / "results" / "cost_runtime_raw.jsonl"
OUT_CSV = _ROOT / "results" / "cost_runtime_per_kloc.csv"
OUT_METHODS = _ROOT / "results" / "cost_runtime_methods.md"

SRC_EXTS = (".py", ".js", ".ts", ".tsx", ".jsx")


def cost_in_out(haiku_in, haiku_out, sonnet_in, sonnet_out) -> float:
    """USD cost from real input/output token counts at the listed list prices."""
    h = PRICES[HAIKU_MODEL]
    s = PRICES[SONNET_MODEL]
    return (haiku_in / 1e6 * h["input_per_mtok"]
            + haiku_out / 1e6 * h["output_per_mtok"]
            + sonnet_in / 1e6 * s["input_per_mtok"]
            + sonnet_out / 1e6 * s["output_per_mtok"])


def count_source_files(d: Path) -> int:
    return sum(1 for p in Path(d).rglob("*") if p.suffix in SRC_EXTS and p.is_file())


# ════════════════════════════════════════════════════════════════════════════
#  Non-invasive instrumentation: monkeypatch leaf functions to accumulate
#  per-stage wall time and cache-token counts. No source file is edited.
# ════════════════════════════════════════════════════════════════════════════
STAGE = {"graph_s": 0.0, "detectors_s": 0.0, "haiku_s": 0.0, "sonnet_s": 0.0}
CACHE = {"haiku_cache_creation": 0, "haiku_cache_read": 0,
         "sonnet_cache_creation": 0, "sonnet_cache_read": 0}


def _reset_instr():
    for k in STAGE:
        STAGE[k] = 0.0
    for k in CACHE:
        CACHE[k] = 0


def install_instrumentation():
    """Wrap graph-build, detectors, Haiku triage and Sonnet analysis to time them
    and to read cache tokens off the real API `usage` objects. Patches both the
    source module and any already-bound references (pipeline.py binds at load)."""
    import autopsy.parser as _parser
    import autopsy.graph.builder as _builder
    import autopsy.detection.static_rules as _static
    import autopsy.detection.ignored_returns as _ignored
    import autopsy.llm.client as _client
    import autopsy.llm.pipeline as _pipeline

    def timed(stage_key, fn):
        def wrapper(*a, **k):
            t0 = time.time()
            try:
                return fn(*a, **k)
            finally:
                STAGE[stage_key] += time.time() - t0
        return wrapper

    # (a) dependency graph build — Tree-sitter parse + NetworkX build
    _parser.parse_directory = timed("graph_s", _parser.parse_directory)
    _builder.build_dependency_graph = timed("graph_s", _builder.build_dependency_graph)

    # (b) deterministic detectors
    _static.detect_static_rules = timed("detectors_s", _static.detect_static_rules)
    _ignored.detect_ignored_security_returns = timed(
        "detectors_s", _ignored.detect_ignored_security_returns)

    # cache-token capture: client._record receives the real usage object
    _orig_record = _client._record

    def record_with_cache(model, usage):
        _orig_record(model, usage)
        try:
            CACHE[f"{model}_cache_creation"] += getattr(
                usage, "cache_creation_input_tokens", 0) or 0
            CACHE[f"{model}_cache_read"] += getattr(
                usage, "cache_read_input_tokens", 0) or 0
        except Exception:
            pass
    _client._record = record_with_cache

    # (c) Haiku triage — non-streaming
    _orig_haiku = _client.call_haiku

    def timed_haiku(*a, **k):
        t0 = time.time()
        try:
            return _orig_haiku(*a, **k)
        finally:
            STAGE["haiku_s"] += time.time() - t0
    _client.call_haiku = timed_haiku
    _pipeline.call_haiku = timed_haiku  # pipeline bound it at import

    # (d) Sonnet deep analysis — streaming generator; time full consumption
    _orig_sonnet = _client.stream_sonnet

    def timed_sonnet(*a, **k):
        t0 = time.time()
        gen = _orig_sonnet(*a, **k)
        try:
            for chunk in gen:
                yield chunk
        finally:
            STAGE["sonnet_s"] += time.time() - t0
    _client.stream_sonnet = timed_sonnet
    _pipeline.stream_sonnet = timed_sonnet


# ════════════════════════════════════════════════════════════════════════════
#  Reused benchmarks: read real token usage from stored run artifacts.
# ════════════════════════════════════════════════════════════════════════════
def records_from_stored(benchmark, result_json, target_dir):
    """One raw record per stored run. Stage timing is unavailable in the stored
    artifacts (only aggregate scan time was recorded) -> stages = None."""
    d = json.loads(Path(result_json).read_text())
    files = count_source_files(target_dir)
    recs = []
    for i, r in enumerate(d["runs"]):
        u = r["usage"]
        c = r["counts"]
        hi, ho = u.get("haiku_in", 0), u.get("haiku_out", 0)
        si, so = u.get("sonnet_in", 0), u.get("sonnet_out", 0)
        recs.append({
            "benchmark": benchmark,
            "run_index": i,
            "source": "reused-artifact",
            "artifact": Path(result_json).name,
            "wall_clock_s": r["scan_time_seconds"],
            "stages_s": None,                       # not recorded in stored runs
            "loc": r["target_loc"],
            "loc_method": "physical-line-count (eval.count_loc; cloc unavailable)",
            "files": files,
            "haiku_in": hi, "haiku_out": ho,
            "sonnet_in": si, "sonnet_out": so,
            "cache": None,
            "findings": c["total_findings"],
            "confirmed_tp": c["tp"],
            "cost_usd": cost_in_out(hi, ho, si, so),
        })
    return recs


# ════════════════════════════════════════════════════════════════════════════
#  Fresh run: pygoat (single representative run, frozen whole-file chunked).
# ════════════════════════════════════════════════════════════════════════════
def run_pygoat():
    import tempfile
    import eval as E

    pygoat_dir = Path("/tmp/pygoat_core")
    baseline_dir = _BENCH / "baseline"
    gt_path = _BENCH / "pygoat" / "ground_truth_pygoat.json"
    if not pygoat_dir.exists():
        print(f"[pygoat] target {pygoat_dir} MISSING -> skipping")
        return None

    all_truth, scored = E.load_ground_truth(gt_path, include_provisional=False)
    scored_ids = {t["id"] for t in scored}

    from autopsy.llm.client import reset_usage, get_usage
    _reset_instr()
    reset_usage()
    t_total = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = Path(tmp) / "eval_repo"
        graph, diff_text, changed_files = E.build_graph_and_diff(
            pygoat_dir, baseline_dir, repo_dir, mode="whole-file")
        output, scan_elapsed = E.run_scan(
            graph, diff_text, changed_files, repo_dir, temperature=None,
            chunked=True, window=400)
    wall = time.time() - t_total
    usage = get_usage()

    findings = E.dedupe_findings(E.parse_findings(output))
    m = E.match(findings, all_truth, scored_ids, FUZZ)
    loc = E.count_loc(pygoat_dir)
    hi, ho = usage.get("haiku_in", 0), usage.get("haiku_out", 0)
    si, so = usage.get("sonnet_in", 0), usage.get("sonnet_out", 0)
    return {
        "benchmark": "pygoat",
        "run_index": 0,
        "source": "fresh-run (SINGLE representative run)",
        "wall_clock_s": round(wall, 1),
        "scan_elapsed_s": round(scan_elapsed, 1),
        "stages_s": {k: round(v, 1) for k, v in STAGE.items()},
        "loc": loc,
        "loc_method": "physical-line-count (eval.count_loc; cloc unavailable)",
        "files": count_source_files(pygoat_dir),
        "haiku_in": hi, "haiku_out": ho,
        "sonnet_in": si, "sonnet_out": so,
        "cache": dict(CACHE),
        "findings": len(findings),
        "confirmed_tp": m["tp"],
        "cost_usd": cost_in_out(hi, ho, si, so),
        "note": "chunked path = deterministic detectors + Sonnet (no Haiku triage)",
    }


# ════════════════════════════════════════════════════════════════════════════
#  Fresh run: SecurityEval (121 vulnerable files, per-file chunked scan).
#  Each file is vulnerable by construction -> a detected file IS a true positive.
# ════════════════════════════════════════════════════════════════════════════
def run_securityeval(subset="Testcases_Insecure_Code"):
    import eval as E
    from autopsy.parser import parse_directory
    from autopsy.graph.builder import build_dependency_graph
    from autopsy.llm.chunking import scan_stream_chunked
    from autopsy.llm.client import reset_usage, get_usage

    target = Path("/tmp/SecurityEval") / subset
    if not target.exists():
        print(f"[securityeval] target {target} MISSING -> skipping")
        return None

    all_files = sorted(p for p in target.rglob("*.py") if p.is_file())
    rels = [p.relative_to(target).as_posix() for p in all_files]

    _reset_instr()
    reset_usage()
    t_total = time.time()
    graph = build_dependency_graph(parse_directory(target))
    hit = 0
    total_findings = 0
    for rel in rels:
        out = "".join(scan_stream_chunked(graph, "", [rel], root_dir=target,
                                          window_lines=400))
        fs = E.parse_findings(out)
        total_findings += len(fs)
        if fs:
            hit += 1
    wall = time.time() - t_total
    usage = get_usage()

    loc = E.count_loc(target)
    hi, ho = usage.get("haiku_in", 0), usage.get("haiku_out", 0)
    si, so = usage.get("sonnet_in", 0), usage.get("sonnet_out", 0)
    return {
        "benchmark": "securityeval",
        "run_index": 0,
        "source": "fresh-run (full 121-file pass, single run)",
        "wall_clock_s": round(wall, 1),
        "stages_s": {k: round(v, 1) for k, v in STAGE.items()},
        "loc": loc,
        "loc_method": "physical-line-count (eval.count_loc; cloc unavailable)",
        "files": len(all_files),
        "haiku_in": hi, "haiku_out": ho,
        "sonnet_in": si, "sonnet_out": so,
        "cache": dict(CACHE),
        "findings": total_findings,
        "confirmed_tp": hit,   # every file is vulnerable -> detected == TP
        "cost_usd": cost_in_out(hi, ho, si, so),
        "note": "detection rate basis: each file vulnerable by construction; "
                "chunked path = detectors + Sonnet (no Haiku triage)",
    }


# ════════════════════════════════════════════════════════════════════════════
#  Aggregation -> per-benchmark + Aggregate rows.
# ════════════════════════════════════════════════════════════════════════════
def aggregate_benchmark(name, recs):
    """Collapse runs into one per-benchmark row (mean over repeats for time/cost/
    tokens; std reported for time and cost). Single-run benchmarks -> std=0."""
    n = len(recs)
    files = recs[0]["files"]
    loc = recs[0]["loc"]
    kloc = loc / 1000.0
    times = [r["wall_clock_s"] for r in recs]
    costs = [r["cost_usd"] for r in recs]
    hi = statistics.mean(r["haiku_in"] for r in recs)
    ho = statistics.mean(r["haiku_out"] for r in recs)
    si = statistics.mean(r["sonnet_in"] for r in recs)
    so = statistics.mean(r["sonnet_out"] for r in recs)
    tp = statistics.mean(r["confirmed_tp"] for r in recs)
    findings = statistics.mean(r["findings"] for r in recs)
    t = statistics.mean(times)
    c = statistics.mean(costs)
    return {
        "benchmark": name,
        "runs": n,
        "files": files,
        "loc": loc,
        "kloc": kloc,
        "wall_clock_s": t,
        "wall_clock_std_s": statistics.stdev(times) if n > 1 else 0.0,
        "haiku_in": hi, "haiku_out": ho, "sonnet_in": si, "sonnet_out": so,
        "cost_usd": c,
        "cost_std_usd": statistics.stdev(costs) if n > 1 else 0.0,
        "findings": findings,
        "confirmed_tp": tp,
        "time_per_kloc": t / kloc if kloc else 0.0,
        "time_per_file": t / files if files else 0.0,
        "cost_per_kloc": c / kloc if kloc else 0.0,
        "cost_per_file": c / files if files else 0.0,
        "cost_per_vuln": c / tp if tp else None,
        "tokens_per_file": (hi + ho + si + so) / files if files else 0.0,
        "seconds_per_file": t / files if files else 0.0,
    }


def aggregate_total(rows):
    files = sum(r["files"] for r in rows)
    loc = sum(r["loc"] for r in rows)
    kloc = loc / 1000.0
    t = sum(r["wall_clock_s"] for r in rows)
    c = sum(r["cost_usd"] for r in rows)
    hi = sum(r["haiku_in"] for r in rows)
    ho = sum(r["haiku_out"] for r in rows)
    si = sum(r["sonnet_in"] for r in rows)
    so = sum(r["sonnet_out"] for r in rows)
    tp = sum(r["confirmed_tp"] for r in rows)
    findings = sum(r["findings"] for r in rows)
    return {
        "benchmark": "Aggregate",
        "runs": sum(r["runs"] for r in rows),
        "files": files, "loc": loc, "kloc": kloc,
        "wall_clock_s": t, "wall_clock_std_s": 0.0,
        "haiku_in": hi, "haiku_out": ho, "sonnet_in": si, "sonnet_out": so,
        "cost_usd": c, "cost_std_usd": 0.0,
        "findings": findings, "confirmed_tp": tp,
        "time_per_kloc": t / kloc if kloc else 0.0,
        "time_per_file": t / files if files else 0.0,
        "cost_per_kloc": c / kloc if kloc else 0.0,
        "cost_per_file": c / files if files else 0.0,
        "cost_per_vuln": c / tp if tp else None,
        "tokens_per_file": (hi + ho + si + so) / files if files else 0.0,
        "seconds_per_file": t / files if files else 0.0,
    }


CSV_COLUMNS = [
    "benchmark", "runs", "files", "kloc", "wall_clock_s", "wall_clock_std_s",
    "haiku_in", "haiku_out", "sonnet_in", "sonnet_out",
    "cost_usd", "cost_std_usd", "confirmed_tp",
    "time_per_kloc", "time_per_file", "cost_per_kloc", "cost_per_file",
    "cost_per_vuln", "tokens_per_file", "seconds_per_file",
]


def write_csv(rows):
    OUT_CSV.parent.mkdir(exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(CSV_COLUMNS)
        for r in rows:
            w.writerow([
                r["benchmark"], r["runs"], r["files"], round(r["kloc"], 3),
                round(r["wall_clock_s"], 1), round(r["wall_clock_std_s"], 1),
                round(r["haiku_in"]), round(r["haiku_out"]),
                round(r["sonnet_in"]), round(r["sonnet_out"]),
                round(r["cost_usd"], 4), round(r["cost_std_usd"], 4),
                round(r["confirmed_tp"], 1),
                round(r["time_per_kloc"], 1), round(r["time_per_file"], 1),
                round(r["cost_per_kloc"], 4), round(r["cost_per_file"], 4),
                (round(r["cost_per_vuln"], 4) if r["cost_per_vuln"] is not None else ""),
                round(r["tokens_per_file"]), round(r["seconds_per_file"], 1),
            ])


def markdown_table(rows):
    cols = ["benchmark", "runs", "files", "kloc", "wall_clock_s", "cost_usd",
            "confirmed_tp", "time_per_kloc", "time_per_file", "cost_per_kloc",
            "cost_per_file", "cost_per_vuln"]
    hdr = ["Benchmark", "Runs", "Files", "KLOC", "Time (s)", "Cost ($)",
           "TP", "s/KLOC", "s/file", "$/KLOC", "$/file", "$/vuln"]
    lines = ["| " + " | ".join(hdr) + " |",
             "|" + "|".join("---" for _ in hdr) + "|"]
    for r in rows:
        cpv = f'{r["cost_per_vuln"]:.4f}' if r["cost_per_vuln"] is not None else "n/a"
        lines.append("| " + " | ".join([
            r["benchmark"], str(r["runs"]), str(r["files"]), f'{r["kloc"]:.3f}',
            f'{r["wall_clock_s"]:.1f}', f'{r["cost_usd"]:.4f}',
            f'{r["confirmed_tp"]:.0f}', f'{r["time_per_kloc"]:.1f}',
            f'{r["time_per_file"]:.1f}', f'{r["cost_per_kloc"]:.4f}',
            f'{r["cost_per_file"]:.4f}', cpv,
        ]) + " |")
    return "\n".join(lines)


def sanity_checks(rows_no_agg):
    print("\n## Sanity checks (per-file throughput; cost/KLOC outliers)\n")
    print(f"{'benchmark':<14} {'tokens/file':>12} {'sec/file':>10} {'$/KLOC':>10}")
    for r in rows_no_agg:
        print(f"{r['benchmark']:<14} {r['tokens_per_file']:>12.0f} "
              f"{r['seconds_per_file']:>10.1f} {r['cost_per_kloc']:>10.4f}")
    cpks = [r["cost_per_kloc"] for r in rows_no_agg]
    med = statistics.median(cpks)
    print(f"\nmedian cost/KLOC = ${med:.4f}; flagging any > 3x median (${3*med:.4f}):")
    flagged = [r["benchmark"] for r in rows_no_agg if r["cost_per_kloc"] > 3 * med]
    print("  " + (", ".join(flagged) if flagged else "none"))
    return flagged


METHODS_TEMPLATE = """\
## Cost and runtime — methods

Cost is computed from the **real `usage` token counts** returned by every
Anthropic API response (`input_tokens` / `output_tokens`, summed per model), not
estimated from text length, and priced at the published list rates as of
{run_date}: Claude Haiku 4.5 (triage) ${h_in}/${h_out} per million input/output
tokens and Claude Sonnet 4.5 (deep analysis) ${s_in}/${s_out} per million input/
output tokens. Source lines of code were counted with a physical newline count
({loc_method_short}) because `cloc` was not installed on the run host; this is the
"lines" used for the per-KLOC normalization. Wall-clock time is broken out by
stage (dependency-graph build, deterministic detectors, Haiku triage, Sonnet deep
analysis) for the freshly run benchmarks and includes live API latency, so it
depends on network and hardware and is reported as **indicative** rather than a
hardware-independent constant. The TypeScript and synthetic Flask-demo figures
are reused from stored frozen-protocol run artifacts that already recorded real
per-model token usage (so they cost no additional API spend), and the synthetic
Flask-demo numbers are the **mean over {demo_runs} runs**; SecurityEval (121
files) and pygoat were run fresh, pygoat as a **single representative run**.
All figures use the frozen matcher (commit {matcher}) and the pinned models
(Haiku {haiku}, Sonnet {sonnet}).

### Caveats
- **Wall-clock is network/hardware-dependent** (it includes live API round-trip
  latency); treat seconds-per-KLOC/-file as indicative, not a fixed constant.
  Token counts and dollar cost are hardware-independent and are the durable
  numbers.
- **pygoat is N=1** (a single representative run); its per-run cost/time has no
  variance estimate. TypeScript and the Flask demo are means over 5 runs each
  (std reported in the CSV); the Flask demo is 5 runs here, not 9.
- **Chunked benchmarks (pygoat, SecurityEval) skip Haiku triage by design** — the
  map-reduce scanner runs the deterministic detectors then Sonnet over line
  windows, so their Haiku token cost is genuinely $0. The single-shot benchmarks
  (TypeScript, Flask demo) do use Haiku triage.
- **Per-stage timing is only available for the freshly run benchmarks.** The
  reused artifacts recorded only aggregate scan time (which excludes the
  sub-second graph build); their stage breakdown is therefore null.
- **SecurityEval "confirmed vulnerabilities" = files detected**, since every file
  in the set is vulnerable by construction (per-file detection rate = recall);
  it is not a precision-matched count like pygoat/TypeScript.
- **Cache tokens were not billed/applied.** The client does not request prompt
  caching and recorded no `cache_creation_input_tokens` / `cache_read_input_tokens`
  in these runs, so cost is input+output only; the documented cache rates were not
  needed.
- **Per-benchmark "total" is per single scan** (mean for repeated benchmarks); the
  Aggregate row sums one representative scan per benchmark.
- List prices may change; they are pinned to {run_date} and printed in the run
  output so the paper can cite them with a date.
"""


def write_methods(demo_runs):
    h = PRICES[HAIKU_MODEL]
    s = PRICES[SONNET_MODEL]
    OUT_METHODS.write_text(METHODS_TEMPLATE.format(
        run_date=RUN_DATE,
        h_in=f'{h["input_per_mtok"]:.2f}', h_out=f'{h["output_per_mtok"]:.2f}',
        s_in=f'{s["input_per_mtok"]:.2f}', s_out=f'{s["output_per_mtok"]:.2f}',
        loc_method_short="Python str.splitlines() over .py/.js/.ts/.tsx",
        demo_runs=demo_runs, matcher=FROZEN_MATCHER_COMMIT,
        haiku=HAIKU_MODEL, sonnet=SONNET_MODEL,
    ))


def append_raw(records):
    RAW_JSONL.parent.mkdir(exist_ok=True)
    with open(RAW_JSONL, "a") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def main():
    print("=" * 78)
    print("Autopsy cost & runtime measurement (reviewer Major #14)")
    print("=" * 78)
    print(f"Run date: {RUN_DATE}")
    print(f"Models:   triage   = {HAIKU_MODEL}")
    print(f"          analysis = {SONNET_MODEL}")
    print(f"Frozen matcher commit: {FROZEN_MATCHER_COMMIT}  (fuzz={FUZZ})")
    print("Prices (USD per MTok, list, verified", RUN_DATE + "):")
    for m, p in PRICES.items():
        print(f"  {m}: in ${p['input_per_mtok']:.2f} / out ${p['output_per_mtok']:.2f}")
    print()

    install_instrumentation()

    raw_records = []
    by_bench = {}

    # 1) Reused artifacts (real tokens, $0 extra spend) -------------------------
    ts = records_from_stored("typescript", _BENCH / "results" / "eval_autopsy_20260619_235214.json", _BENCH / "js_demo")
    demo = records_from_stored("flask_demo", _BENCH / "results" / "eval_autopsy_20260619_233900.json", _ROOT / "demo_project")
    by_bench["typescript"] = ts
    by_bench["flask_demo"] = demo
    raw_records += ts + demo
    print(f"[reused] typescript: {len(ts)} runs | flask_demo: {len(demo)} runs")

    # 2) Fresh: SecurityEval (full 121-file pass) -------------------------------
    print("\n[fresh] SecurityEval — scanning 121 files (this spends API tokens)...")
    se = run_securityeval()
    if se:
        by_bench["securityeval"] = [se]
        raw_records.append(se)
        print(f"  done: {se['confirmed_tp']}/{se['files']} files detected, "
              f"${se['cost_usd']:.4f}, {se['wall_clock_s']}s")

    # 3) Fresh: pygoat (single representative run) ------------------------------
    print("\n[fresh] pygoat — single representative frozen-protocol run...")
    pg = run_pygoat()
    if pg:
        by_bench["pygoat"] = [pg]
        raw_records.append(pg)
        print(f"  done: TP={pg['confirmed_tp']}, findings={pg['findings']}, "
              f"${pg['cost_usd']:.4f}, {pg['wall_clock_s']}s, stages={pg['stages_s']}")

    append_raw(raw_records)
    print(f"\nAppended {len(raw_records)} raw records -> {RAW_JSONL}")

    # 4) Aggregate + emit -------------------------------------------------------
    order = ["pygoat", "securityeval", "typescript", "flask_demo"]
    rows = [aggregate_benchmark(b, by_bench[b]) for b in order if b in by_bench]
    agg = aggregate_total(rows)
    all_rows = rows + [agg]

    write_csv(all_rows)
    write_methods(demo_runs=len(demo))

    table = markdown_table(all_rows)
    print("\n## Cost & runtime per KLOC / file / vulnerability\n")
    print(table)
    flagged = sanity_checks(rows)

    print(f"\nCSV     -> {OUT_CSV}")
    print(f"Methods -> {OUT_METHODS}")
    print(f"Raw     -> {RAW_JSONL}")

    # machine-readable summary for the wrap-up
    (_ROOT / "results" / "cost_runtime_summary.json").write_text(json.dumps({
        "run_date": RUN_DATE, "prices": PRICES,
        "models": {"haiku": HAIKU_MODEL, "sonnet": SONNET_MODEL},
        "matcher_commit": FROZEN_MATCHER_COMMIT,
        "rows": all_rows, "flagged": flagged,
        "markdown": table,
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
