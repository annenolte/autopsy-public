# Autopsy

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-red.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

Autopsy is a vulnerability scanner for AI-generated code. It parses a repository with Tree-sitter into a NetworkX dependency graph, diffs that graph across commits, and uses the resulting structure to do three things a file-at-a-time scanner cannot:

- **Reason across file boundaries.** The root cause of a finding is often not in the file where the symptom appears; the graph makes the call chain explicit.
- **Analyze deletions.** Removing a comment delimiter or a `validate()` function can introduce a vulnerability that never appears as an added line in a diff. Addition-only scanners are blind to this class.
- **Report a blast radius.** After locating a vulnerability, Autopsy reverses the graph to enumerate the callers that can reach it.

Detection runs in two layers: deterministic AST/graph detectors that need no API call, and an LLM pass (Claude Haiku for triage, Sonnet for analysis) windowed over long files.

On OWASP pygoat, Autopsy finds 11/11 labeled vulnerabilities, a strict superset of CodeQL `security-extended` (9/11), Semgrep (7/11), and Bandit (5/11). On SecurityEval it flags 95% of 121 vulnerable files. [Measured results](#measured-results) reports these alongside the ablations and the pre-registered control that bound what they do and do not show.

---

## Background

Code produced by AI assistants is accepted at a rate that outpaces review, which means a codebase accumulates functions nobody has read closely. Two properties of conventional scanners interact badly with that:

1. **They scan files in isolation.** A sink in `db.py` is reported at `db.py`, with no indication of which entry points reach it, so triage requires manually reconstructing the call graph.
2. **They scan additions.** A unified diff of a deleted comment delimiter is one or two characters. The set of live functions in the AST can change substantially, and none of it appears as an addition.

Autopsy builds the graph at the pre- and post-commit SHAs and compares them structurally, so both the additions and the structural consequences of removals are visible to the scan.

---

## Modes

Autopsy exposes four operations. Each is available as a CLI subcommand, a REPL menu entry, a VS Code command, and an HTTP endpoint.

**`s` — SCAN THIS** (`Cmd+Shift+S` in VS Code)

Reads the git diff, scores which code was likely AI-authored using 7 heuristic signals, and scans it. Before the LLM pass it runs deletion analysis and the deterministic detectors. Each finding carries a severity badge (CRITICAL / HIGH / MEDIUM / LOW), file and line, an attack scenario, a suggested fix, and a blast radius.

**`d` — DEBUG THIS** (`Cmd+Shift+D` in VS Code)

Takes an error message or a target file/function. Autopsy extracts the connected subgraph via BFS to a bounded depth and streams root cause, causal chain, suggested fix, and blast radius.

**`o` — ORIENT ME** (`Cmd+Shift+O` in VS Code)

Produces a map of an unfamiliar repository: file tree, architecture overview, module map, data flow, entry points, and complexity hotspots ranked by in-degree. Uses graph properties — in-degree, out-degree, cycle detection — rather than text analysis alone.

**`g` — GRAPH**

Dependency graph statistics (node counts by type, edge counts by relationship) and, in VS Code, an interactive force-directed visualization.

---

## How it works

### The dependency graph

Autopsy parses the repository with Tree-sitter and builds a NetworkX `DiGraph`. Every file, function, and class is a node; every import, call, and inheritance relationship is a directed edge. Nodes carry `type`, `qualified_name`, and `file` attributes.

```
File A (auth/handler.py)
  └── calls → get_user() in db.py
                └── calls → execute_query() in db.py
                              └── SQL injection here
```

Parsed languages (`autopsy/parser/languages.py`): Python (`.py`), JavaScript (`.js`, `.jsx`), TypeScript (`.ts`), TSX (`.tsx`).

### Scan pipeline

Deterministic analysis runs first and requires no API calls; the LLM pass follows.

```
Git Diff
    │
    ▼
┌─────────────────────────┐
│  Phase 1                │  Scan raw diff for deleted comment openers
│  Comment Boundary       │  Flag zero-footprint activations
│  Detection              │  (""", /*, =begin, <!--, etc.)
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Phase 2                │  Build graph at pre-commit SHA
│  Pre/Post Graph Diff    │  Build graph at post-commit SHA
│                         │  Diff: activated nodes, deleted nodes,
│                         │  broken edges, security deletions
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Phase 3                │  SQL string injection → execute sink
│  Deterministic          │  Weak hashing (MD5/SHA1) on secrets
│  Detectors              │  Ignored security-gate return values
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Phase 4                │  Score changed code with 7-signal heuristic
│  AI Authorship          │  Score ≥ 0.5 = likely_ai, scanned first
│  Detection              │  Union with activated_nodes from Phase 2
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│  Phase 5                │  BFS extracts subgraph (max 50 nodes)
│  LLM Pipeline           │  Claude Haiku triages → JSON
│                         │  Claude Sonnet streams deep analysis,
│                         │  windowed over long files
│                         │  Blast radius via reverse BFS
└──────────┬──────────────┘
           │
           ▼
    Terminal / VS Code Panel
    (streamed via SSE)
```

`--no-llm` stops after Phase 4.

### Deletion analysis

`autopsy/detection/deletions.py` covers three deletion-introduced classes.

**Comment boundary deletion (zero-footprint activation).** Deleting the opening delimiter of a multiline comment makes the enclosed block live. The diff shows the removed delimiter; the AST shows new live functions that never appear as additions.

```
- """
  def execute_raw_query(sql):        ← this function is now live
      db.execute(sql)                ← SQL injection, never reviewed
  """
```

Openers detected (`COMMENT_OPENERS`):

| Delimiter | Language |
|-----------|----------|
| `"""` / `'''` | Python |
| `/*` | JS / TS / Java / Go / C / C++ |
| `#=` | Julia |
| `--[[` | Lua |
| `=begin` | Ruby |
| `<!--` | HTML / XML |

Delimiter scanning operates on raw diff text, so the warning fires for any of these. Graph-level follow-through — feeding the activated block through the full pipeline with blast radius — requires a parsed language (Python / JS / TS / TSX). For Julia, Lua, Ruby, and HTML you get the activation warning and the revealed block, not the graph analysis.

When a deletion is detected, the revealed block is checked for executable content (`_revealed_block_is_dangerous`) and, if so, added to scan targets and passed through the same Haiku → Sonnet pipeline as an addition.

```
⚠  ZERO-FOOTPRINT ACTIVATION DETECTED
─────────────────────────────────────────────────────────────
A comment boundary was deleted. Code previously inside this
comment block is now live and was not caught by diff scanning.

File: auth/handler.py
Deleted delimiter: """  (Python multiline string / docstring opener)

Autopsy is scanning the newly activated code for vulnerabilities.
This code does not appear as additions in your git diff.
```

**Security control deletion.** When a removed function's name contains a security keyword — `validate`, `authenticate`, `sanitize`, `authorize`, `verify`, `guard`, `protect`, `rate_limit`, `csrf`, `xss`, `escape`, `hash`, `encrypt`, `permission`, `require`, `restrict` — Autopsy reports it along with every caller that is now potentially unprotected.

```
🚨  SECURITY CONTROL DELETED
─────────────────────────────────────────────────────────────
validate_input() was removed. Its callers may now be unprotected.

Called by: api/routes.py, api/admin.py, middleware/session.py
```

**Broken edge detection.** When a surviving function calls a function that no longer exists, Autopsy reports the dangling dependency.

```
⚠  BROKEN DEPENDENCY DETECTED
─────────────────────────────────────────────────────────────
auth/handler.py::authenticate()  →  utils/crypto.py::hash_password()
hash_password() was deleted. authenticate() is now calling nothing.
```

### Deterministic detectors (no LLM)

These fire without any API call. Their practical property is scale-invariance: an LLM's recall degrades as a codebase grows and attention spreads across more code, whereas an AST/graph rule fires identically on a 200-line file and a 500k-line monorepo, in linear time, with no context-window limit.

| Detector | Module | What it matches |
|---|---|---|
| SQL string injection | `detection/static_rules.py::detect_sql_string_injection` | Parameters interpolated into a SQL string that reaches an execute sink. Project-specific sink names are discovered via `_sql_sink_names`. Matches the interpolated shape; does not match the equivalent bound-parameter query. |
| Weak hashing | `detection/static_rules.py::detect_weak_hashing` | MD5/SHA1 applied to sensitive values, e.g. password hashing. |
| Ignored security returns | `detection/ignored_returns.py::detect_ignored_security_returns` | A security gate is called but its boolean result is discarded — `check_permission(user, id)` as a bare expression statement, so the gate does not affect control flow. |

The ignored-return detector is the case where the graph is load-bearing: the graph records the cross-file `calls` edge to a security-named function, and the AST determines whether the return value is consumed (assigned, tested, returned, passed) or discarded. Together these make the finding decidable without the model noticing it, which matters because an LLM scan tends to fixate on higher-signal bugs such as SQL injection in the same function and reports this pattern inconsistently.

Findings from this layer are deterministic static analysis, not evidence of LLM reasoning. The benchmark harness attributes static-layer and LLM-layer findings separately, and the rules are validated against code they were not written for (`benchmark/heldout/`, `benchmark/validate_heldout.py`).

### Windowed map-reduce scanning

A single whole-file prompt is bounded by its output budget, and long files get truncated — pygoat's `introduction/views.py` is roughly 1,240 lines, so a 500-line cap never reaches most of it. `autopsy/llm/chunking.py::scan_stream_chunked` slides a window over each file instead, so every region gets its own read and its own output budget.

- `iter_line_windows(total_lines, window=400, overlap=40)` — 400-line windows with 40 lines of overlap, so a vulnerability spanning a boundary is seen whole by at least one window.
- `_graph_neighbors_note(...)` / `_graph_subgraph_bodies(...)` attach cross-file dependency context to each window, and can be disabled to isolate the windowing effect.
- Findings across windows are merged and deduped (same file, within 3 lines, same category).

The deterministic layer runs once over the whole repository; only the LLM step is windowed. On pygoat, windowing rather than the dependency-graph note is the measured source of the recall gain over a single prompt — see [Measured results](#measured-results).

### Pre/post commit graph diffing

Autopsy builds the graph at two commits and compares them structurally. File contents are read from the git object database via GitPython blob reads into a `TemporaryDirectory`; the working directory is not modified. Node IDs are normalized after snapshot construction so the graphs are directly comparable.

```python
pre_graph  = build_graph_at_commit(repo_path, pre_commit_sha)
post_graph = build_graph_at_commit(repo_path, post_commit_sha)
graph_diff = diff_graphs(pre_graph, post_graph)

# activated_nodes: in post but not pre — newly live code
# deleted_nodes: in pre but not post — removed functions
# broken_edges: caller exists, callee does not
# security_critical_deletions: deleted security-named functions
```

Any node in `activated_nodes` — whether activated by comment removal, file restructuring, or another mechanism — is added to scan targets and follows the same path as an explicit addition.

### Blast radius

After a finding, Autopsy reverses the graph and runs a second BFS from the vulnerable node to enumerate the caller chains that reach it.

```python
# Forward graph: A → B → C (A calls B which calls C)
# Reverse graph: C → B → A (who can reach C?)

reversed_graph = graph.reverse()
blast_radius = bfs(reversed_graph, vulnerable_node)
```

When blast-radius data is supplied, the prompt is instructed to use the computed graph-derived file and function names rather than inferring them.

```
⚠ CRITICAL — SQL Injection
  Location: db.py:42 in get_user()
  Attack: Unsanitized user input passed directly to execute()

  Blast Radius — 7 files can reach this vulnerability:
  ├── auth/handler.py       → calls get_user() directly
  ├── api/routes.py         → via auth/handler.py
  ├── middleware/session.py → via api/routes.py
  ├── api/admin.py          → calls get_user() directly
  └── ... 3 more

  Any of these entry points exposes the SQL injection.
```

### AI authorship detection

`autopsy/detection/heuristics.py` scores changed code with seven weighted signals. `likely_ai` sections are scanned first.

| Signal | Weight | What it measures |
|--------|--------|-----------------|
| Bulk Addition | 0.20 | Large blocks added in a single commit |
| Boilerplate Density | 0.15 | Ratio of template/scaffold patterns |
| Complete Functions | 0.15 | Fully implemented functions with no TODOs |
| Missing Edge Cases | 0.15 | Happy-path-only handling |
| Commit Message | 0.15 | "Add feature X" with no context or discussion |
| Uniform Style | 0.10 | Consistency of formatting throughout |
| Generated Comments | 0.10 | Docstrings that restate the code |

A weighted score ≥ 0.5 sets `likely_ai`. An explicit AI-authorship marker in the commit message (`commit_message` signal ≥ 0.95) also sets it on its own, because a weighted average otherwise dilutes a single decisive signal below threshold.

### Vulnerability categories

The prompt taxonomy (`autopsy/llm/prompts.py`) plus the categories exercised by the benchmarks:

SQLi · XSS · Auth Bypass · Path Traversal · SSRF · Command Injection · Code Injection · Insecure Deserialization · XXE · SSTI · Weak Crypto (e.g. MD5/SHA1 password hashing) · Secrets Exposure · Race Conditions · Unvalidated Input

Categories are normalized by the benchmark scorer so findings can be compared against other tools' taxonomies.

---

## Measured results

All numbers were measured in this repository and are reproducible via `benchmark/`. Recall means: did the tool find the labeled vulnerabilities. Pinned baseline versions: CodeQL 2.25.6, Semgrep 1.167.0, Bandit 1.9.4.

### OWASP pygoat — third-party app, 11 in-scope vulns, frozen matcher

| Tool | Recall (file + category + ±5 lines) | Findings |
|---|---|---|
| Semgrep (`p/python`) | 64% (7/11) | 14 |
| Bandit | 45% (5/11) | 42 |
| CodeQL (`security-extended`) | 82% (9/11) | 37 |
| Raw Sonnet (single prompt, no graph) | 68% (mean of 2 runs: 7/11, 8/11) | ~19 |
| Autopsy (windowed) | 100% (11/11), both runs | ~110 |

Autopsy's set is a strict superset of every static baseline on this target. Paired McNemar reaches significance against Bandit (p = 0.031); against Semgrep and CodeQL the direction is the same but n = 11 limits power.

### SecurityEval — 121 vulnerable Python files, per-file detection

| Tool | Per-file detection |
|---|---|
| Semgrep (`p/python`) | 19% (23/121) |
| Bandit | 40% (49/121) |
| CodeQL (`security-extended`) | 42% (51/121) |
| Autopsy (full LLM pipeline, windowed) | 95% (115/121) |

### TypeScript demo

Autopsy 95% against raw single-prompt 75%, indicating the pipeline is not Python-specific.

### Specificity on clean code

On a held-out safe code set, Autopsy reported 0 false vulnerabilities per KLOC.

### Ablations

- **Windowing vs single prompt:** +31.8 points on pygoat (95% CI [+27, +36]).
- **Dependency-graph note, on vs off:** +0.0 ± 0.0 points on pygoat. Windowing alone saturates this target, so the cross-file note's marginal recall contribution here is zero. The note is claimed only where it is measured to help: cross-file cases, and as the scaffolding blast radius depends on.

### Matched-budget control (pre-registered)

Given roughly 1.5× the windowed arm's budget, a pooled single-prompt baseline (union of 5 runs, $1.69) also reaches 11/11. On pygoat the windowing advantage is therefore an efficiency result — full recall in one pass (~$1.13) where repeated single-prompt sampling needs about four pooled passes ($1.35) to match — and not evidence that windowing recovers vulnerabilities single prompting categorically cannot. See `benchmark/preregistration_matched_budget.md` and `benchmark/results/matched_budget/summary.md`.

### Scope and limitations

- **Python is the most exercised path.** TS/JS are supported and measured (95% on the TS demo), but coverage is thinner.
- **SecurityEval 95% is file-level detection** — whether Autopsy flagged something in a vulnerable file — not exact line or category localization.
- **The pygoat number is recall, not precision.** Autopsy emits roughly 110 deduped findings against 11 labels. It does not false-positive on the held-out safe set (0/KLOC), but the finding count is not a precision claim.
- **The pygoat edge is an efficiency claim** under matched budget, not a unique-capability claim.
- **Benchmarks cover statically-decidable vulnerabilities only.** Misconfiguration, vulnerable-dependency, and business-logic access-control issues are outside the labeled sets.
- **LLM modes are nondeterministic** (the client exposes no temperature control), so individual runs vary; reported numbers are means over repeats.

---

## Architecture

```
autopsy/
├── cli/
│   ├── main.py                    # Typer CLI (scan/debug/orient/graph/serve)
│   ├── interactive.py             # Single-keypress REPL (readchar)
│   └── splash.py                  # Banner
├── parser/
│   ├── core.py                    # Tree-sitter repo parsing → AST model
│   ├── languages.py               # Grammar registry (py/js/jsx/ts/tsx)
│   ├── extractors.py              # Function/class/import/call extraction
│   └── models.py                  # Parsed-repo dataclasses
├── graph/
│   ├── builder.py                 # NetworkX construction, build_graph_at_commit,
│   │                              # diff_graphs, _normalize_graph_paths
│   ├── subgraph.py                # Bounded BFS subgraph extraction (max 50 nodes)
│   ├── traversal.py               # Traversal + reverse-BFS blast radius
│   └── visualize.py               # Force-directed visualization payload
├── detection/
│   ├── deletions.py               # Comment boundary detection, zero-footprint
│   │                              # activation, deletion output formatters
│   ├── static_rules.py            # SQL string injection + weak hashing (no LLM)
│   ├── ignored_returns.py         # Discarded security-gate returns (no LLM)
│   └── heuristics.py              # 7-signal AI authorship detector
├── llm/
│   ├── pipeline.py                # scan/debug/orient streams, triage, blast radius
│   ├── chunking.py                # Windowed map-reduce scan + finding dedup
│   ├── client.py                  # Anthropic client, model pins, usage accounting
│   └── prompts.py                 # Prompt taxonomy + finding format
├── git/
│   └── diff.py                    # Diff extraction, ref resolution
├── cache/
│   └── embeddings.py              # Voyage embedding cache (optional dependency)
└── server/
    └── app.py                     # FastAPI server (port 7891)
        ├── POST /api/debug
        ├── POST /api/scan
        ├── POST /api/orient
        ├── POST /api/graph
        ├── POST /api/graph/visual
        └── GET  /api/health

extension/
└── src/
    ├── extension.ts               # VS Code extension entry point
    ├── panel.ts                   # Streaming webview panel
    ├── diagnostics.ts             # Inline diagnostics
    ├── graphPanel.ts              # Force-directed dependency graph
    └── client.ts                  # HTTP/SSE client for the local server
```

### VS Code extension

The extension communicates with the FastAPI server over `127.0.0.1:7891`. It starts the server on activation and polls `/api/health` until ready.

- Streaming webview panel — results arrive incrementally via Server-Sent Events
- Inline diagnostics — vulnerable lines are underlined in the editor and listed in the Problems panel
- Interactive graph — force-directed, draggable nodes, color-coded by node type

The server fingerprints a repository by `(relative_path, mtime_ns)` over supported files and caches the parsed graph, so repeated requests against an unchanged tree skip re-parsing.

### CLI REPL

Running `autopsy` with no arguments launches the interactive interface:

```
    A U T O P S Y   v0.1.0
    AI Vulnerability Detective
    ─────────────────────────────────
    Repo: ~/projects/my-app

  > d  DEBUG THIS      Trace a bug across the dependency graph
    s  SCAN THIS       Find vulnerabilities in AI-generated code
    o  ORIENT ME       Map this repo's architecture
    g  GRAPH           Show dependency graph stats
    q  Quit
```

Navigation is by arrow keys or the mode letter. The menu returns after each command; `q` or Ctrl+C exits. `autopsy serve` starts the FastAPI server used by the extension.

---

## Tech stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Code parsing | Tree-sitter ≥ 0.23 | AST generation for Python, JS/JSX, TS, TSX |
| Graph engine | NetworkX ≥ 3.2 | Graph construction, traversal, snapshotting, diffing |
| Git integration | GitPython ≥ 3.1.40 | Diffs, commit history, blob reads for graph snapshots |
| LLM triage | Claude Haiku 4.5 (`claude-haiku-4-5-20251001`) | JSON triage pass (2048 output tokens) |
| LLM analysis | Claude Sonnet 4.5 (`claude-sonnet-4-5-20250929`) | Streaming analysis (8192 output tokens) |
| Code embeddings | Voyage AI `voyage-code-2` (optional) | Semantic similarity for subgraph selection |
| API server | FastAPI ≥ 0.109 + Uvicorn | Local server for the VS Code extension |
| CLI | Typer + Rich + readchar | Terminal REPL |
| Extension | TypeScript + VS Code API | Editor integration |
| Streaming | Server-Sent Events | Output to the VS Code panel |

The Sonnet output cap was raised from 4096 to 8192 because 4096 truncated scans mid-finding.

---

## Installation

Install from source:

```bash
git clone https://github.com/annenolte/autopsy
cd autopsy
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Set an Anthropic API key:

```bash
export ANTHROPIC_API_KEY=your_key_here
```

A `.env` file in the repository root is loaded automatically via `python-dotenv`; copy `.env.example` to `.env` and fill it in. The deterministic detection layer runs with no key — see `--no-llm`.

Optional semantic subgraph selection:

```bash
pip install -e ".[embeddings]"     # adds voyageai
export VOYAGE_API_KEY=your_key_here
```

The VS Code extension is in `extension/` and is not published to the marketplace. Build and install it locally:

```bash
cd extension && npm install && npm run compile
npx vsce package                  # produces autopsy-0.1.0.vsix
code --install-extension autopsy-0.1.0.vsix
```

---

## Usage

### CLI

```bash
# Interactive mode
autopsy

# Scan a repo's most recent changes
autopsy scan /path/to/repo

# Scan uncommitted working-tree changes
autopsy scan /path/to/repo --uncommitted

# Scan a specific ref range
autopsy scan /path/to/repo --base main --head HEAD

# Deterministic layer only — deletion analysis, static rules, authorship. No API calls.
autopsy scan /path/to/repo --no-llm

# Debug an error
autopsy debug /path/to/repo --query "TypeError: cannot read property of undefined"

# Debug a specific function with deeper traversal
autopsy debug /path/to/repo --target get_user --depth 5

# Architecture map
autopsy orient /path/to/repo

# Graph stats, or a target's subgraph
autopsy graph /path/to/repo
autopsy graph /path/to/repo --target db.py --view

# Server for the VS Code extension
autopsy serve --port 7891
```

### VS Code

With the extension installed and a repository open:

- `Cmd+Shift+D` — Debug This
- `Cmd+Shift+S` — Scan This
- `Cmd+Shift+O` — Orient Me

Results stream into the Autopsy panel, and vulnerable lines are underlined in the editor.

---

## Cost

Token usage is tracked per model (`reset_usage` / `get_usage` in `autopsy/llm/client.py`), so cost is measured rather than estimated.

| Workload | Measured cost |
|---|---|
| Deterministic detectors + deletion analysis (`--no-llm`) | $0.00 — no API calls |
| Typical diff scan (Haiku triage + Sonnet analysis) | ~$0.12–0.46 |
| Full windowed scan of pygoat `introduction/` | ~$1.13, ~20 min wall time |
| Single-prompt baseline on the same target | ~$0.34/run |

Cost controls: Haiku handles triage, Sonnet runs only on confirmed findings, the subgraph is capped at 50 nodes, and embeddings are cached to disk. Graph snapshots for deletion analysis use direct blob reads and add no API calls. Per-run cost from token usage at pinned list prices is reproducible via `benchmark/measure_cost_runtime.py`.

---

## Reproducing the evaluation

The evaluation is frozen under `benchmark/`. `benchmark/FROZEN_PROTOCOL.md` pins the targets, the matcher, and the tool versions.

**Environment**

- Python ≥ 3.10
- An Anthropic API key (the scan makes live calls to Haiku and Sonnet)

```bash
# 1. Install Autopsy and its dependencies (editable install)
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. Provide your API key (never commit it — .env is gitignored)
cp .env.example .env        # then edit .env and set ANTHROPIC_API_KEY=sk-...
#   or: export ANTHROPIC_API_KEY=sk-...
```

**Core harness**

```bash
# Single live run (default fuzz tolerance = ±5 lines)
python benchmark/eval.py

# Mean ± standard deviation across repeated runs
python benchmark/eval.py --repeat 5

# The looser legacy matching used during development
python benchmark/eval.py --fuzz-lines 25

# Evaluation scenario (see benchmark/README.md):
#   whole-file = each vulnerable file is net-new AI-generated code (original eval)
#   safe       = diff against a clean baseline (default; harder, more conservative)
python benchmark/eval.py --baseline-mode whole-file --repeat 5

# Ablation: same model, same prompt, same scorer — the only difference is
# Autopsy's graph pipeline.
python benchmark/eval.py --arm both --repeat 5

# Windowed map-reduce scanning, and the graph-note ablation
python benchmark/eval.py --chunked --window-lines 400
python benchmark/eval.py --chunked --graph-mode off      # off | note | subgraph
python benchmark/eval.py --no-graph                      # drop graph context entirely

# Offline wiring check — builds the graph and diff and self-tests the matcher
# with no API call (also the automatic fallback when no key is set)
python benchmark/eval.py --dry-run
```

**Other harnesses**

| Script | What it measures |
|---|---|
| `eval_securityeval.py` / `run_securityeval_repeats.py` | Per-file detection across SecurityEval's 121 vulnerable Python files |
| `compare_tools.py` | Semgrep and Bandit head-to-head on a target, same matcher |
| `run_codeql_baseline.py` + `codeql_sarif_adapter.py` | CodeQL `security-extended` SARIF scored by the frozen matcher |
| `eval_deletions.py` | Deterministic deletion detectors — no API calls |
| `validate_heldout.py` | Static rules validated on code they were not written for (`benchmark/heldout/`) |
| `run_specificity.py` | False vulnerabilities per KLOC on clean code |
| `eval_authorship.py` / `eval_authorship_classifier.py` | The 7-signal AI-authorship detector |
| `eval_subgraph_caps.py` | Sensitivity to the 50-node subgraph cap |
| `measure_cost_runtime.py` / `measure_haiku_stages.py` | USD cost and wall time from token usage at pinned list prices |
| `per_category.py` / `stats.py` | Per-category breakdowns and significance tests |

Supporting documents: `BASELINES.md`, `SECURITYEVAL.md`, `AUTHORSHIP.md`, `SUBGRAPH_CAPS.md`, `TIMING.md`, `preregistration_matched_budget.md`.

**Output shape.** The harness prints the dependency-graph and diff sizes, streams the scan, then prints a results table — true positives, false positives, false negatives, and precision / recall / F1 as whole-number percentages — followed by which ground-truth IDs were true positives, which were missed, and which findings were false positives. A JSON record of every run, including raw scan output, is written to `benchmark/results/eval_<timestamp>.json`.

> **Runs vary.** The scan calls Claude with the model's default sampling (the
> current client exposes no temperature control), so the exact finding set — and
> therefore precision and recall — shifts between runs. Use `--repeat N` to
> characterize the spread rather than reading a single run as definitive.
>
> **Model note.** The analysis model originally used in the paper,
> `claude-sonnet-4-20250514`, has been retired by Anthropic (live calls return a
> 404). The client is pinned to its date-stamped successor,
> `claude-sonnet-4-5-20250929`, so the benchmark runs reproducibly; absolute
> numbers differ from the original model. The triage model
> (`claude-haiku-4-5-20251001`) is unchanged. Ensure Autopsy is installed
> editable from this repository (`pip install -e .`) so the benchmark exercises
> this code rather than another local checkout.

### Benchmark targets

- **`demo_project/`** (repository root) — the vulnerable target: a small
  Flask-style user-management module (search, profile update, export, admin
  tools) carrying twelve planted vulnerabilities (SQL injection, auth bypass,
  MD5 password hashing) across six files.
- **`benchmark/baseline/`** — a reconstructed clean version of the same module:
  identical structure and function signatures with the vulnerabilities removed
  (bound parameters, token expiry/scope checks, PBKDF2 hashing, enforced
  permission checks). It is not recovered original source — no pre-vulnerability
  version was ever committed — so each file is labeled as a reconstruction in its
  header. The baseline is the "before" state; the vulnerable demo is the "after"
  state.
- **`benchmark/pygoat/`** — labels for OWASP pygoat pinned at `19d17cc8`
  (2026-03-28): `ground_truth_pygoat.json` marks 11 in-scope vulnerabilities.
  pygoat itself is not vendored — clone it from
  `github.com/adeyosemanputra/pygoat`; the ground truth references line numbers
  only.
- **`benchmark/js_demo/`** — the TypeScript/JavaScript target.
- **`benchmark/heldout/`** — `safe/` and `vulnerable/` code the static rules were
  not written against, for generality and specificity checks.
- **`benchmark/deletion/`** — targets for the deletion-detector tests.
- **`benchmark/make_diff.py`** — builds a throwaway git repository with two
  commits (baseline → vulnerable) and emits the unified diff, mirroring how
  `autopsy scan` diffs two refs and feeds the diff and the repository's git
  object database into the scan pipeline.
- **`benchmark/ground_truth.json`** — the authoritative list of planted
  vulnerabilities (`id`, `file`, `category`, `line_start`, `line_end`,
  `description`), with line numbers read directly from `demo_project`. A finding
  counts as a true positive when its file basename matches, its normalized
  category matches, and its reported line is within `--fuzz-lines` of the labeled
  range; matching is one-to-one. One entry (`sqli-search-service`) is marked
  `"provisional": true` and is excluded from scoring unless you pass
  `--include-provisional` — see its `provisional_reason` field.

### Replication and failure analysis

The August 2026 replication re-ran the evaluation end to end against the current
models, and a companion pass examined what Autopsy consistently fails to find.
Three documents cover it:

- **[`benchmark/results/results_summary_aug2026.md`](benchmark/results/results_summary_aug2026.md)**
  — results across all phases, with the paid-run ledger and a dated correction
  appended below the separator. Raw per-run artifacts, including the runs that
  failed and were retried, are alongside it under `benchmark/results/`.
- **[`benchmark/results/securityeval_aug2026/stable_misses_analysis.md`](benchmark/results/securityeval_aug2026/stable_misses_analysis.md)**
  — the qualitative failure analysis: which SecurityEval cases are missed
  repeatedly rather than by sampling noise, and the late-file deficit observed on
  pygoat.
- **[`benchmark/prereg_addendum_20260811.md`](benchmark/prereg_addendum_20260811.md)**
  — the addendum registering the replication and the precision extension, written
  before any API call in that round.

---

## Citing this work

This repository is the archived reproducibility artifact accompanying the paper.
Machine-readable metadata is in [`CITATION.cff`](CITATION.cff) and
[`.zenodo.json`](.zenodo.json).

Cite the concept DOI ([10.5281/zenodo.21614411](https://doi.org/10.5281/zenodo.21614411))
to reference the artifact in general — it resolves to the newest release. Cite the
version DOI shown on a specific Zenodo release when the exact state of the code and
results matters.

```bibtex
@software{nolte_autopsy,
  author  = {Nolte, Anne},
  title   = {Autopsy: detecting vulnerabilities in AI-generated code by
             reasoning across dependency graphs},
  year    = {2026},
  doi     = {10.5281/zenodo.21614411},
  url     = {https://github.com/annenolte/autopsy-public},
  license = {MIT}
}
```

---

## Comparison with other tools

Capability matrix. The ✓/✗ marks describe what each tool is designed to do, not how well it does it; for measured detection rates see [Measured results](#measured-results).

| | Copilot / Cursor | Sentry | Semgrep | Autopsy |
|---|---|---|---|---|
| Finds vulnerabilities proactively | ✗ | ✗ | ✓ | ✓ |
| Selects which files to examine | ✗ | ✗ | ✗ | ✓ |
| Traces cross-file root causes | ✗ | ✓ (post-production) | ✗ | ✓ |
| Detects AI-generated code | ✗ | ✗ | ✗ | ✓ |
| Reports blast radius | ✗ | ✗ | ✗ | ✓ |
| Catches deletion-activated code | ✗ | ✗ | ✗ | ✓ |
| Detects security control deletion | ✗ | ✗ | ✗ | ✓ |
| Detects broken dependencies | ✗ | ✓ (runtime) | ✗ | ✓ |
| Runs pre-merge | ✓ | ✗ | ✓ | ✓ |
| Operates on the repository directly | ✗ | ✓ | ✓ | ✓ |
| pygoat recall (11 labeled vulns) | — | — | 64% | 100% |

Semgrep and CodeQL are deterministic and fast and carry no per-run cost; Autopsy's LLM layer is neither, and the two are complementary rather than substitutes. The rows where Autopsy is alone are consequences of the graph and the deletion analysis, which is the part of the design the benchmarks are meant to test.

---

## Provenance

Initial version built at Los Altos Hacks X, April 11–12, 2026, and developed since.

Anne Nolte — [GitHub](https://github.com/annenolte)
