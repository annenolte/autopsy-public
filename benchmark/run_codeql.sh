#!/usr/bin/env bash
# Build CodeQL databases and run the standard security-extended suites on each
# benchmark that has a static-analysis baseline, writing SARIF under
# results/codeql/. This is the SARIF-generation half of the CodeQL baseline; the
# scoring half (same frozen matcher as Semgrep/Bandit) is run separately:
#
#     python benchmark/run_codeql_baseline.py
#
# CodeQL is a pure static analyzer (no model calls). We use the STANDARD
# security-extended query suites — NOT custom or hand-picked queries — so this
# measures off-the-shelf CodeQL, scored exactly like the other static baselines.
#
# Prereqs (done locally; nothing uploaded to GitHub):
#   1. Download the CodeQL CLI bundle (ships CLI + precompiled query packs):
#        https://github.com/github/codeql-action/releases  (codeql-bundle-v2.25.6)
#      and extract so that $CODEQL points at the `codeql` launcher.
#   2. Clone the benchmark sources (NOT vendored in this repo):
#        git clone https://github.com/adeyosemanputra/pygoat.git /tmp/pygoat
#        (cd /tmp/pygoat && git checkout 19d17cc8874861142b330636d068bbde54e86b85)
#        git clone https://github.com/s2e-lab/SecurityEval.git /tmp/SecurityEval
#
# Pinned for the paper (see results/codeql_baseline_report.md):
#   CodeQL CLI 2.25.6 | codeql/python-queries 1.8.4 | codeql/javascript-queries 2.3.11
set -euo pipefail

CODEQL="${CODEQL:-$HOME/codeql-home/codeql/codeql}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/results/codeql"
DBS="${DBS:-/tmp/codeql-dbs}"
PYGOAT="${PYGOAT:-/tmp/pygoat}"
SECEVAL="${SECEVAL:-/tmp/SecurityEval/Testcases_Insecure_Code}"

mkdir -p "$OUT" "$DBS"

# Record the pinned versions the paper cites.
"$CODEQL" version --format=json > "$OUT/codeql_version.json"
"$CODEQL" resolve packs --format=json > "$OUT/resolved_packs.json" 2>/dev/null || true

build_and_analyze () {  # <name> <language> <source-root> <suite>
  local name="$1" lang="$2" src="$3" suite="$4"
  echo "=== $name ($lang, $suite) ==="
  "$CODEQL" database create "$DBS/$name-db" --language="$lang" \
      --source-root="$src" --overwrite
  "$CODEQL" database analyze "$DBS/$name-db" "$suite" \
      --format=sarif-latest --output="$OUT/$name.sarif" --rerun
}

# pygoat — Python, no build needed (checked out at 19d17cc8).
build_and_analyze pygoat       python     "$PYGOAT"                python-security-extended.qls
# SecurityEval — Python, 121-file Insecure_Code set, one database.
build_and_analyze securityeval python     "$SECEVAL"               python-security-extended.qls
# TypeScript benchmark — CodeQL covers TS under --language=javascript.
build_and_analyze typescript   javascript "$REPO/benchmark/js_demo" javascript-security-extended.qls
# Synthetic Flask demo — Python (its comparison table includes static tools).
build_and_analyze demo_project python     "$REPO/demo_project"     python-security-extended.qls

echo "SARIF written under $OUT/. Now score with: python benchmark/run_codeql_baseline.py"
