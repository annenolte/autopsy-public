"""Measure the AI-authorship heuristic's false-positive rate on human code.

Reviewer issues #8/#9: the 7-signal authorship heuristic uses hand-tuned weights
and was only validated anecdotally; it likely fires on ordinary human-written
code. This script runs the heuristic over real commits from a mature library's
**pre-2021 history** (before AI coding assistants were in wide use), so every
file the heuristic flags as "likely AI" is a false positive.

It reports two rates:
  - as-shipped: confidence >= 0.5 including the commit-message signal;
  - code-only : the same but with the commit-message signal removed, to isolate
    the source-code signals.

No LLM / API — the heuristic is deterministic.

    python benchmark/eval_authorship.py --repo /tmp/requests_human \
        --before 2021-01-01 --max-commits 80
"""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from git import Repo

from autopsy.detection.heuristics import analyze_commit, analyze_diff


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--before", default="2021-01-01",
                   help="Only commits before this date (human-era)")
    p.add_argument("--max-commits", type=int, default=80)
    p.add_argument("--min-added", type=int, default=10,
                   help="Ignore files with fewer added lines (heuristic returns ~0)")
    args = p.parse_args()

    repo = Repo(args.repo)
    shas = [c.hexsha for c in repo.iter_commits(before=args.before, max_count=args.max_commits)]
    print(f"repo={args.repo.name}  human-era commits sampled (before {args.before}): {len(shas)}")

    n_files = 0
    fp_shipped = 0
    fp_codeonly = 0
    conf_shipped = []
    conf_codeonly = []
    flagged_signals = Counter()

    for sha in shas:
        for res in analyze_commit(args.repo, sha):
            if not res.file_path.endswith(".py"):
                continue
            if res.lines_added < args.min_added:
                continue
            n_files += 1
            conf_shipped.append(res.confidence)
            if res.likely_ai:
                fp_shipped += 1
                for s in res.signals:
                    if s.score > 0.3:
                        flagged_signals[s.name] += 1
            # code-only: re-run without the commit message
            co = analyze_diff(res.diff_text, file_path=res.file_path)
            conf_codeonly.append(co.confidence)
            if co.likely_ai:
                fp_codeonly += 1

    if n_files == 0:
        print("No qualifying files found.")
        return

    def pct(x):
        return round(100 * x / n_files)

    print(f"\nHuman .py files analyzed (>= {args.min_added} added lines): {n_files}")
    print(f"  FALSE-POSITIVE rate (as-shipped, incl. commit msg): "
          f"{fp_shipped}/{n_files} = {pct(fp_shipped)}%  "
          f"(mean confidence {sum(conf_shipped)/n_files:.2f})")
    print(f"  FALSE-POSITIVE rate (code signals only):            "
          f"{fp_codeonly}/{n_files} = {pct(fp_codeonly)}%  "
          f"(mean confidence {sum(conf_codeonly)/n_files:.2f})")
    print(f"\n  Signals most responsible for false positives:")
    for name, cnt in flagged_signals.most_common():
        print(f"    {name}: {cnt}")


if __name__ == "__main__":
    main()
