"""Evaluate the deletion / zero-footprint detectors (reviewer issue #6).

Builds the before->after diff for benchmark/deletion/ and runs the two
deletion-aware detectors deterministically (no LLM, no API tokens):

  * detect_comment_boundary_deletions  — comment-boundary activation
  * diff_graphs(...).security_critical_deletions — removed security controls

then checks each is recovered against ground_truth_deletion.json. This backs the
paper's "deletion-based vulnerability" novelty with an actual experiment.

    python benchmark/eval_deletions.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_THIS = Path(__file__).resolve().parent
_ROOT = _THIS.parent
# _ROOT keeps `import autopsy` bound to this repo instead of an editable install.
for _p in (str(_THIS), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from make_diff import make_diff  # noqa: E402
from autopsy.detection.deletions import detect_comment_boundary_deletions  # noqa: E402
from autopsy.graph.builder import build_graph_at_commit, diff_graphs  # noqa: E402

BEFORE = _THIS / "deletion" / "before"
AFTER = _THIS / "deletion" / "after"
GT = _THIS / "deletion" / "ground_truth_deletion.json"


def run():
    truth = json.loads(GT.read_text())["vulnerabilities"]
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        diff_text, _changed = make_diff(BEFORE, AFTER, repo)  # before=baseline, after=head

        comment_hits = detect_comment_boundary_deletions(diff_text)
        pre = build_graph_at_commit(str(repo), "HEAD~1")
        post = build_graph_at_commit(str(repo), "HEAD")
        gd = diff_graphs(pre, post)
        sec_deletions = gd.get("security_critical_deletions", [])

    print(f"comment-boundary activations detected: {len(comment_hits)}")
    for h in comment_hits:
        print(f"   {h['file']}: deleted {h['deleted_delimiter']} ({h['severity']})")
    print(f"security-control deletions detected: {len(sec_deletions)}")
    for d in sec_deletions:
        print(f"   {d['name']}  keywords={d.get('matched_keywords')}")

    # Score each ground-truth deletion vuln
    results = []
    for t in truth:
        if t["type"] == "comment_boundary":
            caught = any(h["deleted_delimiter"] == t["delimiter"] for h in comment_hits)
        elif t["type"] == "security_control_deletion":
            caught = any(t["name"] in d["name"] for d in sec_deletions)
        else:
            caught = False
        results.append((t["id"], caught))
        print(f"   [{ 'CAUGHT' if caught else 'MISSED' }] {t['id']}")

    tp = sum(1 for _, c in results if c)
    print(f"\nDeletion-detector recall: {tp}/{len(truth)} = {round(100*tp/len(truth))}%")
    return results


if __name__ == "__main__":
    run()
