"""Deletion-benchmark test (reviewer issue #6).

Confirms the deletion-aware detectors recover the two planted deletion-based
vulnerabilities, and documents the comment detector's over-fire (it flags any
deleted triple-quote, including a benign docstring on a removed function).
No LLM / API.
"""
import sys
import tempfile
from pathlib import Path

_BENCH = Path(__file__).resolve().parent.parent / "benchmark"
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

from make_diff import make_diff
from autopsy.detection.deletions import detect_comment_boundary_deletions
from autopsy.graph.builder import build_graph_at_commit, diff_graphs

BEFORE = _BENCH / "deletion" / "before"
AFTER = _BENCH / "deletion" / "after"


def _run():
    tmp = tempfile.mkdtemp()
    repo = Path(tmp) / "repo"
    diff_text, _ = make_diff(BEFORE, AFTER, repo)
    comment_hits = detect_comment_boundary_deletions(diff_text)
    gd = diff_graphs(build_graph_at_commit(str(repo), "HEAD~1"),
                     build_graph_at_commit(str(repo), "HEAD"))
    return comment_hits, gd


def test_comment_boundary_activation_detected():
    comment_hits, _ = _run()
    files = {h["file"] for h in comment_hits}
    assert any(f.endswith("activation.py") for f in files)


def test_security_control_deletion_detected():
    _, gd = _run()
    names = {d["name"] for d in gd.get("security_critical_deletions", [])}
    assert any("authorize_request" in n for n in names)


def test_comment_detector_suppresses_benign_docstring():
    # Refined heuristic (Part 1C): deleting a normal function whose body is a
    # one-line docstring no longer trips the comment-boundary detector. The
    # opener line is self-closing (`"""text"""`), so nothing executable is
    # revealed — the detector now suppresses it. auth_layer.py is still caught,
    # but by the security-control-deletion detector (see the other test), not by
    # the comment-boundary detector. This replaces the old "over-fires" test.
    comment_hits, _ = _run()
    files = [h["file"] for h in comment_hits]
    assert not any(f.endswith("auth_layer.py") for f in files)
    # The real activation (executable code revealed) is still flagged.
    assert any(f.endswith("activation.py") for f in files)
