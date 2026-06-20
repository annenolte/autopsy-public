"""Tests for deletion-aware analysis: comment boundary detection and graph diff."""

from __future__ import annotations

import networkx as nx

from autopsy.detection.deletions import detect_comment_boundary_deletions
from autopsy.graph.builder import diff_graphs


# ---------------------------------------------------------------------------
# Test 1 — Comment boundary activation
# ---------------------------------------------------------------------------

def test_comment_boundary_activation_is_detected():
    """Deleting a Python triple-quote opener that fronted a SQL injection
    block should be flagged HIGH and attributed to the right file."""
    diff = (
        'diff --git a/auth/handler.py b/auth/handler.py\n'
        'index 1111111..2222222 100644\n'
        '--- a/auth/handler.py\n'
        '+++ b/auth/handler.py\n'
        '@@ -10,7 +10,6 @@ def lookup(user_id):\n'
        '-    """\n'
        '     query = "SELECT * FROM users WHERE id = " + user_id\n'
        '     cursor.execute(query)\n'
        '     return cursor.fetchone()\n'
        '-    """\n'
        '     return None\n'
    )

    findings = detect_comment_boundary_deletions(diff)

    # At least one HIGH-severity finding pointing at the opener.
    openers = [f for f in findings if f["deleted_delimiter"] == '"""']
    assert openers, f"expected a triple-quote finding, got: {findings}"

    f = openers[0]
    assert f["file"] == "auth/handler.py"
    assert f["severity"] == "HIGH"
    assert "zero-footprint" in f["description"].lower()


# ---------------------------------------------------------------------------
# Test 2 — Security control deletion
# ---------------------------------------------------------------------------

def test_security_control_deletion_is_flagged_with_dependents():
    """A deleted node whose name matches a security keyword and has three
    predecessors should appear in security_critical_deletions with all
    three dependents listed and the matched keyword recorded."""
    pre = nx.DiGraph()
    pre.add_node(
        "func:auth/util.py::validate_user_input",
        type="function",
        name="validate_user_input",
    )
    for caller in ("func:api/routes.py::A", "func:api/admin.py::B", "func:mw/session.py::C"):
        pre.add_node(caller, type="function", name=caller.rsplit("::", 1)[-1])
        pre.add_edge(caller, "func:auth/util.py::validate_user_input", type="calls")

    # Post-graph: identical except validate_user_input no longer exists.
    post = nx.DiGraph()
    for caller in ("func:api/routes.py::A", "func:api/admin.py::B", "func:mw/session.py::C"):
        post.add_node(caller, type="function", name=caller.rsplit("::", 1)[-1])

    result = diff_graphs(pre, post)

    crits = result["security_critical_deletions"]
    assert len(crits) == 1
    entry = crits[0]
    assert entry["name"] == "validate_user_input"
    assert "validate" in entry["matched_keywords"]
    assert set(entry["called_by"]) == {
        "func:api/routes.py::A",
        "func:api/admin.py::B",
        "func:mw/session.py::C",
    }
    assert entry["in_degree"] == 3


# ---------------------------------------------------------------------------
# Test 3 — Broken edge detection
# ---------------------------------------------------------------------------

def test_broken_edge_is_detected_when_callee_is_removed():
    """An edge A→B in pre where B no longer exists in post should appear
    as a broken edge with the correct caller and missing callee."""
    pre = nx.DiGraph()
    pre.add_node("A", type="function", name="A")
    pre.add_node("B", type="function", name="B")
    pre.add_edge("A", "B", type="calls")

    post = nx.DiGraph()
    post.add_node("A", type="function", name="A")

    result = diff_graphs(pre, post)

    assert len(result["broken_edges"]) == 1
    be = result["broken_edges"][0]
    assert be["caller"] == "A"
    assert be["missing_callee"] == "B"
