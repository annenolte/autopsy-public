"""Self-contained behavioral tests for the AI-authorship heuristic.

These don't need a cloned corpus (that's what benchmark/eval_authorship.py is
for); they just lock the heuristic's basic discrimination so a refactor can't
silently break it.
"""
from autopsy.detection.heuristics import analyze_diff


# A terse, surgical human-style change: a few lines, no docstrings/boilerplate.
HUMAN_DIFF = """\
+    if user is None:
+        return None
+    name = user.get("name", "")
+    return name.strip()
"""

# A bulk, boilerplate-heavy addition: many complete functions, docstrings,
# section dividers, happy-path only. (No commit message — code signals only.)
AI_DIFF = "\n".join(
    ["+# " + "-" * 20]
    + [
        f"+def handler_{i}(payload):\n"
        f'+    """Handle event {i}.\n'
        f"+\n+    Args:\n+        payload: the event payload.\n+    Returns:\n+        dict result.\n+    \"\"\"\n"
        f"+    data = payload['data']\n"
        f"+    result = process(data)\n"
        f"+    return {{'ok': True, 'result': result}}\n"
        for i in range(6)
    ]
)


def test_terse_human_change_not_flagged():
    res = analyze_diff(HUMAN_DIFF, file_path="util.py")
    assert not res.likely_ai
    assert res.confidence < 0.5


def test_bulk_boilerplate_scores_higher_than_human():
    human = analyze_diff(HUMAN_DIFF, file_path="util.py").confidence
    ai = analyze_diff(AI_DIFF, file_path="handlers.py").confidence
    assert ai > human


def test_claude_coauthor_message_is_decisive():
    res = analyze_diff(HUMAN_DIFF, file_path="util.py",
                       commit_message="Add helper\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
    # the commit-message signal fires...
    assert any(s.name == "commit_message" and s.score >= 0.9 for s in res.signals)
    # ...and an explicit AI marker is now DECISIVE (the weighted average would
    # otherwise dilute it below 0.5).
    assert res.likely_ai is True


def test_normal_human_commit_not_flagged():
    res = analyze_diff(HUMAN_DIFF, file_path="util.py",
                       commit_message="Fix off-by-one in counter")
    assert res.likely_ai is False
