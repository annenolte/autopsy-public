"""Tests for the eval harness finding-deduplication.

Dedup must collapse a finding reported twice at the same location+category
(so one issue is not counted as two false positives) while leaving genuinely
distinct nearby findings alone.
"""
import sys
from pathlib import Path

_BENCH = Path(__file__).resolve().parent.parent / "benchmark"
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import eval as E  # noqa: E402


def _f(category, file, line, title="x"):
    return {"severity": "HIGH", "title": title, "category": category,
            "locations": [{"file": file, "line": line}], "raw": ""}


def test_dedupe_merges_same_location_category():
    findings = [
        _f("Weak Crypto", "auth.py", 34, "static md5"),
        _f("Secrets Exposure", "auth.py", 34, "llm md5 dup"),  # same spot, same norm cat
    ]
    assert len(E.dedupe_findings(findings)) == 1


def test_dedupe_keeps_distinct_nearby_findings():
    # execute_query (18) and execute_read (26) are both SQLi but 8 lines apart:
    # they are distinct sinks and must NOT be merged.
    findings = [
        _f("SQLi", "database.py", 18),
        _f("SQLi", "database.py", 26),
    ]
    assert len(E.dedupe_findings(findings)) == 2


def test_dedupe_keeps_different_categories_same_line():
    findings = [
        _f("SQLi", "admin_api.py", 10),
        _f("Auth Bypass", "admin_api.py", 10),
    ]
    assert len(E.dedupe_findings(findings)) == 2
