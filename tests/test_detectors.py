"""Tests for the deterministic security detectors.

These lock in two properties that matter for the evaluation:
  * the detectors fire on vulnerable code (including held-out code they were
    not written against), and
  * they produce no findings on the safe equivalents (no false positives).
"""
from pathlib import Path

from autopsy.detection.ignored_returns import detect_ignored_security_returns
from autopsy.detection.static_rules import (
    detect_static_rules,
    detect_sql_string_injection,
    detect_weak_hashing,
)

_ROOT = Path(__file__).resolve().parent.parent
DEMO = _ROOT / "demo_project"
SAFE_BASELINE = _ROOT / "benchmark" / "baseline"
HELDOUT_VULN = _ROOT / "benchmark" / "heldout" / "vulnerable"
HELDOUT_SAFE = _ROOT / "benchmark" / "heldout" / "safe"


def _cats(findings):
    return {f["category"] for f in findings}


# ── demo_project (the benchmark target) ───────────────────────────────────────

def test_ignored_return_detected_in_demo():
    findings = detect_ignored_security_returns(DEMO)
    assert any(
        f["callee"] == "check_permission" and f["cross_file"]
        and f["caller_file"] == "user_service.py"
        for f in findings
    )


def test_weak_hash_detected_in_demo():
    findings = detect_weak_hashing(DEMO)
    assert any(f["algorithm"] == "md5" and f["caller_file"] == "auth.py"
               for f in findings)


def test_sql_string_injection_detected_in_demo():
    findings = detect_sql_string_injection(DEMO)
    files = {(f["caller_file"], f["line"]) for f in findings}
    # delete_user and impersonate_user both f-string-inject user_id
    assert ("admin_api.py", 22) in files
    assert ("admin_api.py", 31) in files


# ── safe baseline must be clean (no false positives) ─────────────────────────

def test_no_findings_on_safe_baseline():
    assert detect_ignored_security_returns(SAFE_BASELINE) == []
    assert detect_static_rules(SAFE_BASELINE) == []


# ── held-out generality (code the rules were not written against) ────────────

def test_detectors_generalize_to_heldout_vulnerable():
    findings = detect_ignored_security_returns(HELDOUT_VULN) + detect_static_rules(HELDOUT_VULN)
    assert {"SQLi", "Weak Crypto", "Auth Bypass"} <= _cats(findings)


def test_no_findings_on_heldout_safe():
    findings = detect_ignored_security_returns(HELDOUT_SAFE) + detect_static_rules(HELDOUT_SAFE)
    assert findings == []
