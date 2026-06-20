"""Generality check for the deterministic detectors on held-out code.

Confirms the AST/graph detectors fire on the held-out vulnerable fixture (code
they were not written against) and produce zero findings on its safe version.
This is what lets us claim the rules are general, not tuned to demo_project.

    python benchmark/validate_heldout.py
"""
from __future__ import annotations

import sys
from pathlib import Path

from autopsy.detection.ignored_returns import detect_ignored_security_returns
from autopsy.detection.static_rules import detect_static_rules

_HERE = Path(__file__).resolve().parent
VULN = _HERE / "heldout" / "vulnerable"
SAFE = _HERE / "heldout" / "safe"


def all_findings(root: Path):
    return detect_ignored_security_returns(root) + detect_static_rules(root)


def main() -> int:
    vuln = all_findings(VULN)
    safe = all_findings(SAFE)

    print("Held-out VULNERABLE findings:")
    for f in vuln:
        loc = f"{f['caller_file']}:{f['line']}"
        print(f"  [{f['category']}] {loc}  {f.get('caller_function','')}")
    print(f"\nHeld-out SAFE findings: {len(safe)}")
    for f in safe:
        print(f"  [{f['category']}] {f['caller_file']}:{f['line']}")

    cats = {f["category"] for f in vuln}
    ok = (
        len(safe) == 0
        and {"SQLi", "Weak Crypto", "Auth Bypass"} <= cats
    )
    print("\nGenerality check:",
          "PASS — detectors generalize and produce no false positives on safe code"
          if ok else "FAIL — see output above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
