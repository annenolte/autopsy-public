"""Convert a CodeQL SARIF file into the finding format the frozen matcher consumes.

This is the CodeQL analogue of the inline Semgrep/Bandit adapters in
`benchmark/compare_tools.py`. It produces exactly the same finding dicts those
adapters produce —

    {"category": <free text>, "title": <str>, "locations": [{"file", "line"}]}

— so CodeQL is scored by the *same* frozen matcher (`benchmark/eval.py`), with
the same category-normalization, dedupe, one-to-one assignment and ±5-line fuzz
as Semgrep, Bandit and Autopsy. No CodeQL-specific scoring is introduced here.

The `category` string is assembled from the CodeQL rule id, rule name, the
rule's CWE tags and its short description plus the result message — the analogue
of compare_tools' `f"{check} {cwe} {message}"` for Semgrep. The matcher's
`category_tokens()` reads natural-language needles ("sql injection", "command
injection", ...) out of this blob, so giving it the rule name + CWE tags lets a
CodeQL `py/sql-injection` hit normalize to the SQLi ground-truth category exactly
as Semgrep's `cwe` metadata does.

Path handling: SARIF artifact URIs are relative to the database source root.
We keep that relative path in `locations[].file` (the frozen matcher keys on the
*basename*, so this lines up with ground-truth paths like
`introduction/views.py`). When an absolute path is needed (SecurityEval file-level
detection, where basenames are reused across CWE folders) pass `source_root` and
read `locations[].abspath`.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote


def _collect_rules(run: dict) -> dict[str, dict]:
    """Map ruleId -> rule metadata, gathering from the driver and all extensions.

    CodeQL emits its query rules under tool.extensions[].rules (the driver
    typically carries few or none), so both must be scanned.
    """
    rules: dict[str, dict] = {}
    tool = run.get("tool", {})
    components = [tool.get("driver", {})] + list(tool.get("extensions", []) or [])
    for comp in components:
        for r in comp.get("rules", []) or []:
            rid = r.get("id")
            if rid and rid not in rules:
                rules[rid] = r
    return rules


def _cwe_tags(rule: dict) -> list[str]:
    """Extract human-readable CWE labels from a rule's tags.

    CodeQL tags look like 'external/cwe/cwe-089'; we surface both that and a
    'CWE-089' form so the matcher's category needles (which look for things like
    'sql injection') still have the rule name to read, and downstream reports can
    show the CWE.
    """
    tags = (rule.get("properties", {}) or {}).get("tags", []) or []
    out = []
    for t in tags:
        if "cwe" in t.lower():
            num = t.rsplit("/", 1)[-1]  # cwe-089
            out.append(num)
            digits = "".join(ch for ch in num if ch.isdigit())
            if digits:
                out.append(f"CWE-{digits}")
    return out


def _rule_text(rule: dict) -> str:
    """Name + short/full description text for a rule (drives category matching)."""
    parts = [
        rule.get("name", ""),
        rule.get("id", ""),
        (rule.get("shortDescription", {}) or {}).get("text", ""),
        (rule.get("fullDescription", {}) or {}).get("text", ""),
    ]
    return " ".join(p for p in parts if p)


def sarif_to_findings(
    sarif_path: Path, source_root: Path | None = None
) -> list[dict]:
    """Parse a CodeQL SARIF file into matcher-format findings.

    Each SARIF result becomes one finding with every physicalLocation it cites.
    Returns [] for a SARIF file with no runs/results (e.g. an empty database).
    """
    data = json.loads(Path(sarif_path).read_text())
    findings: list[dict] = []
    for run in data.get("runs", []):
        rules = _collect_rules(run)
        for res in run.get("results", []):
            rid = res.get("ruleId", "") or res.get("rule", {}).get("id", "")
            rule = rules.get(rid, {})
            cwes = _cwe_tags(rule)
            msg = (res.get("message", {}) or {}).get("text", "")
            # category blob, mirroring compare_tools' "<check> <cwe> <message>"
            category = " ".join(
                [rid, _rule_text(rule), " ".join(cwes), msg]
            ).strip()

            locations = []
            for loc in res.get("locations", []) or []:
                phys = loc.get("physicalLocation", {}) or {}
                uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
                uri = unquote(uri)
                line = (phys.get("region", {}) or {}).get("startLine", 0)
                if not uri:
                    continue
                entry = {"file": uri, "line": int(line or 0)}
                if source_root is not None:
                    entry["abspath"] = str((Path(source_root) / uri).resolve())
                if entry not in locations:
                    locations.append(entry)

            if not locations:
                continue
            findings.append({
                "category": category,
                "title": (rule.get("name") or rid or "codeql-finding"),
                "locations": locations,
                "rule_id": rid,
                "cwes": cwes,
            })
    return findings


def query_pack_versions(sarif_path: Path) -> dict[str, str]:
    """Read the analysis tool / query-pack versions recorded in the SARIF.

    These are the pinned versions the paper cites. Returns a flat
    {component-name: version} map drawn from tool.driver and tool.extensions.
    """
    data = json.loads(Path(sarif_path).read_text())
    out: dict[str, str] = {}
    for run in data.get("runs", []):
        tool = run.get("tool", {})
        for comp in [tool.get("driver", {})] + list(tool.get("extensions", []) or []):
            name = comp.get("name")
            ver = comp.get("semanticVersion") or comp.get("version")
            if name and ver:
                out[name] = ver
    return out


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Dump CodeQL SARIF as matcher findings")
    ap.add_argument("sarif", type=Path)
    ap.add_argument("--source-root", type=Path, default=None)
    args = ap.parse_args()
    fs = sarif_to_findings(args.sarif, args.source_root)
    print(f"{len(fs)} findings")
    print(json.dumps(fs, indent=2))
    print("pack versions:", json.dumps(query_pack_versions(args.sarif), indent=2))
