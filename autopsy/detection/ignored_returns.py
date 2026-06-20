"""Deterministic detection of ignored security-gate return values.

A whole class of authorization bugs looks like this:

    def update_user_profile(self, user_id, data, current_user):
        check_permission(current_user, user_id)   # <-- return value discarded!
        ...                                         # proceeds regardless

The call to the security gate is made, but its boolean result is never used to
decide anything — so the gate is decorative and access is never actually
enforced. This is precisely the kind of cross-file finding an LLM scan reports
unreliably (it tends to fixate on louder bugs like SQL injection in the same
function). But it is trivially decidable from the AST plus the dependency graph:

  * the dependency graph already records a `calls` edge from the caller to a
    security-named function (often in another file), and
  * the AST tells us whether that call's return value is consumed (assigned,
    tested in a condition, returned, passed as an argument) or thrown away
    (the call is a bare expression statement).

When the gate's result is thrown away, this module emits a high-confidence
finding deterministically — it does not depend on the model noticing. This is a
capability the dependency graph enables that a plain prompt does not reliably
reproduce.

Only the discard direction is flagged; a call whose result is used is safe.
"""

from __future__ import annotations

from pathlib import Path

from autopsy.parser.core import parse_file
from autopsy.parser.extractors import _find_all, _text
from autopsy.parser.languages import get_parser


# Function-name fragments that denote an authorization / validation gate whose
# return value is meant to be checked. Matched against the final name segment
# of the called function (so `auth.check_permission` and `self.check_permission`
# both match on `check_permission`).
SECURITY_GATE_KEYWORDS: tuple[str, ...] = (
    "check_permission", "has_permission", "is_authorized", "is_allowed",
    "authorize", "authorise", "authenticate", "can_access", "check_access",
    "check_auth", "require_permission", "verify", "validate", "ensure_",
)


def _is_security_gate(base_name: str) -> bool:
    name = base_name.lower()
    return any(kw in name for kw in SECURITY_GATE_KEYWORDS)


def _enclosing_function(line: int, parsed) -> str | None:
    """Qualified name of the function whose body contains `line`, if any."""
    best = None
    for fn in parsed.all_functions:
        if fn.line_start <= line <= fn.line_end:
            # innermost (largest start) wins
            if best is None or fn.line_start > best.line_start:
                best = fn
    return best.qualified_name if best else None


def detect_ignored_security_returns(
    root_dir: Path, only_files: list[str] | None = None
) -> list[dict]:
    """Find calls to security-gate functions whose return value is discarded.

    A return is "discarded" when the call is a bare expression statement (its
    direct parent in the AST is `expression_statement`) — i.e. it is not
    assigned, tested, returned, or passed onward.

    `only_files` (basenames or relative paths) optionally restricts the scan to
    changed files. Returns a list of finding dicts.
    """
    root_dir = Path(root_dir)
    py_paths = [p for p in sorted(root_dir.rglob("*.py"))]

    parsed_by_path = {}
    for p in py_paths:
        pf = parse_file(p)
        if pf is not None and pf.language == "python":
            parsed_by_path[p] = pf

    # Map a function's plain name -> the file that defines it, for cross-file
    # attribution (which file the discarded gate actually lives in).
    definition_file: dict[str, Path] = {}
    for p, pf in parsed_by_path.items():
        for fn in pf.all_functions:
            definition_file.setdefault(fn.name, p)

    only = set(only_files or [])

    findings: list[dict] = []
    for p, pf in parsed_by_path.items():
        rel = p.relative_to(root_dir).as_posix()
        if only and not (rel in only or p.name in only):
            continue

        tree = get_parser("python").parse(pf.source.encode("utf-8"))
        for call in _find_all(tree.root_node, "call"):
            func_node = call.child_by_field_name("function")
            if not func_node:
                continue
            base = _text(func_node).split(".")[-1]
            if not _is_security_gate(base):
                continue
            # Return value discarded iff the call stands alone as a statement.
            parent = call.parent
            if parent is None or parent.type != "expression_statement":
                continue

            line = call.start_point[0] + 1
            caller = _enclosing_function(line, pf)
            callee_path = definition_file.get(base)
            cross_file = callee_path is not None and callee_path != p
            callee_rel = (
                callee_path.relative_to(root_dir).as_posix() if callee_path else None
            )

            findings.append({
                "caller_file": rel,
                "caller_function": caller or "<module>",
                "callee": base,
                "callee_file": callee_rel,
                "cross_file": cross_file,
                "line": line,
                "severity": "HIGH",
                "category": "Auth Bypass",
                "description": (
                    f"{caller or 'code'} calls security gate {base}() but "
                    f"discards its return value, so the check never affects "
                    f"control flow — access is not enforced."
                ),
            })

    return findings


def format_ignored_return_findings(findings: list[dict]) -> str:
    """Render findings as SCAN-format `## [SEVERITY:]` blocks.

    Emitting in the standard finding format means these deterministic results
    flow through the same display and the same eval parser as model findings.
    """
    if not findings:
        return ""

    blocks: list[str] = []
    for f in findings:
        scope = "Cross-file" if f["cross_file"] else "Local"
        callee_loc = f" (defined in `{f['callee_file']}`)" if f["callee_file"] else ""
        blocks.append(
            f"## [SEVERITY: {f['severity']}] {scope} Auth Bypass: "
            f"ignored return of {f['callee']}()\n"
            f"**Category:** {f['category']}\n"
            f"**Location:** `{f['caller_file']}:{f['line']}`\n"
            f"**Attack Scenario:**\n"
            f"{f['caller_function']}() invokes the security gate "
            f"`{f['callee']}()`{callee_loc} but never uses its return value. "
            f"An unauthorized caller reaches the protected operation because the "
            f"gate's verdict is silently dropped.\n"
            f"**Fix:**\n"
            f"Branch on the gate's result, e.g. "
            f"`if not {f['callee']}(...): abort(403)`.\n"
            f"---\n"
        )
    return (
        "🔗 Graph-derived check: security gate return value discarded\n\n"
        + "\n".join(blocks)
    )
