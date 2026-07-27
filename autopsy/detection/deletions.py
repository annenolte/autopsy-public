"""Deletion-aware analysis for the SCAN THIS pipeline.

Addition-only diff scanning misses an entire class of high-impact changes:

  * Comment-boundary deletion — removing the opening delimiter of a multiline
    comment activates an entire dormant block of code that never appears as
    an addition in the git diff. The AST sees new live code, the diff shows
    only a two-character removal. A zero-footprint activation attack.

  * Security-control deletion — a function whose name matches an auth/
    validate/sanitize keyword is removed but its callers remain.

  * Broken dependency — a callee is removed while its caller survives.

This module is responsible for the raw-diff comment boundary scan, plus the
output formatters used by the scan pipeline. The structural pre/post graph
diff lives in autopsy/graph/builder.py.
"""

from __future__ import annotations

import re

# Reuse the deterministic sink patterns from the static-rules layer so the
# deletion detector and the live-code detector agree on what "dangerous" means.
from autopsy.detection.static_rules import _DBAPI_EXEC, _WEAK_HASHES


# Comment-block opening delimiters by language, mapped to their matching closer.
# The closing delimiter is intentionally NOT treated as a trigger — deleting a
# closer turns live code dead (a far less dangerous direction) — but we need it
# to know where the revealed (previously-commented) block ends.
COMMENT_OPENERS: dict[str, tuple[str, str]] = {
    '"""':    ("Python",   "multiline string / docstring opener"),
    "'''":    ("Python",   "multiline string opener"),
    "/*":     ("C-style",  "block comment opener (JS/TS/Java/Go/C/C++)"),
    "#=":     ("Julia",    "block comment opener"),
    "--[[":   ("Lua",      "block comment opener"),
    "=begin": ("Ruby",     "block comment opener"),
    "<!--":   ("HTML/XML", "comment opener"),
}

_CLOSERS: dict[str, str] = {
    '"""': '"""', "'''": "'''", "/*": "*/", "#=": "=#",
    "--[[": "]]", "=begin": "=end", "<!--": "-->",
}

# Extra sink call-names whose mere presence in a revealed block makes it
# dangerous regardless of taint. The two sets above (SQL exec + weak hashes)
# are reused verbatim from static_rules.py; these supplement them for the
# code-activation threat (the revealed block is attacker-chosen, so any
# code-execution / deserialization / SSRF primitive is a sink here).
_EXTRA_SINK_NAMES = {
    "eval", "exec", "popen", "system", "spawn", "fork", "compile",
    "loads", "load", "call", "run", "check_output", "Popen",
    "__import__", "getattr", "setattr",
}
_SINK_NAMES = _DBAPI_EXEC | _WEAK_HASHES | _EXTRA_SINK_NAMES

# A revealed line is "executable" if it defines or runs code. Comment-only,
# blank, or pure-prose lines do not match, so a comment/docstring-only block is
# suppressed (no zero-footprint activation: nothing executable was revealed).
_EXECUTABLE_RE = re.compile(
    r"""^\s*(
        (async\s+)?def\s+\w+        # function definition
        | class\s+\w+              # class definition
        | @\w[\w.]*                # decorator (e.g. @app.route)
        | (from\s+\S+\s+)?import\s+\S+   # import
        | \w[\w.]*\s*=[^=]         # assignment (not ==)
        | \w[\w.]*\s*\(            # a call
        | (return|raise|await|yield|with|for|while|if|elif|else|try)\b
    )""",
    re.VERBOSE,
)

# C-style / brace languages: defs and calls look different; a light check.
_EXECUTABLE_RE_BRACE = re.compile(
    r"""(
        function\s+\w*\s*\(        # function decl
        | \b\w+\s*=>               # arrow function
        | \b(var|let|const)\s+\w+  # binding
        | \w[\w.]*\s*\(            # a call
        | \breturn\b
    )""",
    re.VERBOSE,
)


def _revealed_block_is_dangerous(revealed: list[str], opener: str) -> tuple[bool, str]:
    """True if the revealed (previously-commented) lines contain executable
    definitions or a known sink. Comment-/prose-only blocks return False.

    Returns (is_dangerous, reason). `revealed` are the raw post-prefix code lines
    that were inside the comment block (context/added lines after the deleted
    opener, up to the matching closer).
    """
    exec_re = _EXECUTABLE_RE_BRACE if opener in ("/*",) else _EXECUTABLE_RE
    saw_executable = False
    saw_sink = None
    for ln in revealed:
        s = ln.strip()
        if not s:
            continue
        # Skip pure single-line comments (the block may still wrap prose).
        if s.startswith("#") or s.startswith("//"):
            continue
        # Sink: any known dangerous call-name invoked in the line.
        for call_name in re.findall(r"([A-Za-z_]\w*)\s*\(", s):
            if call_name in _SINK_NAMES:
                saw_sink = call_name
                break
        if saw_sink:
            return True, f"revealed code calls sink `{saw_sink}(...)`"
        if exec_re.search(s):
            saw_executable = True
    if saw_executable:
        return True, "revealed code contains executable definitions/statements"
    return False, "revealed block is comment/docstring/prose-only"


def detect_comment_boundary_deletions(git_diff_text: str) -> list[dict]:
    """Scan a unified git diff for deleted comment-boundary openers that REVEAL
    executable code.

    A deleted opener can mean an entire block of previously dead code is now
    live — and that block will NOT appear as additions in this diff. But deleting
    the opener of a comment/docstring that contained only prose is harmless. So
    this detector now fires only when the revealed block (the lines that follow
    the deleted opener, up to the matching closer) parses to executable
    definitions or contains a sink (reusing the static-rules sink patterns).
    Comment-/docstring-only activations are suppressed.

    Returns a list of dicts:
        {file, deleted_delimiter, raw_line, severity, description, trigger}
    """
    findings: list[dict] = []
    current_file: str | None = None

    lines = git_diff_text.split("\n")
    for i, raw_line in enumerate(lines):
        # Track current file from the diff headers. Prefer the +++ b/ line
        # (the post-image) since it reflects the file as it exists after the
        # change. Fall back to --- a/ when the post-image is /dev/null.
        if raw_line.startswith("+++ "):
            path = raw_line[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path != "/dev/null":
                current_file = path
            continue
        if raw_line.startswith("--- "):
            path = raw_line[4:].strip()
            if path.startswith("a/"):
                path = path[2:]
            if path != "/dev/null" and current_file is None:
                current_file = path
            continue

        # Only deletion lines matter, and only real ones — skip the
        # leading "---" file marker which also begins with "-".
        if not raw_line.startswith("-") or raw_line.startswith("--"):
            continue

        content = raw_line[1:].strip()
        if not content:
            continue

        for opener, (lang, desc) in COMMENT_OPENERS.items():
            if content == opener or content.startswith(opener):
                closer = _CLOSERS.get(opener, opener)
                # A self-closing single-line block (e.g. a one-line docstring
                # `"""text"""`, or `/* ... */`) reveals nothing when deleted —
                # the closer is on the same line. Skip it.
                if content != opener and closer in content[len(opener):]:
                    break
                revealed = _collect_revealed(lines, i + 1, closer)
                dangerous, reason = _revealed_block_is_dangerous(revealed, opener)
                if not dangerous:
                    break  # suppress comment/docstring-only activation
                findings.append({
                    "file": current_file or "unknown",
                    "deleted_delimiter": opener,
                    "raw_line": raw_line,
                    "severity": "HIGH",
                    "trigger": reason,
                    "description": (
                        f"Zero-footprint activation: a '{opener}' "
                        f"({lang} {desc}) was deleted and {reason}. Code "
                        f"previously inside this comment block is now LIVE. The "
                        f"activated code does NOT appear as additions in "
                        f"this diff and will be missed by any diff-only "
                        f"scanner."
                    ),
                })
                break

    return findings


def _collect_revealed(lines: list[str], start: int, closer: str) -> list[str]:
    """Gather the previously-commented code revealed after a deleted opener.

    Walks forward from `start` collecting context (' ') and added ('+') line
    contents until the matching `closer` delimiter or a hunk/file boundary.
    Deleted ('-') lines are skipped (they are leaving, not being revealed).
    """
    out: list[str] = []
    for raw in lines[start:]:
        if (raw.startswith("@@") or raw.startswith("diff --git")
                or raw.startswith("+++ ") or raw.startswith("--- ")
                or raw.startswith("index ")):
            break
        if not raw:
            continue
        prefix, body = raw[0], raw[1:]
        if prefix == "-":
            continue  # being removed, not revealed
        if prefix not in (" ", "+"):
            continue
        if body.strip().startswith(closer):
            break  # reached the end of the revealed block
        out.append(body)
    return out


# ---------------------------------------------------------------------------
# Output formatters — return Markdown-ish strings that the scan pipeline
# yields into the existing _stream_to_console renderer.
# ---------------------------------------------------------------------------

_RULE = "─" * 61


def format_comment_deletion_warning(findings: list[dict]) -> str:
    """Render a warning block for raw-diff comment boundary deletions."""
    if not findings:
        return ""

    lines: list[str] = [
        "⚠  ZERO-FOOTPRINT ACTIVATION DETECTED",
        _RULE,
        "A comment boundary was deleted. Code previously inside this",
        "comment block is now live and was not caught by diff scanning.",
        "",
    ]
    for f in findings:
        lang_desc = ""
        delim = f["deleted_delimiter"]
        if delim in COMMENT_OPENERS:
            lang, desc = COMMENT_OPENERS[delim]
            lang_desc = f"  ({lang} {desc})"
        lines.append(f"File: {f['file']}")
        lines.append(f"Deleted delimiter: {delim}{lang_desc}")
        lines.append(f"Severity: {f['severity']}")
        lines.append("")

    lines.append("Autopsy is scanning the newly activated code for vulnerabilities.")
    lines.append("This code does not appear as additions in your git diff.")
    lines.append("")
    return "\n".join(lines)


def format_security_deletion_warning(graph_diff: dict) -> str:
    """Render a warning block for deletions of probable security controls."""
    deletions = graph_diff.get("security_critical_deletions") or []
    if not deletions:
        return ""

    lines: list[str] = [
        "🚨  SECURITY CONTROL DELETED",
        _RULE,
        "The following functions appear to be security controls that",
        "were removed. Their callers may now be unprotected.",
        "",
    ]
    for d in deletions:
        kws = ", ".join(d["matched_keywords"])
        lines.append(f"{d['name']}()  matched keywords: {kws}")
        callers = d.get("called_by") or []
        if callers:
            lines.append(f"  Called by: {', '.join(callers)}")
        else:
            lines.append("  Called by: (no recorded callers in pre-commit graph)")
        lines.append(f"  In-degree (pre): {d.get('in_degree', 0)}")
        lines.append("")
    return "\n".join(lines)


def format_broken_edge_warning(graph_diff: dict) -> str:
    """Render a warning block for surviving callers of deleted callees."""
    broken = graph_diff.get("broken_edges") or []
    if not broken:
        return ""

    lines: list[str] = [
        "⚠  BROKEN DEPENDENCY DETECTED",
        _RULE,
        "The following functions call code that no longer exists.",
        "",
    ]
    for be in broken:
        caller = be["caller"]
        callee = be["missing_callee"]
        lines.append(f"{caller}  →  {callee}")
        lines.append(
            f"  {callee} was deleted. {caller} is now calling nothing."
        )
        upstream = be.get("callers_of_caller") or []
        if upstream:
            preview = ", ".join(upstream[:5])
            more = "" if len(upstream) <= 5 else f" (+{len(upstream) - 5} more)"
            lines.append(f"  Exposure chain — {caller} is called by: {preview}{more}")
        lines.append("")
    return "\n".join(lines)
