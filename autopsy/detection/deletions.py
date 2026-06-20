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


# Comment-block opening delimiters by language. The closing delimiter is
# intentionally NOT in this map — deleting a closer turns live code dead
# (a far less dangerous direction).
COMMENT_OPENERS: dict[str, tuple[str, str]] = {
    '"""':    ("Python",   "multiline string / docstring opener"),
    "'''":    ("Python",   "multiline string opener"),
    "/*":     ("C-style",  "block comment opener (JS/TS/Java/Go/C/C++)"),
    "#=":     ("Julia",    "block comment opener"),
    "--[[":   ("Lua",      "block comment opener"),
    "=begin": ("Ruby",     "block comment opener"),
    "<!--":   ("HTML/XML", "comment opener"),
}


def detect_comment_boundary_deletions(git_diff_text: str) -> list[dict]:
    """Scan a unified git diff for deleted comment-boundary openers.

    A deleted opener means an entire block of previously dead code is now
    live — and that block will NOT appear as additions in this diff. Any
    addition-only scanner will completely miss it.

    Returns a list of dicts:
        {file, deleted_delimiter, raw_line, severity, description}
    """
    findings: list[dict] = []
    current_file: str | None = None

    for raw_line in git_diff_text.split("\n"):
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
                findings.append({
                    "file": current_file or "unknown",
                    "deleted_delimiter": opener,
                    "raw_line": raw_line,
                    "severity": "HIGH",
                    "description": (
                        f"Zero-footprint activation: a '{opener}' "
                        f"({lang} {desc}) was deleted. Code previously "
                        f"inside this comment block is now LIVE. The "
                        f"activated code does NOT appear as additions in "
                        f"this diff and will be missed by any diff-only "
                        f"scanner."
                    ),
                })
                break

    return findings


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
