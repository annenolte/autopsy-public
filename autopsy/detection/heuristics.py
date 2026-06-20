"""Heuristic signals that code was likely AI-generated.

Each heuristic returns a weighted signal. Combined score determines confidence
that a code block was written by an AI assistant (Copilot, Claude Code, Cursor, etc.).
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from pathlib import Path

from git import Repo, Commit, Diff
from git.exc import InvalidGitRepositoryError


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class AiSignal:
    """A single heuristic signal."""
    name: str
    score: float  # 0.0 to 1.0
    weight: float  # How much this signal matters
    detail: str = ""

    @property
    def weighted_score(self) -> float:
        return self.score * self.weight


@dataclass
class AiDetectionResult:
    """Detection result for a code block or commit."""
    file_path: str
    signals: list[AiSignal] = field(default_factory=list)
    lines_added: int = 0
    lines_removed: int = 0
    diff_text: str = ""

    @property
    def confidence(self) -> float:
        """Overall AI-generated confidence from 0.0 to 1.0."""
        if not self.signals:
            return 0.0
        total_weight = sum(s.weight for s in self.signals)
        if total_weight == 0:
            return 0.0
        return min(1.0, sum(s.weighted_score for s in self.signals) / total_weight)

    @property
    def likely_ai(self) -> bool:
        """True if confidence exceeds threshold, OR a definitive AI marker is
        present.

        Fix: the weighted-average confidence dilutes a single decisive signal —
        e.g. a 'Co-Authored-By: Claude/Copilot/Cursor' trailer scores the
        commit_message signal at 1.0, but averaged against ~zero content signals
        it lands at ~0.15 and never crosses 0.5. An explicit AI-authorship marker
        is ground truth, not a soft guess, so it should be decisive on its own.
        """
        if self.confidence >= 0.5:
            return True
        for s in self.signals:
            if s.name == "commit_message" and s.score >= 0.95:
                return True
        return False

    @property
    def summary(self) -> str:
        pct = int(self.confidence * 100)
        top = sorted(self.signals, key=lambda s: s.weighted_score, reverse=True)[:3]
        reasons = ", ".join(s.name for s in top if s.score > 0.3)
        return f"{pct}% AI-generated confidence ({reasons})"


# ---------------------------------------------------------------------------
# Individual heuristic detectors
# ---------------------------------------------------------------------------

def _signal_bulk_addition(added: int, removed: int) -> AiSignal:
    """Large single-commit additions with few deletions suggest AI generation.
    AI assistants typically add entire functions/files, rarely edit surgically.
    """
    if added == 0:
        return AiSignal("bulk_addition", 0.0, 0.2)

    ratio = added / max(removed, 1)
    # 50+ lines added with >5:1 add/remove ratio is suspicious
    if added >= 50 and ratio >= 5:
        score = min(1.0, (added / 100) * (ratio / 10))
    elif added >= 20 and ratio >= 3:
        score = 0.4
    else:
        score = 0.0

    return AiSignal(
        "bulk_addition", score, 0.2,
        f"+{added}/-{removed} lines (ratio {ratio:.1f}:1)",
    )


def _signal_boilerplate_density(code: str) -> AiSignal:
    """AI-generated code tends to be boilerplate-heavy: docstrings on everything,
    verbose error handling, formulaic patterns.
    """
    lines = code.strip().split("\n")
    if len(lines) < 5:
        return AiSignal("boilerplate_density", 0.0, 0.15)

    total = len(lines)
    docstring_lines = 0
    comment_lines = 0
    empty_lines = 0
    try_except_lines = 0

    in_docstring = False
    for line in lines:
        stripped = line.strip()

        if '"""' in stripped or "'''" in stripped:
            in_docstring = not in_docstring
            docstring_lines += 1
            continue
        if in_docstring:
            docstring_lines += 1
            continue
        if stripped.startswith("#") or stripped.startswith("//"):
            comment_lines += 1
        elif stripped == "":
            empty_lines += 1
        elif stripped in ("try:", "except:", "except Exception:", "except Exception as e:",
                          "finally:", "raise", "pass"):
            try_except_lines += 1

    boilerplate = docstring_lines + comment_lines + try_except_lines
    ratio = boilerplate / max(total - empty_lines, 1)

    # >30% boilerplate is suspicious
    if ratio > 0.4:
        score = 0.9
    elif ratio > 0.3:
        score = 0.6
    elif ratio > 0.2:
        score = 0.3
    else:
        score = 0.0

    return AiSignal(
        "boilerplate_density", score, 0.15,
        f"{int(ratio * 100)}% boilerplate ({docstring_lines} docstring, {comment_lines} comment, {try_except_lines} try/except lines)",
    )


def _signal_uniform_style(code: str) -> AiSignal:
    """AI code has unnaturally consistent formatting — same indentation,
    same patterns, same naming conventions throughout.
    Human code drifts over time.
    """
    lines = [l for l in code.split("\n") if l.strip()]
    if len(lines) < 10:
        return AiSignal("uniform_style", 0.0, 0.1)

    # Check indent consistency
    indents = []
    for line in lines:
        stripped = line.lstrip()
        if stripped:
            indent = len(line) - len(stripped)
            indents.append(indent)

    if len(indents) < 5:
        return AiSignal("uniform_style", 0.0, 0.1)

    # Low standard deviation of non-zero indents = very uniform
    nonzero_indents = [i for i in indents if i > 0]
    if nonzero_indents:
        stdev = statistics.stdev(nonzero_indents) if len(nonzero_indents) > 1 else 0
        # AI code typically uses exact multiples of 4 with no deviation
        all_multiples = all(i % 4 == 0 for i in nonzero_indents)
    else:
        stdev = 0
        all_multiples = True

    # Check line length consistency
    lengths = [len(l) for l in lines]
    len_stdev = statistics.stdev(lengths) if len(lengths) > 1 else 0

    # Very uniform = suspicious
    score = 0.0
    if all_multiples and stdev < 2:
        score += 0.4
    if len_stdev < 15:  # Very consistent line lengths
        score += 0.3

    return AiSignal(
        "uniform_style", min(1.0, score), 0.1,
        f"indent stdev={stdev:.1f}, line length stdev={len_stdev:.1f}, consistent_indent={all_multiples}",
    )


def _signal_complete_functions(code: str) -> AiSignal:
    """AI generates complete, self-contained functions. Humans often write
    incremental partial changes.
    """
    # Count complete function definitions in the added code
    func_pattern = re.compile(
        r"^[\+\s]*(def |function |const \w+ = (?:async )?\(|class )", re.MULTILINE
    )
    matches = func_pattern.findall(code)
    lines = code.strip().split("\n")
    added_lines = [l for l in lines if l.startswith("+") or not l.startswith("-")]

    if not matches or len(added_lines) < 10:
        return AiSignal("complete_functions", 0.0, 0.15)

    # Many complete functions in one commit = likely AI
    funcs_per_100_lines = len(matches) / (len(added_lines) / 100)

    if funcs_per_100_lines >= 3:
        score = 0.8
    elif funcs_per_100_lines >= 2:
        score = 0.5
    elif funcs_per_100_lines >= 1:
        score = 0.3
    else:
        score = 0.0

    return AiSignal(
        "complete_functions", score, 0.15,
        f"{len(matches)} complete function defs in {len(added_lines)} lines",
    )


def _signal_missing_edge_cases(code: str) -> AiSignal:
    """AI code often handles the happy path perfectly but misses edge cases:
    no null checks, no bounds checking, no timeout handling.
    """
    lines = code.strip().split("\n")
    if len(lines) < 10:
        return AiSignal("missing_edge_cases", 0.0, 0.15)

    # Count defensive patterns
    defensive_patterns = [
        r"if\s+\w+\s*(is None|== None|is not None|!= None|\?\?)",
        r"if\s+(not\s+)?\w+\s*:",  # Truthiness checks
        r"\.get\(",  # Dict .get() with default
        r"try\s*:",
        r"except\s+\w+",
        r"if\s+len\(",
        r"assert\s+",
        r"raise\s+\w+Error",
        r"timeout",
        r"max_retries",
    ]

    code_lower = code.lower()
    defensive_count = sum(
        len(re.findall(pat, code, re.IGNORECASE))
        for pat in defensive_patterns
    )

    # Count operations that SHOULD have checks
    risky_patterns = [
        r"\[\w+\]",  # Array/dict access
        r"\.read\(",  # File reads
        r"\.write\(",  # File writes
        r"\.execute\(",  # DB queries
        r"requests?\.(get|post|put|delete)\(",  # HTTP calls
        r"open\(",
        r"json\.loads?\(",
        r"int\(|float\(",  # Type conversions
    ]

    risky_count = sum(
        len(re.findall(pat, code, re.IGNORECASE))
        for pat in risky_patterns
    )

    if risky_count == 0:
        return AiSignal("missing_edge_cases", 0.0, 0.15)

    # Low ratio of defensive:risky = likely AI (handles happy path only)
    ratio = defensive_count / max(risky_count, 1)

    if ratio < 0.3:
        score = 0.7
    elif ratio < 0.5:
        score = 0.4
    elif ratio < 1.0:
        score = 0.2
    else:
        score = 0.0

    return AiSignal(
        "missing_edge_cases", score, 0.15,
        f"{defensive_count} defensive checks for {risky_count} risky operations (ratio {ratio:.2f})",
    )


def _signal_generated_comments(code: str) -> AiSignal:
    """AI assistants leave telltale comment patterns:
    section dividers, over-explained obvious code, 'Here's' phrasing.
    """
    ai_comment_patterns = [
        r"#\s*-{3,}",  # Section dividers: # ---
        r"//\s*-{3,}",
        r"#\s*TODO:?\s*(implement|add|fix|handle)",  # Generic TODOs
        r"#\s*(Here'?s?|This|The following|Below)",  # Explanatory intros
        r"#\s*\w+ function",  # "Main function", "Helper function"
        r"#\s*Import",  # "Import statements"
        r"#\s*(Initialize|Setup|Configure|Create)\s+(the|a)\s+",
        r"\"\"\"[\s\S]{0,50}\.\s*\n\s*\n\s*(Args|Returns|Raises|Parameters|Example)",  # Formulaic docstrings
    ]

    total_matches = 0
    for pat in ai_comment_patterns:
        total_matches += len(re.findall(pat, code, re.MULTILINE | re.IGNORECASE))

    lines = [l for l in code.split("\n") if l.strip()]
    if len(lines) < 5:
        return AiSignal("generated_comments", 0.0, 0.1)

    density = total_matches / (len(lines) / 20)  # per 20 lines

    if density >= 3:
        score = 0.9
    elif density >= 2:
        score = 0.6
    elif density >= 1:
        score = 0.3
    else:
        score = 0.0

    return AiSignal(
        "generated_comments", score, 0.1,
        f"{total_matches} AI-style comments in {len(lines)} lines",
    )


def _signal_commit_message(message: str) -> AiSignal:
    """AI-assisted commits often have generic or overly detailed messages."""
    ai_msg_patterns = [
        r"^(add|create|implement|update|fix|refactor)\s+\w+",  # Very generic verbs
        r"Co-Authored-By:.*claude|copilot|cursor|ai|anthropic",
        r"generated|auto-generated|ai-generated",
        r"^Initial (commit|implementation|setup)",
    ]

    score = 0.0
    for pat in ai_msg_patterns:
        if re.search(pat, message, re.IGNORECASE | re.MULTILINE):
            score = max(score, 0.6)

    # Very long commit messages for small changes = AI
    if len(message) > 200:
        score = max(score, 0.4)

    # "Co-Authored-By: Claude" is a dead giveaway
    if re.search(r"claude|anthropic|copilot|cursor", message, re.IGNORECASE):
        score = 1.0

    return AiSignal(
        "commit_message", score, 0.15,
        f"message: {message[:80]}...",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_diff(diff_text: str, file_path: str = "", commit_message: str = "") -> AiDetectionResult:
    """Analyze a diff string for AI-generation signals."""
    added_lines = [l[1:] for l in diff_text.split("\n") if l.startswith("+") and not l.startswith("+++")]
    removed_lines = [l[1:] for l in diff_text.split("\n") if l.startswith("-") and not l.startswith("---")]

    added_code = "\n".join(added_lines)
    num_added = len(added_lines)
    num_removed = len(removed_lines)

    signals = [
        _signal_bulk_addition(num_added, num_removed),
        _signal_boilerplate_density(added_code),
        _signal_uniform_style(added_code),
        _signal_complete_functions(diff_text),
        _signal_missing_edge_cases(added_code),
        _signal_generated_comments(added_code),
    ]

    if commit_message:
        signals.append(_signal_commit_message(commit_message))

    return AiDetectionResult(
        file_path=file_path,
        signals=signals,
        lines_added=num_added,
        lines_removed=num_removed,
        diff_text=diff_text,
    )


def analyze_commit(
    repo_path: Path,
    commit_sha: str = "HEAD",
) -> list[AiDetectionResult]:
    """Analyze all files changed in a commit for AI-generation signals."""
    try:
        repo = Repo(repo_path, search_parent_directories=True)
    except InvalidGitRepositoryError:
        return []

    commit = repo.commit(commit_sha)
    message = commit.message

    # Get parent for diff
    if commit.parents:
        parent = commit.parents[0]
        diffs = parent.diff(commit, create_patch=True)
    else:
        # First commit — diff against empty tree
        diffs = commit.diff(
            "4b825dc642cb6eb9a060e54bf899d69f82cf10b8",
            create_patch=True,
            R=True,
        )

    results = []
    for diff_item in diffs:
        file_path = diff_item.b_path or diff_item.a_path or ""

        try:
            diff_text = diff_item.diff.decode("utf-8", errors="replace")
        except (AttributeError, UnicodeDecodeError):
            continue

        result = analyze_diff(diff_text, file_path=file_path, commit_message=message)
        results.append(result)

    return results
