"""Tests for AI-generation heuristic detectors."""

from __future__ import annotations

from autopsy.detection.heuristics import (
    _signal_bulk_addition,
    _signal_boilerplate_density,
    _signal_uniform_style,
    _signal_complete_functions,
    _signal_missing_edge_cases,
    _signal_generated_comments,
    _signal_commit_message,
    analyze_diff,
)


class TestBulkAddition:
    def test_bulk_addition_high(self):
        signal = _signal_bulk_addition(added=100, removed=5)
        assert signal.score > 0.5
        assert signal.name == "bulk_addition"

    def test_bulk_addition_low(self):
        signal = _signal_bulk_addition(added=5, removed=5)
        assert signal.score == 0.0

    def test_bulk_addition_zero_added(self):
        signal = _signal_bulk_addition(added=0, removed=10)
        assert signal.score == 0.0


class TestBoilerplateDensity:
    def test_boilerplate_density_high(self):
        # Code that is mostly docstrings and comments
        code = "\n".join(
            ['def foo():', '    """Docstring."""', "    pass"] * 5
            + ['# This is a comment'] * 10
            + ['try:', 'except:', 'pass'] * 3
            + ['x = 1'] * 5
        )
        signal = _signal_boilerplate_density(code)
        assert signal.score > 0.3

    def test_boilerplate_density_low(self):
        # Mostly real code, no comments
        code = "\n".join([f"x_{i} = {i} + 1" for i in range(30)])
        signal = _signal_boilerplate_density(code)
        assert signal.score == 0.0


class TestUniformStyle:
    def test_uniform_style_high(self):
        # Perfectly consistent indentation (multiples of 4)
        lines = []
        for i in range(20):
            if i % 3 == 0:
                lines.append(f"def func_{i}():")
            elif i % 3 == 1:
                lines.append(f"    x = {i}")
            else:
                lines.append(f"    return x")
        code = "\n".join(lines)
        signal = _signal_uniform_style(code)
        # Should detect the uniformity
        assert signal.score > 0.0
        assert signal.name == "uniform_style"

    def test_uniform_style_too_short(self):
        code = "x = 1\ny = 2"
        signal = _signal_uniform_style(code)
        assert signal.score == 0.0


class TestCompleteFunctions:
    def test_complete_functions_high(self):
        # Many function definitions in a short block
        code = "\n".join(
            [f"+def func_{i}(arg):\n+    return arg + {i}" for i in range(10)]
        )
        signal = _signal_complete_functions(code)
        assert signal.score > 0.3

    def test_complete_functions_none(self):
        code = "\n".join([f"+x = {i}" for i in range(20)])
        signal = _signal_complete_functions(code)
        assert signal.score == 0.0


class TestMissingEdgeCases:
    def test_missing_edge_cases_high(self):
        # Risky operations with no defensive checks
        code = "\n".join([
            "data = json.loads(raw)",
            "value = data['key']",
            "f = open('file.txt')",
            "content = f.read()",
            "result = requests.get(url)",
            "num = int(user_input)",
            "db.execute(query)",
            "f.write(output)",
        ] * 3)
        signal = _signal_missing_edge_cases(code)
        assert signal.score > 0.3

    def test_missing_edge_cases_well_defended(self):
        # Lots of defensive patterns
        code = "\n".join([
            "if data is not None:",
            "    try:",
            "        value = data.get('key', default)",
            "    except KeyError:",
            "        raise ValueError('missing')",
            "    if len(items) > 0:",
            "        assert items",
        ] * 4)
        signal = _signal_missing_edge_cases(code)
        # Should have lower score due to good defence
        assert signal.score < 0.5


class TestGeneratedComments:
    def test_generated_comments_high(self):
        # AI-style comments
        code = "\n".join([
            "# ------------------------------------",
            "# Here's the main function",
            "# Import statements",
            "# Initialize the application",
            "# TODO: implement error handling",
            "# Helper function for processing",
            "# The following code handles requests",
            "# Setup the database connection",
            "# Configure the logging",
            "# Create a new instance",
            "x = 1",
            "y = 2",
        ])
        signal = _signal_generated_comments(code)
        assert signal.score > 0.3

    def test_generated_comments_low(self):
        code = "\n".join([f"x_{i} = {i}" for i in range(20)])
        signal = _signal_generated_comments(code)
        assert signal.score == 0.0


class TestCommitMessage:
    def test_commit_message_claude(self):
        signal = _signal_commit_message("Add feature\n\nCo-Authored-By: Claude")
        assert signal.score == 1.0

    def test_commit_message_copilot(self):
        signal = _signal_commit_message("Fix bug\n\nCo-Authored-By: Copilot")
        assert signal.score == 1.0

    def test_commit_message_normal(self):
        signal = _signal_commit_message("chore: bump version to 2.3.1")
        # A normal commit message should not score high
        assert signal.score < 0.8


class TestAnalyzeDiff:
    def test_analyze_diff_full(self):
        diff_text = "\n".join(
            ["--- a/foo.py", "+++ b/foo.py"]
            + [f"+def func_{i}():\n+    return {i}" for i in range(30)]
            + ["-old_line = 1"] * 3
        )

        result = analyze_diff(
            diff_text,
            file_path="foo.py",
            commit_message="Add new module\n\nCo-Authored-By: Claude",
        )

        assert result.file_path == "foo.py"
        assert result.lines_added > 0
        assert result.lines_removed > 0
        assert len(result.signals) > 0
        assert result.confidence >= 0.0
        # With a Claude co-author tag the confidence should be non-trivial
        assert result.confidence > 0.1
        assert isinstance(result.summary, str)
