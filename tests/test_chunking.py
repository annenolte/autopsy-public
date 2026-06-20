"""Tests for the map-reduce chunked scanner.

The point of chunking is coverage: every line of every file must be scanned in
some window, so large files are no longer silently truncated. These tests use a
fake scan_fn so no API calls are made.
"""
import tempfile
from pathlib import Path

from autopsy.llm.chunking import iter_line_windows, scan_stream_chunked


def test_windows_cover_every_line():
    for total in (1, 50, 400, 401, 1000, 1238, 5000):
        covered = set()
        for s, e in iter_line_windows(total, window=400, overlap=40):
            assert 1 <= s <= e <= total
            covered.update(range(s, e + 1))
        assert covered == set(range(1, total + 1)), f"gap for total={total}"


def test_small_file_is_single_window():
    assert list(iter_line_windows(120, window=400)) == [(1, 120)]


def test_chunked_scan_reaches_deep_lines_no_truncation():
    # A 1000-line file with a marker far past the old 500-line truncation point.
    lines = [f"x = {i}" for i in range(1, 1001)]
    lines[899] = "DANGER_MARKER_LINE_900 = eval(user_input)"  # line 900
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "big.py"
        p.write_text("\n".join(lines))

        seen_prompts = []

        def fake_scan(system, user_msg):
            seen_prompts.append(user_msg)
            yield "## [SEVERITY: LOW] noop\n**Category:** Other\n---\n"

        out = "".join(scan_stream_chunked(
            None, "", ["big.py"], root_dir=Path(tmp),
            window_lines=400, overlap=40, scan_fn=fake_scan,
        ))

        # The deep marker must appear in some window's prompt -> it was scanned.
        assert any("DANGER_MARKER_LINE_900" in pr for pr in seen_prompts)
        # And more than one window was needed for a 1000-line file.
        assert len(seen_prompts) >= 3
        assert "scanning big.py" in out
