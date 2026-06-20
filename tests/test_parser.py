"""Tests for the code parser (tree-sitter based extraction)."""

from __future__ import annotations

from pathlib import Path

from autopsy.parser.core import parse_file, parse_directory


class TestParsePythonFile:
    def test_parse_python_file(self, py_file: Path):
        result = parse_file(py_file)
        assert result is not None
        assert result.language == "python"

        # Imports
        module_names = [imp.module for imp in result.imports]
        assert "os" in module_names
        assert "pathlib" in [imp.module for imp in result.imports if imp.names]

        # Top-level functions
        func_names = [f.name for f in result.functions]
        assert "greet" in func_names
        assert "helper" in func_names

        # Class
        class_names = [c.name for c in result.classes]
        assert "Greeter" in class_names

        # Methods inside class
        greeter_cls = next(c for c in result.classes if c.name == "Greeter")
        method_names = [m.name for m in greeter_cls.methods]
        assert "__init__" in method_names
        assert "say_hello" in method_names

        # all_functions includes methods
        all_names = [f.name for f in result.all_functions]
        assert "say_hello" in all_names

    def test_function_params(self, py_file: Path):
        result = parse_file(py_file)
        greet = next(f for f in result.functions if f.name == "greet")
        assert "name" in greet.params

    def test_function_calls_extracted(self, py_file: Path):
        result = parse_file(py_file)
        helper_fn = next(f for f in result.functions if f.name == "helper")
        call_names = [c.name for c in helper_fn.calls]
        assert "greet" in call_names


class TestParseJsFile:
    def test_parse_js_file(self, js_file: Path):
        result = parse_file(js_file)
        assert result is not None
        assert result.language == "javascript"

        # Imports
        modules = [imp.module for imp in result.imports]
        assert "react" in modules

        # Regular function
        func_names = [f.name for f in result.functions]
        assert "App" in func_names

        # Arrow function
        assert "add" in func_names

        # Class
        class_names = [c.name for c in result.classes]
        assert "Widget" in class_names

        # Methods
        widget = next(c for c in result.classes if c.name == "Widget")
        method_names = [m.name for m in widget.methods]
        assert "constructor" in method_names
        assert "render" in method_names


class TestParseDirectory:
    def test_parse_directory(self, sample_repo: Path):
        results = parse_directory(sample_repo)
        # Should parse sample_a.py, sample_b.py, app.jsx — not notes.txt
        paths = [r.path.name for r in results]
        assert "sample_a.py" in paths
        assert "sample_b.py" in paths
        assert "app.jsx" in paths
        assert "notes.txt" not in paths

    def test_skip_dirs(self, sample_repo: Path):
        results = parse_directory(sample_repo)
        parsed_paths = [str(r.path) for r in results]
        assert not any("node_modules" in p for p in parsed_paths)

    def test_unsupported_file_ignored(self, tmp_path: Path):
        (tmp_path / "readme.txt").write_text("hello")
        result = parse_file(tmp_path / "readme.txt")
        assert result is None

        results = parse_directory(tmp_path)
        assert len(results) == 0
