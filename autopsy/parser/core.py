"""Core parsing logic — file and directory parsing orchestration."""

from __future__ import annotations

from pathlib import Path

from autopsy.parser.languages import get_parser, detect_language
from autopsy.parser.models import ParsedFile
from autopsy.parser.extractors import (
    extract_python_imports,
    extract_python_functions,
    extract_python_classes,
    extract_js_imports,
    extract_js_functions,
    extract_js_classes,
    extract_calls,
)

# Directories to always skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", ".next", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "egg-info",
}


def parse_file(path: Path) -> ParsedFile | None:
    """Parse a single file and extract its structure.

    Returns None if the file language is unsupported or the file can't be read.
    """
    language = detect_language(path)
    if not language:
        return None

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return None

    parser = get_parser(language)
    tree = parser.parse(source.encode("utf-8"))
    root = tree.root_node

    if language == "python":
        imports = extract_python_imports(root)
        functions = extract_python_functions(root)
        classes = extract_python_classes(root)
    elif language in ("javascript", "typescript", "tsx"):
        imports = extract_js_imports(root)
        functions = extract_js_functions(root)
        classes = extract_js_classes(root)
    else:
        return None

    # Top-level calls (not inside any function or class)
    top_level_calls = extract_calls(root)
    # Remove calls that belong to functions/classes (approximate: filter by line range)
    owned_lines = set()
    parsed = ParsedFile(
        path=path,
        language=language,
        imports=imports,
        functions=functions,
        classes=classes,
        source=source,
        lines=source.count("\n") + 1,
    )
    for func in parsed.all_functions:
        for line in range(func.line_start, func.line_end + 1):
            owned_lines.add(line)
    for cls in classes:
        for line in range(cls.line_start, cls.line_end + 1):
            owned_lines.add(line)

    parsed.calls = [c for c in top_level_calls if c.line not in owned_lines]
    return parsed


def parse_directory(root_dir: Path, max_files: int = 5000) -> list[ParsedFile]:
    """Recursively parse all supported files in a directory.

    Skips common non-source directories (node_modules, .git, etc.).
    """
    parsed_files = []
    count = 0

    for path in sorted(root_dir.rglob("*")):
        if count >= max_files:
            break

        # Skip excluded directories
        if any(part in SKIP_DIRS for part in path.parts):
            continue

        if not path.is_file():
            continue

        result = parse_file(path)
        if result:
            parsed_files.append(result)
            count += 1

    return parsed_files
