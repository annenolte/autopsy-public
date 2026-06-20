"""Tree-sitter language configuration and initialization."""

from __future__ import annotations

from pathlib import Path
from functools import lru_cache

import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_typescript as tstypescript
from tree_sitter import Language, Parser


LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
}


@lru_cache(maxsize=None)
def get_language(name: str) -> Language:
    """Get a Tree-sitter Language object by name."""
    match name:
        case "python":
            return Language(tspython.language())
        case "javascript":
            return Language(tsjavascript.language())
        case "typescript":
            return Language(tstypescript.language_typescript())
        case "tsx":
            return Language(tstypescript.language_tsx())
        case _:
            raise ValueError(f"Unsupported language: {name}")


@lru_cache(maxsize=None)
def get_parser(language_name: str) -> Parser:
    """Get a configured Tree-sitter parser for the given language."""
    parser = Parser(get_language(language_name))
    return parser


def detect_language(path: Path) -> str | None:
    """Detect language from file extension."""
    return LANGUAGE_MAP.get(path.suffix.lower())
