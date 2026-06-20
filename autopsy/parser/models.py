"""Data models for parsed code structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ImportDef:
    """A single import statement."""

    module: str  # e.g. "os.path" or "flask"
    names: list[str] = field(default_factory=list)  # e.g. ["join", "exists"] or [] for bare import
    alias: str | None = None
    line: int = 0
    is_relative: bool = False


@dataclass
class FunctionDef:
    """A function or method definition."""

    name: str
    qualified_name: str  # e.g. "MyClass.my_method" or just "my_func"
    line_start: int = 0
    line_end: int = 0
    params: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)


@dataclass
class ClassDef:
    """A class definition."""

    name: str
    line_start: int = 0
    line_end: int = 0
    bases: list[str] = field(default_factory=list)
    methods: list[FunctionDef] = field(default_factory=list)


@dataclass
class CallSite:
    """A function/method call."""

    name: str  # e.g. "requests.get" or "my_func"
    line: int = 0
    arguments: list[str] = field(default_factory=list)


@dataclass
class ParsedFile:
    """Complete parse result for a single file."""

    path: Path
    language: str
    imports: list[ImportDef] = field(default_factory=list)
    functions: list[FunctionDef] = field(default_factory=list)
    classes: list[ClassDef] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)  # top-level calls
    source: str = ""
    lines: int = 0

    @property
    def all_functions(self) -> list[FunctionDef]:
        """All functions including methods inside classes."""
        result = list(self.functions)
        for cls in self.classes:
            result.extend(cls.methods)
        return result

    @property
    def all_calls(self) -> list[CallSite]:
        """All call sites across the file."""
        result = list(self.calls)
        for func in self.all_functions:
            result.extend(func.calls)
        return result
