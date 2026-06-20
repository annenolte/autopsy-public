"""Regression test for JS/TS exported-function extraction.

Before the export-unwrap fix, exported functions (the norm in ES modules /
TypeScript) lived inside `export_statement` nodes and were never extracted, so
the dependency graph was empty for idiomatic TS. This locks the fix.
"""
from pathlib import Path

from autopsy.parser.core import parse_file

_JS = Path(__file__).resolve().parent.parent / "benchmark" / "js_demo"


def test_exported_ts_functions_are_extracted():
    auth = {f.name for f in parse_file(_JS / "auth.ts").functions}
    assert {"isAuthorized", "hashPassword"} <= auth
    db = {f.name for f in parse_file(_JS / "db.ts").functions}
    assert "runQuery" in db


def test_ts_imports_are_extracted():
    routes = parse_file(_JS / "routes.ts")
    modules = {imp.module for imp in routes.imports}
    assert "./db" in modules and "./auth" in modules
