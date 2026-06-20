"""Shared test fixtures for the Autopsy test suite."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from autopsy.parser.core import parse_file, parse_directory
from autopsy.graph.builder import build_dependency_graph


# ---------------------------------------------------------------------------
# Sample source code
# ---------------------------------------------------------------------------

SAMPLE_PYTHON = '''\
import os
from pathlib import Path

def greet(name):
    """Say hello."""
    print(f"Hello, {name}")
    return name

def helper():
    greet("world")

class Greeter:
    def __init__(self, name):
        self.name = name

    def say_hello(self):
        greet(self.name)
'''

SAMPLE_PYTHON_B = '''\
from sample_a import greet

def run():
    greet("from B")
'''

SAMPLE_JS = '''\
import React from "react";
import { useState } from "react";

function App() {
    return <div>Hello</div>;
}

class Widget {
    constructor(name) {
        this.name = name;
    }
    render() {
        return this.name;
    }
}

const add = (a, b) => {
    return a + b;
};
'''


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def py_file(tmp_path: Path) -> Path:
    """Write a sample Python file and return its path."""
    p = tmp_path / "sample_a.py"
    p.write_text(SAMPLE_PYTHON)
    return p


@pytest.fixture
def js_file(tmp_path: Path) -> Path:
    """Write a sample JS file and return its path."""
    p = tmp_path / "app.jsx"
    p.write_text(SAMPLE_JS)
    return p


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """Create a small temp repo with Python and JS files, git-initialised."""
    (tmp_path / "sample_a.py").write_text(SAMPLE_PYTHON)
    (tmp_path / "sample_b.py").write_text(SAMPLE_PYTHON_B)
    (tmp_path / "app.jsx").write_text(SAMPLE_JS)
    (tmp_path / "notes.txt").write_text("not code")

    # Also add a file inside node_modules that should be skipped
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("module.exports = {};")

    # Initialise a git repo so API tests can use it
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)

    return tmp_path


@pytest.fixture
def parsed_files(sample_repo: Path):
    """Parse the sample repo and return list of ParsedFile."""
    return parse_directory(sample_repo)


@pytest.fixture
def graph(parsed_files):
    """Build a dependency graph from the parsed sample repo."""
    return build_dependency_graph(parsed_files)
