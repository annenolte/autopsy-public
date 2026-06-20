"""Tests for the FastAPI server endpoints."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from autopsy.server.app import app, _cache


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the server's in-memory cache between tests."""
    _cache.clear()
    yield
    _cache.clear()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def api_repo(tmp_path: Path) -> Path:
    """A minimal git repo for API tests."""
    py = tmp_path / "hello.py"
    py.write_text("def hello():\n    return 'world'\n")

    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)
    return tmp_path


class TestHealth:
    def test_health(self, client: TestClient):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


class TestGraphEndpoint:
    def test_graph_endpoint(self, client: TestClient, api_repo: Path):
        resp = client.post("/api/graph", json={"repo": str(api_repo)})
        assert resp.status_code == 200
        data = resp.json()
        assert "stats" in data
        assert data["stats"]["files"] >= 1
        assert data["stats"]["functions"] >= 1
        assert data["stats"]["total_nodes"] >= 1


class TestBadRepo:
    def test_bad_repo(self, client: TestClient):
        resp = client.post(
            "/api/debug",
            json={
                "repo": "/nonexistent/path/that/does/not/exist",
                "target": "foo.py",
            },
        )
        assert resp.status_code == 400


class TestScanNoChanges:
    def test_scan_no_changes(self, client: TestClient, api_repo: Path):
        """A freshly committed repo with no uncommitted changes should 404."""
        resp = client.post(
            "/api/scan",
            json={"repo": str(api_repo), "uncommitted": True},
        )
        # No uncommitted changes -> 404
        assert resp.status_code == 404


class TestDebugMockedLLM:
    @patch("autopsy.server.app.debug_stream")
    def test_debug_streams_sse(self, mock_debug: MagicMock, client: TestClient, api_repo: Path):
        """Ensure /api/debug returns SSE when the LLM stream is mocked."""
        mock_debug.return_value = iter(["chunk1", "chunk2"])

        resp = client.post(
            "/api/debug",
            json={"repo": str(api_repo), "target": "hello.py", "query": "find bugs"},
        )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = resp.text
        assert "chunk1" in body
        assert "chunk2" in body
        assert "event: done" in body


class TestScanMockedLLM:
    @patch("autopsy.server.app.scan_stream")
    @patch("autopsy.server.app.get_uncommitted_changes")
    def test_scan_with_changes(
        self,
        mock_uncommitted: MagicMock,
        mock_scan: MagicMock,
        client: TestClient,
        api_repo: Path,
    ):
        """Mock both git diff and LLM so no API key is needed."""
        mock_uncommitted.return_value = (
            "+added line\n-removed line",
            ["hello.py"],
        )
        mock_scan.return_value = iter(["scan_result"])

        resp = client.post(
            "/api/scan",
            json={"repo": str(api_repo), "uncommitted": True},
        )
        assert resp.status_code == 200
        assert "scan_result" in resp.text
