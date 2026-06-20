"""Embedding cache — compute once, reuse across runs.

Uses voyage-code-2 for code embeddings. Falls back gracefully if voyageai is not installed.
Cache is stored as JSON on disk in .autopsy_cache/ within the repo.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

CACHE_DIR_NAME = ".autopsy_cache"
EMBEDDINGS_FILE = "embeddings.json"


class EmbeddingCache:
    """Disk-backed cache for code embeddings."""

    def __init__(self, repo_root: Path):
        self.cache_dir = repo_root / CACHE_DIR_NAME
        self.cache_file = self.cache_dir / EMBEDDINGS_FILE
        self._cache: dict[str, dict[str, Any]] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        """Load cache from disk."""
        if self.cache_file.exists():
            try:
                self._cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._cache = {}

    def save(self) -> None:
        """Write cache to disk if dirty."""
        if not self._dirty:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file.write_text(
            json.dumps(self._cache, indent=2), encoding="utf-8"
        )
        self._dirty = False

    @staticmethod
    def _content_hash(content: str) -> str:
        """SHA-256 hash of file content for cache invalidation."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def get(self, file_path: str, content: str) -> list[float] | None:
        """Get cached embedding if content hasn't changed."""
        entry = self._cache.get(file_path)
        if entry is None:
            return None
        if entry.get("hash") != self._content_hash(content):
            return None
        return entry.get("embedding")

    def put(self, file_path: str, content: str, embedding: list[float]) -> None:
        """Store an embedding in cache."""
        self._cache[file_path] = {
            "hash": self._content_hash(content),
            "embedding": embedding,
        }
        self._dirty = True

    def invalidate(self, file_path: str) -> None:
        """Remove a file's cached embedding."""
        if file_path in self._cache:
            del self._cache[file_path]
            self._dirty = True

    @property
    def size(self) -> int:
        return len(self._cache)


def compute_embeddings(
    files: dict[str, str],
    cache: EmbeddingCache,
    batch_size: int = 20,
) -> dict[str, list[float]]:
    """Compute embeddings for files, using cache where possible.

    Args:
        files: Dict of {file_path: file_content}.
        cache: The embedding cache.
        batch_size: How many files to embed per API call.

    Returns:
        Dict of {file_path: embedding_vector}.
    """
    try:
        import voyageai
    except ImportError:
        # voyageai not installed — return empty embeddings
        return {}

    results: dict[str, list[float]] = {}
    to_embed: list[tuple[str, str]] = []

    # Check cache first
    for path, content in files.items():
        cached = cache.get(path, content)
        if cached is not None:
            results[path] = cached
        else:
            to_embed.append((path, content))

    if not to_embed:
        return results

    # Batch embed uncached files
    client = voyageai.Client()
    for i in range(0, len(to_embed), batch_size):
        batch = to_embed[i : i + batch_size]
        texts = [content for _, content in batch]

        try:
            response = client.embed(texts, model="voyage-code-2", input_type="document")
            for (path, content), embedding in zip(batch, response.embeddings):
                results[path] = embedding
                cache.put(path, content, embedding)
        except Exception:
            # If embedding fails for a batch, skip it — embeddings are enhancement, not critical
            continue

    cache.save()
    return results
