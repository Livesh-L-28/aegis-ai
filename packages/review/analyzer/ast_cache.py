"""Bounded, thread-safe content-hash AST cache for LogicFalcon repository intelligence."""

import hashlib
import threading
from collections import OrderedDict

from packages.intelligence.code.indexer import CodeDependency, CodeSymbol


class ContentHashASTCache:
    """Thread-safe LRU cache storing parsed AST symbols and dependencies keyed by content hash.

    Avoids stale results by strictly keying on (file_path, content_sha256).
    Bounds memory consumption via LRU eviction when capacity is reached.
    """

    def __init__(self, max_entries: int = 2000) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self.max_entries = max_entries
        self._cache: OrderedDict[tuple[str, str], tuple[list[CodeSymbol], list[CodeDependency]]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    @staticmethod
    def compute_hash(content: str) -> str:
        """Computes a deterministic SHA-256 hex digest of source code content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def get(
        self, file_path: str, content_hash: str
    ) -> tuple[list[CodeSymbol], list[CodeDependency]] | None:
        """Retrieves cached AST symbols and dependencies if the content hash matches."""
        key = (file_path, content_hash)
        with self._lock:
            if key in self._cache:
                self._hits += 1
                self._cache.move_to_end(key)
                return self._cache[key]
            self._misses += 1
            return None

    def put(
        self,
        file_path: str,
        content_hash: str,
        parsed_result: tuple[list[CodeSymbol], list[CodeDependency]],
    ) -> None:
        """Stores parsed AST symbols and dependencies, evicting the least recently used entry if full."""
        key = (file_path, content_hash)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = parsed_result
                return

            if len(self._cache) >= self.max_entries:
                self._cache.popitem(last=False)
                self._evictions += 1

            self._cache[key] = parsed_result

    def clear(self) -> None:
        """Clears all cached entries and resets statistics."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0

    @property
    def stats(self) -> dict[str, int]:
        """Returns cache telemetry: hits, misses, evictions, current size, and max capacity."""
        with self._lock:
            return {
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "size": len(self._cache),
                "max_entries": self.max_entries,
            }


# Global thread-safe singleton cache across engine invocations
global_ast_cache = ContentHashASTCache(max_entries=2000)
