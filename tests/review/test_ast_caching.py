"""Focused regression tests for content-hash AST caching in LogicFalcon."""

import time
from pathlib import Path

from packages.intelligence.code.indexer import CodeDependency, CodeSymbol, SymbolType
from packages.review.analyzer.ast_cache import ContentHashASTCache
from packages.review.analyzer.dependency_graph import DependencyGraph


def test_ast_cache_hit_and_miss() -> None:
    cache = ContentHashASTCache(max_entries=5)
    file_path = "app/models.py"
    content_v1 = "import os\nclass User:\n    pass\n"
    hash_v1 = cache.compute_hash(content_v1)

    # 1. Initial miss
    assert cache.get(file_path, hash_v1) is None
    assert cache.stats["misses"] == 1
    assert cache.stats["hits"] == 0

    # 2. Put parsed result
    symbols = [
        CodeSymbol(
            name="User",
            qualified_name="User",
            symbol_type=SymbolType.CLASS,
            start_line=2,
            end_line=3,
            file_path=file_path,
        )
    ]
    deps = [CodeDependency(source_file=file_path, target_module="os")]
    cache.put(file_path, hash_v1, (symbols, deps))

    # 3. Cache hit on same hash
    cached = cache.get(file_path, hash_v1)
    assert cached is not None
    cached_symbols, cached_deps = cached
    assert len(cached_symbols) == 1
    assert cached_symbols[0].name == "User"
    assert len(cached_deps) == 1
    assert cached_deps[0].target_module == "os"
    assert cache.stats["hits"] == 1

    # 4. Content change -> different hash -> cache miss (no stale data)
    content_v2 = "import sys\nclass Admin:\n    pass\n"
    hash_v2 = cache.compute_hash(content_v2)
    assert cache.get(file_path, hash_v2) is None
    assert cache.stats["misses"] == 2


def test_ast_cache_lru_bounding() -> None:
    cache = ContentHashASTCache(max_entries=3)

    for i in range(1, 5):
        path = f"file_{i}.py"
        content = f"import mod_{i}\n"
        h = cache.compute_hash(content)
        cache.put(path, h, ([], []))

    # Capacity is 3, so file_1 should have been evicted
    assert cache.stats["evictions"] == 1
    assert cache.stats["size"] == 3

    # Check file_1 is gone
    h1 = cache.compute_hash("import mod_1\n")
    assert cache.get("file_1.py", h1) is None

    # Check file_4 and file_3 are still present
    h4 = cache.compute_hash("import mod_4\n")
    assert cache.get("file_4.py", h4) is not None


def test_dependency_graph_integration_with_ast_cache(tmp_path: Path) -> None:
    # Create sample Python project
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
    mod_a = pkg_dir / "mod_a.py"
    mod_b = pkg_dir / "mod_b.py"

    mod_a.write_text("class Alpha:\n    pass\n", encoding="utf-8")
    mod_b.write_text("import pkg.mod_a\nclass Beta:\n    pass\n", encoding="utf-8")

    custom_cache = ContentHashASTCache(max_entries=100)
    graph = DependencyGraph(repo_root=tmp_path, ast_cache=custom_cache)

    # First pass: cold cache
    t0 = time.perf_counter()
    graph.build_graph()
    t_cold = time.perf_counter() - t0

    assert custom_cache.stats["hits"] == 0
    assert custom_cache.stats["misses"] >= 2
    assert "pkg.mod_a" in graph.internal_import_graph["pkg.mod_b"]

    # Second pass: warm cache with new DependencyGraph sharing custom_cache
    graph2 = DependencyGraph(repo_root=tmp_path, ast_cache=custom_cache)
    t1 = time.perf_counter()
    graph2.build_graph()
    t_warm = time.perf_counter() - t1

    assert custom_cache.stats["hits"] >= 2
    assert "pkg.mod_a" in graph2.internal_import_graph["pkg.mod_b"]
    # Warm pass must not be slower than cold pass
    assert t_warm <= t_cold + 0.05


def test_ast_caching_parity_with_uncached_analysis(tmp_path: Path) -> None:
    """Verifies that cached graph construction produces results identical to uncached construction."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "__init__.py").write_text("", encoding="utf-8")
    (src_dir / "user.py").write_text(
        "class User:\n    def get_id(self) -> int:\n        return 1\n",
        encoding="utf-8",
    )
    (src_dir / "service.py").write_text(
        "import src.user\nclass UserService:\n    pass\n",
        encoding="utf-8",
    )
    (src_dir / "api.py").write_text(
        "import src.service\nclass Controller:\n    pass\n",
        encoding="utf-8",
    )

    # 1. Uncached run
    uncached_graph = DependencyGraph(repo_root=tmp_path, ast_cache=ContentHashASTCache(max_entries=1))
    uncached_graph.build_graph()

    # 2. Warm cached run
    shared_cache = ContentHashASTCache(max_entries=100)
    prime_graph = DependencyGraph(repo_root=tmp_path, ast_cache=shared_cache)
    prime_graph.build_graph()

    cached_graph = DependencyGraph(repo_root=tmp_path, ast_cache=shared_cache)
    cached_graph.build_graph()

    # Verify 100% parity
    assert cached_graph.file_to_module == uncached_graph.file_to_module
    assert cached_graph.module_to_file == uncached_graph.module_to_file
    assert cached_graph.internal_import_graph == uncached_graph.internal_import_graph
    assert cached_graph.reverse_deps == uncached_graph.reverse_deps
    assert cached_graph.find_cycles() == uncached_graph.find_cycles()


def test_ast_caching_content_change_invalidation(tmp_path: Path) -> None:
    """Modifying a file content changes hash, causing an immediate cache miss and updated graph."""
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "core.py").write_text("class Core:\n    pass\n", encoding="utf-8")
    worker = pkg / "worker.py"
    worker.write_text("import app.core\nclass Worker:\n    pass\n", encoding="utf-8")

    cache = ContentHashASTCache(max_entries=50)
    g1 = DependencyGraph(repo_root=tmp_path, ast_cache=cache)
    g1.build_graph()
    assert "app.core" in g1.internal_import_graph["app.worker"]

    # Modify worker to import nothing
    worker.write_text("class WorkerStandalone:\n    pass\n", encoding="utf-8")

    g2 = DependencyGraph(repo_root=tmp_path, ast_cache=cache)
    g2.build_graph()
    # worker should now have 0 internal dependencies
    assert "app.core" not in g2.internal_import_graph["app.worker"]
    # app.core was unchanged and should hit cache
    assert cache.stats["hits"] >= 1


def test_ast_caching_deleted_and_renamed_files(tmp_path: Path) -> None:
    """Deleting or renaming a file correctly updates the graph structure without stale remnants."""
    pkg = tmp_path / "lib"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    file_old = pkg / "old_mod.py"
    file_old.write_text("class Old:\n    pass\n", encoding="utf-8")

    cache = ContentHashASTCache(max_entries=50)
    g1 = DependencyGraph(repo_root=tmp_path, ast_cache=cache)
    g1.build_graph()
    assert "lib.old_mod" in g1.module_to_file

    # Rename file_old to file_new
    file_new = pkg / "new_mod.py"
    file_old.rename(file_new)

    g2 = DependencyGraph(repo_root=tmp_path, ast_cache=cache)
    g2.build_graph()
    assert "lib.old_mod" not in g2.module_to_file
    assert "lib.new_mod" in g2.module_to_file


def test_ast_caching_repeated_runs_stability(tmp_path: Path) -> None:
    """Running multiple successive builds keeps cache stats bounded and produces stable outputs."""
    pkg = tmp_path / "stable"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "alpha.py").write_text("class Alpha:\n    pass\n", encoding="utf-8")
    (pkg / "beta.py").write_text("import stable.alpha\nclass Beta:\n    pass\n", encoding="utf-8")

    cache = ContentHashASTCache(max_entries=10)
    # Cold run
    g_init = DependencyGraph(repo_root=tmp_path, ast_cache=cache)
    g_init.build_graph()
    initial_misses = cache.stats["misses"]

    # 4 Warm runs
    for _ in range(4):
        g = DependencyGraph(repo_root=tmp_path, ast_cache=cache)
        g.build_graph()
        assert "stable.alpha" in g.internal_import_graph["stable.beta"]

    # Hits must have grown by at least 2 per run; misses must remain fixed
    assert cache.stats["misses"] == initial_misses
    assert cache.stats["hits"] >= 8
    assert cache.stats["evictions"] == 0

