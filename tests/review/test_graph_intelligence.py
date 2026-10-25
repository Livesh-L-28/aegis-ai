"""Unit and regression tests for LogicFalcon Stage 2.2 Dependency Graph Intelligence."""

from pathlib import Path

import pytest

from packages.intelligence.code.indexer import CodeSymbol, SymbolType
from packages.review.analyzer.dependency_graph import DependencyGraph
from packages.review.domain.models import ChangedSymbol


@pytest.fixture
def cycle_cluster_repo(tmp_path: Path) -> Path:
    """Creates a repository with a multi-node strongly connected component and satellite nodes.

    Structure:
    - cluster: mod_a -> mod_b -> mod_c -> mod_a (SCC of size 3)
    - satellite: mod_x -> mod_a (depends on cluster, not in cycle)
    - downstream: mod_c -> mod_y (cluster depends on mod_y, not in cycle)
    - isolated: mod_z (independent)
    """
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")

    (pkg / "mod_a.py").write_text(
        "from pkg.mod_b import b_func\n\ndef a_func(): pass\n",
        encoding="utf-8",
    )
    (pkg / "mod_b.py").write_text(
        "from pkg.mod_c import c_func\n\ndef b_func(): pass\n",
        encoding="utf-8",
    )
    (pkg / "mod_c.py").write_text(
        "from pkg.mod_a import a_func\nfrom pkg.mod_y import y_func\n\ndef c_func(): pass\n",
        encoding="utf-8",
    )
    (pkg / "mod_x.py").write_text(
        "from pkg.mod_a import a_func\n\ndef x_func(): pass\n",
        encoding="utf-8",
    )
    (pkg / "mod_y.py").write_text(
        "def y_func(): pass\n",
        encoding="utf-8",
    )
    (pkg / "mod_z.py").write_text(
        "def z_func(): pass\n",
        encoding="utf-8",
    )

    return tmp_path


def test_strongly_connected_components_tarjan(cycle_cluster_repo: Path) -> None:
    """Verifies that Tarjan's SCC algorithm clusters mutually entangled cycles in O(V + E)."""
    graph = DependencyGraph(cycle_cluster_repo)
    graph.build_graph()

    sccs = graph.find_strongly_connected_components()
    assert len(sccs) == 1

    group = sccs[0]
    assert group.id == "SCC-01"
    assert group.size == 3
    assert sorted(group.modules) == ["pkg.mod_a", "pkg.mod_b", "pkg.mod_c"]


def test_shortest_dependency_path_bfs(cycle_cluster_repo: Path) -> None:
    """Verifies BFS shortest path discovery between directly and transitively coupled modules."""
    graph = DependencyGraph(cycle_cluster_repo)
    graph.build_graph()

    # Direct: mod_x -> mod_a
    path_xa = graph.find_shortest_dependency_path("pkg.mod_x", "pkg.mod_a")
    assert path_xa == ["pkg.mod_x", "pkg.mod_a"]

    # Transitive: mod_x -> mod_a -> mod_b -> mod_c -> mod_y
    path_xy = graph.find_shortest_dependency_path("pkg.mod_x", "pkg.mod_y")
    assert path_xy == ["pkg.mod_x", "pkg.mod_a", "pkg.mod_b", "pkg.mod_c", "pkg.mod_y"]

    # Disconnected: mod_z to mod_a has no path
    path_za = graph.find_shortest_dependency_path("pkg.mod_z", "pkg.mod_a")
    assert path_za == []


def test_reverse_dependency_and_affected_tests(tmp_path: Path) -> None:
    """Verifies reverse dependency impact analysis and affected test file identification."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "core.py").write_text("def compute(): return 42\n", encoding="utf-8")
    (src / "service.py").write_text("from src.core import compute\n", encoding="utf-8")

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (tests / "test_core.py").write_text("from src.core import compute\n", encoding="utf-8")
    (tests / "test_service.py").write_text("from src.service import compute\n", encoding="utf-8")

    graph = DependencyGraph(tmp_path)
    graph.build_graph()

    affected = graph.find_affected_artifacts(
        changed_symbols=[
            ChangedSymbol(
                symbol=CodeSymbol(
                    file_path="src/core.py",
                    symbol_type=SymbolType.FUNCTION,
                    name="compute",
                    qualified_name="src.core.compute",
                    start_line=1,
                    end_line=1,
                ),
                file_path="src/core.py",
                change_type="MODIFIED",
            )
        ],
        changed_files=["src/core.py"],
        max_transitive_depth=3,
    )

    # Core change should impact service.py and both test files
    assert "tests/test_core.py" in affected.affected_tests
    assert "tests/test_service.py" in affected.affected_tests
    assert "src/service.py" in affected.reverse_dependencies["src/core.py"]


def test_conservative_dynamic_import_handling(tmp_path: Path) -> None:
    """Verifies that dynamic or unresolved imports do not invent false graph edges."""
    dyn_file = tmp_path / "dyn.py"
    dyn_file.write_text(
        """
import importlib

def load_plugin(name):
    return importlib.import_module(f"plugins.{name}")
""",
        encoding="utf-8",
    )

    graph = DependencyGraph(tmp_path)
    graph.build_graph()

    # Dynamic imports should not create spurious edges in internal graph
    assert len(graph.internal_import_graph["dyn"]) == 0
    assert len(graph.find_cycles()) == 0
