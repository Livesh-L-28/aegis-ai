"""Unit tests for LogicFalcon Stage 2.3 Modularity Metrics and Coupling Analysis."""

from pathlib import Path

import pytest

from packages.review.analyzer.architecture import ArchitectureAnalyzer
from packages.review.analyzer.dependency_graph import DependencyGraph


@pytest.fixture
def controlled_metric_repo(tmp_path: Path) -> Path:
    """Creates a small repository with mathematically determined coupling properties.

    Graph Topology:
    - mod_a imports mod_b and mod_c
      -> Ca = 0 (no one imports a)
      -> Ce = 2 (imports b, c)
      -> Instability I = 2 / (0 + 2) = 1.0 (maximally unstable)

    - mod_b imports mod_c
      -> Ca = 1 (imported by a)
      -> Ce = 1 (imports c)
      -> Instability I = 1 / (1 + 1) = 0.5 (balanced)

    - mod_c imports nothing
      -> Ca = 2 (imported by a, b)
      -> Ce = 0 (imports none)
      -> Instability I = 0 / (2 + 0) = 0.0 (maximally stable)

    - mod_d is completely isolated
      -> Ca = 0
      -> Ce = 0
      -> Instability I = 0.0 (edge case handled gracefully)
    """
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")

    (pkg / "mod_a.py").write_text("from pkg.mod_b import b\nfrom pkg.mod_c import c\n", encoding="utf-8")
    (pkg / "mod_b.py").write_text("from pkg.mod_c import c\n", encoding="utf-8")
    (pkg / "mod_c.py").write_text("def c(): pass\n", encoding="utf-8")
    (pkg / "mod_d.py").write_text("def d(): pass\n", encoding="utf-8")

    return tmp_path


def test_hand_calculated_modularity_metrics(controlled_metric_repo: Path) -> None:
    """Verifies that Ca, Ce, and Instability match exact hand-calculated expected values."""
    graph = DependencyGraph(controlled_metric_repo)
    graph.build_graph()

    coupling = graph.get_module_coupling()

    # Module A: Ca=0, Ce=2, I=1.0
    mod_a = coupling["pkg.mod_a"]
    assert mod_a["afferent_coupling"] == 0
    assert mod_a["efferent_coupling"] == 2
    assert mod_a["instability"] == 1.0
    assert not mod_a["is_hotspot"]

    # Module B: Ca=1, Ce=1, I=0.5
    mod_b = coupling["pkg.mod_b"]
    assert mod_b["afferent_coupling"] == 1
    assert mod_b["efferent_coupling"] == 1
    assert mod_b["instability"] == 0.5
    assert not mod_b["is_hotspot"]

    # Module C: Ca=2, Ce=0, I=0.0
    mod_c = coupling["pkg.mod_c"]
    assert mod_c["afferent_coupling"] == 2
    assert mod_c["efferent_coupling"] == 0
    assert mod_c["instability"] == 0.0
    assert not mod_c["is_hotspot"]

    # Module D (Isolated): Ca=0, Ce=0, I=0.0
    mod_d = coupling["pkg.mod_d"]
    assert mod_d["afferent_coupling"] == 0
    assert mod_d["efferent_coupling"] == 0
    assert mod_d["instability"] == 0.0
    assert not mod_d["is_hotspot"]


def test_hotspot_threshold_classification(tmp_path: Path) -> None:
    """Verifies that high coupling hotspot is flagged when Ce > 15 or Ca > 25."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")

    # Create 16 target modules
    for i in range(16):
        (pkg / f"target_{i:02d}.py").write_text(f"def t{i}(): pass\n", encoding="utf-8")

    # Create god module that imports all 16
    imports_code = "\n".join(f"from pkg.target_{i:02d} import t{i}" for i in range(16))
    (pkg / "god_module.py").write_text(imports_code + "\n", encoding="utf-8")

    graph = DependencyGraph(tmp_path)
    graph.build_graph()
    coupling = graph.get_module_coupling()

    assert coupling["pkg.god_module"]["efferent_coupling"] == 16
    assert coupling["pkg.god_module"]["is_hotspot"] is True
    assert coupling["pkg.target_00"]["is_hotspot"] is False


def test_explainable_health_scoring_breakdown(controlled_metric_repo: Path) -> None:
    """Verifies that ArchitectureAnalyzer produces documented, explainable scoring breakdown."""
    analyzer = ArchitectureAnalyzer(controlled_metric_repo)
    report = analyzer.analyze()

    assert report.health_score == 100.0
    assert "scoring_breakdown" in report.model_dump()
    breakdown = report.scoring_breakdown
    assert breakdown["base_score"] == 100.0
    assert breakdown["final_score"] == 100.0
    assert breakdown["deductions"]["circular_dependencies"]["deducted"] == 0.0
    assert breakdown["deductions"]["boundary_violations"]["deducted"] == 0.0
    assert breakdown["deductions"]["coupling_hotspots"]["deducted"] == 0.0
