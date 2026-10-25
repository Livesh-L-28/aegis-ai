"""Deterministic performance and scalability benchmarks for Change Impact Analysis."""

import time
from pathlib import Path

from packages.review.impact.engine import ChangeImpactEngine


def create_synthetic_impact_benchmark_repo(root: Path, file_count: int) -> Path:
    """Constructs a deterministic synthetic multi-module repository with dependency chains."""
    repo = root / f"bench_repo_{file_count}"
    repo.mkdir(parents=True, exist_ok=True)

    # Core module
    (repo / "__init__.py").write_text("")
    (repo / "base.py").write_text("class BaseEntity:\n    pass\n")

    # Linear chains & fan-out tree
    for i in range(1, file_count):
        parent_name = "base" if i == 1 else f"mod_{i - 1}"
        content = f"import {parent_name}\nclass Entity_{i}:\n    pass\n"
        fname = f"mod_{i}.py"
        (repo / fname).write_text(content)

        # Create test for every 4th module
        if i % 4 == 0:
            test_content = f"import mod_{i}\ndef test_{i}():\n    assert mod_{i} is not None\n"
            (repo / f"test_mod_{i}.py").write_text(test_content)

    return repo


def test_small_repository_change_impact_benchmark(tmp_path: Path) -> None:
    """Benchmark: 50-file repository change impact analysis."""
    repo = create_synthetic_impact_benchmark_repo(tmp_path, 50)
    engine = ChangeImpactEngine(repo, max_depth=35)

    start = time.perf_counter()
    report = engine.analyze(explicit_files=["base.py"], run_re=False)
    elapsed = time.perf_counter() - start

    assert len(report.impacted_entities) >= 30
    assert len(report.recommended_tests) >= 5
    # Must complete fast (under 1.0s)
    assert elapsed < 1.0


def test_medium_repository_change_impact_benchmark(tmp_path: Path) -> None:
    """Benchmark: 200-file repository change impact analysis."""
    repo = create_synthetic_impact_benchmark_repo(tmp_path, 200)
    engine = ChangeImpactEngine(repo, max_depth=120, max_entities=300)

    start = time.perf_counter()
    report = engine.analyze(explicit_files=["base.py"], run_re=False)
    elapsed = time.perf_counter() - start

    assert len(report.impacted_entities) >= 100
    assert len(report.recommended_tests) >= 20
    # Must scale sub-linearly/linearly (under 2.5s)
    assert elapsed < 2.5
