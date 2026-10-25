"""Performance and scalability benchmark suite for LogicFalcon Reverse Engineering Intelligence.

Evaluates throughput, memory bounds, and cold vs warm execution times across
synthetic repositories of various sizes (small: 50 files, medium: 200 files).
"""

import time
from pathlib import Path

import pytest

from packages.review.reverse_engineering.engine import ReverseEngineeringEngine


@pytest.fixture
def small_synthetic_repo(tmp_path: Path) -> Path:
    """Generates a small synthetic repository with 50 source files."""
    repo = tmp_path / "small_repo"
    repo.mkdir()

    # Manifest
    (repo / "pyproject.toml").write_text(
        """[project]
name = "small-benchmark"
version = "0.1.0"
dependencies = ["pydantic"]
"""
    )

    # 5 packages, 10 files each = 50 files
    for pkg_idx in range(5):
        pkg_dir = repo / f"pkg_{pkg_idx}"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("")
        for file_idx in range(9):
            (pkg_dir / f"mod_{file_idx}.py").write_text(
                f"""from pydantic import BaseModel

class Item_{pkg_idx}_{file_idx}(BaseModel):
    id: int
    name: str = "item_{file_idx}"

def calculate_{file_idx}(x: int) -> int:
    \"\"\"Calculates item value.\"\"\"
    return x * {file_idx + 1}
"""
            )

    return repo


@pytest.fixture
def medium_synthetic_repo(tmp_path: Path) -> Path:
    """Generates a medium synthetic repository with 200 source files."""
    repo = tmp_path / "medium_repo"
    repo.mkdir()

    (repo / "pyproject.toml").write_text(
        """[project]
name = "medium-benchmark"
version = "0.1.0"
dependencies = ["fastapi", "pydantic"]
"""
    )

    # 10 packages, 20 files each = 200 files
    for pkg_idx in range(10):
        pkg_dir = repo / f"service_{pkg_idx}"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("")
        for file_idx in range(19):
            (pkg_dir / f"handler_{file_idx}.py").write_text(
                f"""import os
from pydantic import BaseModel

class Payload_{pkg_idx}_{file_idx}(BaseModel):
    key: str
    count: int = {file_idx}

def process_{file_idx}(p: Payload_{pkg_idx}_{file_idx}) -> str:
    env_var = os.getenv("BENCHMARK_ENV_{pkg_idx}")
    return f"processed_{{p.key}}"
"""
            )

    return repo


def test_small_repo_benchmark_throughput(small_synthetic_repo: Path) -> None:
    """Measures analysis throughput on a 50-file repository."""
    engine = ReverseEngineeringEngine(repo_root=small_synthetic_repo)

    start = time.perf_counter()
    report = engine.analyze()
    cold_duration = time.perf_counter() - start

    assert report.inventory.total_files >= 50
    assert report.data_model_inventory.total_models >= 45
    # Small repo should finish comfortably in under 5.0 seconds
    assert cold_duration < 5.0, f"Cold analysis took too long: {cold_duration:.2f}s"

    # Warm run
    warm_start = time.perf_counter()
    warm_report = engine.analyze()
    warm_duration = time.perf_counter() - warm_start
    assert warm_duration < 5.0
    assert warm_report.inventory.total_files == report.inventory.total_files


def test_medium_repo_benchmark_scalability(medium_synthetic_repo: Path) -> None:
    """Measures scalability on a 200-file repository."""
    engine = ReverseEngineeringEngine(repo_root=medium_synthetic_repo)

    start = time.perf_counter()
    report = engine.analyze()
    duration = time.perf_counter() - start

    assert report.inventory.total_files >= 200
    assert len(report.architecture_components) >= 10
    assert report.data_model_inventory.total_models >= 180
    assert len(report.limitations) == 0
    # 200 files should finish in under 15 seconds
    assert duration < 15.0, f"Medium benchmark analysis took: {duration:.2f}s"
