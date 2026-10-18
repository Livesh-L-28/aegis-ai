"""Tests for DependencyGraph and affected test discovery."""

import tempfile
from pathlib import Path

from packages.intelligence.code.indexer import CodeSymbol, SymbolType
from packages.review.analyzer.dependency_graph import DependencyGraph
from packages.review.domain.models import ChangedSymbol


def test_dependency_graph_discovers_affected_tests() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)

        # Create simulated package structure
        pkg = root / "mypackage"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")

        service_file = pkg / "service.py"
        service_file.write_text(
            "def compute():\n    return 42\n", encoding="utf-8"
        )

        client_file = pkg / "client.py"
        client_file.write_text(
            "from mypackage.service import compute\n\ndef call():\n    return compute()\n",
            encoding="utf-8",
        )

        # Create tests
        tests_dir = root / "tests"
        tests_dir.mkdir(parents=True)
        (tests_dir / "__init__.py").write_text("", encoding="utf-8")

        test_service = tests_dir / "test_service.py"
        test_service.write_text(
            "from mypackage.service import compute\n\ndef test_comp():\n    assert compute() == 42\n",
            encoding="utf-8",
        )

        test_client = tests_dir / "test_client.py"
        test_client.write_text(
            "from mypackage.client import call\n\ndef test_cl():\n    assert call() == 42\n",
            encoding="utf-8",
        )

        # Build graph
        graph = DependencyGraph(root)
        graph.build_graph()

        # If mypackage/service.py changed, both test_service.py (direct) and test_client.py (transitive) are affected
        sym = CodeSymbol(
            file_path="mypackage/service.py",
            symbol_type=SymbolType.FUNCTION,
            name="compute",
            qualified_name="compute",
            start_line=1,
            end_line=2,
        )
        changed_sym = ChangedSymbol(
            symbol=sym,
            file_path="mypackage/service.py",
            change_type="MODIFIED",
        )

        artifacts = graph.find_affected_artifacts(
            changed_symbols=[changed_sym],
            changed_files=["mypackage/service.py"],
            max_transitive_depth=2,
        )

        # Both test files should be discovered
        assert "tests/test_service.py" in artifacts.affected_tests
        assert "tests/test_client.py" in artifacts.affected_tests
        assert len(artifacts.discovery_warnings) >= 2
