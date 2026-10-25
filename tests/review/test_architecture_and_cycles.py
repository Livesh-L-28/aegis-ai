"""Tests for architecture analysis, circular dependency detection, and modular boundaries."""

import tempfile
from pathlib import Path

from packages.review.analyzer.architecture import ArchitectureAnalyzer
from packages.review.domain.models import FindingCategory, FindingSeverity


def test_circular_dependency_detection() -> None:
    """Verifies that circular dependency cycles between modules are deterministically detected."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        pkg = root / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")

        # Create cycle: mod_a -> mod_b -> mod_c -> mod_a
        (pkg / "mod_a.py").write_text("from pkg.mod_b import b_func\ndef a_func(): pass\n")
        (pkg / "mod_b.py").write_text("from pkg.mod_c import c_func\ndef b_func(): pass\n")
        (pkg / "mod_c.py").write_text("from pkg.mod_a import a_func\ndef c_func(): pass\n")

        # Independent module with no cycle
        (pkg / "mod_clean.py").write_text("def clean_func(): return 42\n")

        analyzer = ArchitectureAnalyzer(repo_root=root)
        report = analyzer.analyze()

        assert len(report.cycles) == 1
        cycle = report.cycles[0]
        assert cycle.length == 3
        assert "pkg.mod_a" in cycle.modules
        assert "pkg.mod_b" in cycle.modules
        assert "pkg.mod_c" in cycle.modules
        assert "pkg.mod_clean" not in cycle.modules

        # Verify generated findings
        findings = analyzer.generate_findings(report)
        cycle_findings = [f for f in findings if f.rule_id == "ARCH-001"]
        assert len(cycle_findings) == 1
        assert cycle_findings[0].category == FindingCategory.ARCHITECTURE
        assert cycle_findings[0].severity == FindingSeverity.ERROR
        assert "Circular Dependency" in cycle_findings[0].title


def test_architectural_boundary_enforcement() -> None:
    """Verifies that imports violating configured boundary policies are flagged."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        domain_dir = root / "domain"
        domain_dir.mkdir()
        (domain_dir / "__init__.py").write_text("")
        (domain_dir / "models.py").write_text("from adapters.db import DatabaseClient\nclass Entity: pass\n")

        adapters_dir = root / "adapters"
        adapters_dir.mkdir()
        (adapters_dir / "__init__.py").write_text("")
        (adapters_dir / "db.py").write_text("class DatabaseClient: pass\n")

        rules = [
            {
                "name": "domain_cannot_import_adapters",
                "source_pattern": "domain.*",
                "forbidden_pattern": "adapters.*",
                "description": "Domain layer must not depend directly on infrastructure adapters.",
            }
        ]

        analyzer = ArchitectureAnalyzer(repo_root=root, boundary_rules=rules)
        report = analyzer.analyze()

        assert len(report.boundary_violations) == 1
        violation = report.boundary_violations[0]
        assert violation.rule_name == "domain_cannot_import_adapters"
        assert violation.source_module == "domain.models"
        assert violation.target_module == "adapters.db"

        findings = analyzer.generate_findings(report)
        boundary_findings = [f for f in findings if f.rule_id == "ARCH-002"]
        assert len(boundary_findings) == 1
        assert boundary_findings[0].severity == FindingSeverity.WARNING
        assert "domain_cannot_import_adapters" in boundary_findings[0].title


def test_architecture_health_scoring_explainability() -> None:
    """Verifies that repository health scores are strictly bounded and transparently explained."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        app_dir = root / "app"
        app_dir.mkdir()
        (app_dir / "__init__.py").write_text("")
        (app_dir / "service_a.py").write_text("from app.service_b import b\n")
        (app_dir / "service_b.py").write_text("from app.service_a import a\n")

        analyzer = ArchitectureAnalyzer(repo_root=root)
        report = analyzer.analyze()

        assert report.health_score < 100.0
        assert "scoring_breakdown" in report.model_dump()
        breakdown = report.scoring_breakdown
        assert breakdown["base_score"] == 100.0
        assert "circular_dependencies" in breakdown["deductions"]
        assert breakdown["deductions"]["circular_dependencies"]["count"] == 1
        assert breakdown["deductions"]["circular_dependencies"]["deducted"] == 15.0
        assert report.health_score == 85.0
        assert "Good" in report.health_summary or "Moderate" in report.health_summary
