"""Focused regression tests for typed architecture boundary configuration in LogicFalcon."""

from pathlib import Path

import pytest

from packages.review.analyzer.architecture import ArchitectureAnalyzer
from packages.review.domain.models import BoundaryRule
from packages.review.engine import ReviewConfig


def test_boundary_rule_model_validation() -> None:
    rule = BoundaryRule(
        name="no_adapters_in_domain",
        source_pattern="*domain*",
        forbidden_pattern="*adapters*",
        description="Domain must not import adapters",
    )
    assert rule.name == "no_adapters_in_domain"
    assert rule.source_pattern == "*domain*"
    assert rule.forbidden_pattern == "*adapters*"


def test_load_config_json_with_architecture_boundaries(tmp_path: Path) -> None:
    config_file = tmp_path / ".logicfalcon.json"
    config_file.write_text(
        """{
            "max_file_size_bytes": 500000,
            "architecture_boundaries": [
                {
                    "name": "strict_layering",
                    "source_pattern": "core.*",
                    "forbidden_pattern": "ui.*",
                    "description": "Core cannot import UI"
                }
            ]
        }""",
        encoding="utf-8",
    )

    config = ReviewConfig.load_config(repo_root=tmp_path)
    assert config.max_file_size_bytes == 500000
    assert len(config.architecture_boundaries) == 1
    rule = config.architecture_boundaries[0]
    assert rule.name == "strict_layering"
    assert rule.source_pattern == "core.*"
    assert rule.forbidden_pattern == "ui.*"


def test_load_config_yaml_with_architecture_boundaries(tmp_path: Path) -> None:
    config_file = tmp_path / ".logicfalcon.yml"
    config_file.write_text(
        """
max_file_size_bytes: 250000
architecture_boundaries:
  - name: domain_isolation
    source_pattern: "myapp.domain.*"
    forbidden_pattern: "myapp.infrastructure.*"
    description: "Domain must remain isolated from infrastructure"
""",
        encoding="utf-8",
    )

    config = ReviewConfig.load_config(repo_root=tmp_path)
    assert config.max_file_size_bytes == 250000
    assert len(config.architecture_boundaries) == 1
    rule = config.architecture_boundaries[0]
    assert rule.name == "domain_isolation"
    assert rule.source_pattern == "myapp.domain.*"
    assert rule.forbidden_pattern == "myapp.infrastructure.*"


def test_load_config_explicit_path_and_invalid_schema_rejected(tmp_path: Path) -> None:
    bad_config = tmp_path / "bad_config.json"
    bad_config.write_text(
        """{
            "architecture_boundaries": [
                {
                    "name": "missing_forbidden_pattern"
                }
            ]
        }""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as exc_info:
        ReviewConfig.load_config(config_path=bad_config, repo_root=tmp_path, raise_on_error=True)
    assert "Invalid configuration" in str(exc_info.value) or "validation error" in str(exc_info.value).lower()


def test_architecture_analyzer_with_config_boundaries(tmp_path: Path) -> None:
    # Setup directory structure: app/domain/entity.py imports app/infra/db.py
    domain_dir = tmp_path / "app" / "domain"
    infra_dir = tmp_path / "app" / "infra"
    domain_dir.mkdir(parents=True)
    infra_dir.mkdir(parents=True)

    (tmp_path / "app" / "__init__.py").write_text("", encoding="utf-8")
    (domain_dir / "__init__.py").write_text("", encoding="utf-8")
    (infra_dir / "__init__.py").write_text("", encoding="utf-8")

    (infra_dir / "db.py").write_text("class Database:\n    pass\n", encoding="utf-8")
    (domain_dir / "entity.py").write_text("import app.infra.db\nclass Entity:\n    pass\n", encoding="utf-8")

    custom_rule = BoundaryRule(
        name="domain_to_infra_forbidden",
        source_pattern="app.domain.*",
        forbidden_pattern="app.infra.*",
        description="Domain must not import infra",
    )

    analyzer = ArchitectureAnalyzer(repo_root=tmp_path, boundary_rules=[custom_rule.model_dump()])
    report = analyzer.analyze()

    assert len(report.boundary_violations) == 1
    violation = report.boundary_violations[0]
    assert violation.rule_name == "domain_to_infra_forbidden"
    assert "app.domain.entity" in violation.source_module
    assert "app.infra.db" in violation.target_module
