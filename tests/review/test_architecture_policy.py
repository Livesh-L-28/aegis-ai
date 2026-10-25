"""Unit and regression tests for LogicFalcon Stage 2.1 Architecture Policy Engine."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from packages.review.analyzer.architecture import ArchitectureAnalyzer
from packages.review.domain.models import (
    ArchitecturePolicy,
    BoundaryRule,
    LayerDefinition,
    RuleException,
)
from packages.review.engine import ReviewConfig


@pytest.fixture
def policy_repo(tmp_path: Path) -> Path:
    """Creates a temporary repository simulating layered architecture."""
    # domain layer
    domain_dir = tmp_path / "domain"
    domain_dir.mkdir(parents=True)
    (domain_dir / "__init__.py").write_text("", encoding="utf-8")
    (domain_dir / "user.py").write_text(
        "class User:\n    pass\n",
        encoding="utf-8",
    )

    # application layer
    app_dir = tmp_path / "application"
    app_dir.mkdir(parents=True)
    (app_dir / "__init__.py").write_text("", encoding="utf-8")
    (app_dir / "service.py").write_text(
        "from domain.user import User\n\nclass UserService:\n    pass\n",
        encoding="utf-8",
    )

    # infrastructure layer
    infra_dir = tmp_path / "infrastructure"
    infra_dir.mkdir(parents=True)
    (infra_dir / "__init__.py").write_text("", encoding="utf-8")
    (infra_dir / "db.py").write_text(
        "from domain.user import User\n\nclass UserRepository:\n    pass\n",
        encoding="utf-8",
    )

    # ui / presentation layer
    ui_dir = tmp_path / "ui"
    ui_dir.mkdir(parents=True)
    (ui_dir / "__init__.py").write_text("", encoding="utf-8")
    (ui_dir / "cli.py").write_text(
        "from application.service import UserService\n\ndef main():\n    pass\n",
        encoding="utf-8",
    )

    return tmp_path


def test_clean_architecture_layers_pass(policy_repo: Path) -> None:
    """Verifies that allowed layer dependency hierarchy produces zero violations."""
    policy = ArchitecturePolicy(
        layers=[
            LayerDefinition(
                name="domain",
                patterns=["domain*"],
                allowed_dependencies=[],
            ),
            LayerDefinition(
                name="application",
                patterns=["application*"],
                allowed_dependencies=["domain"],
            ),
            LayerDefinition(
                name="infrastructure",
                patterns=["infrastructure*"],
                allowed_dependencies=["domain"],
            ),
            LayerDefinition(
                name="ui",
                patterns=["ui*"],
                allowed_dependencies=["application"],
            ),
        ]
    )

    analyzer = ArchitectureAnalyzer(repo_root=policy_repo, policy=policy)
    report = analyzer.analyze()

    assert len(report.boundary_violations) == 0
    assert report.health_score == 100.0


def test_forbidden_layer_dependency_detected(policy_repo: Path) -> None:
    """Verifies that an illegal layer dependency direction is detected with path evidence."""
    # Introduce domain depending illegally on infrastructure
    domain_file = policy_repo / "domain" / "user.py"
    domain_file.write_text(
        "from infrastructure.db import UserRepository\n\nclass User:\n    pass\n",
        encoding="utf-8",
    )

    policy = ArchitecturePolicy(
        layers=[
            LayerDefinition(
                name="domain",
                patterns=["domain*"],
                allowed_dependencies=[],  # domain must not depend on infrastructure
            ),
            LayerDefinition(
                name="infrastructure",
                patterns=["infrastructure*"],
                allowed_dependencies=["domain"],
            ),
        ]
    )

    analyzer = ArchitectureAnalyzer(repo_root=policy_repo, policy=policy)
    report = analyzer.analyze()

    assert len(report.boundary_violations) == 1
    violation = report.boundary_violations[0]
    assert violation.source_module == "domain.user"
    assert violation.target_module == "infrastructure.db"
    assert violation.rule_type == "LAYER_HIERARCHY"
    assert violation.dependency_path == ["domain.user", "infrastructure.db"]

    findings = analyzer.generate_findings(report)
    arch_findings = [f for f in findings if f.rule_id == "ARCH-002"]
    assert len(arch_findings) == 1
    assert "Path: domain.user -> infrastructure.db" in arch_findings[0].message
    assert arch_findings[0].metadata["rule_type"] == "LAYER_HIERARCHY"


def test_active_exception_suppresses_violation(policy_repo: Path) -> None:
    """Verifies that a documented, non-expired exception successfully suppresses the violation."""
    domain_file = policy_repo / "domain" / "user.py"
    domain_file.write_text(
        "from infrastructure.db import UserRepository\n\nclass User:\n    pass\n",
        encoding="utf-8",
    )

    future_date = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%d")
    policy = ArchitecturePolicy(
        rules=[
            BoundaryRule(
                name="domain_isolation",
                source_pattern="domain*",
                forbidden_pattern="infrastructure*",
                description="Domain must not import infrastructure.",
            )
        ],
        exceptions=[
            RuleException(
                source_pattern="domain*",
                target_pattern="infrastructure*",
                reason="Temporary legacy adapter bridge pending Phase 3 refactoring.",
                expires_at=future_date,
            )
        ],
    )

    analyzer = ArchitectureAnalyzer(repo_root=policy_repo, policy=policy)
    report = analyzer.analyze()

    assert len(report.boundary_violations) == 0


def test_expired_exception_fails_to_suppress(policy_repo: Path) -> None:
    """Verifies that an expired exception no longer suppresses the violation and issues a warning."""
    domain_file = policy_repo / "domain" / "user.py"
    domain_file.write_text(
        "from infrastructure.db import UserRepository\n\nclass User:\n    pass\n",
        encoding="utf-8",
    )

    past_date = (datetime.now(UTC) - timedelta(days=5)).strftime("%Y-%m-%d")
    policy = ArchitecturePolicy(
        rules=[
            BoundaryRule(
                name="domain_isolation",
                source_pattern="domain*",
                forbidden_pattern="infrastructure*",
                description="Domain must not import infrastructure.",
            )
        ],
        exceptions=[
            RuleException(
                source_pattern="domain*",
                target_pattern="infrastructure*",
                reason="Temporary legacy debt exception that has expired.",
                expires_at=past_date,
            )
        ],
    )

    analyzer = ArchitectureAnalyzer(repo_root=policy_repo, policy=policy)
    report = analyzer.analyze()

    assert len(report.boundary_violations) == 1
    violation = report.boundary_violations[0]
    assert "Exception expired" in violation.description
    assert past_date in violation.description


def test_strict_config_validation_diagnostics(tmp_path: Path) -> None:
    """Verifies strict configuration validation: duplicate layers, missing reasons, malformed dates."""
    # 1. Missing reason in exception
    bad_cfg1 = tmp_path / ".logicfalcon.json"
    bad_cfg1.write_text(
        """{
            "architecture_policy": {
                "exceptions": [
                    {"source_pattern": "a*", "target_pattern": "b*", "reason": ""}
                ]
            }
        }""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="non-empty 'reason'"):
        ReviewConfig.load_config(config_path=bad_cfg1, repo_root=tmp_path, raise_on_error=True)

    # 2. Duplicate layer names
    bad_cfg2 = tmp_path / "dup_layer.json"
    bad_cfg2.write_text(
        """{
            "architecture_policy": {
                "layers": [
                    {"name": "core", "patterns": ["core*"]},
                    {"name": "core", "patterns": ["src/core*"]}
                ]
            }
        }""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Duplicate layer definition"):
        ReviewConfig.load_config(config_path=bad_cfg2, repo_root=tmp_path, raise_on_error=True)

    # 3. Malformed expires_at date
    bad_cfg3 = tmp_path / "bad_date.json"
    bad_cfg3.write_text(
        """{
            "architecture_policy": {
                "exceptions": [
                    {"source_pattern": "a*", "target_pattern": "b*", "reason": "Valid reason", "expires_at": "not-a-date"}
                ]
            }
        }""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid 'expires_at' format"):
        ReviewConfig.load_config(config_path=bad_cfg3, repo_root=tmp_path, raise_on_error=True)

    # 4. Path traversal sequence in pattern
    bad_cfg4 = tmp_path / "traversal.json"
    bad_cfg4.write_text(
        """{
            "architecture_policy": {
                "layers": [
                    {"name": "core", "patterns": ["../../etc/*"]}
                ]
            }
        }""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"Path traversal sequence '\.\.' is forbidden"):
        ReviewConfig.load_config(config_path=bad_cfg4, repo_root=tmp_path, raise_on_error=True)
