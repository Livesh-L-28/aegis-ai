import json
from pathlib import Path

import pytest

from logicfalcon import (
    ArchitecturePolicy,
    BoundaryRule,
    CycleGroup,
    LayerDefinition,
    RuleException,
    analyze_architecture,
)
from logicfalcon.cli import run_architecture
from packages.review.cli import format_sarif_report
from packages.review.domain.models import (
    AffectedArtifacts,
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    GitDiffSummary,
    ReviewFinding,
    ReviewReport,
    SourceLocation,
)


def test_sdk_analyze_architecture_contract(tmp_path: Path) -> None:
    """Verifies that the programmatic Python SDK export analyze_architecture and models function as expected."""
    # Create sample module
    (tmp_path / "core.py").write_text("def hello(): return 1\n", encoding="utf-8")

    policy = ArchitecturePolicy(
        layers=[
            LayerDefinition(name="core", patterns=["core*"], allowed_dependencies=[])
        ],
        rules=[
            BoundaryRule(name="rule1", source_pattern="core*", forbidden_pattern="external*")
        ],
        exceptions=[
            RuleException(source_pattern="core*", target_pattern="external*", reason="Legacy adapter bridge")
        ],
    )

    report = analyze_architecture(repo=tmp_path, policy=policy)
    assert report.total_modules == 1
    assert report.health_score == 100.0
    assert isinstance(report.cycle_groups, list)
    assert isinstance(report.layers, list)
    assert len(report.layers) == 1
    assert report.layers[0].name == "core"

    # Verify CycleGroup model contract
    cg = CycleGroup(id="SCC-01", modules=["core", "helper"], size=2)
    assert cg.size == 2
    assert cg.id == "SCC-01"


def test_cli_architecture_show_paths_contract(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verifies that `logicfalcon architecture --show-paths` outputs transitive paths."""
    (tmp_path / "domain.py").write_text("import infra\n", encoding="utf-8")
    (tmp_path / "infra.py").write_text("x = 10\n", encoding="utf-8")

    cfg_file = tmp_path / ".logicfalcon.json"
    cfg_file.write_text(
        """{
            "architecture_boundaries": [
                {
                    "name": "domain_isolation",
                    "source_pattern": "domain*",
                    "forbidden_pattern": "infra*",
                    "description": "Domain must not import infra"
                }
            ]
        }""",
        encoding="utf-8",
    )

    exit_code = run_architecture(["--repo", str(tmp_path), "--config", str(cfg_file), "--show-paths"])
    assert exit_code == 1

    captured = capsys.readouterr()
    assert "🏛️  Architecture & Modularity Report — LogicFalcon" in captured.out
    assert "domain -> infra (domain_isolation)" in captured.out


def test_cli_architecture_json_contract(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verifies that `logicfalcon architecture --format json` produces valid JSON with Stage 2 fields."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")

    exit_code = run_architecture(["--repo", str(tmp_path), "--format", "json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "total_modules" in data
    assert "cycle_groups" in data
    assert "layers" in data
    assert "health_score" in data


def test_sarif_v210_dependency_path_properties() -> None:
    """Verifies that SARIF v2.1.0 report serialization includes dependency_path and rule_type."""
    finding = ReviewFinding(
        rule_id="ARCH-002",
        title="Architectural Boundary Violation",
        message="Domain must not import adapter (Path: domain.user -> adapters.db)",
        severity=FindingSeverity.WARNING,
        category=FindingCategory.ARCHITECTURE,
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="src/domain/user.py", start_line=1),
        tool_name="architecture_analyzer",
        confidence=1.0,
        metadata={
            "source_module": "domain.user",
            "target_module": "adapters.db",
            "rule_name": "domain_isolation",
            "rule_type": "LAYER_HIERARCHY",
            "dependency_path": ["domain.user", "adapters.db"],
            "is_transitive": False,
        },
    )

    report = ReviewReport(
        repository_path=".",
        diff_summary=GitDiffSummary(),
        affected_artifacts=AffectedArtifacts(),
        findings=[finding],
    )

    sarif_str = format_sarif_report(report)
    sarif_json = json.loads(sarif_str)

    assert sarif_json["version"] == "2.1.0"
    results = sarif_json["runs"][0]["results"]
    assert len(results) == 1
    props = results[0]["properties"]
    assert props["dependency_path"] == ["domain.user", "adapters.db"]
    assert props["rule_type"] == "LAYER_HIERARCHY"


def test_baseline_suppression_safety_distinct_violations(tmp_path: Path) -> None:
    """Verifies that baseline suppression cannot accidentally suppress a newly introduced policy violation."""
    # Existing violation: domain -> adapters
    finding1 = ReviewFinding(
        rule_id="ARCH-002",
        title="Architectural Boundary Violation: domain_layer_isolation",
        message="Domain entity must not depend on external infrastructure adapters.",
        severity=FindingSeverity.WARNING,
        category=FindingCategory.ARCHITECTURE,
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="domain/user.py", start_line=1),
        tool_name="architecture_analyzer",
        metadata={
            "source_module": "domain.user",
            "target_module": "adapters.db",
            "rule_name": "domain_layer_isolation",
        },
    )

    # Newly introduced violation in the same file: domain -> cli
    finding2 = ReviewFinding(
        rule_id="ARCH-002",
        title="Architectural Boundary Violation: domain_cli_isolation",
        message="Domain layer must not depend on CLI.",
        severity=FindingSeverity.WARNING,
        category=FindingCategory.ARCHITECTURE,
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="domain/user.py", start_line=1),
        tool_name="architecture_analyzer",
        metadata={
            "source_module": "domain.user",
            "target_module": "cli.view",
            "rule_name": "domain_cli_isolation",
        },
    )

    # Fingerprints must be distinct!
    assert finding1.deduplication_hash != finding2.deduplication_hash

    # Save baseline containing ONLY finding1
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps({"findings": [{"deduplication_hash": finding1.deduplication_hash}]}),
        encoding="utf-8",
    )

    # Emulate baseline filtering
    base_hashes = {finding1.deduplication_hash}
    filtered = [f for f in [finding1, finding2] if f.deduplication_hash not in base_hashes]

    # finding1 is suppressed, but new finding2 is NOT suppressed!
    assert len(filtered) == 1
    assert filtered[0].metadata["rule_name"] == "domain_cli_isolation"
