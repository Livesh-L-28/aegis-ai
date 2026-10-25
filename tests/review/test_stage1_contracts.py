"""Integration contract tests for Stage 1: configuration, architecture boundaries, SARIF, and CLI behavior."""

import json
from pathlib import Path

import pytest

from logicfalcon.cli import run_architecture
from packages.review.analyzer.architecture import ArchitectureAnalyzer
from packages.review.cli import run_cli


def test_cli_architecture_with_yaml_boundary_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # 1. Create a minimal Python project with boundary violation
    domain_dir = tmp_path / "myapp" / "domain"
    infra_dir = tmp_path / "myapp" / "infra"
    domain_dir.mkdir(parents=True)
    infra_dir.mkdir(parents=True)

    (tmp_path / "myapp" / "__init__.py").write_text("", encoding="utf-8")
    (domain_dir / "__init__.py").write_text("", encoding="utf-8")
    (infra_dir / "__init__.py").write_text("", encoding="utf-8")

    (infra_dir / "repo.py").write_text("class Repo:\n    pass\n", encoding="utf-8")
    (domain_dir / "model.py").write_text("import myapp.infra.repo\nclass Model:\n    pass\n", encoding="utf-8")

    # 2. Write .logicfalcon.yml with boundary rule
    yaml_config = tmp_path / ".logicfalcon.yml"
    yaml_config.write_text(
        """
architecture_boundaries:
  - name: domain_isolated_from_infra
    source_pattern: "myapp.domain.*"
    forbidden_pattern: "myapp.infra.*"
    description: "Domain layer must not depend on infrastructure layer."
""",
        encoding="utf-8",
    )

    # 3. Run logicfalcon architecture via run_architecture
    exit_code = run_architecture(["--repo", str(tmp_path), "--format", "json"])
    assert exit_code == 1

    captured = capsys.readouterr()
    report_data = json.loads(captured.out)
    assert report_data["health_score"] < 100.0
    violations = report_data["boundary_violations"]
    assert len(violations) >= 1
    v = violations[0]
    assert v["rule_name"] == "domain_isolated_from_infra"
    assert "myapp.domain.model" in v["source_module"]
    assert "myapp.infra.repo" in v["target_module"]


def test_cli_review_sarif_output_contract(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Create file with security rule trigger (SEC-001: eval)
    vuln_file = tmp_path / "danger.py"
    vuln_file.write_text("x = 1\neval('2 + 2')\n", encoding="utf-8")

    exit_code = run_cli(["--repo", str(tmp_path), "--file", "danger.py", "--format", "sarif"])
    assert exit_code in (0, 1)

    captured = capsys.readouterr()
    sarif = json.loads(captured.out)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "LogicFalcon"

    # Verify at least one result with ruleId SEC-001
    results = run["results"]
    assert len(results) >= 1
    sec_001 = next((r for r in results if r["ruleId"] == "SEC-001"), None)
    assert sec_001 is not None
    assert "danger.py" in sec_001["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_cli_architecture_clean_repo_exit_code_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Create clean, acyclic project
    lib_dir = tmp_path / "cleanpkg"
    lib_dir.mkdir()
    (lib_dir / "__init__.py").write_text("", encoding="utf-8")
    (lib_dir / "math_utils.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    exit_code = run_architecture(["--repo", str(tmp_path), "--format", "json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["health_score"] == 100.0
    assert len(report["cycles"]) == 0
    assert len(report["boundary_violations"]) == 0


def test_cli_invalid_config_file_exit_code_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad_config = tmp_path / "invalid.json"
    bad_config.write_text("{ not valid json }", encoding="utf-8")

    # 1. architecture command with bad config
    code_arch = run_architecture(["--repo", str(tmp_path), "--config", str(bad_config)])
    assert code_arch == 2
    err_arch = capsys.readouterr().err
    assert "Configuration error" in err_arch

    # 2. review command with bad config
    code_rev = run_cli(["--repo", str(tmp_path), "--config", str(bad_config)])
    assert code_rev == 2
    err_rev = capsys.readouterr().err
    assert "Configuration error" in err_rev


def test_polyglot_architecture_analysis_contract(tmp_path: Path) -> None:
    # Create Python backend and TypeScript frontend in same repo
    py_dir = tmp_path / "backend"
    ts_dir = tmp_path / "frontend"
    py_dir.mkdir()
    ts_dir.mkdir()

    (py_dir / "__init__.py").write_text("", encoding="utf-8")
    (py_dir / "service.py").write_text("class PyService:\n    pass\n", encoding="utf-8")

    (ts_dir / "clientA.ts").write_text("import { b } from './clientB';\nexport const a = 1;\n", encoding="utf-8")
    (ts_dir / "clientB.ts").write_text("import { a } from './clientA';\nexport const b = 2;\n", encoding="utf-8")

    analyzer = ArchitectureAnalyzer(repo_root=tmp_path)
    report = analyzer.analyze(files=["backend/service.py", "frontend/clientA.ts", "frontend/clientB.ts"])

    # Total modules should reflect both Python and TypeScript
    assert report.total_modules == 3
    # Cycle in TypeScript should be detected
    assert len(report.cycles) == 1
    cycle = report.cycles[0]
    assert "frontend.clientA" in cycle.modules
    assert "frontend.clientB" in cycle.modules
