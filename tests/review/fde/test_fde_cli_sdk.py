"""Tests for LogicFalcon Forward Deployment Engineering (FDE) CLI and SDK integration."""

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from logicfalcon import (
    DeploymentInventory,
    FdeMission,
    FdeStep,
    OperationCategory,
    PreflightReport,
    Runbook,
    fde_generate_runbook,
    fde_inspect,
    fde_plan,
    fde_preflight,
    fde_run_mission,
)
from logicfalcon.cli import run_main
from packages.review.fde.cli import run_fde_cli


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """Creates a minimal safe sample repository fixture for CLI and SDK tests."""
    repo = tmp_path / "sample_app"
    repo.mkdir()
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo-api"\nversion = "0.1.0"\ndependencies = ["fastapi", "uvicorn", "asyncpg"]\n',
        encoding="utf-8",
    )
    (repo / "docker-compose.yml").write_text(
        "version: '3.8'\nservices:\n  web:\n    image: demo:latest\n    ports:\n      - '8080:8080'\n    environment:\n      - DATABASE_URL=postgresql://localhost:5432/db\n",
        encoding="utf-8",
    )
    (repo / ".env.example").write_text(
        "API_KEY=your_key_here\nDATABASE_URL=postgresql://localhost:5432/app\nPORT=8080\n",
        encoding="utf-8",
    )
    return repo


@pytest.fixture
def sample_mission_file(tmp_path: Path) -> Path:
    """Creates a sample valid FDE mission JSON file."""
    m_file = tmp_path / "test_mission.json"
    mission = FdeMission(
        name="Test Verification Mission",
        objective="Verify system capabilities in isolated test fixture",
        steps=[
            FdeStep(
                id="step-1",
                name="Check Python",
                description="Verify runtime environment",
                target_adapter="system",
                operation="probe_runtime",
                target="python",
                operation_category=OperationCategory.READ_ONLY,
            )
        ],
    )
    m_file.write_text(mission.to_json(), encoding="utf-8")
    return m_file


def test_cli_fde_inspect_text(sample_repo: Path) -> None:
    """Verifies that `logicfalcon fde inspect` outputs human-readable overview."""
    stdout_buf = io.StringIO()
    with patch("sys.stdout", stdout_buf):
        exit_code = run_fde_cli(["inspect", str(sample_repo)])

    assert exit_code == 0
    out = stdout_buf.getvalue()
    assert "LogicFalcon FDE" in out
    assert "FastAPI" in out
    assert "8080" in out
    assert "PostgreSQL" in out


def test_cli_fde_inspect_json(sample_repo: Path) -> None:
    """Verifies that `logicfalcon fde inspect --json` outputs valid schema JSON."""
    stdout_buf = io.StringIO()
    with patch("sys.stdout", stdout_buf):
        exit_code = run_fde_cli(["inspect", str(sample_repo), "--json"])

    assert exit_code == 0
    data = json.loads(stdout_buf.getvalue())
    assert "FastAPI" in data.get("frameworks", [])
    assert 8080 in data.get("declared_ports", [])
    assert "PostgreSQL" in data.get("database_types", [])


def test_cli_fde_preflight(sample_repo: Path) -> None:
    """Verifies that `logicfalcon fde preflight` runs bounded readiness probes."""
    stdout_buf = io.StringIO()
    with patch("sys.stdout", stdout_buf):
        exit_code = run_fde_cli(["preflight", str(sample_repo), "--no-ports", "--no-env", "--json"])

    assert exit_code in (0, 2)
    data = json.loads(stdout_buf.getvalue())
    assert "status" in data
    assert "findings" in data
    assert "observed_evidence" in data


def test_cli_fde_capabilities() -> None:
    """Verifies that `logicfalcon fde capabilities` lists registered adapters."""
    stdout_buf = io.StringIO()
    with patch("sys.stdout", stdout_buf):
        exit_code = run_fde_cli(["capabilities", "--json"])

    assert exit_code == 0
    data = json.loads(stdout_buf.getvalue())
    adapters = data.get("adapters", {})
    assert "http" in adapters
    assert "docker" in adapters
    assert "postgres" in adapters
    assert "mcp" in adapters


def test_cli_fde_plan(sample_repo: Path) -> None:
    """Verifies that `logicfalcon fde plan` generates a mission DAG without executing."""
    stdout_buf = io.StringIO()
    with patch("sys.stdout", stdout_buf):
        exit_code = run_fde_cli(["plan", str(sample_repo), "--json"])

    assert exit_code == 0
    data = json.loads(stdout_buf.getvalue())
    assert "steps" in data
    assert len(data["steps"]) >= 1


def test_cli_fde_runbook(sample_mission_file: Path) -> None:
    """Verifies that `logicfalcon fde runbook` generates operational markdown and json."""
    # Test Markdown output
    stdout_buf = io.StringIO()
    with patch("sys.stdout", stdout_buf):
        exit_code = run_fde_cli(["runbook", str(sample_mission_file)])

    assert exit_code == 0
    md = stdout_buf.getvalue()
    assert "# Operational Runbook:" in md
    assert "Check Python" in md

    # Test JSON output
    stdout_json_buf = io.StringIO()
    with patch("sys.stdout", stdout_json_buf):
        exit_code_json = run_fde_cli(["runbook", str(sample_mission_file), "--json"])

    assert exit_code_json == 0
    data = json.loads(stdout_json_buf.getvalue())
    assert "ordered_instructions" in data


def test_cli_fde_run_mission(sample_mission_file: Path) -> None:
    """Verifies that `logicfalcon fde run` executes the mission through policy enforcement."""
    stdout_buf = io.StringIO()
    with patch("sys.stdout", stdout_buf):
        exit_code = run_fde_cli(["run", str(sample_mission_file), "--json"])

    assert exit_code == 0
    data = json.loads(stdout_buf.getvalue())
    assert data["status"] == "SUCCEEDED"
    assert data["succeeded_steps"] == 1


def test_cli_dispatch_via_run_main(sample_repo: Path) -> None:
    """Verifies that `run_main` correctly routes top-level 'fde' subcommand."""
    stdout_buf = io.StringIO()
    with patch("sys.stdout", stdout_buf):
        exit_code = run_main(["fde", "inspect", str(sample_repo), "--json"])

    assert exit_code == 0
    data = json.loads(stdout_buf.getvalue())
    assert "FastAPI" in data.get("frameworks", [])


def test_sdk_fde_inspect(sample_repo: Path) -> None:
    """Verifies that `fde_inspect` SDK function returns a DeploymentInventory instance."""
    inventory = fde_inspect(sample_repo)
    assert isinstance(inventory, DeploymentInventory)
    assert "FastAPI" in inventory.frameworks
    assert 8080 in inventory.declared_ports
    assert "PostgreSQL" in inventory.database_types


def test_sdk_fde_preflight(sample_repo: Path) -> None:
    """Verifies that `fde_preflight` SDK function runs preflight probes."""
    report = fde_preflight(sample_repo, check_docker=False)
    assert isinstance(report, PreflightReport)
    assert report.status is not None


def test_sdk_fde_plan_and_runbook(sample_repo: Path) -> None:
    """Verifies that `fde_plan` and `fde_generate_runbook` SDK functions work cohesively."""
    mission = fde_plan(sample_repo)
    assert isinstance(mission, FdeMission)
    assert len(mission.steps) >= 1

    runbook = fde_generate_runbook(mission)
    assert isinstance(runbook, Runbook)
    assert len(runbook.ordered_instructions) >= 1


def test_sdk_fde_run_mission(sample_mission_file: Path) -> None:
    """Verifies that `fde_run_mission` executes programmatic mission with report returned."""
    mission = FdeMission(
        name="Programmatic Mission",
        objective="Validate SDK runner",
        steps=[
            FdeStep(
                id="step-sdk",
                name="Probe Runtime",
                description="Check Python version",
                target_adapter="system",
                operation="probe_runtime",
                target="python",
                operation_category=OperationCategory.READ_ONLY,
            )
        ],
    )
    report = fde_run_mission(mission)
    assert report.status.value == "SUCCEEDED"
    assert report.total_steps == 1


def test_cli_backwards_compatibility() -> None:
    """Ensures existing logicfalcon CLI commands remain completely functional and compatible."""
    stdout_buf = io.StringIO()
    with patch("sys.stdout", stdout_buf):
        exit_code = run_main(["capabilities"])

    assert exit_code == 0
    data = json.loads(stdout_buf.getvalue())
    assert "product" in data
    assert data["product"] == "LogicFalcon"
    assert "capabilities" in data
