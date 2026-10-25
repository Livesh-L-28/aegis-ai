"""Integration tests for Change Impact Intelligence with LocalReviewEngine, CLI, and SDK."""

import json
import subprocess
from pathlib import Path

import pytest

from logicfalcon.cli import run_main
from logicfalcon.sdk import analyze_impact
from packages.review.domain.models import FindingCategory
from packages.review.engine import LocalReviewEngine, ReviewConfig
from packages.review.impact.engine import ChangeImpactEngine


@pytest.fixture
def integrated_impact_repo(tmp_path: Path) -> Path:
    """Creates a sample multi-layer repository with intentional security findings."""
    repo = tmp_path / "integrated_impact_repo"
    repo.mkdir()

    # Manifest
    (repo / "pyproject.toml").write_text(
        """[project]
name = "secure-corp-api"
version = "0.2.0"
dependencies = ["fastapi", "pydantic"]

[project.scripts]
api-cli = "api.main:cli_entry"
"""
    )

    # Presentation / API layer with route and intentional security finding (eval)
    api_dir = repo / "api"
    api_dir.mkdir()
    (api_dir / "__init__.py").write_text("")
    (api_dir / "main.py").write_text(
        """from fastapi import FastAPI
from services.auth_service import verify_user

app = FastAPI()

def cli_entry():
    print("Starting CLI")

def dangerous_eval(payload: str):
    # SEC-001: Dangerous Dynamic Code Execution
    return eval(payload)

@app.get("/api/v1/status")
def status_endpoint():
    return {"status": "ok"}
"""
    )

    # Service layer
    services_dir = repo / "services"
    services_dir.mkdir()
    (services_dir / "__init__.py").write_text("")
    (services_dir / "auth_service.py").write_text(
        """from domain.user import UserModel

def verify_user(token: str):
    return UserModel(username="alice", is_admin=True)
"""
    )

    # Domain core layer
    domain_dir = repo / "domain"
    domain_dir.mkdir()
    (domain_dir / "__init__.py").write_text("")
    (domain_dir / "user.py").write_text(
        """from pydantic import BaseModel

class UserModel(BaseModel):
    username: str
    is_admin: bool = False
"""
    )

    # Tests
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "__init__.py").write_text("")
    (tests_dir / "test_api.py").write_text(
        """from api.main import status_endpoint

def test_status():
    assert status_endpoint() == {"status": "ok"}
"""
    )

    # Initialize Git repository
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), check=True, capture_output=True)

    return repo


def test_review_engine_with_impact_analysis_enrichment(integrated_impact_repo: Path) -> None:
    """Verifies that ReviewConfig(include_impact_analysis=True) attaches impact analysis metadata."""
    config = ReviewConfig(include_impact_analysis=True)
    engine = LocalReviewEngine(repo_root=integrated_impact_repo, config=config)

    report = engine.review_files(file_paths=["domain/user.py", "services/auth_service.py", "api/main.py"])

    assert report.metadata.get("impact_analysis_enabled") is True
    impact_meta = report.metadata.get("impact_analysis")
    assert impact_meta is not None
    assert "risk_level" in impact_meta
    assert "risk_score" in impact_meta
    assert impact_meta.get("impacted_entities_count", 0) >= 1
    assert "tests/test_api.py" in impact_meta.get("recommended_tests", [])


def test_security_finding_preservation_invariant_with_impact(integrated_impact_repo: Path) -> None:
    """CRITICAL SAFETY TEST: Verifies that change impact analysis NEVER suppresses or alters security findings."""
    # 1. Baseline without impact analysis
    base_config = ReviewConfig(include_impact_analysis=False)
    base_engine = LocalReviewEngine(repo_root=integrated_impact_repo, config=base_config)
    base_report = base_engine.review_files(file_paths=["api/main.py"])

    # 2. Enriched with impact analysis
    enriched_config = ReviewConfig(include_impact_analysis=True)
    enriched_engine = LocalReviewEngine(repo_root=integrated_impact_repo, config=enriched_config)
    enriched_report = enriched_engine.review_files(file_paths=["api/main.py"])

    base_sec = [f for f in base_report.findings if f.category == FindingCategory.SECURITY]
    enriched_sec = [f for f in enriched_report.findings if f.category == FindingCategory.SECURITY]

    assert len(base_sec) > 0
    assert len(enriched_sec) == len(base_sec)

    for b_f, e_f in zip(base_sec, enriched_sec, strict=False):
        assert b_f.rule_id == e_f.rule_id
        assert b_f.severity == e_f.severity
        assert b_f.location.file_path == e_f.location.file_path
        assert b_f.location.start_line == e_f.location.start_line
        assert b_f.message == e_f.message


def test_change_impact_engine_analyze_with_review(integrated_impact_repo: Path) -> None:
    """Verifies that ChangeImpactEngine.analyze_with_review returns correlated impact and review reports."""
    engine = ChangeImpactEngine(integrated_impact_repo)
    impact_rep, review_rep = engine.analyze_with_review(explicit_files=["api/main.py"])

    assert impact_rep.repository_path == str(integrated_impact_repo)
    assert len(review_rep.findings) > 0

    # Ensure SEC-001 was detected
    assert any(f.rule_id == "SEC-001" for f in review_rep.findings)
    assert "impact_analysis" in review_rep.metadata


def test_cli_impact_command_execution(integrated_impact_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verifies that 'logicfalcon impact' executes successfully via CLI."""
    exit_code = run_main([
        "impact",
        "--repo", str(integrated_impact_repo),
        "--files", "domain/user.py",
        "--format", "json",
    ])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert "change_set" in data


def test_cli_impact_fail_on_risk_flag(integrated_impact_repo: Path) -> None:
    """Verifies that --fail-on-risk returns non-zero when risk meets threshold."""
    # domain/user.py has risk level MEDIUM/LOW
    exit_code = run_main([
        "impact",
        "--repo", str(integrated_impact_repo),
        "--files", "domain/user.py",
        "--fail-on-risk", "LOW",
    ])
    assert exit_code == 1


def test_sdk_analyze_impact_and_formats(integrated_impact_repo: Path) -> None:
    """Verifies programmatic SDK exports: analyze_impact with Markdown and JSON formatting."""
    # 1. Structured model return
    rep = analyze_impact(repo_root=integrated_impact_repo, explicit_files=["domain/user.py"])
    assert rep.repository_path == str(integrated_impact_repo)
    assert len(rep.impacted_entities) >= 1

    # 2. JSON return
    json_str = analyze_impact(
        repo_root=integrated_impact_repo,
        explicit_files=["domain/user.py"],
        format_type="json",
    )
    parsed = json.loads(json_str)
    assert parsed["risk_score"] >= 0.0

    # 3. Markdown return
    md_str = analyze_impact(
        repo_root=integrated_impact_repo,
        explicit_files=["domain/user.py"],
        format_type="markdown",
    )
    assert "# LogicFalcon — Change Impact Intelligence Report" in md_str
