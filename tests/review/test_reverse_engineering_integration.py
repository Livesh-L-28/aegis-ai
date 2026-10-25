"""Integration tests for LogicFalcon Review Engine and Reverse Engineering Intelligence.

Verifies the Phase 5 central objective:
- Contextual enrichment of review findings with architectural components, blast radius,
  and entry-point reachability.
- Strict preservation invariant: security findings are never suppressed, downgraded, or modified.
- Two-way integration between LocalReviewEngine and ReverseEngineeringEngine.
- CLI and SDK contracts.
"""

from pathlib import Path

import pytest

from logicfalcon.cli import run_main
from logicfalcon.sdk import reverse_engineer, review
from packages.review.domain.models import FindingCategory, FindingSeverity
from packages.review.engine import LocalReviewEngine, ReviewConfig
from packages.review.reverse_engineering.engine import ReverseEngineeringEngine


@pytest.fixture
def integrated_review_repo(tmp_path: Path) -> Path:
    """Creates a sample multi-layer repository with intentional security and quality findings."""
    repo = tmp_path / "integrated_project"
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

    # Presentation / API layer with route and intentional security finding (hardcoded secret)
    api_dir = repo / "api"
    api_dir.mkdir()
    (api_dir / "__init__.py").write_text("")
    (api_dir / "main.py").write_text(
        """import os
from fastapi import FastAPI, Depends
from services.auth_service import verify_user

app = FastAPI()

def cli_entry():
    print("Starting CLI")

def run_command(payload: str):
    # SEC-001: Dangerous Dynamic Code Execution
    return eval(payload)

@app.get("/api/v1/status")
def status_endpoint(auth = Depends(verify_user)):
    return {"status": "ok"}
"""
    )

    # Application service layer that imports domain
    services_dir = repo / "services"
    services_dir.mkdir()
    (services_dir / "__init__.py").write_text("")
    (services_dir / "auth_service.py").write_text(
        """from domain.user import UserModel

def verify_user(token: str):
    # QUAL-002: Mutable default argument
    def inner_validate(tags: list = []):
        tags.append(token)
        return True
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

    # Initialize Git repository for fast diff operations
    import subprocess
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(repo), check=True, capture_output=True)

    return repo


def test_review_engine_with_re_context_enrichment(integrated_review_repo: Path) -> None:
    """Verifies that findings are enriched with component, layer, and blast radius context."""
    config = ReviewConfig(include_re_context=True)
    engine = LocalReviewEngine(repo_root=integrated_review_repo, config=config)

    report = engine.review_files(
        file_paths=[
            "api/main.py",
            "services/auth_service.py",
            "domain/user.py",
        ]
    )

    # 1. re_context summary block is populated
    assert report.re_context is not None
    assert report.re_context.get("components_count", 0) > 0
    assert report.re_context.get("api_routes_count", 0) >= 1
    assert report.metadata.get("re_context_enabled") is True

    # 2. Findings exist
    assert len(report.findings) > 0

    # 3. Check hardcoded credential finding in api/main.py
    cred_finding = next((f for f in report.findings if f.rule_id == "SEC-001"), None)
    assert cred_finding is not None
    assert cred_finding.severity == FindingSeverity.CRITICAL

    # Finding metadata must have architectural component and layer
    assert "re_component" in cred_finding.metadata
    assert "api" in cred_finding.metadata["re_component"]
    assert "re_layer" in cred_finding.metadata
    assert cred_finding.metadata["re_layer"] == "presentation_api"

    # Must have blast radius count
    assert "reverse_dependencies_count" in cred_finding.metadata

    # Must identify affected entry points
    assert "entry_points_affected" in cred_finding.metadata
    assert "api-cli" in cred_finding.metadata["entry_points_affected"]


def test_security_finding_preservation_invariant(integrated_review_repo: Path) -> None:
    """CRITICAL SAFETY TEST: Verifies reverse engineering context NEVER suppresses or downgrades security findings."""
    # 1. Run baseline without RE context
    baseline_config = ReviewConfig(include_re_context=False)
    baseline_engine = LocalReviewEngine(repo_root=integrated_review_repo, config=baseline_config)
    baseline_report = baseline_engine.review_files(file_paths=["api/main.py"])

    # 2. Run with RE context enabled
    enriched_config = ReviewConfig(include_re_context=True)
    enriched_engine = LocalReviewEngine(repo_root=integrated_review_repo, config=enriched_config)
    enriched_report = enriched_engine.review_files(file_paths=["api/main.py"])

    # Compare security findings
    baseline_sec = [f for f in baseline_report.findings if f.category == FindingCategory.SECURITY]
    enriched_sec = [f for f in enriched_report.findings if f.category == FindingCategory.SECURITY]

    assert len(baseline_sec) > 0
    # Every security finding in baseline must exist in enriched review with EXACT same rule_id and severity
    assert len(enriched_sec) == len(baseline_sec)
    for b_f, e_f in zip(baseline_sec, enriched_sec, strict=False):
        assert b_f.rule_id == e_f.rule_id
        assert b_f.severity == e_f.severity
        assert b_f.location.file_path == e_f.location.file_path
        assert b_f.location.start_line == e_f.location.start_line


def test_reverse_engineering_engine_with_review(integrated_review_repo: Path) -> None:
    """Verifies analyze_with_review populates review findings within the reverse engineering report."""
    engine = ReverseEngineeringEngine(repo_root=integrated_review_repo)
    report = engine.analyze_with_review(run_review=True)

    assert report.review_summary is not None
    assert report.review_summary["total_findings"] > 0
    assert len(report.review_findings) > 0

    # Review findings should include our SEC-001 finding
    assert any(getattr(f, "rule_id", "") == "SEC-001" for f in report.review_findings)


def test_sdk_review_and_reverse_engineer_integration(integrated_review_repo: Path) -> None:
    """Verifies SDK functions support include_re_context and run_review."""
    # SDK review with RE context
    rev_report = review(repo=integrated_review_repo, include_re_context=True)
    assert rev_report.re_context is not None

    # SDK reverse_engineer with run_review
    re_report = reverse_engineer(repo_root=integrated_review_repo, run_review=True)
    assert len(re_report.review_findings) > 0


def test_cli_reverse_engineer_with_review_exit_code(integrated_review_repo: Path) -> None:
    """Verifies logicfalcon reverse-engineer --with-review returns exit code 2 when findings exist."""
    exit_code = run_main([
        "reverse-engineer",
        "--repo", str(integrated_review_repo),
        "--format", "json",
        "--with-review",
    ])
    assert exit_code == 2
