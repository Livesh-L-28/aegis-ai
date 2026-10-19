"""API Integration tests for Phase 1E Engineering Evidence Graph endpoints."""

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.entities import Organization, Project
from apps.api.app.services.evidence_graph import EvidenceGraphService
from packages.intelligence.evidence.graph_models import (
    EvidenceRecord,
    ProvenanceTag,
    ValidationStatus,
)


@pytest.mark.asyncio
async def test_get_symbols_success_and_pagination(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    # 1. Setup Org & Project
    org = Organization(name="API Test Org", slug=f"api-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="API Proj", slug="api-proj")
    db_session.add(proj)
    await db_session.flush()

    # 2. Index revision with symbols
    service = EvidenceGraphService(db_session)
    files = {
        "pkg/calculator.py": (
            "def add(a, b):\n"
            "    return a + b\n\n"
            "def subtract(a, b):\n"
            "    return a - b\n"
        ),
        "pkg/models.py": (
            "class Entry:\n"
            "    pass\n"
        ),
    }
    sha = "1234567890abcdef1234567890abcdef12345678"
    repo, _rev, _ = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="calc-api-repo",
        commit_sha=sha,
        file_contents=files,
    )

    headers = {
        "x-organization-id": str(org.id),
        "x-user-roles": "ENGINEER",
    }

    # 3. Query all symbols
    res = await client.get(
        f"/api/v1/evidence-graph/repositories/{repo.id}/revisions/{sha}/symbols?limit=10&offset=0",
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3
    names = {s["name"] for s in data["items"]}
    assert names == {"add", "subtract", "Entry"}

    # 4. Filter by file_path
    filter_res = await client.get(
        f"/api/v1/evidence-graph/repositories/{repo.id}/revisions/{sha}/symbols?file_path=pkg/models.py",
        headers=headers,
    )
    assert filter_res.status_code == 200
    filter_data = filter_res.json()
    assert filter_data["total"] == 1
    assert filter_data["items"][0]["name"] == "Entry"


@pytest.mark.asyncio
async def test_symbols_endpoint_validations_and_errors(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    org = Organization(name="Validation Org", slug=f"val-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    headers = {
        "x-organization-id": str(org.id),
        "x-user-roles": "ENGINEER",
    }
    dummy_repo_id = uuid4()

    # Invalid SHA format
    bad_sha_res = await client.get(
        f"/api/v1/evidence-graph/repositories/{dummy_repo_id}/revisions/invalid_sha!/symbols",
        headers=headers,
    )
    assert bad_sha_res.status_code == 400

    # Path traversal attempt in file_path
    sha = "a" * 40
    traversal_res = await client.get(
        f"/api/v1/evidence-graph/repositories/{dummy_repo_id}/revisions/{sha}/symbols?file_path=../etc/passwd",
        headers=headers,
    )
    assert traversal_res.status_code == 400

    # Protected file access attempt
    protected_res = await client.get(
        f"/api/v1/evidence-graph/repositories/{dummy_repo_id}/revisions/{sha}/symbols?file_path=render_schema.json",
        headers=headers,
    )
    assert protected_res.status_code == 400

    # Unknown repository (valid format)
    unknown_res = await client.get(
        f"/api/v1/evidence-graph/repositories/{dummy_repo_id}/revisions/{sha}/symbols",
        headers=headers,
    )
    assert unknown_res.status_code == 404


@pytest.mark.asyncio
async def test_tenant_isolation_symbols_and_evidence(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    # Setup Tenant 1 and Tenant 2
    org1 = Organization(name="Tenant Alpha", slug=f"alpha-{uuid4().hex[:6]}")
    org2 = Organization(name="Tenant Beta", slug=f"beta-{uuid4().hex[:6]}")
    db_session.add_all([org1, org2])
    await db_session.flush()

    proj1 = Project(organization_id=org1.id, name="Project Alpha", slug="proj-alpha")
    db_session.add(proj1)
    await db_session.flush()

    service = EvidenceGraphService(db_session)
    sha = "b" * 40
    repo1, _, _ = await service.index_repository_revision(
        organization_id=org1.id,
        project_id=proj1.id,
        repo_slug="alpha-repo",
        commit_sha=sha,
        file_contents={"main.py": "def main(): pass\n"},
    )

    # Tenant 1 can view its symbols
    t1_headers = {"x-organization-id": str(org1.id), "x-user-roles": "ENGINEER"}
    t1_res = await client.get(
        f"/api/v1/evidence-graph/repositories/{repo1.id}/revisions/{sha}/symbols",
        headers=t1_headers,
    )
    assert t1_res.status_code == 200

    # Tenant 2 cannot access Tenant 1's repository -> must return 404 (no information leakage)
    t2_headers = {"x-organization-id": str(org2.id), "x-user-roles": "ENGINEER"}
    t2_res = await client.get(
        f"/api/v1/evidence-graph/repositories/{repo1.id}/revisions/{sha}/symbols",
        headers=t2_headers,
    )
    assert t2_res.status_code == 404


@pytest.mark.asyncio
async def test_affected_tests_endpoint(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    org = Organization(name="Aff Org", slug=f"aff-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Aff Proj", slug="aff-proj")
    db_session.add(proj)
    await db_session.flush()

    service = EvidenceGraphService(db_session)
    sha = "c" * 40
    files = {
        "services/auth.py": "import db.user\ndef login(): pass\n",
        "tests/test_auth.py": "import services.auth\ndef test_login(): pass\n",
    }
    repo, _, _ = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="auth-service",
        commit_sha=sha,
        file_contents=files,
    )

    headers = {"x-organization-id": str(org.id), "x-user-roles": "ENGINEER"}

    # Discover affected tests for services/auth.py
    res = await client.get(
        f"/api/v1/evidence-graph/repositories/{repo.id}/revisions/{sha}/affected-tests?files=services/auth.py",
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["commit_sha"] == sha
    assert "tests/test_auth.py" in data["affected_tests"]


@pytest.mark.asyncio
async def test_get_evidence_endpoint_filtering(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    org = Organization(name="Ev Org", slug=f"ev-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Ev Proj", slug="ev-proj")
    db_session.add(proj)
    await db_session.flush()

    service = EvidenceGraphService(db_session)
    sha = "d" * 40
    repo, _rev, _ = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="ev-repo",
        commit_sha=sha,
        file_contents={"main.py": "def run(): pass\n"},
    )

    # Record 2 evidence items of different types
    rec1 = EvidenceRecord(
        evidence_type="static_analysis",
        provenance=ProvenanceTag(source="bandit", tool_version="1.7.5"),
        file_path="main.py",
        start_line=1,
        end_line=1,
        content="Static finding",
        structured_payload={"check": "assert"},
        confidence=0.9,
        validation_status=ValidationStatus.VALIDATED,
    )
    rec2 = EvidenceRecord(
        evidence_type="hypothesis",
        provenance=ProvenanceTag(source="ai_reviewer", tool_version="1.0"),
        file_path="main.py",
        start_line=1,
        end_line=1,
        content="AI suggestion",
        structured_payload={"impact": "low"},
        confidence=0.7,
        validation_status=ValidationStatus.UNVERIFIED,
    )
    await service.record_evidence(org.id, rec1, repo.id, sha)
    await service.record_evidence(org.id, rec2, repo.id, sha)

    headers = {"x-organization-id": str(org.id), "x-user-roles": "ENGINEER"}

    # Query all evidence
    all_res = await client.get(
        f"/api/v1/evidence-graph/repositories/{repo.id}/evidence",
        headers=headers,
    )
    assert all_res.status_code == 200
    assert all_res.json()["total"] == 2

    # Filter by evidence_type=STATIC_ANALYSIS
    filtered_res = await client.get(
        f"/api/v1/evidence-graph/repositories/{repo.id}/evidence?evidence_type=STATIC_ANALYSIS",
        headers=headers,
    )
    assert filtered_res.status_code == 200
    assert filtered_res.json()["total"] == 1
    assert filtered_res.json()["items"][0]["evidence_type"] == "STATIC_ANALYSIS"
