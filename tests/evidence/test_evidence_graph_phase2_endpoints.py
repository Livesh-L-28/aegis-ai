"""API integration tests for Phase 2 Engineering Evidence Graph endpoints: capabilities, change impact, and system contracts."""

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.entities import Organization, Project
from apps.api.app.services.evidence_graph import EvidenceGraphService


@pytest.mark.asyncio
async def test_get_parser_capabilities_endpoint(
    client: AsyncClient,
) -> None:
    headers = {
        "x-organization-id": str(uuid4()),
        "x-user-roles": "ENGINEER",
    }
    res = await client.get("/api/v1/evidence-graph/capabilities", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_parsers"] >= 2
    langs = [p["language"] for p in data["supported_languages"]]
    assert "python" in langs
    assert "typescript" in langs


@pytest.mark.asyncio
async def test_change_impact_endpoint_and_security(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    org = Organization(name="Impact Test Org", slug=f"impact-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Impact Proj", slug="impact-proj")
    db_session.add(proj)
    await db_session.flush()

    service = EvidenceGraphService(db_session)
    files = {
        "src/auth/service.ts": "export class AuthService {}\n",
        "tests/auth/test_service.py": "from src.auth.service import AuthService\n",
    }
    sha = "f00baa1234567890abcdef1234567890abcdef12"
    repo, _rev, _ = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="impact-repo",
        commit_sha=sha,
        file_contents=files,
    )

    headers = {
        "x-organization-id": str(org.id),
        "x-user-roles": "ENGINEER",
    }

    # 1. Normal change impact request
    payload = {
        "changed_files": ["src/auth/service.ts"],
        "max_depth": 3,
    }
    res = await client.post(
        f"/api/v1/evidence-graph/repositories/{repo.id}/revisions/{sha}/impact",
        json=payload,
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["commit_sha"] == sha
    assert data["changed_files"] == ["src/auth/service.ts"]
    assert "AuthService" in " ".join(data["affected_symbols"])
    assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    # 2. Security: Path traversal in changed_files rejected with 400
    bad_payload = {
        "changed_files": ["../../etc/passwd"],
        "max_depth": 3,
    }
    bad_res = await client.post(
        f"/api/v1/evidence-graph/repositories/{repo.id}/revisions/{sha}/impact",
        json=bad_payload,
        headers=headers,
    )
    assert bad_res.status_code == 400

    # 3. Security: Protected file render_schema.json rejected with 400
    protected_payload = {
        "changed_files": ["render_schema.json"],
        "max_depth": 3,
    }
    prot_res = await client.post(
        f"/api/v1/evidence-graph/repositories/{repo.id}/revisions/{sha}/impact",
        json=protected_payload,
        headers=headers,
    )
    assert prot_res.status_code == 400


@pytest.mark.asyncio
async def test_system_contracts_endpoint_and_tenant_isolation(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    org1 = Organization(name="Org 1", slug=f"org1-{uuid4().hex[:6]}")
    org2 = Organization(name="Org 2", slug=f"org2-{uuid4().hex[:6]}")
    db_session.add_all([org1, org2])
    await db_session.flush()

    proj = Project(organization_id=org1.id, name="Contracts Proj", slug="contracts-proj")
    db_session.add(proj)
    await db_session.flush()

    service = EvidenceGraphService(db_session)
    files = {
        "apps/api/app/endpoints/items.py": (
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/items')\n"
            "def list_items():\n"
            "    return []\n"
        ),
        "src/client.ts": (
            "export async function fetchItems() {\n"
            "    return fetch('/items');\n"
            "}\n"
        ),
    }
    sha = "beef1234567890abcdef1234567890abcdef1234"
    repo, _rev, _ = await service.index_repository_revision(
        organization_id=org1.id,
        project_id=proj.id,
        repo_slug="contracts-repo",
        commit_sha=sha,
        file_contents=files,
    )

    headers_org1 = {
        "x-organization-id": str(org1.id),
        "x-user-roles": "ENGINEER",
    }

    # 1. Successful query for org1
    res = await client.get(
        f"/api/v1/evidence-graph/repositories/{repo.id}/revisions/{sha}/api-contracts",
        headers=headers_org1,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["commit_sha"] == sha
    assert len(data["api_endpoints"]) >= 1
    assert data["api_endpoints"][0]["route_path"] == "/items"
    assert len(data["client_api_calls"]) >= 1
    assert data["client_api_calls"][0]["route_path"] == "/items"

    # 2. Strict Tenant Isolation: org2 cannot access org1 repository (404)
    headers_org2 = {
        "x-organization-id": str(org2.id),
        "x-user-roles": "ENGINEER",
    }
    cross_res = await client.get(
        f"/api/v1/evidence-graph/repositories/{repo.id}/revisions/{sha}/api-contracts",
        headers=headers_org2,
    )
    assert cross_res.status_code == 404
