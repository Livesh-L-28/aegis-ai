import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient) -> None:
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] in ["LogicFalcon (powered by AEGIS AI)", "AEGIS AI"]
    assert "version" in data
    # Ensure X-Request-ID and security headers are present
    assert "x-request-id" in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


@pytest.mark.asyncio
async def test_version_endpoint(client: AsyncClient) -> None:
    response = await client.get("/api/v1/version")
    assert response.status_code == 200
    data = response.json()
    assert data["app_name"] in ["LogicFalcon (powered by AEGIS AI)", "AEGIS AI"]
    assert data["api_version"] == "v1"
    assert "environment" in data


@pytest.mark.asyncio
async def test_organization_and_project_lifecycle(client: AsyncClient) -> None:
    # 1. Create Organization
    org_res = await client.post(
        "/api/v1/organizations",
        json={"name": "Acme Corp", "slug": "acme-corp", "description": "Primary test org"},
        headers={"x-user-roles": "OWNER"},
    )
    assert org_res.status_code == 201
    org_data = org_res.json()
    org_id = org_data["id"]
    assert org_data["name"] == "Acme Corp"
    assert org_data["slug"] == "acme-corp"

    # 2. List Organizations
    list_orgs = await client.get("/api/v1/organizations", headers={"x-user-roles": "VIEWER"})
    assert list_orgs.status_code == 200
    assert any(o["id"] == org_id for o in list_orgs.json())

    # 3. Create Project under Organization
    proj_res = await client.post(
        "/api/v1/projects",
        json={"name": "Core Service", "slug": "core-svc", "description": "Backend engine"},
        headers={"x-organization-id": org_id, "x-user-roles": "ENGINEER"},
    )
    assert proj_res.status_code == 201
    proj_data = proj_res.json()
    proj_id = proj_data["id"]
    assert proj_data["organization_id"] == org_id
    assert proj_data["slug"] == "core-svc"

    # 4. List Projects under Organization
    list_proj = await client.get(
        "/api/v1/projects",
        headers={"x-organization-id": org_id, "x-user-roles": "VIEWER"},
    )
    assert list_proj.status_code == 200
    assert len(list_proj.json()) == 1
    assert list_proj.json()[0]["id"] == proj_id

    # 5. Verify Audit Log was generated
    audit_res = await client.get(
        "/api/v1/audit",
        headers={"x-organization-id": org_id, "x-user-roles": "OWNER"},
    )
    assert audit_res.status_code == 200
    events = audit_res.json()
    actions = [e["action"] for e in events]
    assert "organization.created" in actions
    assert "project.created" in actions
