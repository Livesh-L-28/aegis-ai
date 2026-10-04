import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_strict_cross_tenant_isolation(client: AsyncClient) -> None:
    """MANDATORY SECURITY REQUIREMENT:

    Tenant A must never be able to view, read, update, or delete Project B belonging to Tenant B.
    """
    # 1. Create Organization A
    res_a = await client.post(
        "/api/v1/organizations",
        json={"name": "Tenant Alpha", "slug": "tenant-alpha"},
        headers={"x-user-roles": "OWNER"},
    )
    assert res_a.status_code == 201
    org_a_id = res_a.json()["id"]

    # 2. Create Organization B
    res_b = await client.post(
        "/api/v1/organizations",
        json={"name": "Tenant Beta", "slug": "tenant-beta"},
        headers={"x-user-roles": "OWNER"},
    )
    assert res_b.status_code == 201
    org_b_id = res_b.json()["id"]

    # 3. Create Project A in Organization A
    proj_a_res = await client.post(
        "/api/v1/projects",
        json={"name": "Project Alpha", "slug": "proj-alpha"},
        headers={"x-organization-id": org_a_id, "x-user-roles": "OWNER"},
    )
    assert proj_a_res.status_code == 201
    proj_a_id = proj_a_res.json()["id"]

    # 4. Create Project B in Organization B
    proj_b_res = await client.post(
        "/api/v1/projects",
        json={"name": "Project Beta", "slug": "proj-beta"},
        headers={"x-organization-id": org_b_id, "x-user-roles": "OWNER"},
    )
    assert proj_b_res.status_code == 201
    proj_b_id = proj_b_res.json()["id"]

    # --- CROSS-TENANT TEST 1: Tenant A attempts to READ Project B ---
    # Case 1a: Tenant A requests Project B while passing Org A context -> Must 404 (or 403)
    read_b_with_org_a = await client.get(
        f"/api/v1/projects/{proj_b_id}",
        headers={"x-organization-id": org_a_id, "x-user-roles": "OWNER"},
    )
    assert read_b_with_org_a.status_code == 404
    assert read_b_with_org_a.json()["error"]["code"] == "RESOURCE_NOT_FOUND"

    # Case 1b: User belonging strictly to Org A tries to spoof Org B header
    await client.get(
        f"/api/v1/projects/{proj_b_id}",
        headers={
            "x-organization-id": org_b_id,
            "x-user-roles": "OWNER",
        },
    )
    # When user context is restricted to org_a
    from apps.api.app.core.security import get_current_principal
    from apps.api.app.main import app
    from packages.security.rbac import AuthenticatedPrincipal, Role

    async def get_user_bound_to_org_a() -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal(
            user_id="user_alpha",
            email="alpha@example.com",
            roles=[Role.OWNER],
            current_organization_id=org_a_id,
        )

    app.dependency_overrides[get_current_principal] = get_user_bound_to_org_a

    spoofed_attempt = await client.get(
        f"/api/v1/projects/{proj_b_id}",
        headers={"x-organization-id": org_b_id},
    )
    assert spoofed_attempt.status_code == 403
    assert spoofed_attempt.json()["error"]["code"] == "TENANT_ACCESS_DENIED"

    # Reset dependency override
    app.dependency_overrides.pop(get_current_principal, None)

    # --- CROSS-TENANT TEST 2: Tenant A attempts to UPDATE Project B ---
    update_attempt = await client.patch(
        f"/api/v1/projects/{proj_b_id}",
        json={"name": "Hacked Name"},
        headers={"x-organization-id": org_a_id, "x-user-roles": "OWNER"},
    )
    assert update_attempt.status_code == 404

    # --- CROSS-TENANT TEST 3: Tenant A attempts to DELETE Project B ---
    delete_attempt = await client.delete(
        f"/api/v1/projects/{proj_b_id}",
        headers={"x-organization-id": org_a_id, "x-user-roles": "OWNER"},
    )
    assert delete_attempt.status_code == 404

    # --- CROSS-TENANT TEST 4: Resource enumeration across tenants ---
    list_org_a_projects = await client.get(
        "/api/v1/projects",
        headers={"x-organization-id": org_a_id, "x-user-roles": "OWNER"},
    )
    assert list_org_a_projects.status_code == 200
    returned_ids = [p["id"] for p in list_org_a_projects.json()]
    assert proj_a_id in returned_ids
    assert proj_b_id not in returned_ids


@pytest.mark.asyncio
async def test_rbac_forbidden_operations(client: AsyncClient) -> None:
    """Verify role permission enforcement on mutating operations."""
    # Create Org
    res = await client.post(
        "/api/v1/organizations",
        json={"name": "Security Org", "slug": "sec-org"},
        headers={"x-user-roles": "OWNER"},
    )
    org_id = res.json()["id"]

    # VIEWER attempting to create a project must be 403 FORBIDDEN
    forbidden_create = await client.post(
        "/api/v1/projects",
        json={"name": "Unauthorized Project", "slug": "unauth-proj"},
        headers={"x-organization-id": org_id, "x-user-roles": "VIEWER"},
    )
    assert forbidden_create.status_code == 403
    assert forbidden_create.json()["error"]["code"] == "FORBIDDEN"
