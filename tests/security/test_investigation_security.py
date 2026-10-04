"""Phase 4 Security Tests: Strict Tenant Isolation across Incidents, Investigations, Evidence, and Reasoning."""

from uuid import uuid4

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_cross_tenant_incident_and_investigation_isolation(client: AsyncClient) -> None:
    """Security Requirement: Tenant A must never access Tenant B incidents, investigations, evidence, or reasoning."""
    # 1. Create Org A
    res_a = await client.post(
        "/api/v1/organizations",
        json={"name": "Tenant Alpha", "slug": f"alpha-{uuid4().hex[:6]}"},
        headers={"x-user-roles": "OWNER"},
    )
    assert res_a.status_code == 201
    org_a_id = res_a.json()["id"]

    # 2. Create Org B
    res_b = await client.post(
        "/api/v1/organizations",
        json={"name": "Tenant Beta", "slug": f"beta-{uuid4().hex[:6]}"},
        headers={"x-user-roles": "OWNER"},
    )
    assert res_b.status_code == 201
    org_b_id = res_b.json()["id"]

    headers_a = {"x-organization-id": org_a_id, "x-user-roles": "OWNER"}
    headers_b = {"x-organization-id": org_b_id, "x-user-roles": "OWNER"}

    # 3. Create Incident in Org A
    inc_a_res = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Incident Alpha Confidential",
            "description": "Sensitive database event",
            "severity": "CRITICAL",
            "service_name": "order-service",
        },
        headers=headers_a,
    )
    assert inc_a_res.status_code == 201
    inc_a_id = inc_a_res.json()["id"]

    # 4. Create Incident in Org B
    inc_b_res = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Incident Beta Confidential",
            "description": "Sensitive payment event",
            "severity": "HIGH",
            "service_name": "payment-service",
        },
        headers=headers_b,
    )
    assert inc_b_res.status_code == 201
    inc_b_id = inc_b_res.json()["id"]

    # 5. Org B attempts to read Incident A -> Must 404
    read_a_from_b = await client.get(f"/api/v1/incidents/{inc_a_id}", headers=headers_b)
    assert read_a_from_b.status_code == 404

    # 6. Create Investigation in Org A
    inv_a_res = await client.post(
        f"/api/v1/incidents/{inc_a_id}/investigations",
        json={"created_by": "analyst-a"},
        headers=headers_a,
    )
    assert inv_a_res.status_code == 201
    inv_a_id = inv_a_res.json()["id"]

    # 7. Org B attempts to read Investigation A -> Must 404
    read_inv_from_b = await client.get(f"/api/v1/investigations/{inv_a_id}", headers=headers_b)
    assert read_inv_from_b.status_code == 404

    # 8. Run Investigation A
    run_a = await client.post(f"/api/v1/investigations/{inv_a_id}/run", headers=headers_a)
    assert run_a.status_code == 200

    # 9. Org B attempts to read Evidence or Reasoning Result of A -> Must 404
    ev_from_b = await client.get(f"/api/v1/investigations/{inv_a_id}/evidence", headers=headers_b)
    assert ev_from_b.status_code == 404

    res_from_b = await client.get(f"/api/v1/investigations/{inv_a_id}/result", headers=headers_b)
    assert res_from_b.status_code == 404

    # 10. Verify listing incidents for Org B only returns Incident B
    list_b = await client.get("/api/v1/incidents", headers=headers_b)
    assert list_b.status_code == 200
    b_ids = [i["id"] for i in list_b.json()]
    assert inc_b_id in b_ids
    assert inc_a_id not in b_ids
