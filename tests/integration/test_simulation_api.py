import pytest
from httpx import AsyncClient

from packages.simulation.scenarios import simulation_registry


@pytest.mark.asyncio
async def test_simulation_scenarios_listing_and_inspection(client: AsyncClient) -> None:
    res = await client.get("/api/v1/simulation/scenarios", headers={"x-user-roles": "OWNER"})
    assert res.status_code == 200
    scenarios = res.json()
    assert len(scenarios) >= 5
    ids = [s["id"] for s in scenarios]
    assert "INC-001" in ids
    assert "INC-002" in ids
    assert "INC-003" in ids
    assert "INC-004" in ids
    assert "INC-005" in ids


@pytest.mark.asyncio
async def test_scenario_activation_and_deactivation_lifecycle(client: AsyncClient) -> None:
    # 1. Create Organization for tenant context
    org_res = await client.post(
        "/api/v1/organizations",
        json={"name": "Fault Org", "slug": "fault-org"},
        headers={"x-user-roles": "OWNER"},
    )
    org_id = org_res.json()["id"]

    # 2. Activate Scenario INC-003
    act_res = await client.post(
        "/api/v1/simulation/scenarios/INC-003/activate",
        headers={"x-organization-id": org_id, "x-user-roles": "OWNER"},
    )
    assert act_res.status_code == 200
    assert act_res.json()["enabled"] is True
    sc_active = simulation_registry.get("INC-003")
    assert sc_active is not None
    assert sc_active.enabled is True

    # 3. Deactivate Scenario
    deact_res = await client.post(
        "/api/v1/simulation/scenarios/INC-003/deactivate",
        headers={"x-organization-id": org_id, "x-user-roles": "OWNER"},
    )
    assert deact_res.status_code == 200
    assert deact_res.json()["enabled"] is False
    sc_inactive = simulation_registry.get("INC-003")
    assert sc_inactive is not None
    assert sc_inactive.enabled is False

    # 4. Verify Audit Log was generated for simulation actions
    audit_res = await client.get(
        "/api/v1/audit",
        headers={"x-organization-id": org_id, "x-user-roles": "OWNER"},
    )
    assert audit_res.status_code == 200
    actions = [e["action"] for e in audit_res.json()]
    assert "simulation.scenario.activated" in actions
    assert "simulation.scenario.deactivated" in actions


@pytest.mark.asyncio
async def test_deployment_event_trigger_and_query(client: AsyncClient) -> None:
    org_res = await client.post(
        "/api/v1/organizations",
        json={"name": "Deploy Org", "slug": "deploy-org"},
        headers={"x-user-roles": "OWNER"},
    )
    org_id = org_res.json()["id"]

    deploy_res = await client.post(
        "/api/v1/simulation/deployments",
        json={
            "service_name": "order-service",
            "target_version": "1.2.0",
            "previous_version": "1.1.0",
            "induce_regression": False,
        },
        headers={"x-organization-id": org_id, "x-user-roles": "OWNER"},
    )
    assert deploy_res.status_code == 201
    deploy_data = deploy_res.json()
    assert deploy_data["service_name"] == "order-service"
    assert deploy_data["version"] == "1.2.0"

    history_res = await client.get(
        "/api/v1/observability/deployments",
        headers={"x-user-roles": "VIEWER"},
    )
    assert history_res.status_code == 200
    assert any(d["service_name"] == "order-service" for d in history_res.json())


@pytest.mark.asyncio
async def test_unauthorized_simulation_operations(client: AsyncClient) -> None:
    # VIEWER cannot activate scenarios
    forbidden_act = await client.post(
        "/api/v1/simulation/scenarios/INC-001/activate",
        headers={"x-organization-id": "11111111-1111-1111-1111-111111111111", "x-user-roles": "VIEWER"},
    )
    assert forbidden_act.status_code == 403
