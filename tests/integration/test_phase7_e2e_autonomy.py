"""Phase 7 End-to-End Integration Tests: Bounded Autonomy, Incident Loop, Emergency Stop, and Operational Learning."""

from uuid import uuid4

import pytest
from httpx import AsyncClient

from packages.simulation.scenarios import simulation_registry


async def _setup_test_org_and_incident(client: AsyncClient) -> dict[str, str]:
    org_res = await client.post(
        "/api/v1/organizations",
        json={"name": "Phase 7 Autonomous Org", "slug": f"p7-{uuid4().hex[:6]}"},
        headers={"x-user-roles": "OWNER"},
    )
    assert org_res.status_code == 201
    org_id = org_res.json()["id"]

    headers = {"x-organization-id": org_id, "x-user-roles": "OWNER"}

    inc_res = await client.post(
        "/api/v1/incidents",
        headers=headers,
        json={
            "title": "Payment Service Redis Latency Surge",
            "description": "Payment timeouts due to intermittent Redis connectivity",
            "severity": "MEDIUM",
            "service_name": "payment-service",
            "source": "SIMULATION",
        },
    )
    assert inc_res.status_code == 201
    inc_id = inc_res.json()["id"]

    return {"org_id": org_id, "inc_id": inc_id}


@pytest.mark.asyncio
async def test_canonical_autonomous_remediation_lifecycle_e2e(client: AsyncClient) -> None:
    """CANONICAL AUTONOMOUS FLOW:

    Incident -> Policy -> Agent Loop -> Bounded Execution -> Validation -> Learning Record.
    """
    env = await _setup_test_org_and_incident(client)
    org_id = env["org_id"]
    inc_id = env["inc_id"]

    headers = {"x-organization-id": org_id, "x-user-roles": "OWNER"}

    # 1. Activate simulated fault
    simulation_registry.activate("INC-002")

    # 2. Configure Autonomy Policy permitting low-risk auto-restart
    pol_res = await client.post(
        "/api/v1/autonomy/policies",
        headers=headers,
        json={
            "environment": "production-sim",
            "service": "payment-service",
            "autonomy_level": "LEVEL_2_AUTO_EXECUTE_LOW_RISK",
            "allowed_actions": ["SERVICE_RESTART", "CACHE_INVALIDATION"],
            "maximum_risk": "LOW",
        },
    )
    assert pol_res.status_code == 201

    # 3. Trigger Reliability Agent
    run_res = await client.post(
        f"/api/v1/autonomy/incidents/{inc_id}/run-agent",
        headers=headers,
    )
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["state"] == "COMPLETED", f"Run did not complete: {run_data.get('outcome')}"
    assert run_data["tool_calls_count"] > 0
    assert "successfully applied and validated" in run_data["outcome"].lower()

    # 4. Verify operational learning was recorded
    learn_res = await client.get("/api/v1/autonomy/learnings", headers=headers)
    assert learn_res.status_code == 200
    learnings = learn_res.json()
    assert len(learnings) > 0
    assert any(item["service_name"] == "payment-service" for item in learnings)


@pytest.mark.asyncio
async def test_kill_switch_emergency_stop_lifecycle_e2e(client: AsyncClient) -> None:
    """EMERGENCY STOP FLOW:

    Admin activates Kill Switch -> Agent run denied -> Admin restores Kill Switch.
    """
    env = await _setup_test_org_and_incident(client)
    org_id = env["org_id"]
    inc_id = env["inc_id"]

    headers = {"x-organization-id": org_id, "x-user-roles": "OWNER"}

    # 1. Trip kill switch
    trip_res = await client.post("/api/v1/autonomy/kill-switch/disable", headers=headers)
    assert trip_res.status_code == 200
    assert trip_res.json()["kill_switch_active"] is True

    # 2. Attempt agent run while kill switch active -> Run halts in AWAITING_APPROVAL/FAILED
    run_res = await client.post(
        f"/api/v1/autonomy/incidents/{inc_id}/run-agent",
        headers=headers,
    )
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["autonomy_decision"] == "DENY"

    # 3. Restore kill switch
    restore_res = await client.post("/api/v1/autonomy/kill-switch/enable", headers=headers)
    assert restore_res.status_code == 200
    assert restore_res.json()["kill_switch_active"] is False


@pytest.mark.asyncio
async def test_evaluation_benchmark_and_slo_endpoints_e2e(client: AsyncClient) -> None:
    """EVALUATION & SLO ENDPOINTS:

    Verify golden dataset execution, release gate verification, and SLO evaluation.
    """
    env = await _setup_test_org_and_incident(client)
    org_id = env["org_id"]
    headers = {"x-organization-id": org_id, "x-user-roles": "OWNER"}

    # 1. Run evaluation benchmark
    eval_res = await client.post("/api/v1/autonomy/evaluations/run", headers=headers)
    assert eval_res.status_code == 200
    eval_data = eval_res.json()
    assert eval_data["release_gate_passed"] is True
    assert eval_data["safety_violations_count"] == 0

    # 2. Inspect SLO
    slo_res = await client.get("/api/v1/autonomy/slo/order-service", headers=headers)
    assert slo_res.status_code == 200
    slo_data = slo_res.json()
    assert slo_data["service_name"] == "order-service"
    assert slo_data["error_budget_remaining"] > 0.0
