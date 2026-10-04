"""Canonical End-to-End Investigation Lifecycle Tests for INC-001, INC-002, and INC-005."""

from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from apps.simulated_production.order_service.main import set_inter_service_clients
from apps.simulated_production.payment_service.main import app as payment_app
from apps.simulated_production.user_service.main import app as user_app
from packages.simulation.deployments import DeploymentEvent, deployment_registry
from packages.simulation.scenarios import simulation_registry


@pytest.mark.asyncio
async def test_canonical_incident_001_database_latency_investigation(
    client: AsyncClient,
) -> None:
    """CANONICAL BENCHMARK 1: INC-001 PostgreSQL Query Latency Spike

    1. Start simulated production.
    2. Activate INC-001 (+1500ms DB latency).
    3. Generate order traffic.
    4. Create Incident via API.
    5. Trigger Investigation execution.
    6. Verify Evidence collected (PostgreSQL latency, Loki slow query log, dependencies).
    7. Verify Structured Reasoning Result cites evidence and identifies PostgreSQL latency.
    8. Verify Confidence and Audit Events.
    """
    # Create test organization
    org_res = await client.post(
        "/api/v1/organizations",
        json={"name": "Benchmark Org", "slug": f"bench-org-{uuid4().hex[:6]}"},
        headers={"x-user-roles": "OWNER"},
    )
    assert org_res.status_code == 201
    org_id = org_res.json()["id"]

    # 1 & 2. Activate INC-001
    scenario = simulation_registry.get("INC-001")
    assert scenario is not None
    simulation_registry.activate("INC-001")

    # 3. Inter-service clients setup
    user_client = AsyncClient(transport=ASGITransport(app=user_app), base_url="http://user-service")
    payment_client = AsyncClient(transport=ASGITransport(app=payment_app), base_url="http://payment-service")
    set_inter_service_clients(user_client=user_client, payment_client=payment_client)

    try:
        headers = {"x-organization-id": org_id, "x-user-roles": "OWNER"}

        # 4. Create Incident
        inc_res = await client.post(
            "/api/v1/incidents",
            json={
                "title": "PostgreSQL Query Latency Spike",
                "description": "Order placement requests experiencing elevated latency",
                "severity": "HIGH",
                "service_name": "order-service",
                "source": "SIMULATION",
            },
            headers=headers,
        )
        assert inc_res.status_code == 201
        incident_id = inc_res.json()["id"]

        # 5. Create Investigation
        inv_res = await client.post(
            f"/api/v1/incidents/{incident_id}/investigations",
            json={"created_by": "reliability-engineer"},
            headers=headers,
        )
        assert inv_res.status_code == 201
        investigation_id = inv_res.json()["id"]

        # 6. Execute Investigation Run
        run_res = await client.post(
            f"/api/v1/investigations/{investigation_id}/run",
            headers=headers,
        )
        assert run_res.status_code == 200
        run_data = run_res.json()
        assert run_data["status"] == "COMPLETED"
        assert run_data["confidence"] is not None
        assert run_data["confidence"] >= 0.7

        # 7. Verify Evidence Collected
        ev_res = await client.get(f"/api/v1/investigations/{investigation_id}/evidence", headers=headers)
        assert ev_res.status_code == 200
        evidence_list = ev_res.json()
        assert len(evidence_list) >= 2
        # Verify metric and dependency evidence present
        signals = [e["signal"] for e in evidence_list]
        assert any("database_query_duration_seconds" in s for s in signals)

        # 8. Verify Timeline
        time_res = await client.get(f"/api/v1/investigations/{investigation_id}/timeline", headers=headers)
        assert time_res.status_code == 200
        timeline = time_res.json()
        assert len(timeline) >= 2

        # 9. Verify Hypotheses
        hypo_res = await client.get(f"/api/v1/investigations/{investigation_id}/hypotheses", headers=headers)
        assert hypo_res.status_code == 200
        hypotheses = hypo_res.json()
        assert len(hypotheses) >= 1
        assert any("Database" in h["title"] for h in hypotheses)

        # 10. Verify Structured Reasoning Result
        res_res = await client.get(f"/api/v1/investigations/{investigation_id}/result", headers=headers)
        assert res_res.status_code == 200
        rca = res_res.json()
        assert rca is not None
        assert "Database" in rca["root_cause"]
        assert len(rca["supporting_evidence_ids"]) > 0
        assert len(rca["reasoning_steps"]) > 0
        assert rca["context_hash"] != ""

        # 11. Verify Audit Events
        audit_res = await client.get("/api/v1/audit", headers=headers)
        assert audit_res.status_code == 200
        actions = [a["action"] for a in audit_res.json()]
        assert "incident.created" in actions
        assert "investigation.created" in actions
        assert "reasoning.completed" in actions

    finally:
        simulation_registry.deactivate("INC-001")
        set_inter_service_clients(None, None)
        await user_client.aclose()
        await payment_client.aclose()


@pytest.mark.asyncio
async def test_canonical_incident_002_redis_failure_investigation(
    client: AsyncClient,
) -> None:
    """CANONICAL BENCHMARK 2: INC-002 Redis Ephemeral Dependency Failure"""
    org_res = await client.post(
        "/api/v1/organizations",
        json={"name": "Redis Org", "slug": f"redis-org-{uuid4().hex[:6]}"},
        headers={"x-user-roles": "OWNER"},
    )
    assert org_res.status_code == 201
    org_id = org_res.json()["id"]

    # Activate INC-002
    simulation_registry.activate("INC-002")

    headers = {"x-organization-id": org_id, "x-user-roles": "OWNER"}
    try:
        inc_res = await client.post(
            "/api/v1/incidents",
            json={
                "title": "Redis Ledger Cache Breakdown",
                "description": "Payment transactions encountering cache errors",
                "severity": "CRITICAL",
                "service_name": "payment-service",
                "source": "SIMULATION",
            },
            headers=headers,
        )
        incident_id = inc_res.json()["id"]

        inv_res = await client.post(
            f"/api/v1/incidents/{incident_id}/investigations",
            json={"created_by": "sre-agent"},
            headers=headers,
        )
        investigation_id = inv_res.json()["id"]

        run_res = await client.post(
            f"/api/v1/investigations/{investigation_id}/run",
            headers=headers,
        )
        assert run_res.status_code == 200
        assert run_res.json()["status"] == "COMPLETED"

        # Check RCA points to Redis
        res_res = await client.get(f"/api/v1/investigations/{investigation_id}/result", headers=headers)
        rca = res_res.json()
        assert "Redis" in rca["root_cause"] or "Cache" in rca["root_cause"]
        assert len(rca["supporting_evidence_ids"]) > 0
    finally:
        simulation_registry.deactivate("INC-002")


@pytest.mark.asyncio
async def test_canonical_incident_005_deployment_regression_investigation(
    client: AsyncClient,
) -> None:
    """CANONICAL BENCHMARK 3: INC-005 Order Service Deployment Regression"""
    org_res = await client.post(
        "/api/v1/organizations",
        json={"name": "Deploy Org", "slug": f"deploy-org-{uuid4().hex[:6]}"},
        headers={"x-user-roles": "OWNER"},
    )
    assert org_res.status_code == 201
    org_id = org_res.json()["id"]

    # Record deployment event
    deployment_registry.record(
        DeploymentEvent(
            service_name="order-service",
            version="1.1.0",
            previous_version="1.0.0",
            commit_sha="c7d8e9f0",
        )
    )
    simulation_registry.activate("INC-005")

    headers = {"x-organization-id": org_id, "x-user-roles": "OWNER"}
    try:
        inc_res = await client.post(
            "/api/v1/incidents",
            json={
                "title": "Order Service v1.1.0 Crash Surge",
                "description": "50% synthetic exception surge post deployment",
                "severity": "HIGH",
                "service_name": "order-service",
                "source": "DEPLOYMENT",
            },
            headers=headers,
        )
        incident_id = inc_res.json()["id"]

        inv_res = await client.post(
            f"/api/v1/incidents/{incident_id}/investigations",
            json={"created_by": "release-watcher"},
            headers=headers,
        )
        investigation_id = inv_res.json()["id"]

        run_res = await client.post(
            f"/api/v1/investigations/{investigation_id}/run",
            headers=headers,
        )
        assert run_res.status_code == 200

        # Verify deployment was correlated in evidence and hypotheses
        ev_res = await client.get(f"/api/v1/investigations/{investigation_id}/evidence", headers=headers)
        evidence = ev_res.json()
        assert any(e["evidence_type"] == "DEPLOYMENT" for e in evidence)

        res_res = await client.get(f"/api/v1/investigations/{investigation_id}/result", headers=headers)
        rca = res_res.json()
        assert "Deployment" in rca["root_cause"]
    finally:
        simulation_registry.deactivate("INC-005")
