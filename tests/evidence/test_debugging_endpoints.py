"""API integration tests for Phase 3 Autonomous Debugging endpoints."""

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.entities import Organization, Project
from apps.api.app.services.evidence_graph import EvidenceGraphService


@pytest.mark.asyncio
async def test_debugging_capabilities_endpoint(client: AsyncClient) -> None:
    headers = {
        "x-organization-id": str(uuid4()),
        "x-user-roles": "ENGINEER",
    }
    res = await client.get("/api/v1/debugging/capabilities", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "python" in data["supported_languages"]
    assert "typescript" in data["supported_languages"]
    assert data["autonomous_patch_application"] is False
    assert data["secret_redaction_enabled"] is True


@pytest.mark.asyncio
async def test_debugging_analysis_lifecycle_endpoints(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    # 1. Setup Org & Project
    org = Organization(name="Debug Org", slug=f"debug-org-{uuid4().hex[:6]}")
    db_session.add(org)
    await db_session.flush()

    proj = Project(organization_id=org.id, name="Debug Proj", slug="debug-proj")
    db_session.add(proj)
    await db_session.flush()

    # 2. Index a revision with python and test code
    service = EvidenceGraphService(db_session)
    files = {
        "apps/api/app/services/checkout.py": (
            "def calculate_total(cart):\n"
            "    return cart['price'] * cart['qty']\n"
        ),
        "tests/services/test_checkout.py": (
            "from apps.api.app.services.checkout import calculate_total\n"
            "def test_checkout():\n"
            "    calculate_total({'price': 10, 'qty': 2})\n"
        ),
    }
    sha = "c0ffee1234567890abcdef1234567890abcdef12"
    repo, _rev, _ = await service.index_repository_revision(
        organization_id=org.id,
        project_id=proj.id,
        repo_slug="checkout-repo",
        commit_sha=sha,
        file_contents=files,
    )

    headers = {
        "x-organization-id": str(org.id),
        "x-user-roles": "ENGINEER",
    }

    # 3. Submit Incident
    payload = {
        "title": "KeyError in Checkout calculate_total",
        "exception_type": "KeyError",
        "exception_message": "KeyError: 'price' in calculate_total",
        "raw_stack_trace": (
            'File "apps/api/app/services/checkout.py", line 2, in calculate_total\n'
            "    return cart['price'] * cart['qty']\n"
        ),
        "repository_id": str(repo.id),
        "commit_sha": sha,
    }
    create_res = await client.post("/api/v1/debugging/analyses", json=payload, headers=headers)
    assert create_res.status_code == 201
    analysis_data = create_res.json()
    analysis_id = analysis_data["id"]
    assert analysis_data["status"] == "COMPLETED"
    assert analysis_data["localized_frames_count"] == 1
    assert analysis_data["hypotheses_count"] >= 1

    # 4. Get Analysis Status
    get_res = await client.get(f"/api/v1/debugging/analyses/{analysis_id}", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["id"] == analysis_id

    # 5. Get Localized Frames
    frames_res = await client.get(f"/api/v1/debugging/analyses/{analysis_id}/frames", headers=headers)
    assert frames_res.status_code == 200
    frames = frames_res.json()
    assert len(frames) == 1
    assert frames[0]["file_path"] == "apps/api/app/services/checkout.py"
    assert frames[0]["is_resolved"] is True
    assert frames[0]["matched_symbol"] == "calculate_total"

    # 6. Get Correlated Evidence
    ev_res = await client.get(f"/api/v1/debugging/analyses/{analysis_id}/evidence", headers=headers)
    assert ev_res.status_code == 200
    evidence = ev_res.json()
    assert len(evidence) >= 1

    # 7. Get Hypotheses
    hyp_res = await client.get(f"/api/v1/debugging/analyses/{analysis_id}/hypotheses", headers=headers)
    assert hyp_res.status_code == 200
    hypotheses = hyp_res.json()
    assert len(hypotheses) >= 1
    assert hypotheses[0]["score"] > 0

    # 8. Get Verification Plan
    plan_res = await client.get(f"/api/v1/debugging/analyses/{analysis_id}/verification-plan", headers=headers)
    assert plan_res.status_code == 200
    plan = plan_res.json()
    assert len(plan) >= 1
    assert plan[0]["is_executable"] is False

    # 9. Get Fix Proposals
    fixes_res = await client.get(f"/api/v1/debugging/analyses/{analysis_id}/fixes", headers=headers)
    assert fixes_res.status_code == 200
    fixes = fixes_res.json()
    assert len(fixes) >= 1
    assert fixes[0]["validation_status"] == "VALIDATION_PASSED"

    # 10. Cancel Endpoint
    cancel_res = await client.post(f"/api/v1/debugging/analyses/{analysis_id}/cancel", headers=headers)
    assert cancel_res.status_code == 200


@pytest.mark.asyncio
async def test_debugging_tenant_isolation(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    org1 = Organization(name="Org 1", slug=f"org1-{uuid4().hex[:6]}")
    org2 = Organization(name="Org 2", slug=f"org2-{uuid4().hex[:6]}")
    db_session.add_all([org1, org2])
    await db_session.flush()

    headers_org1 = {"x-organization-id": str(org1.id), "x-user-roles": "ENGINEER"}
    headers_org2 = {"x-organization-id": str(org2.id), "x-user-roles": "ENGINEER"}

    # Create run in org 1
    res = await client.post(
        "/api/v1/debugging/analyses",
        json={
            "title": "Org 1 incident",
            "exception_type": "ValueError",
            "exception_message": "test",
        },
        headers=headers_org1,
    )
    assert res.status_code == 201
    analysis_id = res.json()["id"]

    # Org 1 can read
    assert (await client.get(f"/api/v1/debugging/analyses/{analysis_id}", headers=headers_org1)).status_code == 200

    # Org 2 reading Org 1's run returns 404 Not Found (strict isolation)
    assert (await client.get(f"/api/v1/debugging/analyses/{analysis_id}", headers=headers_org2)).status_code == 404
    assert (await client.get(f"/api/v1/debugging/analyses/{analysis_id}/frames", headers=headers_org2)).status_code == 404
    assert (await client.get(f"/api/v1/debugging/analyses/{analysis_id}/evidence", headers=headers_org2)).status_code == 404
    assert (await client.get(f"/api/v1/debugging/analyses/{analysis_id}/hypotheses", headers=headers_org2)).status_code == 404
