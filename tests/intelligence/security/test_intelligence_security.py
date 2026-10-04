from uuid import UUID

import pytest
from httpx import AsyncClient

from packages.intelligence.knowledge.store import DocumentSourceType, knowledge_store


@pytest.mark.asyncio
async def test_intelligence_tenant_isolation(client: AsyncClient) -> None:
    """Security Test: Tenant A knowledge and context must never leak to Tenant B."""
    org_a = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    org_b = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

    # Ingest document strictly for Tenant A
    knowledge_store.ingest_document(
        organization_id=org_a,
        title="Confidential Tenant A Architecture",
        source_type=DocumentSourceType.ARCHITECTURE,
        source_uri="secret/arch.md",
        content="Secret keys and internal topology for Tenant Alpha only.",
    )

    # Ingest document strictly for Tenant B
    knowledge_store.ingest_document(
        organization_id=org_b,
        title="Tenant B Runbook",
        source_type=DocumentSourceType.RUNBOOK,
        source_uri="docs/tenant_b.md",
        content="Public operating procedure for Tenant Beta.",
    )

    # Search knowledge authenticated as Tenant B
    res_b = await client.post(
        "/api/v1/intelligence/knowledge/search",
        json={"query": "Confidential Tenant A Architecture"},
        headers={"x-organization-id": str(org_b), "x-user-roles": "OWNER"},
    )
    assert res_b.status_code == 200
    b_matches = res_b.json()
    # Must NOT find Tenant A's document
    matching_titles = [m["title"] for m in b_matches]
    assert "Confidential Tenant A Architecture" not in matching_titles


@pytest.mark.asyncio
async def test_unified_service_context_api_and_audit(client: AsyncClient) -> None:
    org_id = UUID("33333333-3333-3333-3333-333333333333")

    # Ingest relevant runbook
    knowledge_store.ingest_document(
        organization_id=org_id,
        title="Order Service Troubleshooting Guide",
        source_type=DocumentSourceType.RUNBOOK,
        source_uri="docs/order.md",
        content="# Order Service\nGuide for diagnosing order creation timeouts and database latencies.",
    )

    # Query Unified Context API for order-service
    res = await client.get(
        "/api/v1/intelligence/services/order-service/context",
        headers={"x-organization-id": str(org_id), "x-user-roles": "OWNER"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["service_name"] == "order-service"
    assert "runtime_dependencies" in data
    # Runtime dependencies should include payment-service and postgres
    dep_targets = [d["target_service_name"] for d in data["runtime_dependencies"]]
    assert "payment-service" in dep_targets or "postgres" in dep_targets
    # Knowledge should include relevant order guide
    knowledge_titles = [k["title"] for k in data["relevant_knowledge"]]
    assert any("Order Service" in t for t in knowledge_titles)


@pytest.mark.asyncio
async def test_unified_search_api_endpoint(client: AsyncClient) -> None:
    org_id = UUID("44444444-4444-4444-4444-444444444444")
    res = await client.post(
        "/api/v1/intelligence/search",
        json={"query": "order", "limit": 5},
        headers={"x-organization-id": str(org_id), "x-user-roles": "OWNER"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["query"] == "order"
    assert "system_matches" in data
    assert "code_matches" in data
    assert "knowledge_matches" in data
