"""Unit and integration tests for Phase 4 Evidence Engine."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from packages.intelligence.evidence.engine import EvidenceEngine
from packages.intelligence.evidence.models import (
    EvidenceItem,
    EvidenceType,
)
from packages.simulation.scenarios import simulation_registry


@pytest.mark.asyncio
async def test_evidence_engine_collection_and_deduplication() -> None:
    org_id = uuid4()
    inv_id = uuid4()

    # Enable simulation scenario INC-001
    scenario = simulation_registry.get("INC-001")
    assert scenario is not None
    simulation_registry.activate("INC-001")

    engine = EvidenceEngine()
    try:
        evidence = await engine.collect_all(
            organization_id=org_id,
            investigation_id=inv_id,
            service_name="order-service",
            incident_time=datetime.now(UTC),
        )

        assert len(evidence) > 0
        # Verify deterministic provenance exists on every item
        for item in evidence:
            assert item.provenance != ""
            assert item.confidence >= 0.0
            assert item.relevance_score > 0.0

        # Check telemetry metric was normalized
        metric_items = [e for e in evidence if e.evidence_type == EvidenceType.METRIC]
        assert len(metric_items) >= 1
        assert any("database_query_duration_seconds" in m.signal for m in metric_items)

        # Check ranking: highest relevance score comes first
        for i in range(len(evidence) - 1):
            assert evidence[i].relevance_score >= evidence[i + 1].relevance_score

        # Check deduplication prevents duplicate identical observations
        deduped = engine.deduplicate_evidence(evidence + evidence)
        assert len(deduped) == len(evidence)

    finally:
        simulation_registry.deactivate("INC-001")


@pytest.mark.asyncio
async def test_timeline_construction_linking_evidence() -> None:
    org_id = uuid4()
    inv_id = uuid4()
    t_now = datetime.now(UTC)

    e1 = EvidenceItem(
        organization_id=org_id,
        investigation_id=inv_id,
        evidence_type=EvidenceType.DEPLOYMENT,
        source="deployments",
        signal="version:1.1.0",
        observed_at=t_now,
        content="Deployment completed",
        provenance="deployments:v1.1.0",
    )
    e2 = EvidenceItem(
        organization_id=org_id,
        investigation_id=inv_id,
        evidence_type=EvidenceType.METRIC,
        source="prometheus",
        signal="database_query_duration_seconds",
        observed_at=t_now,
        content="Database latency spiked",
        provenance="prometheus:db",
    )

    engine = EvidenceEngine()
    timeline = engine.construct_timeline([e1, e2], incident_title="Database Latency Spike")

    assert len(timeline) == 2
    assert timeline[0].evidence_ids == [e1.id]
    assert timeline[1].evidence_ids == [e2.id]
