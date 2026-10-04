"""Tests for reasoning context builder, hypothesis scoring, grounding validation, and hallucination rejection."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from packages.intelligence.evidence.models import EvidenceItem, EvidenceType
from packages.intelligence.reasoning.context import ReasoningContextBuilder
from packages.intelligence.reasoning.hypotheses import HypothesisEngine, HypothesisStatus
from packages.intelligence.reasoning.provider import MockReasoningProvider
from packages.intelligence.reasoning.validator import (
    GroundingValidationError,
    GroundingValidator,
)


@pytest.mark.asyncio
async def test_hypothesis_generation_and_scoring() -> None:
    org_id = uuid4()
    inv_id = uuid4()
    t_now = datetime.now(UTC)

    e_db = EvidenceItem(
        organization_id=org_id,
        investigation_id=inv_id,
        evidence_type=EvidenceType.METRIC,
        source="prometheus",
        signal="database_query_duration_seconds",
        observed_at=t_now,
        content="PostgreSQL latency spike observed",
        provenance="prometheus:db",
    )
    e_dep = EvidenceItem(
        organization_id=org_id,
        investigation_id=inv_id,
        evidence_type=EvidenceType.DEPENDENCY,
        source="system-registry",
        signal="dependency:order-service->postgres",
        observed_at=t_now,
        content="order-service depends on postgres",
        provenance="topology:order-service->postgres",
    )

    hypo_engine = HypothesisEngine()
    hypotheses = hypo_engine.generate_hypotheses(
        investigation_id=inv_id,
        evidence=[e_db, e_dep],
        service_name="order-service",
    )

    assert len(hypotheses) > 0
    top_h = hypotheses[0]
    assert "Database" in top_h.title
    assert top_h.status in (HypothesisStatus.SUPPORTED, HypothesisStatus.CANDIDATE)
    assert top_h.score >= 0.5
    assert e_db.id in top_h.supporting_evidence_ids


@pytest.mark.asyncio
async def test_hallucination_rejection() -> None:
    """Rigorous Hallucination Test: Model referencing non-existent evidence IDs must be rejected."""
    org_id = uuid4()
    inv_id = uuid4()

    valid_evidence = [
        EvidenceItem(
            organization_id=org_id,
            investigation_id=inv_id,
            evidence_type=EvidenceType.METRIC,
            source="prometheus",
            signal="database_query_duration_seconds",
            content="Valid evidence observation",
            provenance="prometheus:metric",
        )
    ]

    mock_provider = MockReasoningProvider(simulate_hallucination=True)
    builder = ReasoningContextBuilder()
    context = builder.build_context(
        incident_id=uuid4(),
        investigation_id=inv_id,
        incident_title="Test Incident",
        incident_description="",
        incident_severity="HIGH",
        detected_at=datetime.now(UTC).isoformat(),
        service_name="order-service",
        evidence=valid_evidence,
        timeline=[],
        hypotheses=[],
    )

    hallucinated_out = await mock_provider.reason(context)

    # Grounding validator MUST raise GroundingValidationError
    with pytest.raises(GroundingValidationError, match="Model hallucinated non-existent"):
        GroundingValidator.validate_groundedness(hallucinated_out, valid_evidence)


@pytest.mark.asyncio
async def test_contradiction_handling() -> None:
    """Contradiction Test: Contradicting evidence must be retained and penalize confidence."""
    org_id = uuid4()
    inv_id = uuid4()
    t_early = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    t_later = datetime(2026, 1, 1, 10, 5, 0, tzinfo=UTC)

    # Deployment occurred at 10:05
    e_deploy = EvidenceItem(
        organization_id=org_id,
        investigation_id=inv_id,
        evidence_type=EvidenceType.DEPLOYMENT,
        source="deployments",
        signal="version:1.1.0",
        observed_at=t_later,
        content="Deployment of order-service v1.1.0",
        provenance="deployments:v1.1.0",
    )
    # Errors started EARLIER at 10:00 (contradicts deployment causality)
    e_prior_error = EvidenceItem(
        organization_id=org_id,
        investigation_id=inv_id,
        evidence_type=EvidenceType.METRIC,
        source="prometheus",
        signal="orders_failed_total",
        observed_at=t_early,
        content="Orders failing before deployment",
        provenance="prometheus:error",
    )

    hypo_engine = HypothesisEngine()
    hypotheses = hypo_engine.generate_hypotheses(
        investigation_id=inv_id,
        evidence=[e_deploy, e_prior_error],
        service_name="order-service",
    )

    deploy_hypo = next((h for h in hypotheses if "deployment" in h.title.lower()), None)
    assert deploy_hypo is not None
    # Contradicting evidence MUST be discovered
    assert len(deploy_hypo.contradicting_evidence_ids) > 0
    assert e_prior_error.id in deploy_hypo.contradicting_evidence_ids


@pytest.mark.asyncio
async def test_insufficient_evidence_unknown_result() -> None:
    """No False Certainty Test: Insufficient evidence yields UNKNOWN root cause and low confidence."""
    mock_provider = MockReasoningProvider(simulate_unknown=True)
    builder = ReasoningContextBuilder()
    context = builder.build_context(
        incident_id=uuid4(),
        investigation_id=uuid4(),
        incident_title="Mystery Glitch",
        incident_description="",
        incident_severity="LOW",
        detected_at=datetime.now(UTC).isoformat(),
        service_name="order-service",
        evidence=[],
        timeline=[],
        hypotheses=[],
    )

    out = await mock_provider.reason(context)
    assert out.root_cause == "UNKNOWN"
    assert out.confidence <= 0.3

    final_conf = GroundingValidator.calculate_final_confidence(
        model_confidence=out.confidence,
        supporting_evidence=[],
        contradicting_evidence=[],
        is_unknown=True,
    )
    assert final_conf <= 0.3
