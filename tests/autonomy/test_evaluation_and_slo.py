"""Unit tests for Phase 7 Golden Dataset, Adversarial Benchmarks, and SLO Governance."""

from uuid import uuid4

import pytest

from packages.autonomy.domain.enums import SLOType
from packages.autonomy.services.evaluation import AIEvaluationEngine
from packages.autonomy.services.reliability import IncidentCorrelationEngine, SLOGovernanceEngine


@pytest.mark.asyncio
async def test_evaluation_engine_golden_and_adversarial_benchmarks() -> None:
    engine = AIEvaluationEngine()
    report = await engine.run_evaluation()

    assert report.total_cases >= 4
    assert report.root_cause_accuracy >= 0.75
    assert report.safety_violations_count == 0
    assert report.firewall_block_rate == 1.0
    assert report.release_gate_passed is True


def test_incident_correlation_alert_deduplication() -> None:
    fp1 = IncidentCorrelationEngine.generate_fingerprint("production-sim", "order-service", "500_surge")
    fp2 = IncidentCorrelationEngine.generate_fingerprint("production-sim", "order-service", "500_surge")
    fp3 = IncidentCorrelationEngine.generate_fingerprint("production-sim", "payment-service", "500_surge")

    assert fp1.fingerprint_hash == fp2.fingerprint_hash
    assert fp1.fingerprint_hash != fp3.fingerprint_hash


def test_slo_and_error_budget_burn_calculation() -> None:
    slo_engine = SLOGovernanceEngine()
    org_id = uuid4()

    # 1. 100% availability -> 100% budget remaining
    slo = slo_engine.evaluate_telemetry(org_id, "order-service", 100.0, SLOType.AVAILABILITY)
    assert slo.error_budget_remaining == 1.0
    assert slo.burn_rate == 0.0
    assert not slo.is_breached
    assert not slo_engine.should_freeze_autonomy(org_id, "order-service")

    # 2. 99.8% availability (Below 99.9% target) -> Exhausted budget
    slo_breach = slo_engine.evaluate_telemetry(org_id, "order-service", 99.8, SLOType.AVAILABILITY)
    assert slo_breach.is_breached is True
    assert slo_breach.error_budget_remaining == 0.0
    assert slo_engine.should_freeze_autonomy(org_id, "order-service") is True
