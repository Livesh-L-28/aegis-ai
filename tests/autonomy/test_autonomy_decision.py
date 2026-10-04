"""Unit tests for Phase 7 Autonomy Decision Engine, Circuit Breaker, and Guardrails."""

from uuid import uuid4

from packages.autonomy.domain.enums import (
    AutonomyCircuitState,
    AutonomyDecisionType,
    AutonomyLevel,
)
from packages.autonomy.domain.models import AutonomyPolicy
from packages.autonomy.services.decision import AutonomyCircuitBreaker, AutonomyDecisionEngine
from packages.remediation.domain.enums import RemediationActionType
from packages.remediation.domain.models import (
    BlastRadiusReport,
    RemediationAction,
    RemediationProposal,
    RollbackPlan,
)
from packages.security.policy import AIRiskLevel


def _make_test_proposal(
    action_type: RemediationActionType = RemediationActionType.SERVICE_RESTART,
    risk: AIRiskLevel = AIRiskLevel.LOW,
    affected_services: list[str] | None = None,
    with_rollback: bool = True,
) -> RemediationProposal:
    actions = [
        RemediationAction(
            action_type=action_type,
            target="order-service",
            parameters={"service_name": "order-service"},
            risk_level=risk,
        )
    ]
    rollback_plan = (
        RollbackPlan(
            action_type=RemediationActionType.SERVICE_RESTART,
            target="order-service",
            parameters={"service_name": "order-service"},
        )
        if with_rollback
        else RollbackPlan(
            action_type=RemediationActionType.ROLLBACK,
            target="",
            parameters={},
        )
    )
    prop = RemediationProposal(
        incident_id=uuid4(),
        organization_id=uuid4(),
        service_name="order-service",
        title="Test Proposal",
        description="Testing autonomy decisions",
        root_cause_reference="Transient error",
        risk_level=risk,
        actions=actions,
        blast_radius=BlastRadiusReport(
            affected_services=affected_services or ["order-service"],
            affected_dependencies=[],
            affected_environments=["production-sim"],
        ),
        rollback_plan=rollback_plan,
    )
    prop.remediation_hash = prop.compute_remediation_hash()
    return prop


def test_autonomy_decision_low_risk_permitted() -> None:
    engine = AutonomyDecisionEngine(circuit_breaker=AutonomyCircuitBreaker())
    policy = AutonomyPolicy(
        organization_id=uuid4(),
        autonomy_level=AutonomyLevel.LEVEL_2,
        allowed_actions=[RemediationActionType.SERVICE_RESTART],
        maximum_risk=AIRiskLevel.LOW,
    )
    proposal = _make_test_proposal(action_type=RemediationActionType.SERVICE_RESTART, risk=AIRiskLevel.LOW)

    res = engine.evaluate(proposal, policy)
    assert res.decision == AutonomyDecisionType.AUTONOMOUSLY_EXECUTE
    assert res.allowed is True


def test_autonomy_decision_high_risk_requires_approval() -> None:
    engine = AutonomyDecisionEngine(circuit_breaker=AutonomyCircuitBreaker())
    policy = AutonomyPolicy(
        organization_id=uuid4(),
        autonomy_level=AutonomyLevel.LEVEL_2,
        allowed_actions=[RemediationActionType.SERVICE_RESTART],
        maximum_risk=AIRiskLevel.LOW,  # Max risk is LOW
    )
    proposal = _make_test_proposal(action_type=RemediationActionType.DEPLOYMENT, risk=AIRiskLevel.HIGH)

    res = engine.evaluate(proposal, policy)
    assert res.decision == AutonomyDecisionType.REQUIRE_APPROVAL
    assert res.allowed is False


def test_autonomy_decision_critical_risk_unconditionally_denied() -> None:
    engine = AutonomyDecisionEngine(circuit_breaker=AutonomyCircuitBreaker())
    policy = AutonomyPolicy(
        organization_id=uuid4(),
        autonomy_level=AutonomyLevel.LEVEL_3,
        maximum_risk=AIRiskLevel.HIGH,
    )
    proposal = _make_test_proposal(risk=AIRiskLevel.CRITICAL)

    res = engine.evaluate(proposal, policy)
    assert res.decision == AutonomyDecisionType.DENY
    assert res.allowed is False


def test_kill_switch_blocks_execution() -> None:
    engine = AutonomyDecisionEngine(circuit_breaker=AutonomyCircuitBreaker())
    engine.set_kill_switch(True)

    policy = AutonomyPolicy(organization_id=uuid4())
    proposal = _make_test_proposal(risk=AIRiskLevel.LOW)

    res = engine.evaluate(proposal, policy)
    assert res.decision == AutonomyDecisionType.DENY
    assert res.allowed is False
    assert "kill switch" in res.explanation.reasons[0].lower()


def test_change_freeze_forces_recommend_only() -> None:
    engine = AutonomyDecisionEngine(circuit_breaker=AutonomyCircuitBreaker())
    engine.set_change_freeze(True)

    policy = AutonomyPolicy(organization_id=uuid4())
    proposal = _make_test_proposal(risk=AIRiskLevel.LOW)

    res = engine.evaluate(proposal, policy)
    assert res.decision == AutonomyDecisionType.RECOMMEND_ONLY
    assert res.allowed is False


def test_circuit_breaker_trips_after_failures() -> None:
    cb = AutonomyCircuitBreaker(failure_threshold=2)
    engine = AutonomyDecisionEngine(circuit_breaker=cb)

    assert not cb.is_tripped()
    cb.record_failure()
    assert not cb.is_tripped()
    cb.record_failure()
    assert cb.is_tripped()
    assert cb.state == AutonomyCircuitState.OPEN

    policy = AutonomyPolicy(organization_id=uuid4())
    proposal = _make_test_proposal(risk=AIRiskLevel.LOW)
    res = engine.evaluate(proposal, policy)
    assert res.decision == AutonomyDecisionType.REQUIRE_APPROVAL
    assert "circuit breaker is open" in res.explanation.reasons[0].lower()
