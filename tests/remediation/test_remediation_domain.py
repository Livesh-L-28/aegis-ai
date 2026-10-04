"""Phase 6 Unit Tests: Remediation domain, risk engine, and action registry."""

from uuid import uuid4

from packages.remediation.domain.enums import (
    RemediationActionType,
)
from packages.remediation.domain.models import RemediationAction, RemediationProposal
from packages.remediation.domain.registry import RemediationActionRegistry
from packages.remediation.domain.risk import RemediationRiskEngine
from packages.security.policy import AIRiskLevel


def test_action_registry_validation() -> None:
    registry = RemediationActionRegistry()

    # Valid service restart
    valid, _msg = registry.validate_action(
        RemediationActionType.SERVICE_RESTART,
        {"service_name": "order-service"},
    )
    assert valid

    # Missing required service_name
    invalid, err = registry.validate_action(
        RemediationActionType.SERVICE_RESTART,
        {},
    )
    assert not invalid
    assert "missing required parameter" in err.lower()


def test_risk_engine_max_escalation() -> None:
    risk_engine = RemediationRiskEngine()

    actions = [
        RemediationAction(
            action_type=RemediationActionType.SERVICE_RESTART,
            target="order-service",
            parameters={"service_name": "order-service"},
            risk_level=AIRiskLevel.LOW,
        ),
        RemediationAction(
            action_type=RemediationActionType.CONFIG_CHANGE,
            target="order-service",
            parameters={"service_name": "order-service", "key": "timeout", "value": 10},
            risk_level=AIRiskLevel.MEDIUM,
        ),
        RemediationAction(
            action_type=RemediationActionType.DEPLOYMENT,
            target="order-service",
            parameters={"service_name": "order-service", "target_version": "1.2.0"},
            risk_level=AIRiskLevel.HIGH,
        ),
    ]

    proposal_risk = risk_engine.evaluate_proposal_risk(actions)
    assert proposal_risk == AIRiskLevel.HIGH


def test_risk_engine_critical_for_destructive_actions() -> None:
    risk_engine = RemediationRiskEngine()

    action = RemediationAction(
        action_type=RemediationActionType.CONFIG_CHANGE,
        target="postgres",
        parameters={"service_name": "postgres", "drop_database": True},
    )
    risk = risk_engine.evaluate_action_risk(action)
    assert risk == AIRiskLevel.CRITICAL


def test_blast_radius_calculation() -> None:
    risk_engine = RemediationRiskEngine()
    report = risk_engine.calculate_blast_radius(
        service_name="order-service",
        dependencies=["postgres", "payment-service"],
    )
    assert "order-service" in report.affected_services
    assert "postgres" in report.affected_services
    assert "payment-service" in report.affected_services
    assert len(report.affected_services) == 3


def test_remediation_hash_determinism() -> None:
    inc_id = uuid4()
    org_id = uuid4()
    p1 = RemediationProposal(
        incident_id=inc_id,
        organization_id=org_id,
        service_name="order-service",
        title="Fix order service",
        description="Fix description",
        root_cause_reference="Postgres timeout",
        actions=[
            RemediationAction(
                action_type=RemediationActionType.SERVICE_RESTART,
                target="order-service",
                parameters={"service_name": "order-service"},
            )
        ],
    )
    h1 = p1.compute_remediation_hash()

    p2 = RemediationProposal(
        incident_id=inc_id,
        organization_id=org_id,
        service_name="order-service",
        title="Fix order service",
        description="Fix description",
        root_cause_reference="Postgres timeout",
        actions=[
            RemediationAction(
                action_type=RemediationActionType.SERVICE_RESTART,
                target="order-service",
                parameters={"service_name": "order-service"},
            )
        ],
    )
    h2 = p2.compute_remediation_hash()

    assert h1 == h2

    # Mutate action parameters
    p2.actions[0].parameters["grace_period"] = 30
    h3 = p2.compute_remediation_hash()
    assert h1 != h3
