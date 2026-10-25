"""Tests for LogicFalcon FDE State Machine, Policy Gateway, and Mission Orchestrator."""

from unittest.mock import MagicMock, patch

import pytest

from packages.review.fde.adapters import AdapterRegistry, HttpAdapter
from packages.review.fde.models import (
    FdeMission,
    FdeStep,
    OperationCategory,
    StepDependency,
    StepRiskLevel,
    StepStatus,
)
from packages.review.fde.orchestration import (
    InvalidStateTransitionError,
    MissionOrchestrator,
    MissionStatus,
    PolicyGateway,
    PolicyViolationError,
    StepStateMachine,
)

# ==============================================================================
# 1. StepStateMachine Tests
# ==============================================================================


def test_state_machine_legal_transitions() -> None:
    assert StepStateMachine.can_transition(StepStatus.PENDING, StepStatus.READY)
    assert StepStateMachine.can_transition(StepStatus.READY, StepStatus.RUNNING)
    assert StepStateMachine.can_transition(StepStatus.RUNNING, StepStatus.SUCCEEDED)
    assert StepStateMachine.can_transition(StepStatus.RUNNING, StepStatus.FAILED)
    assert StepStateMachine.can_transition(StepStatus.FAILED, StepStatus.READY)

    # Execute transition
    res = StepStateMachine.transition(StepStatus.PENDING, StepStatus.READY)
    assert res == StepStatus.READY


def test_state_machine_illegal_transitions() -> None:
    # Cannot jump directly from PENDING to SUCCEEDED
    assert not StepStateMachine.can_transition(StepStatus.PENDING, StepStatus.SUCCEEDED)
    with pytest.raises(InvalidStateTransitionError):
        StepStateMachine.transition(StepStatus.PENDING, StepStatus.SUCCEEDED)

    # Cannot transition out of SUCCEEDED (terminal)
    assert not StepStateMachine.can_transition(StepStatus.SUCCEEDED, StepStatus.RUNNING)
    with pytest.raises(InvalidStateTransitionError):
        StepStateMachine.transition(StepStatus.SUCCEEDED, StepStatus.RUNNING)


# ==============================================================================
# 2. PolicyGateway Tests
# ==============================================================================


def test_policy_gateway_read_only_allowed() -> None:
    registry = AdapterRegistry()
    registry.register(HttpAdapter())
    gateway = PolicyGateway(registry)

    step = FdeStep(
        id="check-health",
        name="Check Web Health",
        description="Verify service is alive",
        adapter_id="http",
        operation="http_health_check",
        target="http://localhost:8000/health",
        parameters={"url": "http://localhost:8000/health"},
        operation_category=OperationCategory.READ_ONLY,
        risk_level=StepRiskLevel.LOW,
        requires_approval=False,
    )

    mock_resp = MagicMock(status_code=200, content=b"OK", text="OK", headers={})
    with patch("httpx.Client.get", return_value=mock_resp):
        res = gateway.execute_step(
            mission_id="mission-1",
            step=step,
            adapter_id="http",
            operation="http_health_check",
            params={"url": "http://localhost:8000/health"},
        )
        assert res.success
        assert len(gateway.audit_log) == 1
        assert gateway.audit_log[0].allowed is True


def test_policy_gateway_blocks_unauthorized_mutation() -> None:
    registry = AdapterRegistry()
    registry.register(HttpAdapter())
    gateway = PolicyGateway(registry)

    step = FdeStep(
        id="trigger-deploy",
        name="Trigger Deploy Webhook",
        description="Send deployment webhook",
        adapter_id="http",
        operation="http_post",
        target="http://deploy.internal/deploy",
        parameters={"url": "http://deploy.internal/deploy", "json": {"action": "deploy"}},
        operation_category=OperationCategory.CONSEQUENTIAL_MUTATION,
        risk_level=StepRiskLevel.HIGH,
        requires_approval=True,
    )

    with pytest.raises(PolicyViolationError) as exc_info:
        gateway.execute_step(
            mission_id="mission-1",
            step=step,
            adapter_id="http",
            operation="http_post",
            params={"url": "http://deploy.internal/deploy", "json": {"action": "deploy"}},
        )
    assert "requires explicit human approval token" in str(exc_info.value)
    assert len(gateway.audit_log) == 1
    assert gateway.audit_log[0].allowed is False


def test_policy_gateway_approved_and_tamper_detection() -> None:
    registry = AdapterRegistry()
    registry.register(HttpAdapter())
    gateway = PolicyGateway(registry)

    params = {"url": "http://deploy.internal/deploy", "json": {"action": "deploy"}}
    step = FdeStep(
        id="trigger-deploy",
        name="Trigger Deploy Webhook",
        description="Send deployment webhook",
        adapter_id="http",
        operation="http_post",
        target="http://deploy.internal/deploy",
        parameters=params,
        operation_category=OperationCategory.CONSEQUENTIAL_MUTATION,
        risk_level=StepRiskLevel.HIGH,
        requires_approval=True,
    )

    token = gateway.grant_approval(
        mission_id="mission-1",
        step_id=step.id,
        adapter_id="http",
        operation="http_post",
        target=step.target,
        params=params,
    )

    # 1. Execution with valid token succeeds
    mock_resp = MagicMock(status_code=200, content=b'{"status":"ok"}', text='{"status":"ok"}', headers={})
    with patch("httpx.Client.post", return_value=mock_resp):
        res = gateway.execute_step(
            mission_id="mission-1",
            step=step,
            adapter_id="http",
            operation="http_post",
            params=params,
            approval_token=token,
        )
        assert res.success

    # 2. Tampering with parameters invalidates approval
    tampered_params = {"url": "http://deploy.internal/deploy", "json": {"action": "destroy"}}
    with pytest.raises(PolicyViolationError):
        gateway.execute_step(
            mission_id="mission-1",
            step=step,
            adapter_id="http",
            operation="http_post",
            params=tampered_params,
            approval_token=token,
        )


# ==============================================================================
# 3. MissionOrchestrator Tests
# ==============================================================================


def test_orchestrator_multi_step_dag_execution() -> None:
    registry = AdapterRegistry()
    registry.register(HttpAdapter())
    orchestrator = MissionOrchestrator(registry)

    # DAG: step-1 (health check) -> step-2 (fetch metadata)
    step1 = FdeStep(
        id="step-1",
        name="Health Check",
        description="Verify service",
        adapter_id="http",
        operation="http_health_check",
        target="http://localhost:8000/health",
        parameters={"url": "http://localhost:8000/health"},
        operation_category=OperationCategory.READ_ONLY,
        risk_level=StepRiskLevel.LOW,
    )
    step2 = FdeStep(
        id="step-2",
        name="Fetch Metadata",
        description="Get service version",
        adapter_id="http",
        operation="http_get",
        target="http://localhost:8000/version",
        parameters={"url": "http://localhost:8000/version"},
        operation_category=OperationCategory.READ_ONLY,
        risk_level=StepRiskLevel.LOW,
        dependencies=[StepDependency(step_id="step-1")],
    )

    mission = FdeMission(name="Deploy Verification", objective="Verify service endpoints", steps=[step1, step2])

    mock_resp = MagicMock(status_code=200, content=b'{"version": "1.0"}', text='{"version": "1.0"}', headers={})
    with patch("httpx.Client.get", return_value=mock_resp):
        report = orchestrator.run_mission(mission)
        assert report.status == MissionStatus.SUCCEEDED
        assert report.total_steps == 2
        assert report.succeeded_steps == 2
        assert len(report.evidence_records) == 2
        report_dict = report.to_dict()
        assert report_dict["status"] == "SUCCEEDED"


def test_orchestrator_dependency_failure_blocks_dependents() -> None:
    registry = AdapterRegistry()
    registry.register(HttpAdapter())
    orchestrator = MissionOrchestrator(registry)

    # step-1 fails -> step-2 should be BLOCKED
    step1 = FdeStep(
        id="step-1",
        description="Verify service",
        adapter_id="http",
        operation="http_health_check",
        target="http://localhost:8000/health",
        parameters={"url": "http://localhost:8000/health"},
        operation_category=OperationCategory.READ_ONLY,
        risk_level=StepRiskLevel.LOW,
    )
    step2 = FdeStep(
        id="step-2",
        description="Action depending on step 1",
        adapter_id="http",
        operation="http_get",
        target="http://localhost:8000/info",
        parameters={"url": "http://localhost:8000/info"},
        operation_category=OperationCategory.READ_ONLY,
        risk_level=StepRiskLevel.LOW,
        dependencies=[StepDependency(step_id="step-1")],
    )

    mission = FdeMission(name="Failure Flow", objective="Test dependency failure cascade", steps=[step1, step2])

    mock_resp = MagicMock(status_code=500, content=b"Server Error", text="Server Error", headers={})
    with patch("httpx.Client.get", return_value=mock_resp):
        report = orchestrator.run_mission(mission)
        assert report.status == MissionStatus.FAILED
        assert report.succeeded_steps == 0
        assert report.failed_steps == 1
        assert report.blocked_steps == 1

        summary_map = {s.step_id: s for s in report.step_summaries}
        assert summary_map["step-1"].status == StepStatus.FAILED
        assert summary_map["step-2"].status == StepStatus.BLOCKED


def test_orchestrator_cancellation() -> None:
    registry = AdapterRegistry()
    registry.register(HttpAdapter())
    orchestrator = MissionOrchestrator(registry)

    step1 = FdeStep(
        id="step-1",
        description="Step 1",
        adapter_id="http",
        operation="http_get",
        target="http://localhost:8000/1",
        parameters={"url": "http://localhost:8000/1"},
    )
    step2 = FdeStep(
        id="step-2",
        description="Step 2",
        adapter_id="http",
        operation="http_get",
        target="http://localhost:8000/2",
        parameters={"url": "http://localhost:8000/2"},
        dependencies=[StepDependency(step_id="step-1")],
    )

    mission = FdeMission(name="Cancelled Mission", objective="Test cancellation", steps=[step1, step2])

    # Cancel before execution runs
    orchestrator.cancel()
    report = orchestrator.run_mission(mission)
    assert report.status == MissionStatus.CANCELLED
    assert report.cancelled_steps == 2
