"""Phase 6 Unit Tests: Preflight validation, Sandbox execution, Validation, and Rollback."""

import pytest

from packages.remediation.domain.enums import (
    ExecutionStatus,
    RemediationActionType,
    RemediationStatus,
)
from packages.remediation.domain.models import (
    RemediationAction,
    RollbackPlan,
)
from packages.remediation.services.executor import RemediationSandboxExecutor
from packages.remediation.services.preflight import PreflightValidator
from packages.remediation.services.validator import PostRemediationValidator
from packages.security.policy import AIRiskLevel
from packages.simulation.scenarios import simulation_registry
from tests.remediation.test_approval_workflow import _build_test_proposal


@pytest.mark.asyncio
async def test_preflight_and_successful_execution_and_validation() -> None:
    validator = PreflightValidator()
    executor = RemediationSandboxExecutor()
    post_validator = PostRemediationValidator()

    # 1. Activate INC-002 (Redis failure in simulation)
    simulation_registry.activate("INC-002")
    sc = simulation_registry.get("INC-002")
    assert sc is not None and sc.enabled is True

    # 2. Build proposal addressing INC-002
    proposal = _build_test_proposal(risk=AIRiskLevel.LOW)
    proposal.actions = [
        RemediationAction(
            action_type=RemediationActionType.SERVICE_RESTART,
            target="payment-service",
            parameters={"service_name": "payment-service"},
            risk_level=AIRiskLevel.LOW,
        )
    ]
    proposal.remediation_hash = proposal.compute_remediation_hash()

    # 3. Preflight check
    preflight = validator.validate_preflight(proposal)
    assert preflight.passed is True

    # 4. Sandbox Execution
    execution = await executor.execute_proposal(proposal, preflight)
    assert execution.status == ExecutionStatus.VALIDATING

    # 5. Post-remediation Validation (fault was cleared)
    val_passed = await post_validator.validate_remediation(proposal, execution)
    assert val_passed is True
    assert execution.status == ExecutionStatus.SUCCEEDED
    assert proposal.status == RemediationStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_failed_validation_triggers_rollback() -> None:
    validator = PreflightValidator()
    executor = RemediationSandboxExecutor()
    post_validator = PostRemediationValidator()

    proposal = _build_test_proposal(risk=AIRiskLevel.LOW)
    proposal.rollback_plan = RollbackPlan(
        action_type=RemediationActionType.CONFIG_CHANGE,
        target="payment-service",
        parameters={"service_name": "payment-service", "key": "timeout", "value": 5000},
    )
    proposal.remediation_hash = proposal.compute_remediation_hash()

    preflight = validator.validate_preflight(proposal)
    execution = await executor.execute_proposal(proposal, preflight)

    # Force validation failure
    val_passed = await post_validator.validate_remediation(proposal, execution, force_failure=True)
    assert val_passed is False
    assert execution.status == ExecutionStatus.FAILED

    # Trigger rollback
    rb_res = await executor.execute_rollback(proposal)
    assert rb_res["status"] == "completed"
    assert proposal.status == RemediationStatus.ROLLED_BACK
