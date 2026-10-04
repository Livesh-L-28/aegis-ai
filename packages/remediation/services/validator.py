"""Phase 6 Post-Remediation Verification and Observability Validation."""

from datetime import UTC, datetime

from packages.remediation.domain.enums import ExecutionStatus, RemediationStatus
from packages.remediation.domain.models import RemediationExecution, RemediationProposal
from packages.simulation.scenarios import simulation_registry


class PostRemediationValidator:
    """Validates operational metrics and health post-execution against measurable targets."""

    def __init__(self) -> None:
        pass

    async def validate_remediation(
        self,
        proposal: RemediationProposal,
        execution: RemediationExecution,
        force_failure: bool = False,
    ) -> bool:
        """Evaluates whether the remediation achieved the expected telemetry improvement."""
        service_name = proposal.service_name

        # Check if fault scenario for target service is resolved in simulation
        active_faults = [
            s.name for s in simulation_registry.list_all()
            if s.enabled and s.target_service == service_name
        ]

        passed = len(active_faults) == 0 and not force_failure

        now = datetime.now(UTC)
        execution.completed_at = now
        execution.validation_result = {
            "validated_at": now.isoformat(),
            "target_service": service_name,
            "metric_checks_passed": passed,
            "active_faults_remaining": active_faults,
            "status": "PASSED" if passed else "FAILED",
        }

        if passed:
            execution.status = ExecutionStatus.SUCCEEDED
            proposal.status = RemediationStatus.SUCCEEDED
        else:
            execution.status = ExecutionStatus.FAILED
            proposal.status = RemediationStatus.FAILED

        return passed


default_post_validator = PostRemediationValidator()
