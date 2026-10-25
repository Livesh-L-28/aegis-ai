"""Mission Orchestrator for LogicFalcon FDE dependency-ordered workflow execution."""

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.fde.adapters.registry import AdapterRegistry
from packages.review.fde.models import (
    FdeEvidence,
    FdeMission,
    FdeStep,
    StepStatus,
)
from packages.review.fde.orchestration.policy_gateway import (
    PolicyGateway,
    PolicyViolationError,
)
from packages.review.fde.orchestration.state_machine import (
    MissionStatus,
    StepStateMachine,
)


@dataclass
class StepExecutionSummary:
    """Execution outcome summary for a single mission step."""

    step_id: str
    status: StepStatus
    operation: str
    target: str
    success: bool
    execution_time_seconds: float = 0.0
    error: str | None = None
    evidence: FdeEvidence | None = None


@dataclass
class MissionExecutionReport:
    """Comprehensive execution summary for a completed or terminated mission."""

    mission_id: str
    status: MissionStatus
    started_at: datetime
    completed_at: datetime
    total_steps: int
    succeeded_steps: int
    failed_steps: int
    blocked_steps: int
    cancelled_steps: int
    step_summaries: list[StepExecutionSummary] = field(default_factory=list)
    evidence_records: list[FdeEvidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "total_steps": self.total_steps,
            "succeeded_steps": self.succeeded_steps,
            "failed_steps": self.failed_steps,
            "blocked_steps": self.blocked_steps,
            "cancelled_steps": self.cancelled_steps,
            "step_summaries": [
                {
                    "step_id": s.step_id,
                    "status": s.status.value,
                    "operation": s.operation,
                    "target": s.target,
                    "success": s.success,
                    "execution_time_seconds": s.execution_time_seconds,
                    "error": s.error,
                }
                for s in self.step_summaries
            ],
            "evidence_count": len(self.evidence_records),
        }


class MissionOrchestrator:
    """Orchestrates dependency-ordered mission workflows with policy enforcement and evidence logging."""

    def __init__(self, registry: AdapterRegistry, policy_gateway: PolicyGateway | None = None) -> None:
        self.registry = registry
        self.policy_gateway = policy_gateway or PolicyGateway(registry)
        self._cancelled = False

    def cancel(self) -> None:
        """Signals active orchestrator execution to cancel pending steps safely."""
        self._cancelled = True

    def reset(self) -> None:
        """Resets orchestrator state for a new run."""
        self._cancelled = False

    def run_mission(
        self,
        mission: FdeMission,
        approval_tokens: dict[str, str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> MissionExecutionReport:
        """Executes mission steps in dependency topological order."""
        started_at = datetime.now(UTC)
        tokens = approval_tokens or {}

        # 1. Validate DAG and establish topological levels
        mission.validate_dag()
        ordered_levels = mission.get_execution_order()

        # Track runtime step status and step lookups
        step_map: dict[str, FdeStep] = {step.id: step for step in mission.steps}
        step_statuses: dict[str, StepStatus] = {step.id: StepStatus.PENDING for step in mission.steps}
        step_summaries: list[StepExecutionSummary] = []
        evidence_records: list[FdeEvidence] = []

        failed_step_ids: set[str] = set()
        blocked_step_ids: set[str] = set()

        for level in ordered_levels:
            if self._cancelled:
                # Cancel remaining steps
                for step_id in level:
                    step_statuses[step_id] = StepStateMachine.transition(
                        step_statuses[step_id], StepStatus.CANCELLED, "Mission cancelled"
                    )
                    step_summaries.append(
                        StepExecutionSummary(
                            step_id=step_id,
                            status=StepStatus.CANCELLED,
                            operation=step_map[step_id].operation,
                            target=step_map[step_id].target,
                            success=False,
                            error="Execution cancelled by operator",
                        )
                    )
                continue

            for step_id in level:
                step = step_map[step_id]

                # Check if any dependencies failed or were blocked
                dep_failures = [dep.step_id for dep in step.dependencies if dep.step_id in failed_step_ids or dep.step_id in blocked_step_ids]
                if dep_failures:
                    blocked_step_ids.add(step_id)
                    step_statuses[step_id] = StepStateMachine.transition(
                        step_statuses[step_id], StepStatus.BLOCKED, f"Dependencies failed: {dep_failures}"
                    )
                    step_summaries.append(
                        StepExecutionSummary(
                            step_id=step_id,
                            status=StepStatus.BLOCKED,
                            operation=step.operation,
                            target=step.target,
                            success=False,
                            error=f"Dependency failure in: {', '.join(dep_failures)}",
                        )
                    )
                    continue

                # Transition: PENDING -> READY -> RUNNING
                step_statuses[step_id] = StepStateMachine.transition(
                    step_statuses[step_id], StepStatus.READY, "Dependencies satisfied"
                )
                step_statuses[step_id] = StepStateMachine.transition(
                    step_statuses[step_id], StepStatus.RUNNING, "Starting execution"
                )

                # Execute step through PolicyGateway
                start_time = time.perf_counter()
                token = tokens.get(step_id)
                params = step.parameters.copy()

                try:
                    res = self.policy_gateway.execute_step(
                        mission_id=mission.id,
                        step=step,
                        adapter_id=step.adapter_id,
                        operation=step.operation,
                        params=params,
                        approval_token=token,
                        context=context,
                    )
                    elapsed = time.perf_counter() - start_time

                    if res.success:
                        step_statuses[step_id] = StepStateMachine.transition(
                            step_statuses[step_id], StepStatus.SUCCEEDED, "Operation completed successfully"
                        )
                        summary = StepExecutionSummary(
                            step_id=step_id,
                            status=StepStatus.SUCCEEDED,
                            operation=step.operation,
                            target=step.target,
                            success=True,
                            execution_time_seconds=elapsed,
                            evidence=res.evidence,
                        )
                    else:
                        failed_step_ids.add(step_id)
                        step_statuses[step_id] = StepStateMachine.transition(
                            step_statuses[step_id], StepStatus.FAILED, res.error or "Operation failed"
                        )
                        summary = StepExecutionSummary(
                            step_id=step_id,
                            status=StepStatus.FAILED,
                            operation=step.operation,
                            target=step.target,
                            success=False,
                            execution_time_seconds=elapsed,
                            error=res.error,
                            evidence=res.evidence,
                        )

                except PolicyViolationError as pve:
                    elapsed = time.perf_counter() - start_time
                    failed_step_ids.add(step_id)
                    step_statuses[step_id] = StepStateMachine.transition(
                        step_statuses[step_id], StepStatus.FAILED, str(pve)
                    )
                    summary = StepExecutionSummary(
                        step_id=step_id,
                        status=StepStatus.FAILED,
                        operation=step.operation,
                        target=step.target,
                        success=False,
                        execution_time_seconds=elapsed,
                        error=str(pve),
                    )

                except Exception as ex:
                    elapsed = time.perf_counter() - start_time
                    failed_step_ids.add(step_id)
                    step_statuses[step_id] = StepStateMachine.transition(
                        step_statuses[step_id], StepStatus.FAILED, str(ex)
                    )
                    summary = StepExecutionSummary(
                        step_id=step_id,
                        status=StepStatus.FAILED,
                        operation=step.operation,
                        target=step.target,
                        success=False,
                        execution_time_seconds=elapsed,
                        error=redact_secrets_in_text(str(ex)),
                    )

                step_summaries.append(summary)
                if summary.evidence:
                    evidence_records.append(summary.evidence)

        completed_at = datetime.now(UTC)

        succeeded = sum(1 for s in step_summaries if s.status == StepStatus.SUCCEEDED)
        failed = sum(1 for s in step_summaries if s.status == StepStatus.FAILED)
        blocked = sum(1 for s in step_summaries if s.status == StepStatus.BLOCKED)
        cancelled = sum(1 for s in step_summaries if s.status == StepStatus.CANCELLED)

        if self._cancelled or cancelled > 0:
            final_status = MissionStatus.CANCELLED
        elif failed > 0:
            final_status = MissionStatus.FAILED
        elif blocked > 0:
            final_status = MissionStatus.BLOCKED
        else:
            final_status = MissionStatus.SUCCEEDED

        return MissionExecutionReport(
            mission_id=mission.id,
            status=final_status,
            started_at=started_at,
            completed_at=completed_at,
            total_steps=len(mission.steps),
            succeeded_steps=succeeded,
            failed_steps=failed,
            blocked_steps=blocked,
            cancelled_steps=cancelled,
            step_summaries=step_summaries,
            evidence_records=evidence_records,
        )
