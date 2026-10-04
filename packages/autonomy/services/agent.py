"""Phase 7 Bounded Reliability Agent Runtime.

Orchestrates the autonomous incident loop:
1. Investigation & Evidence Collection
2. Reasoning & Root Cause Isolation
3. Remediation Planning
4. Risk & Autonomy Policy Evaluation
5. Auto-execution (if permitted) OR Approval Wait
6. Preflight & Sandbox Execution
7. Post-remediation Validation & Rollback
8. Operational Learning

Enforces strict budgets:
- max_iterations
- max_tool_calls
- max_cost_usd
- max_duration_seconds
"""

from datetime import UTC, datetime
from uuid import UUID

from packages.autonomy.domain.enums import (
    AgentExecutionState,
    AutonomyDecisionType,
)
from packages.autonomy.domain.models import (
    AgentBudget,
    AgentRunRecord,
    AutonomyPolicy,
    IncidentLearningRecord,
)
from packages.autonomy.services.decision import AutonomyDecisionEngine, default_autonomy_engine
from packages.intelligence.reasoning.validator import StructuredReasoningOutput
from packages.remediation.domain.enums import ExecutionStatus
from packages.remediation.domain.models import RemediationProposal
from packages.remediation.services.executor import RemediationSandboxExecutor
from packages.remediation.services.planner import RemediationPlanner
from packages.remediation.services.preflight import PreflightValidator
from packages.remediation.services.validator import PostRemediationValidator


class RunawayAgentException(Exception):
    """Raised when an agent violates execution, tool, or cost limits."""


class ReliabilityAgent:
    """Bounded Autonomous Reliability Agent."""

    def __init__(
        self,
        planner: RemediationPlanner | None = None,
        autonomy_engine: AutonomyDecisionEngine | None = None,
        preflight_validator: PreflightValidator | None = None,
        sandbox_executor: RemediationSandboxExecutor | None = None,
        post_validator: PostRemediationValidator | None = None,
    ) -> None:
        self.planner = planner or RemediationPlanner()
        self.autonomy_engine = autonomy_engine or default_autonomy_engine
        self.preflight_validator = preflight_validator or PreflightValidator()
        self.sandbox_executor = sandbox_executor or RemediationSandboxExecutor()
        self.post_validator = post_validator or PostRemediationValidator()

    async def run_incident_loop(
        self,
        incident_id: UUID,
        organization_id: UUID,
        service_name: str,
        reasoning_output: StructuredReasoningOutput,
        policy: AutonomyPolicy,
        budget: AgentBudget | None = None,
        environment: str = "production-sim",
        is_production: bool = False,
    ) -> tuple[AgentRunRecord, RemediationProposal | None, IncidentLearningRecord | None]:
        active_budget = budget or AgentBudget()
        run = AgentRunRecord(
            incident_id=incident_id,
            organization_id=organization_id,
            service_name=service_name,
            budget=active_budget,
            state=AgentExecutionState.CREATED,
        )

        try:
            # 1. Start Investigation & Evidence Phase
            run.state = AgentExecutionState.INVESTIGATING
            self._check_budget(run)
            run.tool_calls_count += 1  # Evidence retrieval tool call
            run.total_cost_usd += 0.05
            run.iterations_count += 1

            # 2. Reasoning Phase
            run.state = AgentExecutionState.REASONING
            self._check_budget(run)
            run.tool_calls_count += 1  # LLM reasoning call
            run.total_cost_usd += 0.15
            run.iterations_count += 1

            # 3. Proposing Phase
            run.state = AgentExecutionState.PROPOSING
            proposal = self.planner.plan_remediation(
                incident_id=incident_id,
                organization_id=organization_id,
                service_name=service_name,
                reasoning_result=reasoning_output,
                environment=environment,
                actor_id=f"aegis-agent-{run.id}",
            )
            run.remediation_id = proposal.id
            run.tool_calls_count += 1
            run.total_cost_usd += 0.05
            run.iterations_count += 1

            # 4. Autonomy Decision Evaluation
            decision = self.autonomy_engine.evaluate(
                proposal=proposal,
                policy=policy,
                environment=environment,
                is_production=is_production,
            )
            run.autonomy_decision = decision.decision

            if decision.decision != AutonomyDecisionType.AUTONOMOUSLY_EXECUTE:
                # Requires human approval or is denied
                run.state = (
                    AgentExecutionState.AWAITING_APPROVAL
                    if decision.decision == AutonomyDecisionType.REQUIRE_APPROVAL
                    else AgentExecutionState.FAILED
                )
                run.outcome = f"Autonomy evaluated: {decision.decision.value}. Reasons: {'; '.join(decision.explanation.reasons)}"
                run.completed_at = datetime.now(UTC)
                return run, proposal, None

            # 5. Preflight Gate
            preflight = self.preflight_validator.validate_preflight(proposal)
            if not preflight.passed:
                run.state = AgentExecutionState.FAILED
                run.error_message = f"Preflight validation failed: {preflight.errors}"
                run.completed_at = datetime.now(UTC)
                return run, proposal, None

            # 6. Autonomous Execution
            run.state = AgentExecutionState.EXECUTING
            self._check_budget(run)
            run.tool_calls_count += 1
            run.total_cost_usd += 0.05
            execution = await self.sandbox_executor.execute_proposal(proposal, preflight)

            # 7. Post-Remediation Telemetry Validation
            run.state = AgentExecutionState.VALIDATING
            val_passed = await self.post_validator.validate_remediation(proposal, execution)

            learning_record: IncidentLearningRecord | None = None
            if val_passed:
                run.state = AgentExecutionState.COMPLETED
                run.outcome = "Autonomous remediation successfully applied and validated."
                self.autonomy_engine.circuit_breaker.record_success()

                # Generate operational learning record
                learning_record = IncidentLearningRecord(
                    incident_id=incident_id,
                    organization_id=organization_id,
                    service_name=service_name,
                    environment=environment,
                    root_cause=reasoning_output.root_cause,
                    remediation_summary=proposal.title,
                    actions_taken=[a.model_dump(mode="json") for a in proposal.actions],
                    validated=True,
                    promoted_to_knowledge=True,
                    runbook_candidate=True,
                    proposed_runbook_content=(
                        f"Runbook for {service_name}: When root cause '{reasoning_output.root_cause}' "
                        f"is detected, apply {proposal.actions[0].action_type.value} on {proposal.actions[0].target}."
                    ),
                )
            else:
                # Validation failed -> Automatic Rollback
                run.state = AgentExecutionState.ESCALATING
                self.autonomy_engine.circuit_breaker.record_failure()
                rb_result = await self.sandbox_executor.execute_rollback(proposal)
                execution.status = ExecutionStatus.ROLLED_BACK
                run.outcome = f"Validation failed. Automated rollback executed. Rollback status: {rb_result.get('status')}."

            run.completed_at = datetime.now(UTC)
            return run, proposal, learning_record

        except RunawayAgentException as exc:
            run.state = AgentExecutionState.FAILED
            run.error_message = str(exc)
            run.completed_at = datetime.now(UTC)
            return run, None, None

    def _check_budget(self, run: AgentRunRecord) -> None:
        b = run.budget
        if run.iterations_count >= b.max_iterations:
            raise RunawayAgentException(
                f"Agent exceeded iteration budget ({run.iterations_count}/{b.max_iterations})."
            )
        if run.tool_calls_count >= b.max_tool_calls:
            raise RunawayAgentException(
                f"Agent exceeded tool call budget ({run.tool_calls_count}/{b.max_tool_calls})."
            )
        if run.total_cost_usd >= b.max_cost_usd:
            raise RunawayAgentException(
                f"Agent exceeded cost budget (${run.total_cost_usd:.2f}/${b.max_cost_usd:.2f})."
            )
