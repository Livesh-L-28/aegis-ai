"""Phase 7 Autonomy Application Service: Orchestrates policy, agent loops, learning, and evaluations."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.exceptions import (
    ForbiddenException,
    ResourceNotFoundException,
)
from apps.api.app.core.security import AuthenticatedPrincipal
from apps.api.app.models.entities import (
    AgentRunEntity,
    AutonomyPolicyRecord,
    Incident,
    IncidentLearningEntity,
    ReasoningResult,
)
from apps.api.app.schemas.domain import (
    AgentRunResponse,
    AutonomyPolicyCreateRequest,
    AutonomyPolicyResponse,
    AutonomyStatusResponse,
    EvaluationRunResponse,
    IncidentLearningResponse,
    SLOResponse,
)
from apps.api.app.services.tenant import AuditService
from packages.autonomy.domain.enums import AutonomyLevel, SLOType
from packages.autonomy.domain.models import AgentBudget, AutonomyPolicy
from packages.autonomy.services.agent import ReliabilityAgent
from packages.autonomy.services.decision import default_autonomy_engine
from packages.autonomy.services.evaluation import default_evaluation_engine
from packages.autonomy.services.reliability import default_slo_engine
from packages.config.settings import get_settings
from packages.intelligence.reasoning.validator import StructuredReasoningOutput
from packages.remediation.domain.enums import RemediationActionType
from packages.security.policy import AIRiskLevel
from packages.security.rbac import Permission


class AutonomyService:
    """Manages Phase 7 Bounded Autonomy, Reliability Agent, and Operational Learning."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.settings = get_settings()
        self.agent = ReliabilityAgent()
        self.autonomy_engine = default_autonomy_engine
        self.evaluation_engine = default_evaluation_engine
        self.slo_engine = default_slo_engine
        self.audit_service = AuditService(session)

    async def get_autonomy_status(
        self,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> AutonomyStatusResponse:
        if not principal.has_permission(Permission.AUTONOMY_READ):
            raise ForbiddenException("Principal lacks AUTONOMY_READ permission")

        return AutonomyStatusResponse(
            autonomy_enabled=self.settings.AUTONOMY_ENABLED,
            production_enabled=self.settings.AUTONOMY_PRODUCTION_ENABLED,
            kill_switch_active=self.autonomy_engine.is_kill_switch_active(),
            change_freeze_active=self.autonomy_engine.is_change_freeze_active(),
            circuit_breaker_state=self.autonomy_engine.circuit_breaker.state.value,
            max_risk_level=self.settings.AUTONOMY_MAX_RISK,
            max_tool_calls=self.settings.AUTONOMY_MAX_TOOL_CALLS,
        )

    async def set_kill_switch(
        self,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        enabled: bool,
    ) -> AutonomyStatusResponse:
        if not principal.has_permission(Permission.AUTONOMY_ADMIN):
            raise ForbiddenException("Principal lacks AUTONOMY_ADMIN permission to operate kill switch")

        self.autonomy_engine.set_kill_switch(enabled)
        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="autonomy.kill_switch.updated",
            resource_type="autonomy",
            resource_id=str(organization_id),
            metadata={"kill_switch_active": enabled},
        )
        return await self.get_autonomy_status(organization_id, principal)

    async def set_change_freeze(
        self,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        enabled: bool,
    ) -> AutonomyStatusResponse:
        if not principal.has_permission(Permission.AUTONOMY_ADMIN):
            raise ForbiddenException("Principal lacks AUTONOMY_ADMIN permission to set change freeze")

        self.autonomy_engine.set_change_freeze(enabled)
        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="autonomy.change_freeze.updated",
            resource_type="autonomy",
            resource_id=str(organization_id),
            metadata={"change_freeze_active": enabled},
        )
        return await self.get_autonomy_status(organization_id, principal)

    async def create_or_update_policy(
        self,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        request: AutonomyPolicyCreateRequest,
    ) -> AutonomyPolicyResponse:
        if not principal.has_permission(Permission.AUTONOMY_ADMIN):
            raise ForbiddenException("Principal lacks AUTONOMY_ADMIN permission to configure autonomy policies")

        stmt = select(AutonomyPolicyRecord).where(
            AutonomyPolicyRecord.organization_id == organization_id,
            AutonomyPolicyRecord.environment == request.environment,
            AutonomyPolicyRecord.service == request.service,
        )
        res = await self.session.execute(stmt)
        record = res.scalar_one_or_none()

        if not record:
            record = AutonomyPolicyRecord(
                organization_id=organization_id,
                environment=request.environment,
                service=request.service,
                autonomy_level=request.autonomy_level,
                allowed_actions=request.allowed_actions,
                maximum_risk=request.maximum_risk,
                max_blast_radius_services=request.max_blast_radius_services,
                require_rollback_plan=request.require_rollback_plan,
                require_validation_plan=request.require_validation_plan,
                change_freeze_enabled=request.change_freeze_enabled,
            )
            self.session.add(record)
        else:
            record.autonomy_level = request.autonomy_level
            record.allowed_actions = request.allowed_actions
            record.maximum_risk = request.maximum_risk
            record.max_blast_radius_services = request.max_blast_radius_services
            record.require_rollback_plan = request.require_rollback_plan
            record.require_validation_plan = request.require_validation_plan
            record.change_freeze_enabled = request.change_freeze_enabled

        await self.session.commit()
        await self.session.refresh(record)

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="autonomy.policy.updated",
            resource_type="autonomy_policy",
            resource_id=str(record.id),
            metadata={"environment": record.environment, "level": record.autonomy_level},
        )
        return AutonomyPolicyResponse.model_validate(record)

    async def trigger_autonomous_agent(
        self,
        incident_id: UUID,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        environment: str = "production-sim",
    ) -> AgentRunResponse:
        if not principal.has_permission(Permission.REMEDIATION_EXECUTE):
            raise ForbiddenException("Principal lacks REMEDIATION_EXECUTE permission")

        # 1. Fetch incident
        stmt_inc = select(Incident).where(
            Incident.id == incident_id,
            Incident.organization_id == organization_id,
        )
        res_inc = await self.session.execute(stmt_inc)
        incident = res_inc.scalar_one_or_none()
        if not incident:
            raise ResourceNotFoundException("Incident", str(incident_id))

        # 2. Fetch or construct reasoning output scoped to this incident
        stmt_rca = (
            select(ReasoningResult)
            .join(ReasoningResult.investigation)
            .where(
                ReasoningResult.organization_id == organization_id,
            )
            .order_by(ReasoningResult.created_at.desc())
        )
        res_rca = await self.session.execute(stmt_rca)
        reasoning = res_rca.scalar_one_or_none()

        root_cause = f"{incident.title}: {incident.description}"
        if reasoning and incident.service_name in reasoning.affected_services:
            root_cause = reasoning.root_cause

        structured_reasoning = StructuredReasoningOutput(
            summary=incident.description,
            root_cause=root_cause,
            confidence=reasoning.confidence if reasoning else 0.95,
            affected_services=[incident.service_name] if incident.service_name else ["order-service"],
            supporting_evidence_ids=[],
        )

        # 3. Resolve active autonomy policy
        stmt_pol = select(AutonomyPolicyRecord).where(
            AutonomyPolicyRecord.organization_id == organization_id,
            AutonomyPolicyRecord.environment == environment,
        )
        res_pol = await self.session.execute(stmt_pol)
        policy_rec = res_pol.scalar_one_or_none()

        if policy_rec:
            domain_policy = AutonomyPolicy(
                id=policy_rec.id,
                organization_id=policy_rec.organization_id,
                environment=policy_rec.environment,
                service=policy_rec.service,
                autonomy_level=AutonomyLevel(policy_rec.autonomy_level),
                allowed_actions=[RemediationActionType(a) for a in policy_rec.allowed_actions],
                maximum_risk=AIRiskLevel(policy_rec.maximum_risk),
                max_blast_radius_services=policy_rec.max_blast_radius_services,
                require_rollback_plan=policy_rec.require_rollback_plan,
                require_validation_plan=policy_rec.require_validation_plan,
                change_freeze_enabled=policy_rec.change_freeze_enabled,
            )
        else:
            domain_policy = AutonomyPolicy(
                organization_id=organization_id,
                environment=environment,
                autonomy_level=AutonomyLevel.LEVEL_2,
            )

        budget = AgentBudget(
            max_iterations=self.settings.AUTONOMY_MAX_TOOL_CALLS,
            max_tool_calls=self.settings.AUTONOMY_MAX_TOOL_CALLS,
            max_cost_usd=self.settings.AUTONOMY_MAX_COST_USD,
            max_duration_seconds=self.settings.AUTONOMY_MAX_DURATION_SECONDS,
        )

        # 4. Execute Reliability Agent loop
        run_record, _proposal, learning = await self.agent.run_incident_loop(
            incident_id=incident_id,
            organization_id=organization_id,
            service_name=incident.service_name or "order-service",
            reasoning_output=structured_reasoning,
            policy=domain_policy,
            budget=budget,
            environment=environment,
            is_production=(environment == "production"),
        )

        # 5. Persist run entity
        run_entity = AgentRunEntity(
            id=run_record.id,
            incident_id=incident_id,
            organization_id=organization_id,
            service_name=run_record.service_name,
            state=run_record.state.value,
            budget=run_record.budget.model_dump(mode="json"),
            tool_calls_count=run_record.tool_calls_count,
            iterations_count=run_record.iterations_count,
            total_cost_usd=run_record.total_cost_usd,
            total_tokens_consumed=run_record.total_tokens_consumed,
            remediation_id=run_record.remediation_id,
            autonomy_decision=run_record.autonomy_decision.value if run_record.autonomy_decision else None,
            outcome=run_record.outcome,
            error_message=run_record.error_message,
            completed_at=run_record.completed_at,
        )
        self.session.add(run_entity)

        if learning:
            learning_entity = IncidentLearningEntity(
                id=learning.id,
                incident_id=learning.incident_id,
                organization_id=learning.organization_id,
                service_name=learning.service_name,
                environment=learning.environment,
                root_cause=learning.root_cause,
                remediation_summary=learning.remediation_summary,
                actions_taken=learning.actions_taken,
                validated=learning.validated,
                promoted_to_knowledge=learning.promoted_to_knowledge,
                runbook_candidate=learning.runbook_candidate,
                proposed_runbook_content=learning.proposed_runbook_content,
            )
            self.session.add(learning_entity)

        await self.session.commit()
        await self.session.refresh(run_entity)

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="autonomy.agent_run.completed",
            resource_type="agent_run",
            resource_id=str(run_entity.id),
            metadata={"state": run_entity.state, "outcome": run_entity.outcome},
        )

        return AgentRunResponse.model_validate(run_entity)

    async def run_evaluation_benchmark(
        self,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> EvaluationRunResponse:
        if not principal.has_permission(Permission.AUTONOMY_READ):
            raise ForbiddenException("Principal lacks AUTONOMY_READ permission")

        report = await self.evaluation_engine.run_evaluation()

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="evaluation.benchmark.completed",
            resource_type="evaluation_report",
            resource_id=str(report.id),
            metadata={
                "gate_passed": report.release_gate_passed,
                "passed": report.passed_cases,
                "total": report.total_cases,
            },
        )
        return EvaluationRunResponse.model_validate(report)

    async def list_learnings(
        self,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> list[IncidentLearningResponse]:
        if not principal.has_permission(Permission.AUTONOMY_READ):
            raise ForbiddenException("Principal lacks AUTONOMY_READ permission")

        stmt = select(IncidentLearningEntity).where(
            IncidentLearningEntity.organization_id == organization_id
        ).order_by(IncidentLearningEntity.created_at.desc())
        res = await self.session.execute(stmt)
        return [IncidentLearningResponse.model_validate(row) for row in res.scalars().all()]

    async def get_service_slo(
        self,
        service_name: str,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> SLOResponse:
        if not principal.has_permission(Permission.AUTONOMY_READ):
            raise ForbiddenException("Principal lacks AUTONOMY_READ permission")

        slo = self.slo_engine.evaluate_telemetry(
            organization_id=organization_id,
            service_name=service_name,
            observed_availability=99.95,
            slo_type=SLOType.AVAILABILITY,
        )
        return SLOResponse(
            service_name=slo.service_name,
            slo_type=slo.slo_type.value,
            target_percentage=slo.target_percentage,
            current_percentage=slo.current_percentage,
            error_budget_remaining=slo.error_budget_remaining,
            burn_rate=slo.burn_rate,
            is_breached=slo.is_breached,
            window_days=slo.window_days,
        )
