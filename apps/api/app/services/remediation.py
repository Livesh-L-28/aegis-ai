"""Phase 6 Remediation Application Service: Orchestrates planning, approval, preflight, execution, validation, rollback, and audit."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.exceptions import (
    ConflictException,
    ForbiddenException,
    ResourceNotFoundException,
    ValidationException,
)
from apps.api.app.models.entities import (
    Incident,
    ReasoningResult,
    Remediation,
    RemediationApprovalRecord,
    RemediationExecutionRecord,
)
from apps.api.app.services.tenant import AuditService
from packages.intelligence.reasoning.validator import StructuredReasoningOutput
from packages.remediation.domain.enums import (
    ApprovalDecision,
    ExecutionStatus,
    RemediationActionType,
    RemediationStatus,
)
from packages.remediation.domain.models import (
    PreflightResult,
    RemediationAction,
    RemediationApproval,
    RemediationProposal,
    RollbackPlan,
    ValidationPlan,
)
from packages.remediation.services.approval import (
    ApprovalWorkflowService,
    default_approval_service,
)
from packages.remediation.services.executor import (
    RemediationSandboxExecutor,
    default_sandbox_executor,
)
from packages.remediation.services.planner import (
    RemediationPlanner,
    default_remediation_planner,
)
from packages.remediation.services.preflight import (
    PreflightValidator,
    default_preflight_validator,
)
from packages.remediation.services.validator import (
    PostRemediationValidator,
    default_post_validator,
)
from packages.security.policy import AIPolicyEngine, AIRiskLevel, default_policy_engine
from packages.security.rbac import AuthenticatedPrincipal, Permission


class RemediationService:
    """Enterprise Remediation Service orchestrating Phase 6 controlled remediation workflows."""

    def __init__(
        self,
        session: AsyncSession,
        audit_service: AuditService | None = None,
        planner: RemediationPlanner = default_remediation_planner,
        approval_service: ApprovalWorkflowService = default_approval_service,
        preflight_validator: PreflightValidator = default_preflight_validator,
        executor: RemediationSandboxExecutor = default_sandbox_executor,
        post_validator: PostRemediationValidator = default_post_validator,
        policy_engine: AIPolicyEngine = default_policy_engine,
    ) -> None:
        self.session = session
        self.audit_service = audit_service or AuditService(session)
        self.planner = planner
        self.approval_service = approval_service
        self.preflight_validator = preflight_validator
        self.executor = executor
        self.post_validator = post_validator
        self.policy_engine = policy_engine

    async def propose_remediation(
        self,
        incident_id: UUID,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        environment: str = "production-sim",
    ) -> Remediation:
        """Generates a structured remediation proposal from the incident's latest verified reasoning result."""
        if not principal.has_permission(Permission.REMEDIATION_PROPOSE):
            raise ForbiddenException("Principal lacks REMEDIATION_PROPOSE permission")

        # 1. Fetch incident
        stmt = select(Incident).where(
            Incident.id == incident_id,
            Incident.organization_id == organization_id,
        )
        res = await self.session.execute(stmt)
        incident = res.scalar_one_or_none()
        if not incident:
            raise ResourceNotFoundException("Incident", str(incident_id))

        # 2. Fetch latest ReasoningResult
        stmt_reasoning = select(ReasoningResult).where(
            ReasoningResult.organization_id == organization_id,
        ).order_by(ReasoningResult.created_at.desc())
        res_reasoning = await self.session.execute(stmt_reasoning)
        reasoning = res_reasoning.scalar_one_or_none()

        root_cause = (
            reasoning.root_cause
            if reasoning
            else f"{incident.title}: {incident.description}"
        )
        evidence_ids = reasoning.supporting_evidence_ids if reasoning else []

        mock_reasoning_out = StructuredReasoningOutput(
            summary=reasoning.summary if reasoning else incident.description,
            root_cause=root_cause,
            confidence=reasoning.confidence if reasoning else 0.95,
            affected_services=reasoning.affected_services if reasoning else ([incident.service_name] if incident.service_name else []),
            supporting_evidence_ids=[],
        )

        # 3. Plan structured proposal
        proposal: RemediationProposal = self.planner.plan_remediation(
            incident_id=incident_id,
            organization_id=organization_id,
            service_name=incident.service_name or "order-service",
            reasoning_result=mock_reasoning_out,
            environment=environment,
            actor_id=principal.user_id,
        )

        # 4. Check policy
        policy_res = self.policy_engine.evaluate_remediation_proposal(
            risk_level=proposal.risk_level,
            environment=environment,
            has_approval=False,
        )
        if policy_res.risk_level == AIRiskLevel.CRITICAL:
            proposal.status = RemediationStatus.REJECTED

        # 5. Persist Remediation entity
        entity = Remediation(
            id=proposal.id,
            incident_id=proposal.incident_id,
            organization_id=proposal.organization_id,
            service_name=proposal.service_name,
            title=proposal.title,
            description=proposal.description,
            root_cause_reference=proposal.root_cause_reference,
            evidence_ids=[str(e) for e in evidence_ids],
            risk_level=proposal.risk_level.value,
            status=proposal.status.value,
            actions=[a.model_dump(mode="json") for a in proposal.actions],
            blast_radius=proposal.blast_radius.model_dump(mode="json"),
            validation_plan=proposal.validation_plan.model_dump(mode="json"),
            rollback_plan=proposal.rollback_plan.model_dump(mode="json"),
            remediation_hash=proposal.remediation_hash,
            created_by=proposal.created_by,
            expires_at=proposal.expires_at,
        )
        self.session.add(entity)
        await self.session.commit()
        await self.session.refresh(entity)

        # 6. Audit event
        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="remediation.proposed",
            resource_type="remediation",
            resource_id=str(entity.id),
            metadata={"risk_level": entity.risk_level, "hash": entity.remediation_hash},
        )

        return entity

    async def get_remediation(
        self,
        remediation_id: UUID,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> Remediation:
        if not principal.has_permission(Permission.REMEDIATION_READ):
            raise ForbiddenException("Principal lacks REMEDIATION_READ permission")

        stmt = select(Remediation).where(
            Remediation.id == remediation_id,
            Remediation.organization_id == organization_id,
        )
        res = await self.session.execute(stmt)
        rem = res.scalar_one_or_none()
        if not rem:
            raise ResourceNotFoundException("Remediation", str(remediation_id))
        return rem

    async def list_remediations(
        self,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        limit: int = 50,
    ) -> list[Remediation]:
        if not principal.has_permission(Permission.REMEDIATION_READ):
            raise ForbiddenException("Principal lacks REMEDIATION_READ permission")

        stmt = (
            select(Remediation)
            .where(Remediation.organization_id == organization_id)
            .order_by(Remediation.created_at.desc())
            .limit(limit)
        )
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def preflight_remediation(
        self,
        remediation_id: UUID,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> PreflightResult:
        rem = await self.get_remediation(remediation_id, organization_id, principal)
        proposal = self._to_domain_proposal(rem)

        # Find approval if exists
        stmt_app = select(RemediationApprovalRecord).where(
            RemediationApprovalRecord.remediation_id == remediation_id,
            RemediationApprovalRecord.decision == ApprovalDecision.APPROVED.value,
        ).order_by(RemediationApprovalRecord.created_at.desc())
        res_app = await self.session.execute(stmt_app)
        app_record = res_app.scalar_one_or_none()

        domain_app: RemediationApproval | None = None
        if app_record:
            domain_app = RemediationApproval(
                id=app_record.id,
                remediation_id=app_record.remediation_id,
                organization_id=app_record.organization_id,
                approver_id=app_record.approver_id,
                decision=ApprovalDecision(app_record.decision),
                reason=app_record.reason,
                policy_version=app_record.policy_version,
                remediation_hash=app_record.remediation_hash,
                created_at=app_record.created_at,
                expires_at=app_record.expires_at,
            )

        preflight = self.preflight_validator.validate_preflight(proposal, domain_app)

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="remediation.preflight.completed",
            resource_type="remediation",
            resource_id=str(rem.id),
            metadata={"passed": preflight.passed, "errors": preflight.errors},
        )
        return preflight

    async def approve_remediation(
        self,
        remediation_id: UUID,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        reason: str = "Authorized by on-call engineer following runbook verification",
    ) -> RemediationApprovalRecord:
        rem = await self.get_remediation(remediation_id, organization_id, principal)
        proposal = self._to_domain_proposal(rem)

        try:
            approval = self.approval_service.approve_proposal(
                proposal=proposal,
                principal=principal,
                reason=reason,
            )
        except PermissionError as e:
            raise ForbiddenException(str(e)) from e
        except ValueError as e:
            raise ValidationException(str(e)) from e

        # Update remediation status in DB
        rem.status = proposal.status.value
        rem.remediation_hash = proposal.remediation_hash

        # Persist approval
        app_record = RemediationApprovalRecord(
            id=approval.id,
            remediation_id=rem.id,
            organization_id=organization_id,
            approver_id=principal.user_id,
            decision=approval.decision.value,
            reason=approval.reason,
            policy_version=approval.policy_version,
            remediation_hash=approval.remediation_hash,
            expires_at=approval.expires_at,
        )
        self.session.add(app_record)
        await self.session.commit()
        await self.session.refresh(app_record)

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="remediation.approved",
            resource_type="remediation",
            resource_id=str(rem.id),
            metadata={"approver": principal.user_id, "hash": approval.remediation_hash},
        )
        return app_record

    async def reject_remediation(
        self,
        remediation_id: UUID,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        reason: str,
    ) -> RemediationApprovalRecord:
        rem = await self.get_remediation(remediation_id, organization_id, principal)
        proposal = self._to_domain_proposal(rem)

        try:
            approval = self.approval_service.reject_proposal(
                proposal=proposal,
                principal=principal,
                reason=reason,
            )
        except PermissionError as e:
            raise ForbiddenException(str(e)) from e
        except ValueError as e:
            raise ValidationException(str(e)) from e

        rem.status = proposal.status.value

        app_record = RemediationApprovalRecord(
            id=approval.id,
            remediation_id=rem.id,
            organization_id=organization_id,
            approver_id=principal.user_id,
            decision=approval.decision.value,
            reason=approval.reason,
            policy_version=approval.policy_version,
            remediation_hash=approval.remediation_hash,
            expires_at=approval.expires_at,
        )
        self.session.add(app_record)
        await self.session.commit()
        await self.session.refresh(app_record)

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="remediation.rejected",
            resource_type="remediation",
            resource_id=str(rem.id),
            metadata={"rejector": principal.user_id, "reason": reason},
        )
        return app_record

    async def execute_remediation(
        self,
        remediation_id: UUID,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        environment: str = "production-sim",
    ) -> RemediationExecutionRecord:
        """Executes approved remediation in sandbox, runs post-remediation validation, and triggers rollback on failure."""
        if not principal.has_permission(Permission.REMEDIATION_EXECUTE):
            raise ForbiddenException("Principal lacks REMEDIATION_EXECUTE permission")

        rem = await self.get_remediation(remediation_id, organization_id, principal)
        if rem.status not in (RemediationStatus.APPROVED.value, RemediationStatus.PREFLIGHT.value):
            raise ConflictException(f"Remediation is not in an executable state ({rem.status})")

        preflight = await self.preflight_remediation(remediation_id, organization_id, principal)
        if not preflight.passed:
            raise ConflictException(f"Preflight validation failed: {'; '.join(preflight.errors)}")

        proposal = self._to_domain_proposal(rem)

        # 1. Audit execution started
        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="remediation.execution.started",
            resource_type="remediation",
            resource_id=str(rem.id),
        )

        # 2. Execute via Sandbox Executor
        domain_exec = await self.executor.execute_proposal(
            proposal=proposal,
            preflight=preflight,
            executor_id=principal.user_id,
            environment=environment,
        )

        # 3. Post-remediation Validation
        val_passed = await self.post_validator.validate_remediation(proposal, domain_exec)

        # 4. Handle rollback on validation failure if high-risk
        if not val_passed:
            await self.audit_service.log_event(
                organization_id=organization_id,
                actor_user_id=principal.user_id,
                action="remediation.validation.failed",
                resource_type="remediation",
                resource_id=str(rem.id),
            )
            # Trigger automatic safe rollback
            rem.status = RemediationStatus.ROLLING_BACK.value
            rb_result = await self.executor.execute_rollback(proposal, environment)
            domain_exec.rollback_result = rb_result
            domain_exec.status = ExecutionStatus.ROLLED_BACK
            rem.status = RemediationStatus.ROLLED_BACK.value
            await self.audit_service.log_event(
                organization_id=organization_id,
                actor_user_id=principal.user_id,
                action="remediation.rollback.completed",
                resource_type="remediation",
                resource_id=str(rem.id),
            )
        else:
            rem.status = RemediationStatus.SUCCEEDED.value
            await self.audit_service.log_event(
                organization_id=organization_id,
                actor_user_id=principal.user_id,
                action="remediation.execution.completed",
                resource_type="remediation",
                resource_id=str(rem.id),
            )

        # 5. Persist Execution Record
        exec_entity = RemediationExecutionRecord(
            id=domain_exec.id,
            remediation_id=rem.id,
            organization_id=organization_id,
            attempt=domain_exec.attempt,
            executor_id=principal.user_id,
            environment=environment,
            target=proposal.service_name,
            status=domain_exec.status.value,
            started_at=domain_exec.started_at,
            completed_at=domain_exec.completed_at,
            preflight_result=preflight.model_dump(mode="json"),
            validation_result=domain_exec.validation_result,
            rollback_result=domain_exec.rollback_result,
            error=domain_exec.error,
        )
        self.session.add(exec_entity)
        await self.session.commit()
        await self.session.refresh(exec_entity)
        return exec_entity

    async def rollback_remediation(
        self,
        remediation_id: UUID,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        environment: str = "production-sim",
    ) -> RemediationExecutionRecord:
        """Manual explicit rollback endpoint."""
        if not principal.has_permission(Permission.REMEDIATION_EXECUTE):
            raise ForbiddenException("Principal lacks REMEDIATION_EXECUTE permission")

        rem = await self.get_remediation(remediation_id, organization_id, principal)
        proposal = self._to_domain_proposal(rem)

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="remediation.rollback.started",
            resource_type="remediation",
            resource_id=str(rem.id),
        )

        rb_result = await self.executor.execute_rollback(proposal, environment)
        rem.status = RemediationStatus.ROLLED_BACK.value

        exec_entity = RemediationExecutionRecord(
            remediation_id=rem.id,
            organization_id=organization_id,
            attempt=2,
            executor_id=principal.user_id,
            environment=environment,
            target=proposal.service_name,
            status=ExecutionStatus.ROLLED_BACK.value,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            preflight_result={},
            validation_result={"manual_rollback": True},
            rollback_result=rb_result,
        )
        self.session.add(exec_entity)
        await self.session.commit()
        await self.session.refresh(exec_entity)

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action="remediation.rollback.completed",
            resource_type="remediation",
            resource_id=str(rem.id),
        )
        return exec_entity

    def _to_domain_proposal(self, entity: Remediation) -> RemediationProposal:
        actions = [
            RemediationAction(
                action_type=RemediationActionType(a["action_type"]),
                target=a["target"],
                parameters=a.get("parameters", {}),
                risk_level=AIRiskLevel(a.get("risk_level", "MEDIUM")),
                validation_step=a.get("validation_step", ""),
                rollback_step=a.get("rollback_step", ""),
            )
            for a in entity.actions
        ]
        return RemediationProposal(
            id=entity.id,
            incident_id=entity.incident_id,
            organization_id=entity.organization_id,
            service_name=entity.service_name,
            title=entity.title,
            description=entity.description,
            root_cause_reference=entity.root_cause_reference,
            evidence_ids=entity.evidence_ids,
            risk_level=AIRiskLevel(entity.risk_level),
            status=RemediationStatus(entity.status),
            actions=actions,
            validation_plan=ValidationPlan(**entity.validation_plan),
            rollback_plan=RollbackPlan(**entity.rollback_plan),
            remediation_hash=entity.remediation_hash,
            created_by=entity.created_by,
            created_at=entity.created_at,
            expires_at=entity.expires_at,
        )
