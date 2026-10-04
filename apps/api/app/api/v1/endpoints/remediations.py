"""Phase 6 Remediation REST API Endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import (
    get_db_session,
    require_tenant_context,
)
from apps.api.app.schemas.domain import (
    PreflightResponse,
    RemediationApprovalRequest,
    RemediationApprovalResponse,
    RemediationCreateRequest,
    RemediationExecutionResponse,
    RemediationProposalResponse,
    RemediationRejectRequest,
)
from apps.api.app.services.remediation import RemediationService
from packages.security.rbac import AuthenticatedPrincipal

router = APIRouter(tags=["AI Remediation"])


@router.post(
    "/incidents/{incident_id}/remediations",
    response_model=RemediationProposalResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_remediation(
    incident_id: UUID,
    payload: RemediationCreateRequest = RemediationCreateRequest(),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> RemediationProposalResponse:
    """Propose a structured AI remediation plan from the incident's root cause and evidence."""
    service = RemediationService(session)
    rem = await service.propose_remediation(
        incident_id=incident_id,
        organization_id=org_id,
        principal=principal,
        environment=payload.target_environment,
    )
    return RemediationProposalResponse.model_validate(rem)


@router.get("/remediations", response_model=list[RemediationProposalResponse])
async def list_remediations(
    limit: int = Query(50, ge=1, le=100),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[RemediationProposalResponse]:
    """List tenant-scoped remediation proposals."""
    service = RemediationService(session)
    remediations = await service.list_remediations(
        organization_id=org_id,
        principal=principal,
        limit=limit,
    )
    return [RemediationProposalResponse.model_validate(r) for r in remediations]


@router.get("/remediations/{remediation_id}", response_model=RemediationProposalResponse)
async def get_remediation(
    remediation_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> RemediationProposalResponse:
    """Get remediation proposal by ID."""
    service = RemediationService(session)
    rem = await service.get_remediation(
        remediation_id=remediation_id,
        organization_id=org_id,
        principal=principal,
    )
    return RemediationProposalResponse.model_validate(rem)


@router.post("/remediations/{remediation_id}/preflight", response_model=PreflightResponse)
async def preflight_remediation(
    remediation_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> PreflightResponse:
    """Run preflight validation on remediation proposal (targets, schema, rollback, approval)."""
    service = RemediationService(session)
    res = await service.preflight_remediation(
        remediation_id=remediation_id,
        organization_id=org_id,
        principal=principal,
    )
    return PreflightResponse(
        passed=res.passed,
        remediation_id=res.remediation_id,
        remediation_hash=res.remediation_hash,
        target_exists=res.target_exists,
        service_exists=res.service_exists,
        schema_valid=res.schema_valid,
        rollback_available=res.rollback_available,
        approval_valid=res.approval_valid,
        hash_intact=res.hash_intact,
        details=res.details,
        errors=res.errors,
    )


@router.post("/remediations/{remediation_id}/approve", response_model=RemediationApprovalResponse)
async def approve_remediation(
    remediation_id: UUID,
    payload: RemediationApprovalRequest = RemediationApprovalRequest(),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> RemediationApprovalResponse:
    """Explicit human approval of a remediation proposal with cryptographic hash binding."""
    service = RemediationService(session)
    approval = await service.approve_remediation(
        remediation_id=remediation_id,
        organization_id=org_id,
        principal=principal,
        reason=payload.reason,
    )
    return RemediationApprovalResponse.model_validate(approval)


@router.post("/remediations/{remediation_id}/reject", response_model=RemediationApprovalResponse)
async def reject_remediation(
    remediation_id: UUID,
    payload: RemediationRejectRequest,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> RemediationApprovalResponse:
    """Explicit human rejection of a remediation proposal."""
    service = RemediationService(session)
    approval = await service.reject_remediation(
        remediation_id=remediation_id,
        organization_id=org_id,
        principal=principal,
        reason=payload.reason,
    )
    return RemediationApprovalResponse.model_validate(approval)


@router.post("/remediations/{remediation_id}/execute", response_model=RemediationExecutionResponse)
async def execute_remediation(
    remediation_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> RemediationExecutionResponse:
    """Execute approved remediation in controlled sandbox, run post-validation, and auto-rollback on failure."""
    service = RemediationService(session)
    exec_record = await service.execute_remediation(
        remediation_id=remediation_id,
        organization_id=org_id,
        principal=principal,
    )
    return RemediationExecutionResponse.model_validate(exec_record)


@router.post("/remediations/{remediation_id}/rollback", response_model=RemediationExecutionResponse)
async def rollback_remediation(
    remediation_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> RemediationExecutionResponse:
    """Manual trigger to execute rollback plan for remediation."""
    service = RemediationService(session)
    exec_record = await service.rollback_remediation(
        remediation_id=remediation_id,
        organization_id=org_id,
        principal=principal,
    )
    return RemediationExecutionResponse.model_validate(exec_record)
