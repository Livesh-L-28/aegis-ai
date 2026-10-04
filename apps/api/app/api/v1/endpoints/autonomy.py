"""Phase 7 Autonomy, Agent Runtime & Continuous Evaluation Endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.security import AuthenticatedPrincipal, get_current_principal
from apps.api.app.dependencies.core import (
    get_db_session,
    require_tenant_context,
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
from apps.api.app.services.autonomy import AutonomyService

router = APIRouter(prefix="/autonomy", tags=["Phase 7 - Autonomy & Reliability Engine"])


@router.get("/status", response_model=AutonomyStatusResponse)
async def get_autonomy_status(
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> AutonomyStatusResponse:
    """Inspect current autonomy engine operational state, flags, circuit breaker, and limits."""
    service = AutonomyService(session)
    return await service.get_autonomy_status(org_id, principal)


@router.post("/kill-switch/disable", response_model=AutonomyStatusResponse)
async def trip_kill_switch(
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> AutonomyStatusResponse:
    """Emergency stop: Immediately halts all autonomous remediation execution."""
    service = AutonomyService(session)
    return await service.set_kill_switch(org_id, principal, enabled=True)


@router.post("/kill-switch/enable", response_model=AutonomyStatusResponse)
async def restore_kill_switch(
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> AutonomyStatusResponse:
    """Restores autonomous capabilities after emergency stop review."""
    service = AutonomyService(session)
    return await service.set_kill_switch(org_id, principal, enabled=False)


@router.post("/change-freeze", response_model=AutonomyStatusResponse)
async def set_change_freeze(
    enabled: bool = True,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> AutonomyStatusResponse:
    """Toggles global or tenant change freeze; in freeze mode, mutations are denied."""
    service = AutonomyService(session)
    return await service.set_change_freeze(org_id, principal, enabled=enabled)


@router.post("/policies", response_model=AutonomyPolicyResponse, status_code=status.HTTP_201_CREATED)
async def configure_autonomy_policy(
    request: AutonomyPolicyCreateRequest,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> AutonomyPolicyResponse:
    """Configures environment-specific bounded autonomy policies and allowlists."""
    service = AutonomyService(session)
    return await service.create_or_update_policy(org_id, principal, request)


@router.post("/incidents/{incident_id}/run-agent", response_model=AgentRunResponse)
async def run_reliability_agent(
    incident_id: UUID,
    environment: str = "production-sim",
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> AgentRunResponse:
    """Executes a bounded Reliability Agent loop to investigate, propose, and autonomously act."""
    service = AutonomyService(session)
    return await service.trigger_autonomous_agent(
        incident_id=incident_id,
        organization_id=org_id,
        principal=principal,
        environment=environment,
    )


@router.post("/evaluations/run", response_model=EvaluationRunResponse)
async def trigger_evaluation_benchmark(
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> EvaluationRunResponse:
    """Runs the golden benchmark evaluation suite and evaluates release gates."""
    service = AutonomyService(session)
    return await service.run_evaluation_benchmark(org_id, principal)


@router.get("/learnings", response_model=list[IncidentLearningResponse])
async def list_incident_learnings(
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[IncidentLearningResponse]:
    """Retrieves operational knowledge generated from validated autonomous incident resolutions."""
    service = AutonomyService(session)
    return await service.list_learnings(org_id, principal)


@router.get("/slo/{service_name}", response_model=SLOResponse)
async def get_service_slo(
    service_name: str,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> SLOResponse:
    """Evaluates service reliability SLO and error budget health."""
    service = AutonomyService(session)
    return await service.get_service_slo(service_name, org_id, principal)
