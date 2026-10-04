"""Phase 4 Incident and Investigation endpoints."""

from collections.abc import Sequence
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import (
    get_db_session,
    require_tenant_context,
)
from apps.api.app.repositories.investigation import (
    EvidenceRepository,
    HypothesisRepository,
    ReasoningResultRepository,
)
from apps.api.app.schemas.domain import (
    EvidenceResponse,
    HypothesisResponse,
    IncidentCreate,
    IncidentResponse,
    InvestigationCreate,
    InvestigationResponse,
    ReasoningResultResponse,
)
from apps.api.app.services.intelligence.investigation import InvestigationService
from packages.security.rbac import AuthenticatedPrincipal, Permission

router = APIRouter(tags=["Incidents & Investigations"])


# --- Incident Endpoints ---
@router.post(
    "/incidents",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_incident(
    payload: IncidentCreate,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> IncidentResponse:
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    incident = await service.create_incident(
        organization_id=org_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        service_name=payload.service_name,
        source=payload.source,
        metadata=payload.metadata,
        actor_id=principal.user_id,
    )
    return IncidentResponse.model_validate(incident)


@router.get(
    "/incidents",
    response_model=list[IncidentResponse],
)
async def list_incidents(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> Sequence[IncidentResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    incidents = await service.list_incidents(org_id, limit, offset)
    return [IncidentResponse.model_validate(i) for i in incidents]


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentResponse,
)
async def get_incident(
    incident_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> IncidentResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    incident = await service.get_incident(incident_id, org_id)
    return IncidentResponse.model_validate(incident)


# --- Investigation Endpoints ---
@router.post(
    "/incidents/{incident_id}/investigations",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_investigation(
    incident_id: UUID,
    payload: InvestigationCreate,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> InvestigationResponse:
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    inv = await service.create_investigation(
        incident_id=incident_id,
        organization_id=org_id,
        created_by=payload.created_by or principal.user_id,
        metadata=payload.metadata,
    )
    return InvestigationResponse.model_validate(inv)


@router.get(
    "/incidents/{incident_id}/investigations",
    response_model=list[InvestigationResponse],
)
async def list_incident_investigations(
    incident_id: UUID,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> Sequence[InvestigationResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    invs = await service.list_investigations_for_incident(incident_id, org_id, limit, offset)
    return [InvestigationResponse.model_validate(inv) for inv in invs]


@router.get(
    "/investigations/{investigation_id}",
    response_model=InvestigationResponse,
)
async def get_investigation(
    investigation_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> InvestigationResponse:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    inv = await service.get_investigation(investigation_id, org_id)
    return InvestigationResponse.model_validate(inv)


@router.post(
    "/investigations/{investigation_id}/run",
    response_model=InvestigationResponse,
)
async def run_investigation(
    investigation_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> InvestigationResponse:
    if not principal.has_permission(Permission.PROJECT_WRITE):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    try:
        inv = await service.run_investigation(
            investigation_id=investigation_id,
            organization_id=org_id,
            actor_id=principal.user_id,
        )
        return InvestigationResponse.model_validate(inv)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err)) from val_err
    except PermissionError as perm_err:
        raise HTTPException(status_code=403, detail=str(perm_err)) from perm_err



@router.get(
    "/investigations/{investigation_id}/evidence",
    response_model=list[EvidenceResponse],
)
async def get_investigation_evidence(
    investigation_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> Sequence[EvidenceResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    # Validate investigation belongs to organization
    await service.get_investigation(investigation_id, org_id)
    repo = EvidenceRepository(session)
    items = await repo.list_by_investigation(investigation_id, org_id)
    return [EvidenceResponse.model_validate(e) for e in items]


@router.get(
    "/investigations/{investigation_id}/hypotheses",
    response_model=list[HypothesisResponse],
)
async def get_investigation_hypotheses(
    investigation_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> Sequence[HypothesisResponse]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    await service.get_investigation(investigation_id, org_id)
    repo = HypothesisRepository(session)
    items = await repo.list_by_investigation(investigation_id)
    return [HypothesisResponse.model_validate(h) for h in items]


@router.get(
    "/investigations/{investigation_id}/result",
    response_model=ReasoningResultResponse | None,
)
async def get_investigation_result(
    investigation_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ReasoningResultResponse | None:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    await service.get_investigation(investigation_id, org_id)
    repo = ReasoningResultRepository(session)
    res = await repo.get_by_investigation(investigation_id)
    return ReasoningResultResponse.model_validate(res) if res else None


@router.get(
    "/investigations/{investigation_id}/timeline",
)
async def get_investigation_timeline(
    investigation_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    session: AsyncSession = Depends(get_db_session),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[dict]:
    if not principal.has_permission(Permission.PROJECT_READ):
        raise HTTPException(status_code=403, detail="Forbidden")
    service = InvestigationService(session)
    inv = await service.get_investigation(investigation_id, org_id)
    repo = EvidenceRepository(session)
    evidence_items = await repo.list_by_investigation(investigation_id, org_id)

    # Map DB evidence models to EvidenceItem for timeline generator
    from packages.intelligence.evidence.models import EvidenceItem, EvidenceSeverity, EvidenceType
    timeline_items = [
        EvidenceItem(
            id=ev.id,
            organization_id=ev.organization_id,
            investigation_id=ev.investigation_id,
            evidence_type=EvidenceType(ev.evidence_type),
            source=ev.source,
            service_name=ev.service_name,
            signal=ev.signal,
            observed_at=ev.observed_at,
            severity=EvidenceSeverity.MEDIUM,
            content=ev.content,
            structured_data=ev.structured_data,
            confidence=ev.confidence,
            relevance_score=ev.relevance_score,
            provenance=ev.provenance,
        )
        for ev in evidence_items
    ]
    timeline_entries = service.evidence_engine.construct_timeline(
        timeline_items,
        incident_title=inv.incident.title,
    )
    return [t.model_dump() for t in timeline_entries]

