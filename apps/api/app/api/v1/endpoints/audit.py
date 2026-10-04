from uuid import UUID

from fastapi import APIRouter, Depends, Query

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import (
    get_audit_service,
    require_tenant_context,
)
from apps.api.app.schemas.domain import AuditEventResponse
from apps.api.app.services.tenant import AuditService
from packages.security.rbac import AuthenticatedPrincipal

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("", response_model=list[AuditEventResponse])
async def list_audit_events(
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    audit_service: AuditService = Depends(get_audit_service),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> list[AuditEventResponse]:
    """List append-only audit events scoped strictly to the organization tenant."""
    events = await audit_service.list_audit_events(
        organization_id=org_id,
        principal=principal,
        limit=limit,
        offset=offset,
    )
    return [AuditEventResponse.model_validate(e) for e in events]
