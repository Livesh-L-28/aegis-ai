from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import get_org_service, get_request_id
from apps.api.app.schemas.domain import OrganizationCreate, OrganizationResponse
from apps.api.app.services.tenant import OrganizationService
from packages.security.rbac import AuthenticatedPrincipal

router = APIRouter(prefix="/organizations", tags=["Organizations"])


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    org_service: OrganizationService = Depends(get_org_service),
    request_id: str = Depends(get_request_id),
) -> OrganizationResponse:
    """Create a new tenant organization."""
    org = await org_service.create_organization(
        dto=payload, principal=principal, request_id=request_id
    )
    return OrganizationResponse.model_validate(org)


@router.get("", response_model=list[OrganizationResponse])
async def list_organizations(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    org_service: OrganizationService = Depends(get_org_service),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> list[OrganizationResponse]:
    """List organizations."""
    orgs = await org_service.list_organizations(principal=principal, limit=limit, offset=offset)
    return [OrganizationResponse.model_validate(o) for o in orgs]


@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    organization_id: UUID,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    org_service: OrganizationService = Depends(get_org_service),
) -> OrganizationResponse:
    """Get single organization by UUID."""
    org = await org_service.get_organization(organization_id=organization_id, principal=principal)
    return OrganizationResponse.model_validate(org)
