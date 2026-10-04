from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from apps.api.app.core.security import get_current_principal
from apps.api.app.dependencies.core import (
    get_project_service,
    get_request_id,
    require_tenant_context,
)
from apps.api.app.schemas.domain import (
    ProjectCreate,
    ProjectResponse,
    ProjectUpdate,
)
from apps.api.app.services.tenant import ProjectService
from packages.security.rbac import AuthenticatedPrincipal

router = APIRouter(prefix="/projects", tags=["Projects"])


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreate,
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    project_service: ProjectService = Depends(get_project_service),
    request_id: str = Depends(get_request_id),
) -> ProjectResponse:
    """Create project within the tenant organization context."""
    project = await project_service.create_project(
        organization_id=org_id,
        dto=payload,
        principal=principal,
        request_id=request_id,
    )
    return ProjectResponse.model_validate(project)


@router.get("", response_model=list[ProjectResponse])
async def list_projects(
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    project_service: ProjectService = Depends(get_project_service),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> list[ProjectResponse]:
    """List projects strictly scoped to the tenant organization."""
    projects = await project_service.list_projects(
        organization_id=org_id,
        principal=principal,
        limit=limit,
        offset=offset,
    )
    return [ProjectResponse.model_validate(p) for p in projects]


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    project_service: ProjectService = Depends(get_project_service),
) -> ProjectResponse:
    """Get project by ID with strict tenant boundary enforcement."""
    project = await project_service.get_project(
        project_id=project_id,
        organization_id=org_id,
        principal=principal,
    )
    return ProjectResponse.model_validate(project)


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: UUID,
    payload: ProjectUpdate,
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    project_service: ProjectService = Depends(get_project_service),
    request_id: str = Depends(get_request_id),
) -> ProjectResponse:
    """Update project with strict tenant boundary enforcement."""
    project = await project_service.update_project(
        project_id=project_id,
        organization_id=org_id,
        dto=payload,
        principal=principal,
        request_id=request_id,
    )
    return ProjectResponse.model_validate(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: UUID,
    org_id: UUID = Depends(require_tenant_context),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    project_service: ProjectService = Depends(get_project_service),
    request_id: str = Depends(get_request_id),
) -> None:
    """Delete project with strict tenant boundary enforcement."""
    await project_service.delete_project(
        project_id=project_id,
        organization_id=org_id,
        principal=principal,
        request_id=request_id,
    )
