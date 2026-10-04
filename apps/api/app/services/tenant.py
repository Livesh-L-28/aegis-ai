from collections.abc import Sequence
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.core.exceptions import (
    ConflictException,
    ForbiddenException,
    ResourceNotFoundException,
)
from apps.api.app.models.entities import AuditEvent, Organization, Project
from apps.api.app.repositories.tenant import (
    AuditRepository,
    OrganizationRepository,
    ProjectRepository,
)
from apps.api.app.schemas.domain import (
    OrganizationCreate,
    ProjectCreate,
    ProjectUpdate,
)
from packages.events.contracts import EventType
from packages.security.rbac import AuthenticatedPrincipal, Permission


class AuditService:
    """Append-only audit event logging service."""

    def __init__(self, session: AsyncSession) -> None:
        self.repo = AuditRepository(session)

    async def log_event(
        self,
        organization_id: UUID,
        actor_user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        request_id: str | None = None,
        metadata: dict | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            event_metadata=metadata or {},
        )
        return await self.repo.create(event)

    async def list_audit_events(
        self,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[AuditEvent]:
        if not principal.has_permission(Permission.AUDIT_READ):
            raise ForbiddenException("Permission 'audit:read' required")
        return await self.repo.list_by_organization(organization_id, limit, offset)


class OrganizationService:
    """Service handling multi-tenant Organization operations."""

    def __init__(self, session: AsyncSession, audit_service: AuditService) -> None:
        self.repo = OrganizationRepository(session)
        self.audit_service = audit_service

    async def create_organization(
        self,
        dto: OrganizationCreate,
        principal: AuthenticatedPrincipal,
        request_id: str | None = None,
    ) -> Organization:
        if not principal.has_permission(Permission.ORG_WRITE):
            raise ForbiddenException("Permission 'organization:write' required")

        existing = await self.repo.get_by_slug(dto.slug)
        if existing:
            raise ConflictException(f"Organization with slug '{dto.slug}' already exists")

        org = Organization(name=dto.name, slug=dto.slug, description=dto.description)
        created = await self.repo.create(org)

        await self.audit_service.log_event(
            organization_id=created.id,
            actor_user_id=principal.user_id,
            action=EventType.ORG_CREATED.value,
            resource_type="organization",
            resource_id=str(created.id),
            request_id=request_id,
            metadata={"slug": created.slug, "name": created.name},
        )
        return created

    async def get_organization(
        self, organization_id: UUID, principal: AuthenticatedPrincipal
    ) -> Organization:
        if not principal.has_permission(Permission.ORG_READ):
            raise ForbiddenException("Permission 'organization:read' required")
        org = await self.repo.get_by_id(organization_id)
        if not org:
            raise ResourceNotFoundException("Organization", organization_id)
        return org

    async def list_organizations(
        self, principal: AuthenticatedPrincipal, limit: int = 50, offset: int = 0
    ) -> Sequence[Organization]:
        if not principal.has_permission(Permission.ORG_READ):
            raise ForbiddenException("Permission 'organization:read' required")
        return await self.repo.list_all(limit=limit, offset=offset)


class ProjectService:
    """Tenant-enforced Project service."""

    def __init__(self, session: AsyncSession, audit_service: AuditService) -> None:
        self.repo = ProjectRepository(session)
        self.audit_service = audit_service

    async def create_project(
        self,
        organization_id: UUID,
        dto: ProjectCreate,
        principal: AuthenticatedPrincipal,
        request_id: str | None = None,
    ) -> Project:
        if not principal.has_permission(Permission.PROJECT_WRITE):
            raise ForbiddenException("Permission 'project:write' required")

        existing = await self.repo.get_by_slug_and_org(dto.slug, organization_id)
        if existing:
            raise ConflictException(f"Project with slug '{dto.slug}' already exists in organization")

        project = Project(
            organization_id=organization_id,
            name=dto.name,
            slug=dto.slug,
            description=dto.description,
        )
        created = await self.repo.create(project)

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action=EventType.PROJECT_CREATED.value,
            resource_type="project",
            resource_id=str(created.id),
            request_id=request_id,
            metadata={"slug": created.slug, "name": created.name},
        )
        return created

    async def get_project(
        self,
        project_id: UUID,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
    ) -> Project:
        if not principal.has_permission(Permission.PROJECT_READ):
            raise ForbiddenException("Permission 'project:read' required")

        # Explicit tenant boundary query
        project = await self.repo.get_by_id_and_org(project_id, organization_id)
        if not project:
            raise ResourceNotFoundException("Project", project_id)
        return project

    async def list_projects(
        self,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[Project]:
        if not principal.has_permission(Permission.PROJECT_READ):
            raise ForbiddenException("Permission 'project:read' required")

        return await self.repo.list_by_organization(organization_id, limit=limit, offset=offset)

    async def update_project(
        self,
        project_id: UUID,
        organization_id: UUID,
        dto: ProjectUpdate,
        principal: AuthenticatedPrincipal,
        request_id: str | None = None,
    ) -> Project:
        if not principal.has_permission(Permission.PROJECT_WRITE):
            raise ForbiddenException("Permission 'project:write' required")

        project = await self.get_project(project_id, organization_id, principal)
        if dto.name is not None:
            project.name = dto.name
        if dto.description is not None:
            project.description = dto.description

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action=EventType.PROJECT_UPDATED.value,
            resource_type="project",
            resource_id=str(project.id),
            request_id=request_id,
            metadata={"name": project.name},
        )
        return project

    async def delete_project(
        self,
        project_id: UUID,
        organization_id: UUID,
        principal: AuthenticatedPrincipal,
        request_id: str | None = None,
    ) -> None:
        if not principal.has_permission(Permission.PROJECT_DELETE):
            raise ForbiddenException("Permission 'project:delete' required")

        project = await self.get_project(project_id, organization_id, principal)
        await self.repo.delete(project)

        await self.audit_service.log_event(
            organization_id=organization_id,
            actor_user_id=principal.user_id,
            action=EventType.PROJECT_DELETED.value,
            resource_type="project",
            resource_id=str(project_id),
            request_id=request_id,
        )
