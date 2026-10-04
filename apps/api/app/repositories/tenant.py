from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.entities import AuditEvent, Organization, Project
from apps.api.app.repositories.base import BaseRepository


class OrganizationRepository(BaseRepository[Organization]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Organization, session)

    async def get_by_slug(self, slug: str) -> Organization | None:
        query = select(Organization).where(Organization.slug == slug)
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    async def list_all(self, limit: int = 50, offset: int = 0) -> Sequence[Organization]:
        query = select(Organization).limit(limit).offset(offset).order_by(Organization.created_at.desc())
        res = await self.session.execute(query)
        return res.scalars().all()


class ProjectRepository(BaseRepository[Project]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Project, session)

    async def get_by_id_and_org(self, project_id: UUID, organization_id: UUID) -> Project | None:
        """Enforce organization tenant isolation in SQL query."""
        query = select(Project).where(
            Project.id == project_id,
            Project.organization_id == organization_id,
        )
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    async def list_by_organization(
        self, organization_id: UUID, limit: int = 50, offset: int = 0
    ) -> Sequence[Project]:
        """Tenant-isolated project listing."""
        query = (
            select(Project)
            .where(Project.organization_id == organization_id)
            .limit(limit)
            .offset(offset)
            .order_by(Project.created_at.desc())
        )
        res = await self.session.execute(query)
        return res.scalars().all()

    async def get_by_slug_and_org(self, slug: str, organization_id: UUID) -> Project | None:
        query = select(Project).where(
            Project.slug == slug,
            Project.organization_id == organization_id,
        )
        res = await self.session.execute(query)
        return res.scalar_one_or_none()


class AuditRepository(BaseRepository[AuditEvent]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(AuditEvent, session)

    async def list_by_organization(
        self, organization_id: UUID, limit: int = 50, offset: int = 0
    ) -> Sequence[AuditEvent]:
        query = (
            select(AuditEvent)
            .where(AuditEvent.organization_id == organization_id)
            .limit(limit)
            .offset(offset)
            .order_by(AuditEvent.created_at.desc())
        )
        res = await self.session.execute(query)
        return res.scalars().all()
