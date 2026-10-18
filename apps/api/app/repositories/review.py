"""Tenant-isolated repository for Code Review Sessions and Findings."""

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.app.models.entities import ReviewFindingEntity, ReviewSessionEntity
from apps.api.app.repositories.base import BaseRepository


class ReviewSessionRepository(BaseRepository[ReviewSessionEntity]):
    """Repository managing ReviewSession persistence with strict tenant boundaries."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(ReviewSessionEntity, session)

    async def get_by_id_and_org(
        self,
        session_id: UUID,
        organization_id: UUID,
        include_findings: bool = False,
    ) -> ReviewSessionEntity | None:
        query = select(ReviewSessionEntity).where(
            ReviewSessionEntity.id == session_id,
            ReviewSessionEntity.organization_id == organization_id,
        )
        if include_findings:
            query = query.options(selectinload(ReviewSessionEntity.findings))
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    async def list_by_organization(
        self,
        organization_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[ReviewSessionEntity]:
        query = (
            select(ReviewSessionEntity)
            .where(ReviewSessionEntity.organization_id == organization_id)
            .order_by(ReviewSessionEntity.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        res = await self.session.execute(query)
        return res.scalars().all()


class ReviewFindingRepository(BaseRepository[ReviewFindingEntity]):
    """Repository managing individual ReviewFinding entities with tenant filtering."""

    def __init__(self, session: AsyncSession) -> None:
        super().__init__(ReviewFindingEntity, session)

    async def add_all_findings(
        self,
        findings: list[ReviewFindingEntity],
    ) -> list[ReviewFindingEntity]:
        for finding in findings:
            self.session.add(finding)
        await self.session.flush()
        return findings

    async def list_by_review_session(
        self,
        review_id: UUID,
        organization_id: UUID,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[ReviewFindingEntity]:
        query = select(ReviewFindingEntity).where(
            ReviewFindingEntity.review_id == review_id,
            ReviewFindingEntity.organization_id == organization_id,
        )
        if severity:
            query = query.where(ReviewFindingEntity.severity == severity.upper())
        if category:
            query = query.where(ReviewFindingEntity.category == category.upper())

        query = (
            query.order_by(ReviewFindingEntity.start_line.asc())
            .limit(limit)
            .offset(offset)
        )
        res = await self.session.execute(query)
        return res.scalars().all()

    async def count_by_review_session(
        self,
        review_id: UUID,
        organization_id: UUID,
        severity: str | None = None,
        category: str | None = None,
    ) -> int:
        query = select(func.count(ReviewFindingEntity.id)).where(
            ReviewFindingEntity.review_id == review_id,
            ReviewFindingEntity.organization_id == organization_id,
        )
        if severity:
            query = query.where(ReviewFindingEntity.severity == severity.upper())
        if category:
            query = query.where(ReviewFindingEntity.category == category.upper())
        res = await self.session.execute(query)
        return res.scalar_one() or 0
