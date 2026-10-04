"""Tenant-isolated repositories for Phase 4 Incidents, Investigations, Evidence, Hypotheses, and Reasoning."""

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.app.models.entities import (
    Evidence,
    Hypothesis,
    Incident,
    Investigation,
    ReasoningResult,
)
from apps.api.app.repositories.base import BaseRepository


class IncidentRepository(BaseRepository[Incident]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Incident, session)

    async def get_by_id_and_org(self, incident_id: UUID, organization_id: UUID) -> Incident | None:
        query = select(Incident).where(
            Incident.id == incident_id,
            Incident.organization_id == organization_id,
        )
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    async def list_by_organization(
        self, organization_id: UUID, limit: int = 50, offset: int = 0
    ) -> Sequence[Incident]:
        query = (
            select(Incident)
            .where(Incident.organization_id == organization_id)
            .limit(limit)
            .offset(offset)
            .order_by(Incident.created_at.desc())
        )
        res = await self.session.execute(query)
        return res.scalars().all()


class InvestigationRepository(BaseRepository[Investigation]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Investigation, session)

    async def get_by_id_and_org(
        self, investigation_id: UUID, organization_id: UUID
    ) -> Investigation | None:
        query = (
            select(Investigation)
            .where(
                Investigation.id == investigation_id,
                Investigation.organization_id == organization_id,
            )
            .options(
                selectinload(Investigation.incident),
                selectinload(Investigation.evidence_items),
                selectinload(Investigation.hypotheses),
                selectinload(Investigation.reasoning_result),
            )
        )
        res = await self.session.execute(query)
        return res.scalar_one_or_none()

    async def list_by_incident(
        self, incident_id: UUID, organization_id: UUID, limit: int = 50, offset: int = 0
    ) -> Sequence[Investigation]:
        query = (
            select(Investigation)
            .where(
                Investigation.incident_id == incident_id,
                Investigation.organization_id == organization_id,
            )
            .limit(limit)
            .offset(offset)
            .order_by(Investigation.created_at.desc())
        )
        res = await self.session.execute(query)
        return res.scalars().all()


class EvidenceRepository(BaseRepository[Evidence]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Evidence, session)

    async def list_by_investigation(
        self, investigation_id: UUID, organization_id: UUID
    ) -> Sequence[Evidence]:
        query = (
            select(Evidence)
            .where(
                Evidence.investigation_id == investigation_id,
                Evidence.organization_id == organization_id,
            )
            .order_by(Evidence.relevance_score.desc(), Evidence.observed_at.asc())
        )
        res = await self.session.execute(query)
        return res.scalars().all()


class HypothesisRepository(BaseRepository[Hypothesis]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(Hypothesis, session)

    async def list_by_investigation(
        self, investigation_id: UUID
    ) -> Sequence[Hypothesis]:
        query = (
            select(Hypothesis)
            .where(Hypothesis.investigation_id == investigation_id)
            .order_by(Hypothesis.score.desc())
        )
        res = await self.session.execute(query)
        return res.scalars().all()


class ReasoningResultRepository(BaseRepository[ReasoningResult]):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__(ReasoningResult, session)

    async def get_by_investigation(
        self, investigation_id: UUID
    ) -> ReasoningResult | None:
        query = select(ReasoningResult).where(ReasoningResult.investigation_id == investigation_id)
        res = await self.session.execute(query)
        return res.scalar_one_or_none()
