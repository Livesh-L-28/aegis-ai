"""Application service coordinating code review execution, background tasks, and persistence."""

from collections.abc import Sequence
from typing import ClassVar
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.app.models.entities import ReviewFindingEntity, ReviewSessionEntity
from apps.api.app.repositories.review import ReviewFindingRepository, ReviewSessionRepository
from apps.api.app.schemas.domain import ReviewCreateRequest
from packages.logging.logger import get_logger
from packages.review.domain.models import ReviewReport, ReviewStatus
from packages.review.engine import LocalReviewEngine, ReviewCancelledException, ReviewConfig

logger = get_logger("aegis.services.review")


class CodeReviewService:
    """Service orchestrating code review lifecycle, tenant-isolated persistence, and execution."""

    # Tenant-scoped cooperative cancellation registry: (session_id, organization_id) -> bool
    _active_cancellations: ClassVar[dict[tuple[UUID, UUID], bool]] = {}

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.session_repo = ReviewSessionRepository(session)
        self.finding_repo = ReviewFindingRepository(session)

    @classmethod
    def signal_cancellation(cls, session_id: UUID, organization_id: UUID) -> None:
        """Signals in-memory cooperative cancellation for a specific tenant-scoped review."""
        cls._active_cancellations[(session_id, organization_id)] = True

    @classmethod
    def is_cancelled(cls, session_id: UUID, organization_id: UUID) -> bool:
        """Checks whether cancellation has been requested for a specific tenant-scoped review."""
        return cls._active_cancellations.get((session_id, organization_id), False)

    @classmethod
    def clear_cancellation(cls, session_id: UUID, organization_id: UUID) -> None:
        """Cleans up the in-memory cancellation tracking token."""
        cls._active_cancellations.pop((session_id, organization_id), None)

    async def create_review_session(
        self,
        organization_id: UUID,
        payload: ReviewCreateRequest,
    ) -> ReviewSessionEntity:
        """Initializes a new review session in PENDING state."""
        entity = ReviewSessionEntity(
            organization_id=organization_id,
            project_id=payload.project_id,
            repository_name=payload.repository_name,
            review_type="API",
            base_commit=payload.base_commit,
            head_commit=payload.head_commit,
            status=ReviewStatus.PENDING.value,
            review_metadata=payload.metadata,
        )
        created = await self.session_repo.create(entity)
        return created

    async def execute_review(
        self,
        session_id: UUID,
        organization_id: UUID,
        diff_text: str,
        enable_ai: bool = False,
    ) -> ReviewSessionEntity:
        """Executes review analysis and persists findings with cooperative cancellation checks."""
        session_entity = await self.session_repo.get_by_id_and_org(session_id, organization_id)
        if not session_entity:
            raise ValueError(f"Review session {session_id} not found")

        # 1. Early cancellation check (before execution begins)
        if (
            self.is_cancelled(session_id, organization_id)
            or session_entity.status == ReviewStatus.CANCELLED.value
        ):
            logger.info("Skipping execution of cancelled review session %s", session_id)
            session_entity.status = ReviewStatus.CANCELLED.value
            await self.session_repo.update(session_entity)
            self.clear_cancellation(session_id, organization_id)
            return session_entity

        session_entity.status = ReviewStatus.RUNNING.value
        await self.session_repo.update(session_entity)

        config = ReviewConfig(enable_ai_review=enable_ai)
        engine = LocalReviewEngine(repo_root=".", config=config)

        def check_cancelled() -> bool:
            return self.is_cancelled(session_id, organization_id)

        try:
            report: ReviewReport = await engine.review_diff_async(
                diff_text=diff_text,
                enable_ai=enable_ai,
                cancellation_token=check_cancelled,
            )

            # 2. Intermediate cancellation check (before persisting findings)
            refreshed = await self.session_repo.get_by_id_and_org(session_id, organization_id)
            if (
                self.is_cancelled(session_id, organization_id)
                or (refreshed and refreshed.status == ReviewStatus.CANCELLED.value)
            ):
                logger.info("Review %s cancelled mid-flight; discarding unpersisted findings", session_id)
                if refreshed:
                    refreshed.status = ReviewStatus.CANCELLED.value
                    await self.session_repo.update(refreshed)
                    self.clear_cancellation(session_id, organization_id)
                    return refreshed
                session_entity.status = ReviewStatus.CANCELLED.value
                self.clear_cancellation(session_id, organization_id)
                return session_entity

            # Persist findings
            finding_entities: list[ReviewFindingEntity] = []
            for f in report.findings:
                fe = ReviewFindingEntity(
                    review_id=session_id,
                    organization_id=organization_id,
                    file_path=f.location.file_path,
                    start_line=f.location.start_line,
                    end_line=f.location.end_line or f.location.start_line,
                    rule_id=f.rule_id,
                    title=f.title,
                    message=f.message,
                    severity=f.severity.value,
                    category=f.category.value,
                    origin=f.origin.value,
                    confidence=f.confidence,
                    technical_evidence=f.technical_evidence,
                    suggestion=f.suggestion,
                    deduplication_hash=f.deduplication_hash,
                    tool_name=f.tool_name,
                    finding_metadata=f.metadata,
                )
                finding_entities.append(fe)

            await self.finding_repo.add_all_findings(finding_entities)

            # 3. Near-completion check (ensure cancelled state is never overwritten)
            final_check = await self.session_repo.get_by_id_and_org(session_id, organization_id)
            if (
                self.is_cancelled(session_id, organization_id)
                or (final_check and final_check.status == ReviewStatus.CANCELLED.value)
            ):
                if final_check:
                    final_check.status = ReviewStatus.CANCELLED.value
                    await self.session_repo.update(final_check)
                    self.clear_cancellation(session_id, organization_id)
                    return final_check
                session_entity.status = ReviewStatus.CANCELLED.value
                self.clear_cancellation(session_id, organization_id)
                return session_entity

            session_entity.status = ReviewStatus.COMPLETED.value
            summary_msg = f"Completed review: {len(report.findings)} findings across {len(report.files_reviewed)} files."
            session_entity.summary = summary_msg
            session_entity.total_findings = len(report.findings)
            session_entity.execution_time_seconds = report.execution_time_seconds
            await self.session_repo.update(session_entity)
            self.clear_cancellation(session_id, organization_id)
            return session_entity

        except ReviewCancelledException:
            logger.info("Review session %s halted via cooperative cancellation token.", session_id)
            refreshed = await self.session_repo.get_by_id_and_org(session_id, organization_id)
            target = refreshed or session_entity
            target.status = ReviewStatus.CANCELLED.value
            await self.session_repo.update(target)
            self.clear_cancellation(session_id, organization_id)
            return target

        except Exception as e:
            # Never overwrite a CANCELLED state with FAILED
            if (
                self.is_cancelled(session_id, organization_id)
                or session_entity.status == ReviewStatus.CANCELLED.value
            ):
                session_entity.status = ReviewStatus.CANCELLED.value
                await self.session_repo.update(session_entity)
                self.clear_cancellation(session_id, organization_id)
                return session_entity

            logger.error("Review session %s failed: %s", session_id, e)
            session_entity.status = ReviewStatus.FAILED.value
            session_entity.summary = f"Review failed: {e}"
            await self.session_repo.update(session_entity)
            self.clear_cancellation(session_id, organization_id)
            return session_entity

    async def get_session(
        self,
        session_id: UUID,
        organization_id: UUID,
    ) -> ReviewSessionEntity | None:
        return await self.session_repo.get_by_id_and_org(session_id, organization_id)

    async def cancel_session(
        self,
        session_id: UUID,
        organization_id: UUID,
        reason: str = "User requested cancellation",
    ) -> ReviewSessionEntity | None:
        """Cancels an in-flight review session cooperatively."""
        session = await self.session_repo.get_by_id_and_org(session_id, organization_id)
        if not session:
            return None
        self.signal_cancellation(session_id, organization_id)
        session.status = ReviewStatus.CANCELLED.value
        session.cancellation_reason = reason
        return await self.session_repo.update(session)

    async def list_findings(
        self,
        session_id: UUID,
        organization_id: UUID,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[ReviewFindingEntity]:
        return await self.finding_repo.list_by_review_session(
            review_id=session_id,
            organization_id=organization_id,
            severity=severity,
            category=category,
            limit=limit,
            offset=offset,
        )

    async def list_sessions(
        self,
        organization_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[ReviewSessionEntity]:
        return await self.session_repo.list_by_organization(organization_id, limit, offset)
