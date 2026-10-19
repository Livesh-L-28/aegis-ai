"""Autonomous debugging orchestration service: executes deterministic evidence-grounded root-cause analysis."""

import time
from datetime import UTC, datetime
from typing import Any, ClassVar
from uuid import UUID

from apps.api.app.services.evidence_graph import EvidenceGraphService
from packages.intelligence.debugging.analyzer import RootCauseAnalyzer
from packages.intelligence.debugging.collector import DebuggingEvidenceCollector
from packages.intelligence.debugging.localizer import FailureLocalizer
from packages.intelligence.debugging.models import (
    DebuggingAnalysisRun,
    DebuggingAnalysisStatus,
    DebuggingIncidentInput,
    HypothesisVerdict,
)
from packages.intelligence.debugging.normalizer import IncidentNormalizer
from packages.intelligence.debugging.remediation_proposals import (
    FixProposalService,
    FixValidationService,
)
from packages.intelligence.debugging.verification import VerificationPlanner
from packages.intelligence.reasoning.provider import ReasoningModelProvider
from packages.logging.logger import get_logger
from packages.service_runtime.metrics import (
    AEGIS_DEBUGGING_ANALYSES_TOTAL,
    AEGIS_DEBUGGING_ANALYSIS_DURATION_SECONDS,
    AEGIS_DEBUGGING_HYPOTHESES_TOTAL,
    AEGIS_DEBUGGING_PROPOSALS_TOTAL,
)

logger = get_logger("aegis.intelligence.debugging")


class AutonomousDebuggingService:
    """Coordinates end-to-end failure ingestion, frame localization, evidence correlation,

    hypothesis ranking, safe verification planning, and minimal patch proposals.
    """

    _runs: ClassVar[dict[UUID, DebuggingAnalysisRun]] = {}

    def __init__(
        self,
        service: EvidenceGraphService,
        llm_provider: ReasoningModelProvider | None = None,
    ) -> None:
        self.service = service
        self.localizer = FailureLocalizer(service)
        self.collector = DebuggingEvidenceCollector(service)
        self.analyzer = RootCauseAnalyzer(llm_provider=llm_provider)

    async def start_analysis(
        self,
        organization_id: UUID,
        payload: DebuggingIncidentInput,
    ) -> DebuggingAnalysisRun:
        """Executes full autonomous debugging investigation with strict tenant isolation."""
        t0 = time.perf_counter()

        # 1. Normalize and sanitize incident input
        normalized = IncidentNormalizer.normalize(payload)

        run = DebuggingAnalysisRun(
            organization_id=organization_id,
            incident=normalized,
            status=DebuggingAnalysisStatus.RUNNING,
            started_at=datetime.now(UTC),
        )
        self._runs[run.id] = run

        try:
            # 2. Localize stack frames against indexed repository revision
            localized_frames = await self.localizer.localize_frames(
                organization_id=organization_id,
                repository_id=normalized.repository_id,
                commit_sha=normalized.commit_sha,
                frames=normalized.parsed_frames,
            )
            run.localized_frames = localized_frames

            # 3. Retrieve correlated technical evidence from Evidence Graph
            evidence = await self.collector.collect_evidence(
                organization_id=organization_id,
                incident=normalized,
                localized_frames=localized_frames,
            )
            run.correlated_evidence = evidence

            # 4. Generate competing root-cause hypotheses and rank them
            hypotheses = await self.analyzer.analyze_root_cause(
                incident=normalized,
                localized_frames=localized_frames,
                evidence=evidence,
            )
            run.hypotheses = hypotheses

            for h in hypotheses:
                AEGIS_DEBUGGING_HYPOTHESES_TOTAL.labels(verdict=h.verdict.value).inc()

            # Check if evidence was insufficient
            if hypotheses and hypotheses[0].verdict == HypothesisVerdict.INSUFFICIENT_EVIDENCE:
                run.status = DebuggingAnalysisStatus.INSUFFICIENT_EVIDENCE
                run.summary = "Investigation concluded: Insufficient evidence to establish verifiable root cause."
                run.completed_at = datetime.now(UTC)
                AEGIS_DEBUGGING_ANALYSES_TOTAL.labels(status="insufficient_evidence").inc()
                AEGIS_DEBUGGING_ANALYSIS_DURATION_SECONDS.observe(time.perf_counter() - t0)
                return run

            # 5. Generate safe verification plan
            verification_steps = VerificationPlanner.plan_verification(
                hypotheses=hypotheses,
                evidence=evidence,
            )
            run.verification_plan = verification_steps

            # 6. Generate minimal patch proposals for top hypotheses
            raw_proposals = FixProposalService.generate_proposals(
                hypotheses=hypotheses,
                localized_frames=localized_frames,
            )

            # 7. Layered validation on patch proposals
            validated_proposals = [
                FixValidationService.validate_proposal(p, localized_frames)
                for p in raw_proposals
            ]
            run.fix_proposals = validated_proposals

            for p in validated_proposals:
                AEGIS_DEBUGGING_PROPOSALS_TOTAL.labels(validation_status=p.validation_status.value).inc()

            # 8. Complete analysis run
            run.status = DebuggingAnalysisStatus.COMPLETED
            run.completed_at = datetime.now(UTC)
            top_title = hypotheses[0].title if hypotheses else "None"
            run.summary = (
                f"Completed autonomous debugging: Identified {len(hypotheses)} hypothesis(es). "
                f"Top root cause: {top_title}. {len(validated_proposals)} patch proposal(s) validated."
            )

            AEGIS_DEBUGGING_ANALYSES_TOTAL.labels(status="completed").inc()
            AEGIS_DEBUGGING_ANALYSIS_DURATION_SECONDS.observe(time.perf_counter() - t0)
            return run

        except Exception as exc:
            logger.error("Autonomous debugging analysis run %s failed: %s", run.id, exc)
            run.status = DebuggingAnalysisStatus.FAILED
            run.error_message = str(exc)
            run.completed_at = datetime.now(UTC)
            AEGIS_DEBUGGING_ANALYSES_TOTAL.labels(status="failed").inc()
            AEGIS_DEBUGGING_ANALYSIS_DURATION_SECONDS.observe(time.perf_counter() - t0)
            return run

    async def get_analysis_run(
        self,
        organization_id: UUID,
        analysis_id: UUID,
    ) -> DebuggingAnalysisRun | None:
        """Retrieves an analysis run strictly enforcing organization tenant boundary."""
        run = self._runs.get(analysis_id)
        if not run:
            return None
        if run.organization_id != organization_id:
            # Cross-tenant read access strictly forbidden; return None to yield 404
            return None
        return run

    async def cancel_analysis_run(
        self,
        organization_id: UUID,
        analysis_id: UUID,
    ) -> DebuggingAnalysisRun | None:
        """Cancels an ongoing analysis run."""
        run = await self.get_analysis_run(organization_id, analysis_id)
        if not run:
            return None
        if run.status in (DebuggingAnalysisStatus.PENDING, DebuggingAnalysisStatus.RUNNING):
            run.status = DebuggingAnalysisStatus.CANCELLED
            run.completed_at = datetime.now(UTC)
            run.summary = "Analysis cancelled by operator request."
            AEGIS_DEBUGGING_ANALYSES_TOTAL.labels(status="cancelled").inc()
        return run

    @classmethod
    def get_capabilities(cls) -> dict[str, Any]:
        """Returns structured metadata of debugging engine capabilities."""
        return {
            "supported_languages": ["python", "typescript", "javascript"],
            "stack_trace_formats": ["python_traceback", "nodejs_v8_trace", "structured_frames"],
            "supported_verdicts": [v.value for v in HypothesisVerdict],
            "verification_actions": ["RUN_TEST", "INSPECT_CONTRACT", "VALIDATE_CONFIG", "STATIC_CHECK"],
            "remediation_mode": "PROPOSAL_ONLY_UNIFIED_DIFF",
            "autonomous_patch_application": False,
            "secret_redaction_enabled": True,
        }
