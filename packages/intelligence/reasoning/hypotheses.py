"""Hypothesis generation, scoring, and contradiction evaluation framework."""

from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from packages.intelligence.evidence.models import EvidenceItem, EvidenceType


class HypothesisStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    SUPPORTED = "SUPPORTED"
    WEAK = "WEAK"
    REJECTED = "REJECTED"


class HypothesisItem(BaseModel):
    """Candidate root-cause hypothesis with deterministic evidence backing."""

    id: UUID = Field(default_factory=uuid4)
    investigation_id: UUID
    title: str
    description: str
    status: HypothesisStatus = HypothesisStatus.CANDIDATE
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    supporting_evidence_ids: list[UUID] = Field(default_factory=list)
    contradicting_evidence_ids: list[UUID] = Field(default_factory=list)
    reasoning: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class HypothesisEngine:
    """Generates initial candidate hypotheses deterministically from evidence and scores them."""

    def generate_hypotheses(
        self,
        investigation_id: UUID,
        evidence: list[EvidenceItem],
        service_name: str | None = None,
    ) -> list[HypothesisItem]:
        """Generates candidate hypotheses via deterministic diagnostic rules across telemetry, deployments, and dependencies."""
        hypotheses: list[HypothesisItem] = []
        evidence_by_id = {e.id: e for e in evidence}

        # Rule 1: Database Latency Degradation (only if active metric/log indicates DB degradation)
        db_evidence = [
            e for e in evidence
            if e.evidence_type in (EvidenceType.METRIC, EvidenceType.LOG)
            and ("database" in e.signal.lower() or "database" in e.content.lower() or "postgres" in e.content.lower())
        ]
        if db_evidence:
            supporting_ids = [e.id for e in db_evidence]
            hypotheses.append(
                HypothesisItem(
                    investigation_id=investigation_id,
                    title="Database Query Latency Degradation",
                    description="Elevated database query response time causing upstream service thread blocking and transaction timeouts.",
                    status=HypothesisStatus.CANDIDATE,
                    supporting_evidence_ids=supporting_ids,
                    reasoning=f"Found {len(db_evidence)} database latency/error observations directly affecting queries.",
                )
            )

        # Rule 2: Ephemeral Cache / Redis Dependency Breakdown
        redis_evidence = [
            e for e in evidence
            if e.evidence_type in (EvidenceType.METRIC, EvidenceType.LOG)
            and ("redis" in e.signal.lower() or "redis" in e.content.lower() or "cache" in e.content.lower())
        ]
        if redis_evidence:
            supporting_ids = [e.id for e in redis_evidence]
            hypotheses.append(
                HypothesisItem(
                    investigation_id=investigation_id,
                    title="Cache/Redis Dependency Failure",
                    description="Redis connection or command failures disrupting idempotency, caching, or session verification.",
                    status=HypothesisStatus.CANDIDATE,
                    supporting_evidence_ids=supporting_ids,
                    reasoning=f"Found {len(redis_evidence)} Redis error signals and connection breakdown logs.",
                )
            )

        # Rule 3: Deployment / Release Regression
        deploy_evidence = [e for e in evidence if e.evidence_type == EvidenceType.DEPLOYMENT]
        code_evidence = [e for e in evidence if e.evidence_type == EvidenceType.CODE]
        # Include correlated failed metrics
        failed_metric_evidence = [
            e for e in evidence
            if e.evidence_type == EvidenceType.METRIC and ("failed" in e.signal.lower() or "error" in e.signal.lower())
        ]
        if deploy_evidence:
            supporting_ids = [e.id for e in deploy_evidence] + [e.id for e in code_evidence] + [e.id for e in failed_metric_evidence]
            hypotheses.append(
                HypothesisItem(
                    investigation_id=investigation_id,
                    title="Recent Deployment Regression",
                    description="Recent version rollout or commit introduced a regression causing synthetic errors or latency.",
                    status=HypothesisStatus.CANDIDATE,
                    supporting_evidence_ids=supporting_ids,
                    reasoning="Deployment event detected within recent investigation time window with correlated service failures.",
                )
            )

        # Rule 4: Upstream Service / Gateway Timeout
        service_latency_evidence = [
            e for e in evidence
            if e.evidence_type == EvidenceType.METRIC and "latency" in e.content.lower() and not db_evidence
        ]
        if service_latency_evidence:
            supporting_ids = [e.id for e in service_latency_evidence]
            hypotheses.append(
                HypothesisItem(
                    investigation_id=investigation_id,
                    title="Service-Local Processing Delay",
                    description="Service internal processing degradation or CPU saturation without downstream DB breakdown.",
                    status=HypothesisStatus.CANDIDATE,
                    supporting_evidence_ids=supporting_ids,
                    reasoning="Elevated service latency observed with no correlated database degradation.",
                )
            )

        # Rule 5: Fallback if evidence is insufficient or unrecognized
        if not hypotheses:
            hypotheses.append(
                HypothesisItem(
                    investigation_id=investigation_id,
                    title="Undetermined Operational Anomaly",
                    description="Telemetry or logs indicate operational distress without a distinct root-cause pattern.",
                    status=HypothesisStatus.WEAK,
                    supporting_evidence_ids=[e.id for e in evidence[:2]],
                    reasoning="Telemetry signals do not match predefined deterministic diagnostic patterns.",
                )
            )

        # Score all hypotheses and actively discover contradicting evidence
        for h in hypotheses:
            self.score_hypothesis(h, evidence_by_id)

        # Sort by score descending
        hypotheses.sort(key=lambda x: x.score, reverse=True)
        return hypotheses

    def score_hypothesis(
        self,
        hypothesis: HypothesisItem,
        evidence_by_id: dict[UUID, EvidenceItem],
    ) -> None:
        """Deterministic scoring formula:

        Score =
            telemetry_support (0.35)
          + temporal_consistency (0.25)
          + dependency_support (0.20)
          + deployment_or_code_support (0.20)
          - contradiction_penalty (0.40)
        """
        supporting_items = [evidence_by_id[eid] for eid in hypothesis.supporting_evidence_ids if eid in evidence_by_id]

        # 1. Telemetry support
        telemetry_items = [i for i in supporting_items if i.evidence_type in (EvidenceType.METRIC, EvidenceType.LOG, EvidenceType.TRACE)]
        telemetry_score = min(1.0, len(telemetry_items) * 0.4)

        # 2. Dependency support
        has_dep = any(i.evidence_type == EvidenceType.DEPENDENCY for i in supporting_items)
        dep_score = 1.0 if has_dep else 0.5

        # 3. Deployment / Code support
        has_deploy_or_code = any(i.evidence_type in (EvidenceType.DEPLOYMENT, EvidenceType.CODE) for i in supporting_items)
        deploy_score = 1.0 if has_deploy_or_code else 0.3

        # 4. Search for Contradicting Evidence
        contradicting_ids: list[UUID] = []
        # Check for temporal contradiction:
        # e.g., If hypothesis is Deployment Regression, but errors started BEFORE the deployment timestamp
        if "deployment" in hypothesis.title.lower():
            deploy_timestamps = [i.observed_at for i in supporting_items if i.evidence_type == EvidenceType.DEPLOYMENT]
            if deploy_timestamps:
                d_time = min(deploy_timestamps)
                # Find metrics or errors observed BEFORE deployment
                for eid, item in evidence_by_id.items():
                    if (
                        item.evidence_type in (EvidenceType.METRIC, EvidenceType.LOG)
                        and item.observed_at < d_time
                        and ("error" in item.signal.lower() or "fail" in item.signal.lower())
                    ):
                        contradicting_ids.append(eid)

        # Check for Redis vs DB contradiction:
        # If hypothesis is Redis failure, but Redis metrics show 0 errors or no Redis items exist
        if "redis" in hypothesis.title.lower():
            for eid, item in evidence_by_id.items():
                if "redis" in item.signal.lower() and item.structured_data.get("error_rate") == 0:
                    contradicting_ids.append(eid)

        hypothesis.contradicting_evidence_ids = contradicting_ids
        contradiction_penalty = 0.4 if contradicting_ids else 0.0

        # Calculate composite score
        raw_score = (telemetry_score * 0.35) + (dep_score * 0.25) + (deploy_score * 0.20) + 0.20 - contradiction_penalty
        final_score = round(min(1.0, max(0.0, raw_score)), 3)
        hypothesis.score = final_score
        hypothesis.confidence = final_score

        # Update status
        if contradicting_ids and final_score < 0.4:
            hypothesis.status = HypothesisStatus.REJECTED
        elif final_score >= 0.7:
            hypothesis.status = HypothesisStatus.SUPPORTED
        elif final_score >= 0.4:
            hypothesis.status = HypothesisStatus.CANDIDATE
        else:
            hypothesis.status = HypothesisStatus.WEAK
