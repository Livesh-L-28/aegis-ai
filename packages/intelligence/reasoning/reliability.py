"""AIReliabilityService: Telemetry, Costs, Hallucination Indicators, and Reliability Reporting."""

import time
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from packages.logging.logger import get_logger
from packages.reliability.adapter import (
    AIReliabilityEngine,
    default_reliability_engine,
)
from packages.reliability.domain import (
    ExecutionRecordDTO,
    ReliabilityDiagnosisResult,
    ReliabilityStatus,
)

logger = get_logger("aegis.intelligence.reliability")


class AIReliabilityMetrics(BaseModel):
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    firewall_blocked_requests: int = 0
    policy_denied_requests: int = 0
    grounding_failures: int = 0
    fallback_requests: int = 0
    avg_duration_ms: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_estimated_cost_usd: float = 0.0
    grounding_rate: float = 1.0
    availability_rate: float = 1.0
    safety_rate: float = 1.0
    overall_reliability_score: float = 1.0


class AIReliabilityService:
    """In-memory and persistent tracker for AI Trust and Reliability performance metrics,
    integrated with the standalone aireliability engine adapter."""

    def __init__(self, engine: AIReliabilityEngine | None = None) -> None:
        self._records: list[dict[str, Any]] = []
        self._engine: AIReliabilityEngine = engine or default_reliability_engine

    def record_execution(
        self,
        organization_id: UUID,
        operation: str,
        provider: str,
        model: str,
        duration_ms: float,
        status: str,  # "SUCCESS" | "FAILED" | "FIREWALL_BLOCKED" | "POLICY_DENIED" | "GROUNDING_FAILED"
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        did_fallback: bool = False,
        estimated_cost: float | None = None,
        claims_supported: int = 0,
        claims_total: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record an individual AI execution with cost, token, and safety metrics."""
        rec = {
            "organization_id": str(organization_id),
            "operation": operation,
            "provider": provider,
            "model": model,
            "duration_ms": duration_ms,
            "status": status,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "did_fallback": did_fallback,
            "estimated_cost": estimated_cost,
            "claims_supported": claims_supported,
            "claims_total": claims_total,
            "timestamp": time.time(),
            "metadata": metadata or {},
        }
        self._records.append(rec)
        return rec

    def compute_metrics(self, organization_id: UUID | None = None) -> AIReliabilityMetrics:
        """Decomposes AI Reliability across Availability, Grounding, Safety, Validity, and Performance."""
        records = [
            r for r in self._records
            if organization_id is None or r["organization_id"] == str(organization_id)
        ]
        total = len(records)
        if total == 0:
            return AIReliabilityMetrics()

        successful = sum(1 for r in records if r["status"] == "SUCCESS")
        firewall_blocked = sum(1 for r in records if r["status"] == "FIREWALL_BLOCKED")
        policy_denied = sum(1 for r in records if r["status"] == "POLICY_DENIED")
        grounding_failures = sum(1 for r in records if r["status"] == "GROUNDING_FAILED")
        failed = sum(1 for r in records if r["status"] in ("FAILED", "TIMEOUT"))
        fallbacks = sum(1 for r in records if r.get("did_fallback"))

        total_dur = sum(r["duration_ms"] for r in records)
        in_tokens = sum(r.get("input_tokens") or 0 for r in records)
        out_tokens = sum(r.get("output_tokens") or 0 for r in records)
        total_cost = sum(r.get("estimated_cost") or 0.0 for r in records)

        # Decomposed scores:
        # Availability: non-technical provider failures
        avail_rate = round(max(0.0, (total - failed) / total), 3)

        # Grounding rate: evaluated groundedness
        claims_sup = sum(r.get("claims_supported", 0) for r in records)
        claims_tot = sum(r.get("claims_total", 0) for r in records)
        ground_rate = round(claims_sup / claims_tot if claims_tot > 0 else (1.0 - (grounding_failures / total)), 3)

        # Safety rate: clean requests without malicious blocks
        safety_rate = round(1.0 - ((firewall_blocked + policy_denied) / total), 3)

        # Composite decomposable reliability score:
        # 40% Availability + 35% Grounding + 25% Safety
        composite_score = round((avail_rate * 0.40) + (ground_rate * 0.35) + (safety_rate * 0.25), 3)

        return AIReliabilityMetrics(
            total_requests=total,
            successful_requests=successful,
            failed_requests=failed,
            firewall_blocked_requests=firewall_blocked,
            policy_denied_requests=policy_denied,
            grounding_failures=grounding_failures,
            fallback_requests=fallbacks,
            avg_duration_ms=round(total_dur / total, 2),
            total_input_tokens=in_tokens,
            total_output_tokens=out_tokens,
            total_estimated_cost_usd=round(total_cost, 4),
            grounding_rate=ground_rate,
            availability_rate=avail_rate,
            safety_rate=safety_rate,
            overall_reliability_score=composite_score,
        )

    def get_summary(self, organization_id: UUID | None = None) -> Any:
        metrics = self.compute_metrics(organization_id=organization_id)
        records = [
            r for r in self._records
            if organization_id is None or r["organization_id"] == str(organization_id)
        ]

        class _Summary:
            def __init__(self, m: AIReliabilityMetrics, recs: list[dict[str, Any]]) -> None:
                self.total_requests = m.total_requests
                self.successful_requests = m.successful_requests
                self.failed_requests = m.failed_requests
                self.availability_rate = m.availability_rate
                self.grounding_rate = m.grounding_rate
                self.safety_rate = m.safety_rate
                self.reliability_score = m.overall_reliability_score
                self.avg_latency_ms = m.avg_duration_ms
                self.total_input_tokens = m.total_input_tokens
                self.total_output_tokens = m.total_output_tokens
                self.total_cost_usd = m.total_estimated_cost_usd
                self.hallucination_indicators = {
                    "unsupported_claims": sum(1 for r in recs if r.get("claims_total", 0) > r.get("claims_supported", 0)),
                    "invalid_evidence_references": sum(1 for r in recs if r["status"] == "GROUNDING_FAILED"),
                    "schema_violations": 0,
                    "missing_citations": sum(1 for r in recs if r.get("claims_total", 0) > 0 and r.get("claims_supported", 0) == 0),
                }
                self.score_breakdown = {
                    "availability_component": round(m.availability_rate * 0.40, 3),
                    "grounding_component": round(m.grounding_rate * 0.35, 3),
                    "safety_component": round(m.safety_rate * 0.25, 3),
                }

        return _Summary(metrics, records)

    def analyze_execution(self, record_dict: dict[str, Any]) -> ReliabilityDiagnosisResult:
        """Run deep root cause analysis on an execution record via the aireliability package."""
        status_map = {
            "SUCCESS": ReliabilityStatus.SUCCESS,
            "FAILED": ReliabilityStatus.FAILED,
            "TIMEOUT": ReliabilityStatus.TIMEOUT,
            "FIREWALL_BLOCKED": ReliabilityStatus.FIREWALL_BLOCKED,
            "POLICY_DENIED": ReliabilityStatus.POLICY_DENIED,
            "GROUNDING_FAILED": ReliabilityStatus.GROUNDING_FAILED,
        }
        status_val = status_map.get(record_dict.get("status", "FAILED"), ReliabilityStatus.FAILED)
        dto = ExecutionRecordDTO(
            organization_id=UUID(record_dict["organization_id"]) if isinstance(record_dict["organization_id"], str) else record_dict["organization_id"],
            service_name=record_dict.get("service_name", "ai-service"),
            operation=record_dict.get("operation", "reasoning"),
            provider=record_dict.get("provider", "unknown"),
            model=record_dict.get("model", "unknown"),
            duration_ms=float(record_dict.get("duration_ms", 0.0)),
            status=status_val,
            input_tokens=record_dict.get("input_tokens"),
            output_tokens=record_dict.get("output_tokens"),
            did_fallback=bool(record_dict.get("did_fallback", False)),
            estimated_cost=record_dict.get("estimated_cost"),
            claims_supported=int(record_dict.get("claims_supported", 0)),
            claims_total=int(record_dict.get("claims_total", 0)),
            prompt_text=record_dict.get("metadata", {}).get("prompt"),
            output_text=record_dict.get("metadata", {}).get("output"),
            error_message=record_dict.get("metadata", {}).get("error"),
            metadata=record_dict.get("metadata", {}),
        )
        return self._engine.analyze_execution_trace(dto)

    def health_status(self) -> dict[str, Any]:
        """Health and version reporting for the underlying AI reliability engine."""
        return self._engine.health_status()

    @classmethod
    def get_default_service(cls) -> "AIReliabilityService":
        return default_reliability_service


default_reliability_service = AIReliabilityService()

