"""Production Adapter integrating the original standalone aireliability package (0.1.0) into AEGIS."""

import time
from typing import Any

from packages.logging.logger import get_logger
from packages.reliability.domain import (
    AIReliabilityEngine,
    ExecutionRecordDTO,
    ReliabilityDiagnosisResult,
    ReliabilityEvaluationResult,
    ReliabilityStatus,
)
from packages.service_runtime.metrics import (
    AIRELIABILITY_ANALYSIS_DURATION_SECONDS,
    AIRELIABILITY_ANALYSIS_FAILED_TOTAL,
    AIRELIABILITY_ANALYSIS_TOTAL,
)

logger = get_logger("aegis.reliability.adapter")

try:
    import aireliability
    from aireliability.core.models import (
        ExecutionStatus as AIRelExecutionStatus,
    )
    from aireliability.core.models import (
        ExecutionTrace as AIRelExecutionTrace,
    )
    from aireliability.core.models import (
        FailureReport as AIRelFailureReport,
    )
    from aireliability.core.models import (
        FailureSeverity as AIRelFailureSeverity,
    )
    from aireliability.core.models import (
        StepType as AIRelStepType,
    )
    from aireliability.core.models import (
        TraceStep as AIRelTraceStep,
    )
    from aireliability.diagnosis.analyzer import (
        RootCauseAnalyzer as AIRelRootCauseAnalyzer,
    )
    from aireliability.evaluation import (
        MaxLatency as AIRelMaxLatency,
    )
    from aireliability.evaluation import (
        OutputContains as AIRelOutputContains,
    )
    _AIRELIABILITY_AVAILABLE = True
except ImportError:
    _AIRELIABILITY_AVAILABLE = False
    aireliability = None  # type: ignore[assignment]
    AIRelExecutionStatus = None  # type: ignore[assignment, misc]
    AIRelExecutionTrace = None  # type: ignore[assignment, misc]
    AIRelFailureReport = None  # type: ignore[assignment, misc]
    AIRelFailureSeverity = None  # type: ignore[assignment, misc]
    AIRelStepType = None  # type: ignore[assignment, misc]
    AIRelTraceStep = None  # type: ignore[assignment, misc]
    AIRelRootCauseAnalyzer = None  # type: ignore[assignment, misc]
    AIRelMaxLatency = None  # type: ignore[assignment, misc]
    AIRelOutputContains = None  # type: ignore[assignment, misc]


class AIReliabilityPackageAdapter(AIReliabilityEngine):
    """Adapter bridging AEGIS AI telemetry, investigations, and evaluations to aireliability."""

    def __init__(self, fail_safe: bool = True) -> None:
        self.fail_safe = fail_safe
        self._version = "0.1.0"
        self._analyzer: Any = None
        self._initialize()

    def _initialize(self) -> None:
        if _AIRELIABILITY_AVAILABLE and AIRelRootCauseAnalyzer is not None:
            try:
                self._analyzer = AIRelRootCauseAnalyzer()
                logger.info("aireliability package initialized successfully (version %s)", self._version)
            except Exception as exc:
                logger.error("Failed to instantiate aireliability RootCauseAnalyzer: %s", exc)
                self._analyzer = None
        else:
            logger.warning("aireliability package is not installed or available")
            self._analyzer = None

    def is_healthy(self) -> bool:
        return self._analyzer is not None

    def health_status(self) -> dict[str, Any]:
        healthy = self.is_healthy()
        return {
            "enabled": True,
            "healthy": healthy,
            "version": self._version,
            "package_name": "aireliability",
            "runtime_status": "operational" if healthy else "unavailable",
        }

    def _map_to_aireliability_trace(self, record: ExecutionRecordDTO) -> Any:
        """Convert tenant-scoped AEGIS ExecutionRecordDTO into aireliability ExecutionTrace."""
        if not _AIRELIABILITY_AVAILABLE:
            return None

        # Determine trace status
        if record.status == ReliabilityStatus.SUCCESS:
            trace_status = AIRelExecutionStatus.COMPLETED
        else:
            trace_status = AIRelExecutionStatus.FAILED

        # Build steps
        step = AIRelTraceStep(
            id=f"step-{record.record_id[:8]}",
            type=AIRelStepType.LLM,
            name=f"{record.service_name}.{record.operation}",
            input={"prompt": record.prompt_text or ""} if record.prompt_text else None,
            output={"text": record.output_text or ""} if record.output_text else None,
            duration_ms=record.duration_ms,
            metadata={
                "provider": record.provider,
                "model": record.model,
                "status": record.status.value,
                "error": record.error_message,
            },
        )

        trace = AIRelExecutionTrace(
            trace_id=record.record_id,
            input=record.prompt_text,
            output=record.output_text,
            status=trace_status,
            latency_ms=record.duration_ms,
            cost=record.estimated_cost,
            token_usage={
                "prompt_tokens": record.input_tokens or 0,
                "completion_tokens": record.output_tokens or 0,
                "total_tokens": (record.input_tokens or 0) + (record.output_tokens or 0),
            },
            steps=[step],
            metadata={
                "organization_id": str(record.organization_id),
                "service_name": record.service_name,
                "operation": record.operation,
                "provider": record.provider,
                "model": record.model,
                "did_fallback": record.did_fallback,
            },
        )
        return trace

    def analyze_execution_trace(
        self,
        record: ExecutionRecordDTO,
    ) -> ReliabilityDiagnosisResult:
        """Execute causal root-cause diagnosis using aireliability."""
        start_time = time.perf_counter()
        if not self.is_healthy():
            AIRELIABILITY_ANALYSIS_FAILED_TOTAL.labels(service=record.service_name, reason="engine_unhealthy").inc()
            return ReliabilityDiagnosisResult(
                report_id=f"rep-fallback-{record.record_id[:8]}",
                trace_id=record.record_id,
                status="FAIL" if record.status != ReliabilityStatus.SUCCESS else "PASS",
                primary_cause_description=record.error_message or f"Execution status: {record.status.value}",
                summary="aireliability engine unavailable; fallback diagnosis used",
            )

        try:
            trace = self._map_to_aireliability_trace(record)
            failures = []
            if record.status != ReliabilityStatus.SUCCESS:
                severity = AIRelFailureSeverity.HIGH
                if record.status in (ReliabilityStatus.FIREWALL_BLOCKED, ReliabilityStatus.POLICY_DENIED):
                    category = "security"
                    fail_type = "policy_violation"
                elif record.status == ReliabilityStatus.GROUNDING_FAILED:
                    category = "grounding"
                    fail_type = "hallucination"
                elif record.status == ReliabilityStatus.TIMEOUT:
                    category = "performance"
                    fail_type = "timeout"
                else:
                    category = "system"
                    fail_type = "execution_error"

                failures.append(
                    AIRelFailureReport(
                        trace_id=record.record_id,
                        category=category,
                        type=fail_type,
                        message=record.error_message or f"AI operation failed with status {record.status.value}",
                        severity=severity,
                    )
                )

            # Invoke original package's RootCauseAnalyzer
            report = self._analyzer.diagnose(trace=trace, failures=failures)
            duration = time.perf_counter() - start_time

            AIRELIABILITY_ANALYSIS_DURATION_SECONDS.labels(service=record.service_name).observe(duration)
            AIRELIABILITY_ANALYSIS_TOTAL.labels(service=record.service_name, status=report.status.lower()).inc()

            primary_cat = report.primary_cause.category.value if report.primary_cause and hasattr(report.primary_cause.category, "value") else (str(report.primary_cause.category) if report.primary_cause else None)
            primary_type = report.primary_cause.type.value if report.primary_cause and hasattr(report.primary_cause.type, "value") else (str(report.primary_cause.type) if report.primary_cause else None)
            primary_desc = report.primary_cause.description if report.primary_cause else None
            conf = report.primary_cause.confidence if report.primary_cause else 1.0

            causal_chain_strs = [
                f"{link.source} -> {link.target} ({link.relationship})"
                for link in report.causal_chain
            ]

            return ReliabilityDiagnosisResult(
                report_id=report.id,
                trace_id=record.record_id,
                status=report.status,
                primary_category=primary_cat,
                primary_cause_type=primary_type,
                primary_cause_description=primary_desc,
                confidence=conf,
                causal_chain=causal_chain_strs,
                summary=report.summary,
                metadata={
                    "package": "aireliability",
                    "package_version": self._version,
                    "analysis_duration_ms": round(duration * 1000.0, 2),
                },
            )
        except Exception as exc:
            duration = time.perf_counter() - start_time
            logger.error("Error executing aireliability trace diagnosis: %s", exc)
            AIRELIABILITY_ANALYSIS_FAILED_TOTAL.labels(service=record.service_name, reason="diagnosis_exception").inc()
            if not self.fail_safe:
                raise
            return ReliabilityDiagnosisResult(
                report_id=f"rep-err-{record.record_id[:8]}",
                trace_id=record.record_id,
                status="FAIL",
                primary_cause_description=f"Diagnosis error: {exc}",
                summary=f"aireliability diagnosis encountered error: {exc}",
            )

    def evaluate_expectations(
        self,
        record: ExecutionRecordDTO,
        max_latency_ms: float | None = None,
        expected_substring: str | None = None,
    ) -> ReliabilityEvaluationResult:
        """Evaluate declarative expectations (MaxLatency, OutputContains) via aireliability."""
        if not self.is_healthy():
            return ReliabilityEvaluationResult(
                case_id=record.record_id,
                passed=record.status == ReliabilityStatus.SUCCESS,
                score=1.0 if record.status == ReliabilityStatus.SUCCESS else 0.0,
                failures=["aireliability engine unavailable"],
            )

        start_time = time.perf_counter()
        trace = self._map_to_aireliability_trace(record)
        failures_list = []
        passed_all = True
        scores: list[float] = []

        try:
            if max_latency_ms is not None:
                lat_exp = AIRelMaxLatency(max_latency_ms=max_latency_ms)
                res = lat_exp.evaluate(trace)
                if not res.passed:
                    passed_all = False
                    failures_list.append(res.message)
                scores.append(float(res.score) if res.passed and res.score is not None else 0.0)

            if expected_substring is not None:
                str_exp = AIRelOutputContains(expected_substring=expected_substring)
                res = str_exp.evaluate(trace)
                if not res.passed:
                    passed_all = False
                    failures_list.append(res.message)
                scores.append(float(res.score) if res.passed and res.score is not None else 0.0)

            final_score = (sum(scores) / len(scores)) if scores else 1.0
            duration = (time.perf_counter() - start_time) * 1000.0

            return ReliabilityEvaluationResult(
                case_id=record.record_id,
                passed=passed_all,
                score=final_score,
                failures=failures_list,
                duration_ms=duration,
                evaluator_details={
                    "max_latency_ms": max_latency_ms,
                    "expected_substring": expected_substring,
                },
            )
        except Exception as exc:
            logger.error("Error evaluating expectations with aireliability: %s", exc)
            return ReliabilityEvaluationResult(
                case_id=record.record_id,
                passed=False,
                score=0.0,
                failures=[f"Evaluation exception: {exc}"],
            )


default_reliability_engine = AIReliabilityPackageAdapter()
