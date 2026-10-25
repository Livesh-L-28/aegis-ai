"""Base adapter contracts and capability models for LogicFalcon FDE."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.fde.models import (
    FdeEvidence,
    OperationCategory,
    StepRiskLevel,
    StepStatus,
)


class AdapterHealthStatus(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class AdapterHealth:
    """Represents health check status for an adapter."""

    status: AdapterHealthStatus
    message: str
    latency_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AdapterCapability:
    """Declares a distinct operation supported by an adapter."""

    name: str
    description: str
    operation_category: OperationCategory
    risk_level: StepRiskLevel
    requires_approval: bool = False
    parameters_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class AdapterExecutionResult:
    """Structured result returned by an adapter operation."""

    success: bool
    operation: str
    output: Any
    error: str | None = None
    error_category: str | None = None
    execution_time_seconds: float = 0.0
    evidence: FdeEvidence | None = None

    def sanitize(self) -> "AdapterExecutionResult":
        """Returns a copy of result with sensitive tokens redacted."""
        clean_err = redact_secrets_in_text(self.error) if self.error else None
        clean_out = self.output
        if isinstance(clean_out, str):
            clean_out = redact_secrets_in_text(clean_out)
        elif isinstance(clean_out, dict):
            clean_out = self._sanitize_dict(clean_out)
        return AdapterExecutionResult(
            success=self.success,
            operation=self.operation,
            output=clean_out,
            error=clean_err,
            error_category=self.error_category,
            execution_time_seconds=self.execution_time_seconds,
            evidence=self.evidence,
        )

    def _sanitize_dict(self, d: dict[str, Any]) -> dict[str, Any]:
        sanitized: dict[str, Any] = {}
        for k, v in d.items():
            k_lower = k.lower()
            if any(s in k_lower for s in ("token", "key", "secret", "password", "auth")):
                sanitized[k] = "[REDACTED]"
            elif isinstance(v, str):
                sanitized[k] = redact_secrets_in_text(v)
            elif isinstance(v, dict):
                sanitized[k] = self._sanitize_dict(v)
            else:
                sanitized[k] = v
        return sanitized


class BaseAdapter(ABC):
    """Abstract base contract for FDE infrastructure and service adapters."""

    def __init__(self, adapter_id: str, version: str = "1.0.0") -> None:
        self.adapter_id = adapter_id
        self.version = version

    @property
    @abstractmethod
    def capabilities(self) -> list[AdapterCapability]:
        """Returns list of declared capabilities supported by this adapter."""
        ...

    def get_capability(self, operation: str) -> AdapterCapability | None:
        """Looks up a declared capability by operation name."""
        for cap in self.capabilities:
            if cap.name == operation:
                return cap
        return None

    def supports(self, operation: str) -> bool:
        """Checks if operation is explicitly supported."""
        return self.get_capability(operation) is not None

    @abstractmethod
    def check_health(self) -> AdapterHealth:
        """Performs a bounded, non-mutating health check."""
        ...

    @abstractmethod
    def execute(
        self,
        operation: str,
        params: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> AdapterExecutionResult:
        """Executes an authorized operation with bounded parameters."""
        ...

    def cleanup(self) -> None:  # noqa: B027
        """Releases any local resources or open connections."""
        pass

    def create_evidence(
        self,
        step_id: str,
        operation: str,
        target: str,
        outcome: str,
        raw_output: str,
        mission_id: str = "ad-hoc",
    ) -> FdeEvidence:
        """Helper to create standardized sanitized evidence records."""
        status = StepStatus.SUCCEEDED if outcome == "SUCCESS" else StepStatus.FAILED
        return FdeEvidence(
            mission_id=mission_id,
            step_id=step_id,
            adapter_name=self.adapter_id,
            operation=operation,
            status=status,
            sanitized_output=redact_secrets_in_text(raw_output)[:50_000],
            metadata={"target": target, "outcome": outcome},
            timestamp=datetime.now(UTC),
        )
