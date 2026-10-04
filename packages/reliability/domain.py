"""Domain models and protocols for AI Reliability integration."""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ReliabilityStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    FIREWALL_BLOCKED = "FIREWALL_BLOCKED"
    POLICY_DENIED = "POLICY_DENIED"
    GROUNDING_FAILED = "GROUNDING_FAILED"


class ExecutionRecordDTO(BaseModel):
    """Normalized AEGIS AI execution record."""
    record_id: str = Field(default_factory=lambda: str(uuid4()))
    organization_id: UUID
    project_id: UUID | None = None
    environment_id: str | None = None
    service_name: str
    operation: str
    provider: str
    model: str
    duration_ms: float
    status: ReliabilityStatus
    input_tokens: int | None = None
    output_tokens: int | None = None
    did_fallback: bool = False
    estimated_cost: float | None = None
    claims_supported: int = 0
    claims_total: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    prompt_text: str | None = None
    output_text: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReliabilityDiagnosisResult(BaseModel):
    """Result of causal root cause analysis executed by aireliability."""
    report_id: str
    trace_id: str
    status: str  # PASS / FAIL
    primary_category: str | None = None
    primary_cause_type: str | None = None
    primary_cause_description: str | None = None
    confidence: float = 1.0
    causal_chain: list[str] = Field(default_factory=list)
    summary: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReliabilityEvaluationResult(BaseModel):
    """Result of benchmark expectation evaluation executed by aireliability."""
    case_id: str
    passed: bool
    score: float = 1.0
    failures: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0
    evaluator_details: dict[str, Any] = Field(default_factory=dict)


class AIReliabilityEngine(ABC):
    """Abstract interface defining the AI Reliability contract for AEGIS."""

    @abstractmethod
    def is_healthy(self) -> bool:
        """Verify underlying engine is operational."""
        ...

    @abstractmethod
    def health_status(self) -> dict[str, Any]:
        """Component health metadata."""
        ...

    @abstractmethod
    def analyze_execution_trace(
        self,
        record: ExecutionRecordDTO,
    ) -> ReliabilityDiagnosisResult:
        """Run deep trace diagnosis on an execution record."""
        ...

    @abstractmethod
    def evaluate_expectations(
        self,
        record: ExecutionRecordDTO,
        max_latency_ms: float | None = None,
        expected_substring: str | None = None,
    ) -> ReliabilityEvaluationResult:
        """Evaluate declarative latency/output expectations using aireliability."""
        ...
