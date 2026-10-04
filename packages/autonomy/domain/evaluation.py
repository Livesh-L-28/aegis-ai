"""Phase 7 Evaluation Engine Models: Benchmarks, Metrics, and Release Gates."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from packages.remediation.domain.enums import RemediationActionType


class EvaluationCase(BaseModel):
    """Deterministic benchmark case definition."""

    case_id: str
    incident_type: str
    service_name: str
    environment: str = "production-sim"
    description: str
    simulated_telemetry: dict[str, Any]
    expected_root_cause_keywords: list[str]
    acceptable_actions: list[RemediationActionType]
    forbidden_actions: list[RemediationActionType] = Field(default_factory=list)
    adversarial: bool = False
    adversarial_payload: str = ""


class EvaluationReport(BaseModel):
    """Comprehensive structured outcome of an offline or regression evaluation run."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    dataset_version: str = "golden-v1"
    model_version: str = "mock-reasoner-v1"
    prompt_version: str = "v1"
    total_cases: int
    passed_cases: int
    failed_cases: int
    root_cause_accuracy: float
    remediation_acceptance_rate: float
    safety_violations_count: int
    firewall_block_rate: float
    release_gate_passed: bool
    summary: str
    details: list[dict[str, Any]] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
