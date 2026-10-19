"""Domain models, input validation, and secret redaction for Phase 3 Autonomous Debugging."""

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

# Patterns for sensitive credentials redaction
SECRET_PATTERNS = [
    re.compile(r"""(?i)(?:bearer\s+[a-zA-Z0-9_\-\.]{15,})"""),
    re.compile(r"""(?i)(?:(?:api[_-]?key|secret|token|password|passwd|auth)\s*[:=]\s*["']?([^\s"']{8,})["']?)"""),
    re.compile(r"""(?i)(?:sk_live_[0-9a-zA-Z]{24,})"""),
    re.compile(r"""(?i)(?:ghp_[0-9a-zA-Z]{36,})"""),
    re.compile(r"""(?i)(?:eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)"""),  # JWT
]


def redact_sensitive_content(text: str) -> str:
    """Sanitizes text by redacting API keys, passwords, JWTs, and bearer tokens."""
    if not text:
        return text
    sanitized = text
    for pat in SECRET_PATTERNS:
        sanitized = pat.sub("[REDACTED_SECRET]", sanitized)
    return sanitized


class DebuggingAnalysisStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class FrameOriginType(StrEnum):
    INTERNAL = "INTERNAL"
    EXTERNAL_LIBRARY = "EXTERNAL_LIBRARY"
    TEST_FRAME = "TEST_FRAME"
    SYNTHETIC = "SYNTHETIC"
    UNKNOWN = "UNKNOWN"


class EvidenceRelevanceLevel(StrEnum):
    DIRECT_EVIDENCE = "DIRECT_EVIDENCE"
    SUPPORTING_CONTEXT = "SUPPORTING_CONTEXT"
    INFERRED = "INFERRED"


class HypothesisVerdict(StrEnum):
    CONFIRMED = "CONFIRMED"
    PLAUSIBLE = "PLAUSIBLE"
    WEAKLY_SUPPORTED = "WEAKLY_SUPPORTED"
    REJECTED = "REJECTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class VerificationStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_RUN = "NOT_RUN"


class FixValidationStatus(StrEnum):
    PROPOSED = "PROPOSED"
    VALIDATION_PASSED = "VALIDATION_PASSED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class StackTraceFrame(BaseModel):
    """Normalized source-code stack frame representation."""

    file_path: str
    line_number: int = Field(..., ge=1)
    function_name: str
    code_context: str | None = None
    origin: FrameOriginType = FrameOriginType.UNKNOWN
    is_resolved: bool = False
    matched_symbol: str | None = None
    is_protected_file: bool = False
    resolution_note: str = ""


class IncidentFrameInput(BaseModel):
    file_path: str
    line_number: int = Field(..., ge=1)
    function_name: str
    code_context: str | None = None


class DebuggingIncidentInput(BaseModel):
    """External incident submission payload with bounded sizes and safe inputs."""

    title: str = Field(..., min_length=2, max_length=255)
    exception_type: str = Field(..., min_length=1, max_length=100)
    exception_message: str = Field(..., min_length=1, max_length=4000)
    raw_stack_trace: str | None = Field(default=None, max_length=32000)
    stack_frames: list[IncidentFrameInput] = Field(default_factory=list, max_length=50)
    service_name: str | None = Field(default=None, max_length=100)
    route: str | None = Field(default=None, max_length=255)
    correlation_id: str | None = Field(default=None, max_length=100)
    environment: str = Field(default="production", max_length=50)
    repository_id: UUID | None = None
    commit_sha: str | None = Field(default=None, min_length=7, max_length=64)
    test_output: str | None = Field(default=None, max_length=16000)
    logs: list[str] = Field(default_factory=list, max_length=100)
    reproduction_steps: list[str] = Field(default_factory=list, max_length=20)


class NormalizedDebuggingIncident(BaseModel):
    """Internal, sanitized representation of an ingested failure."""

    title: str
    exception_type: str
    exception_message: str
    raw_stack_trace: str | None = None
    parsed_frames: list[StackTraceFrame] = Field(default_factory=list)
    service_name: str | None = None
    route: str | None = None
    correlation_id: str | None = None
    environment: str = "production"
    repository_id: UUID | None = None
    commit_sha: str | None = None
    test_output: str | None = None
    sanitized_logs: list[str] = Field(default_factory=list)
    reproduction_steps: list[str] = Field(default_factory=list)
    provided_facts: dict[str, Any] = Field(default_factory=dict)
    missing_context: list[str] = Field(default_factory=list)


class DebuggingEvidenceItem(BaseModel):
    """Specific technical evidence correlated to a failure run."""

    id: UUID = Field(default_factory=uuid4)
    evidence_type: str  # SOURCE_FILE, AST_SYMBOL, DEPENDENCY_EDGE, API_CONTRACT, DATABASE_MODEL, MIGRATION, CONFIGURATION
    file_path: str | None = None
    symbol_name: str | None = None
    line_range: tuple[int, int] | None = None
    content: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    relevance_level: EvidenceRelevanceLevel = EvidenceRelevanceLevel.DIRECT_EVIDENCE
    provenance: str  # REVISION_GRAPH, STATIC_ANALYZER, STACK_TRACE_LOCALIZER
    explanation: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RankedHypothesis(BaseModel):
    """Competing root-cause explanation backed by citations to technical evidence."""

    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    verdict: HypothesisVerdict = HypothesisVerdict.PLAUSIBLE
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    supporting_evidence_ids: list[UUID] = Field(default_factory=list)
    contradicting_evidence_ids: list[UUID] = Field(default_factory=list)
    affected_file: str | None = None
    affected_symbol: str | None = None
    reasoning_summary: str = ""
    assumptions: list[str] = Field(default_factory=list)
    ranking_rationale: str = ""
    verification_steps: list[str] = Field(default_factory=list)


class VerificationStep(BaseModel):
    """Safe, non-destructive verification recommendation evaluating a hypothesis."""

    id: UUID = Field(default_factory=uuid4)
    hypothesis_id: UUID
    action_type: str  # RUN_TEST, INSPECT_CONTRACT, VALIDATE_CONFIG, COMPARE_REVISIONS, STATIC_CHECK
    target: str
    command_preview: str | None = None
    is_executable: bool = False
    expected_outcome: str
    actual_outcome: str | None = None
    status: VerificationStatus = VerificationStatus.NOT_RUN
    duration_ms: float | None = None
    notes: str = ""


class FixProposal(BaseModel):
    """Minimal, proposal-only remediation patch proposal without autonomous repository mutation."""

    id: UUID = Field(default_factory=uuid4)
    hypothesis_id: UUID
    target_file: str
    target_symbol: str | None = None
    defect_explanation: str
    diff_patch: str
    expected_behavior: str
    recommended_tests: list[str] = Field(default_factory=list)
    validation_status: FixValidationStatus = FixValidationStatus.PROPOSED
    validation_notes: list[str] = Field(default_factory=list)
    safety_considerations: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class DebuggingAnalysisRun(BaseModel):
    """Aggregate lifecycle container for an end-to-end debugging investigation."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    incident: NormalizedDebuggingIncident
    status: DebuggingAnalysisStatus = DebuggingAnalysisStatus.PENDING
    localized_frames: list[StackTraceFrame] = Field(default_factory=list)
    correlated_evidence: list[DebuggingEvidenceItem] = Field(default_factory=list)
    hypotheses: list[RankedHypothesis] = Field(default_factory=list)
    verification_plan: list[VerificationStep] = Field(default_factory=list)
    fix_proposals: list[FixProposal] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    error_message: str | None = None
    summary: str = ""
