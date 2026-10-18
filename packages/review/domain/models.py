"""Normalized domain models for the AEGIS AI Repository Intelligence & Code Review Engine."""

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from packages.intelligence.code.indexer import CodeSymbol


class FindingSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class FindingCategory(StrEnum):
    SECURITY = "SECURITY"
    RELIABILITY = "RELIABILITY"
    QUALITY = "QUALITY"
    COMPATIBILITY = "COMPATIBILITY"
    TEST_COVERAGE = "TEST_COVERAGE"
    PERFORMANCE = "PERFORMANCE"


class FindingOrigin(StrEnum):
    STATIC_ANALYSIS = "STATIC_ANALYSIS"      # Deterministic linter or compiler tool
    SECURITY_HEURISTIC = "SECURITY_HEURISTIC"  # AST-based heuristic pattern check
    HYPOTHESIS = "HYPOTHESIS"                  # AI-generated or unverified hypothesis


class ValidationStatus(StrEnum):
    VALIDATED = "VALIDATED"
    UNVERIFIED = "UNVERIFIED"
    REJECTED_LOCATION = "REJECTED_LOCATION"
    REJECTED_CONTRADICTED = "REJECTED_CONTRADICTED"


class ReviewStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ReviewType(StrEnum):
    LOCAL = "LOCAL"
    API = "API"
    GITHUB_PR = "GITHUB_PR"


class SourceLocation(BaseModel):
    file_path: str
    start_line: int
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    symbol_name: str | None = None


def generate_finding_fingerprint(
    file_path: str,
    start_line: int,
    category: str,
    rule_id: str,
) -> str:
    """Generates a stable deterministic fingerprint for deduplicating findings."""
    raw = f"{file_path.strip().lower()}:{start_line}:{category.strip().upper()}:{rule_id.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class ReviewFinding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    review_id: UUID | None = None
    rule_id: str
    title: str
    message: str
    severity: FindingSeverity
    category: FindingCategory
    origin: FindingOrigin
    location: SourceLocation
    suggestion: str | None = None
    technical_evidence: str = ""
    validation_status: ValidationStatus = ValidationStatus.VALIDATED
    deduplication_hash: str = ""
    tool_name: str
    confidence: float = 1.0  # 1.0 for deterministic tools, < 1.0 for heuristics/hypotheses
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def model_post_init(self, __context: Any) -> None:
        if not self.deduplication_hash:
            self.deduplication_hash = generate_finding_fingerprint(
                file_path=self.location.file_path,
                start_line=self.location.start_line,
                category=self.category.value,
                rule_id=self.rule_id,
            )


class DiffChangeType(StrEnum):
    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    RENAMED = "RENAMED"
    BINARY = "BINARY"


class DiffHunk(BaseModel):
    old_start: int
    old_length: int
    new_start: int
    new_length: int
    header: str = ""
    lines: list[str] = Field(default_factory=list)
    added_lines: list[int] = Field(default_factory=list)    # 1-indexed line numbers in new file
    deleted_lines: list[int] = Field(default_factory=list)  # 1-indexed line numbers in old file


class ChangedFile(BaseModel):
    old_path: str | None = None
    new_path: str | None = None
    change_type: DiffChangeType
    hunks: list[DiffHunk] = Field(default_factory=list)
    is_binary: bool = False
    added_lines_count: int = 0
    deleted_lines_count: int = 0


class GitDiffSummary(BaseModel):
    base_commit: str | None = None
    head_commit: str | None = None
    files: list[ChangedFile] = Field(default_factory=list)
    total_added_lines: int = 0
    total_deleted_lines: int = 0
    is_truncated: bool = False
    warnings: list[str] = Field(default_factory=list)


class ChangedSymbol(BaseModel):
    symbol: CodeSymbol
    file_path: str
    change_type: str = "MODIFIED"  # ADDED, MODIFIED, REMOVED
    changed_line_ranges: list[tuple[int, int]] = Field(default_factory=list)


class AffectedArtifacts(BaseModel):
    changed_symbols: list[ChangedSymbol] = Field(default_factory=list)
    affected_tests: list[str] = Field(default_factory=list)
    reverse_dependencies: dict[str, list[str]] = Field(default_factory=dict)
    discovery_warnings: list[str] = Field(default_factory=list)


class ReviewReport(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    repository_path: str
    base_commit: str | None = None
    head_commit: str | None = None
    diff_summary: GitDiffSummary
    affected_artifacts: AffectedArtifacts
    findings: list[ReviewFinding] = Field(default_factory=list)
    files_reviewed: list[str] = Field(default_factory=list)
    execution_time_seconds: float = 0.0
    is_clean: bool = True
    errors: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReviewSession(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    project_id: UUID | None = None
    repository_name: str
    review_type: ReviewType = ReviewType.LOCAL
    base_commit: str | None = None
    head_commit: str | None = None
    status: ReviewStatus = ReviewStatus.PENDING
    summary: str = ""
    total_findings: int = 0
    findings: list[ReviewFinding] = Field(default_factory=list)
    execution_time_seconds: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    cancellation_reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
