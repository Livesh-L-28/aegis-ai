"""Evidence domain models and schemas for Phase 4 Evidence Engine."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EvidenceType(StrEnum):
    LOG = "LOG"
    METRIC = "METRIC"
    TRACE = "TRACE"
    DEPLOYMENT = "DEPLOYMENT"
    SERVICE = "SERVICE"
    DEPENDENCY = "DEPENDENCY"
    CODE = "CODE"
    COMMIT = "COMMIT"
    KNOWLEDGE = "KNOWLEDGE"
    CONFIGURATION = "CONFIGURATION"


class EvidenceSeverity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceItem(BaseModel):
    """Normalized canonical representation of an evidence item."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    investigation_id: UUID
    evidence_type: EvidenceType
    source: str = Field(..., description="Provider or collector source (e.g. prometheus, loki, otel, topology, git)")
    service_name: str | None = Field(default=None, description="Affected service or component name")
    signal: str = Field(..., description="Specific metric, log level, event, or topology node")
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    severity: EvidenceSeverity = EvidenceSeverity.MEDIUM
    content: str = Field(..., description="Human-readable description or summary of the evidence observation")
    structured_data: dict[str, Any] = Field(default_factory=dict, description="Raw normalized data payload")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Provider/collector confidence")
    relevance_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Score computed during ranking")
    provenance: str = Field(..., description="Traceable provenance citation: query, file path, span ID, or commit hash")
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineEntry(BaseModel):
    """A chronological event in an incident timeline with links to evidence items."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    title: str
    description: str
    service_name: str | None = None
    event_type: str = "TELEMETRY"
    evidence_ids: list[UUID] = Field(default_factory=list)
