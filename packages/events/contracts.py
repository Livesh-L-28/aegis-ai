from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EventType(StrEnum):
    # Tenant & Resource Events
    ORG_CREATED = "organization.created"
    ORG_UPDATED = "organization.updated"
    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_DELETED = "project.deleted"
    ENV_CREATED = "environment.created"
    SERVICE_CREATED = "service.created"
    MEMBERSHIP_CREATED = "membership.created"
    AUTH_DENIED = "authorization.denied"

    # Future Roadmap Events (Phases 2 - 7 architectural extension contracts)
    INCIDENT_DETECTED = "incident.detected"
    INVESTIGATION_CREATED = "investigation.created"
    EVIDENCE_COLLECTION_STARTED = "evidence.collection.started"
    EVIDENCE_COLLECTION_COMPLETED = "evidence.collection.completed"
    ROOT_CAUSE_PROPOSED = "root_cause.proposed"
    REMEDIATION_CREATED = "remediation.created"
    VALIDATION_STARTED = "validation.started"
    VALIDATION_COMPLETED = "validation.completed"
    APPROVAL_REQUESTED = "approval.requested"
    DEPLOYMENT_STARTED = "deployment.started"
    DEPLOYMENT_COMPLETED = "deployment.completed"
    INCIDENT_RESOLVED = "incident.resolved"

    # AI Reliability Engine Events (aireliability integration)
    AI_RELIABILITY_ANALYSIS_STARTED = "ai.reliability.analysis.started"
    AI_RELIABILITY_ANALYSIS_COMPLETED = "ai.reliability.analysis.completed"
    AI_RELIABILITY_ANALYSIS_FAILED = "ai.reliability.analysis.failed"
    AI_RELIABILITY_REGRESSION_STARTED = "ai.reliability.regression.started"
    AI_RELIABILITY_REGRESSION_COMPLETED = "ai.reliability.regression.completed"


class BaseEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    event_type: EventType
    organization_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor_id: str | None = None
    request_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class EventPublisher(Protocol):
    """Protocol for future event brokers (Redis PubSub, Kafka, NATS, SQS)."""

    async def publish(self, event: BaseEvent) -> None: ...


class InMemoryEventPublisher:
    """In-memory event publisher for Phase 1 testing and local foundations."""

    def __init__(self) -> None:
        self.published_events: list[BaseEvent] = []

    async def publish(self, event: BaseEvent) -> None:
        self.published_events.append(event)
