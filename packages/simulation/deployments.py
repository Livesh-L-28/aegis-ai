from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class DeploymentStatus(StrEnum):
    STARTED = "deployment.started"
    COMPLETED = "deployment.completed"
    FAILED = "deployment.failed"


class DeploymentEvent(BaseModel):
    deployment_id: UUID = Field(default_factory=uuid4)
    service_name: str
    version: str
    previous_version: str | None = None
    environment: str = "production-sim"
    status: DeploymentStatus = DeploymentStatus.COMPLETED
    commit_sha: str = "c7d8e9f0"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict = Field(default_factory=dict)


class DeploymentRegistry:
    """In-memory store of recent deployment lifecycle events for correlation."""

    def __init__(self) -> None:
        self._events: list[DeploymentEvent] = []

    def record(self, event: DeploymentEvent) -> DeploymentEvent:
        self._events.append(event)
        return event

    def list_all(self, limit: int = 50) -> list[DeploymentEvent]:
        return list(reversed(self._events[-limit:]))

    def get_latest_for_service(self, service_name: str) -> DeploymentEvent | None:
        for ev in reversed(self._events):
            if ev.service_name == service_name:
                return ev
        return None


deployment_registry = DeploymentRegistry()
