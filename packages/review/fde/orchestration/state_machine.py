"""Deterministic state machine and transition rules for LogicFalcon FDE missions and steps."""

from enum import StrEnum
from typing import ClassVar

from packages.review.fde.models import StepStatus


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal state transition is attempted."""

    def __init__(self, current_status: StepStatus, target_status: StepStatus, reason: str = "") -> None:
        msg = f"Illegal state transition from {current_status.value} to {target_status.value}."
        if reason:
            msg += f" Reason: {reason}"
        super().__init__(msg)
        self.current_status = current_status
        self.target_status = target_status


class MissionStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class StepStateMachine:
    """Enforces legal, strictly bounded transitions for workflow steps."""

    LEGAL_TRANSITIONS: ClassVar[dict[StepStatus, set[StepStatus]]] = {
        StepStatus.PENDING: {StepStatus.READY, StepStatus.BLOCKED, StepStatus.CANCELLED},
        StepStatus.READY: {StepStatus.RUNNING, StepStatus.BLOCKED, StepStatus.CANCELLED},
        StepStatus.RUNNING: {StepStatus.SUCCEEDED, StepStatus.FAILED, StepStatus.BLOCKED, StepStatus.CANCELLED},
        StepStatus.FAILED: {StepStatus.READY},  # Only retryable if explicitly moved back to READY under retry policy
        StepStatus.BLOCKED: {StepStatus.READY, StepStatus.CANCELLED},
        StepStatus.SUCCEEDED: set(),  # Terminal state
        StepStatus.CANCELLED: set(),  # Terminal state
    }

    @classmethod
    def can_transition(cls, from_status: StepStatus, to_status: StepStatus) -> bool:
        """Determines if a transition is permitted by the state machine."""
        allowed = cls.LEGAL_TRANSITIONS.get(from_status, set())
        return to_status in allowed

    @classmethod
    def transition(cls, from_status: StepStatus, to_status: StepStatus, reason: str = "") -> StepStatus:
        """Executes a transition or raises InvalidStateTransitionError."""
        if not cls.can_transition(from_status, to_status):
            raise InvalidStateTransitionError(from_status, to_status, reason)
        return to_status
