"""Phase 7 Autonomy & Reliability Domain Enums."""

from enum import StrEnum


class AutonomyLevel(StrEnum):
    """Explicit bounded autonomy levels."""

    LEVEL_0 = "LEVEL_0_OBSERVE_ONLY"
    LEVEL_1 = "LEVEL_1_RECOMMEND"
    LEVEL_2 = "LEVEL_2_AUTO_EXECUTE_LOW_RISK"
    LEVEL_3 = "LEVEL_3_AUTO_EXECUTE_APPROVED_CLASSES"
    LEVEL_4 = "LEVEL_4_FULLY_AUTONOMOUS"  # PERMANENTLY DISABLED IN AEGIS


class AutonomyDecisionType(StrEnum):
    """Deterministic decision engine outputs."""

    AUTONOMOUSLY_EXECUTE = "AUTONOMOUSLY_EXECUTE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    RECOMMEND_ONLY = "RECOMMEND_ONLY"
    DENY = "DENY"


class AgentExecutionState(StrEnum):
    """Explicit state machine for Reliability Agent runs."""

    CREATED = "CREATED"
    INVESTIGATING = "INVESTIGATING"
    EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION"
    REASONING = "REASONING"
    PROPOSING = "PROPOSING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    VALIDATING = "VALIDATING"
    ESCALATING = "ESCALATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AutonomyCircuitState(StrEnum):
    """Autonomy system circuit breaker state."""

    CLOSED = "CLOSED"  # Healthy: permitted operations can auto-execute
    OPEN = "OPEN"      # Tripped: auto-execution blocked, requires human review
    HALF_OPEN = "HALF_OPEN"


class SLOType(StrEnum):
    """Supported Reliability Objective types."""

    AVAILABILITY = "AVAILABILITY"
    LATENCY_P95 = "LATENCY_P95"
    LATENCY_P99 = "LATENCY_P99"
    ERROR_RATE = "ERROR_RATE"
    PAYMENT_SUCCESS_RATE = "PAYMENT_SUCCESS_RATE"
