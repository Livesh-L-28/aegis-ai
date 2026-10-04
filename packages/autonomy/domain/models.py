"""Phase 7 Autonomy & Reliability Domain Models."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from packages.autonomy.domain.enums import (
    AgentExecutionState,
    AutonomyDecisionType,
    AutonomyLevel,
    SLOType,
)
from packages.remediation.domain.enums import RemediationActionType
from packages.security.policy import AIRiskLevel


class AutonomyPolicy(BaseModel):
    """Declarative tenant/environment policy governing autonomous capabilities."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    environment: str = "production-sim"
    service: str = "*"
    autonomy_level: AutonomyLevel = AutonomyLevel.LEVEL_2
    allowed_actions: list[RemediationActionType] = Field(
        default_factory=lambda: [
            RemediationActionType.SERVICE_RESTART,
            RemediationActionType.CACHE_INVALIDATION,
        ]
    )
    maximum_risk: AIRiskLevel = AIRiskLevel.LOW
    max_blast_radius_services: int = 1
    require_rollback_plan: bool = True
    require_validation_plan: bool = True
    change_freeze_enabled: bool = False
    rate_limit_executions_per_hour: int = 5
    version: str = "1.0"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AutonomyExplanation(BaseModel):
    """Human-understandable transparent explanation for the autonomy decision."""

    policy_version: str
    reasons: list[str]
    risk_level: str
    blast_radius_count: int
    allowlist_matched: bool
    circuit_state: str
    change_freeze: bool


class AutonomyDecisionResult(BaseModel):
    """Output of the AutonomyDecisionEngine."""

    decision: AutonomyDecisionType
    allowed: bool
    risk_level: AIRiskLevel
    autonomy_level: AutonomyLevel
    explanation: AutonomyExplanation
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AgentBudget(BaseModel):
    """Enforces strict bounds preventing runaway agent behaviors."""

    max_iterations: int = 10
    max_tool_calls: int = 15
    max_duration_seconds: int = 120
    max_cost_usd: float = 2.0
    max_tokens: int = 10000
    max_remediation_attempts: int = 3


class AgentRunRecord(BaseModel):
    """Audit log of an autonomous agent execution lifecycle."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    organization_id: UUID
    service_name: str
    state: AgentExecutionState = AgentExecutionState.CREATED
    budget: AgentBudget = Field(default_factory=AgentBudget)
    tool_calls_count: int = 0
    iterations_count: int = 0
    total_cost_usd: float = 0.0
    total_tokens_consumed: int = 0
    remediation_id: UUID | None = None
    autonomy_decision: AutonomyDecisionType | None = None
    outcome: str = ""
    error_message: str | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None


class SLODefinition(BaseModel):
    """Reliability objective tracking target and remaining error budget."""

    id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    service_name: str
    slo_type: SLOType
    target_percentage: float = 99.9  # e.g., 99.9%
    current_percentage: float = 100.0
    error_budget_remaining: float = 1.0  # 1.0 = 100% budget remains
    burn_rate: float = 0.0
    is_breached: bool = False
    window_days: int = 30
    last_evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IncidentFingerprint(BaseModel):
    """Alert deduplication fingerprint."""

    environment: str
    service: str
    symptom: str
    time_window_key: str
    fingerprint_hash: str


class IncidentLearningRecord(BaseModel):
    """Structured operational knowledge learned from completed, validated incidents."""

    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    organization_id: UUID
    service_name: str
    environment: str
    root_cause: str
    remediation_summary: str
    actions_taken: list[dict[str, Any]]
    validated: bool = True
    promoted_to_knowledge: bool = False
    runbook_candidate: bool = False
    proposed_runbook_content: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
