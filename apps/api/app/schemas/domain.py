from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Health & System Schemas ---
class HealthResponse(BaseSchema):
    status: str = "ok"
    service: str = "aegis-api"
    version: str = "0.1.0"


class DependencyStatus(BaseSchema):
    status: str  # "healthy" | "unhealthy"
    latency_ms: float | None = None
    error: str | None = None


class ReadinessResponse(BaseSchema):
    status: str  # "ready" | "not_ready"
    dependencies: dict[str, DependencyStatus]


class VersionResponse(BaseSchema):
    app_name: str
    version: str
    environment: str
    api_version: str = "v1"


# --- Organization Schemas ---
class OrganizationCreate(BaseSchema):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)
    description: str | None = None


class OrganizationResponse(BaseSchema):
    id: UUID
    name: str
    slug: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime


# --- Project Schemas ---
class ProjectCreate(BaseSchema):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)
    description: str | None = None


class ProjectUpdate(BaseSchema):
    name: str | None = Field(None, min_length=2, max_length=255)
    description: str | None = None


class ProjectResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    name: str
    slug: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime


# --- Environment Schemas ---
class EnvironmentCreate(BaseSchema):
    name: str = Field(..., min_length=2, max_length=100)
    slug: str = Field(..., min_length=2, max_length=100)


class EnvironmentResponse(BaseSchema):
    id: UUID
    project_id: UUID
    organization_id: UUID
    name: str
    slug: str
    created_at: datetime


# --- Service Schemas ---
class ServiceCreate(BaseSchema):
    name: str = Field(..., min_length=2, max_length=100)
    slug: str = Field(..., min_length=2, max_length=100)
    repo_url: str | None = None


class ServiceResponse(BaseSchema):
    id: UUID
    environment_id: UUID
    organization_id: UUID
    name: str
    slug: str
    repo_url: str | None = None
    created_at: datetime


# --- Audit Schemas ---
class AuditEventResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    actor_user_id: str
    action: str
    resource_type: str
    resource_id: str
    request_id: str | None = None
    event_metadata: dict
    created_at: datetime


# --- Phase 4 Incident & Investigation Schemas ---
class IncidentCreate(BaseSchema):
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(default="", max_length=5000)
    severity: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    service_name: str | None = Field(default=None, max_length=100)
    source: str = Field(default="MANUAL", pattern="^(MANUAL|SIMULATION|TELEMETRY|DEPLOYMENT)$")
    metadata: dict = Field(default_factory=dict)


class IncidentResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    title: str
    description: str
    severity: str
    status: str
    source: str
    service_name: str | None = None
    detected_at: datetime
    resolved_at: datetime | None = None
    incident_metadata: dict
    created_at: datetime
    updated_at: datetime


class InvestigationCreate(BaseSchema):
    created_by: str = Field(default="system", max_length=255)
    metadata: dict = Field(default_factory=dict)


class InvestigationResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    incident_id: UUID
    status: str
    created_by: str
    summary: str | None = None
    confidence: float | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    investigation_metadata: dict
    created_at: datetime
    updated_at: datetime


class EvidenceResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    investigation_id: UUID
    evidence_type: str
    source: str
    service_name: str | None = None
    signal: str
    observed_at: datetime
    content: str
    structured_data: dict
    confidence: float
    relevance_score: float
    provenance: str
    created_at: datetime


class HypothesisResponse(BaseSchema):
    id: UUID
    investigation_id: UUID
    title: str
    description: str
    status: str
    score: float
    confidence: float
    supporting_evidence_ids: list[str]
    contradicting_evidence_ids: list[str]
    reasoning: str
    created_at: datetime


class ReasoningResultResponse(BaseSchema):
    id: UUID
    investigation_id: UUID
    summary: str
    root_cause: str
    confidence: float
    affected_services: list[str]
    supporting_evidence_ids: list[str]
    contradicting_evidence_ids: list[str]
    reasoning_steps: list[dict]
    model_provider: str
    model_name: str
    prompt_version: str
    context_hash: str
    created_at: datetime


# --- Phase 5 AI Trust & Reliability Schemas ---
class AIModelMetadataResponse(BaseSchema):
    name: str
    provider: str
    version: str
    capabilities: list[str]
    context_limit: int
    enabled: bool
    priority: int
    cost_per_1k_input_tokens: float | None = None
    cost_per_1k_output_tokens: float | None = None


class AIProviderResponse(BaseSchema):
    name: str
    status: str
    capabilities: list[str]
    circuit_state: str
    failure_count: int
    models: list[str]


class AIComponentHealth(BaseSchema):
    status: str
    details: dict | None = None


class AIHealthResponse(BaseSchema):
    status: str  # healthy | degraded | unhealthy
    api: AIComponentHealth
    firewall: AIComponentHealth
    policy_engine: AIComponentHealth
    model_router: AIComponentHealth
    grounding_validator: AIComponentHealth
    reliability_engine: AIComponentHealth | None = None


class AIReliabilityResponse(BaseSchema):
    total_requests: int
    successful_requests: int
    failed_requests: int
    availability_rate: float
    grounding_rate: float
    safety_rate: float
    reliability_score: float
    avg_latency_ms: float
    total_input_tokens: int
    total_output_tokens: int
    total_cost_usd: float
    hallucination_indicators: dict[str, int]
    score_breakdown: dict[str, float]


class AIUsageRecordResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    provider: str
    model: str
    operation: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    estimated_cost: float | None = None
    duration_ms: float | None = None
    status: str
    created_at: datetime


class AIPolicyResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    name: str
    version: str
    enabled: bool
    rules: dict
    created_at: datetime
    updated_at: datetime


class FirewallStatusResponse(BaseSchema):
    enabled: bool
    healthy: bool
    version: str
    policy_version: str


# --- Phase 6 Remediation Schemas ---
class RemediationCreateRequest(BaseSchema):
    target_environment: str = "production-sim"


class RemediationApprovalRequest(BaseSchema):
    reason: str = "Approved by on-call engineer"


class RemediationRejectRequest(BaseSchema):
    reason: str


class RemediationActionSchema(BaseSchema):
    id: UUID
    action_type: str
    target: str
    parameters: dict
    risk_level: str
    timeout_seconds: int
    validation_step: str
    rollback_step: str


class RemediationProposalResponse(BaseSchema):
    id: UUID
    incident_id: UUID
    organization_id: UUID
    service_name: str
    title: str
    description: str
    root_cause_reference: str
    evidence_ids: list[str]
    risk_level: str
    status: str
    actions: list[dict]
    blast_radius: dict
    validation_plan: dict
    rollback_plan: dict
    remediation_hash: str
    created_by: str
    created_at: datetime
    expires_at: datetime | None = None


class RemediationApprovalResponse(BaseSchema):
    id: UUID
    remediation_id: UUID
    organization_id: UUID
    approver_id: str
    decision: str
    reason: str
    policy_version: str
    remediation_hash: str
    created_at: datetime
    expires_at: datetime


class PreflightResponse(BaseSchema):
    passed: bool
    remediation_id: UUID
    remediation_hash: str
    target_exists: bool
    service_exists: bool
    schema_valid: bool
    rollback_available: bool
    approval_valid: bool
    hash_intact: bool
    details: dict
    errors: list[str]


class RemediationExecutionResponse(BaseSchema):
    id: UUID
    remediation_id: UUID
    attempt: int
    executor_id: str
    environment: str
    target: str
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    preflight_result: dict
    validation_result: dict
    rollback_result: dict
    error: str | None = None


# --- Phase 7 Autonomy & Reliability Schemas ---
class AutonomyPolicyCreateRequest(BaseSchema):
    environment: str = "production-sim"
    service: str = "*"
    autonomy_level: str = "LEVEL_2_AUTO_EXECUTE_LOW_RISK"
    allowed_actions: list[str] = ["SERVICE_RESTART", "CACHE_INVALIDATION"]
    maximum_risk: str = "LOW"
    max_blast_radius_services: int = 1
    require_rollback_plan: bool = True
    require_validation_plan: bool = True
    change_freeze_enabled: bool = False


class AutonomyPolicyResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    environment: str
    service: str
    autonomy_level: str
    allowed_actions: list[str]
    maximum_risk: str
    max_blast_radius_services: int
    require_rollback_plan: bool
    require_validation_plan: bool
    change_freeze_enabled: bool
    version: str
    created_at: datetime


class AutonomyStatusResponse(BaseSchema):
    autonomy_enabled: bool
    production_enabled: bool
    kill_switch_active: bool
    change_freeze_active: bool
    circuit_breaker_state: str
    max_risk_level: str
    max_tool_calls: int


class AgentRunResponse(BaseSchema):
    id: UUID
    incident_id: UUID
    organization_id: UUID
    service_name: str
    state: str
    budget: dict
    tool_calls_count: int
    iterations_count: int
    total_cost_usd: float
    total_tokens_consumed: int
    remediation_id: UUID | None = None
    autonomy_decision: str | None = None
    outcome: str
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


class IncidentLearningResponse(BaseSchema):
    id: UUID
    incident_id: UUID
    organization_id: UUID
    service_name: str
    environment: str
    root_cause: str
    remediation_summary: str
    actions_taken: list[dict]
    validated: bool
    promoted_to_knowledge: bool
    runbook_candidate: bool
    proposed_runbook_content: str
    created_at: datetime


class EvaluationRunResponse(BaseSchema):
    id: UUID
    dataset_version: str
    model_version: str
    prompt_version: str
    total_cases: int
    passed_cases: int
    failed_cases: int
    root_cause_accuracy: float
    remediation_acceptance_rate: float
    safety_violations_count: int
    firewall_block_rate: float
    release_gate_passed: bool
    summary: str
    evaluated_at: datetime


class SLOResponse(BaseSchema):
    service_name: str
    slo_type: str
    target_percentage: float
    current_percentage: float
    error_budget_remaining: float
    burn_rate: float
    is_breached: bool
    window_days: int




