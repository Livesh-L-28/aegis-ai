from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Health & System Schemas ---
class HealthResponse(BaseSchema):
    status: str = "ok"
    service: str = "aegis-api"
    version: str = "0.1.1"


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






# --- Code Review Schemas ---
class ReviewCreateRequest(BaseSchema):
    repository_name: str
    diff_text: str
    base_commit: str | None = None
    head_commit: str | None = None
    project_id: UUID | None = None
    enable_ai: bool = False
    metadata: dict = Field(default_factory=dict)


class ReviewCancelRequest(BaseSchema):
    reason: str = "User requested cancellation"


class ReviewFindingResponse(BaseSchema):
    id: UUID
    review_id: UUID
    file_path: str
    start_line: int
    end_line: int
    rule_id: str
    title: str
    message: str
    severity: str
    category: str
    origin: str
    confidence: float
    technical_evidence: str
    suggestion: str | None = None
    deduplication_hash: str
    tool_name: str
    created_at: datetime


class ReviewSessionResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    project_id: UUID | None = None
    repository_name: str
    review_type: str
    base_commit: str | None = None
    head_commit: str | None = None
    status: str
    summary: str
    total_findings: int
    execution_time_seconds: float
    cancellation_reason: str | None = None
    created_at: datetime
    updated_at: datetime


# --- Engineering Evidence Graph Schemas ---
class CodeSymbolResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    file_node_id: UUID
    name: str
    qualified_name: str
    symbol_type: str
    start_line: int
    end_line: int
    signature: str = ""
    docstring_summary: str | None = None
    created_at: datetime


class PaginatedSymbolsResponse(BaseSchema):
    items: list[CodeSymbolResponse]
    total: int
    limit: int
    offset: int


class AffectedTestsResponse(BaseSchema):
    repository_id: UUID
    commit_sha: str
    changed_files: list[str]
    affected_tests: list[str]


class EngineeringEvidenceResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    repository_id: UUID | None = None
    revision_id: UUID | None = None
    evidence_type: str
    provenance_source: str
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    symbol_name: str | None = None
    content: str
    structured_payload: dict = Field(default_factory=dict)
    confidence: float
    content_hash: str
    validation_status: str
    created_at: datetime


class PaginatedEvidenceResponse(BaseSchema):
    items: list[EngineeringEvidenceResponse]
    total: int
    limit: int
    offset: int


# --- Phase 2 System Intelligence Schemas ---
class ParserCapabilityItem(BaseSchema):
    language: str
    support_status: str
    file_extensions: list[str]
    parser_version: str
    features: list[str] = Field(default_factory=list)


class ParserCapabilitiesResponse(BaseSchema):
    supported_languages: list[ParserCapabilityItem]
    total_parsers: int


class ChangeImpactRequest(BaseSchema):
    changed_files: list[str]
    max_depth: int = Field(3, ge=1, le=10)


class ChangeImpactResponse(BaseSchema):
    repository_id: UUID
    commit_sha: str
    changed_files: list[str]
    affected_symbols: list[str]
    affected_tests: list[str]
    affected_api_endpoints: list[str]
    affected_database_models: list[str]
    risk_level: str
    risk_reasons: list[str]
    selection_explanations: dict[str, str]
    unresolved_dependencies: list[str]
    confidence: float


class SystemContractsResponse(BaseSchema):
    repository_id: UUID
    commit_sha: str
    api_endpoints: list[dict] = Field(default_factory=list)
    client_api_calls: list[dict] = Field(default_factory=list)
    database_models: list[dict] = Field(default_factory=list)
    migrations: list[dict] = Field(default_factory=list)
    config_references: list[dict] = Field(default_factory=list)


# --- Phase 3 Autonomous Debugging Schemas ---
class DebuggingCapabilitiesResponse(BaseSchema):
    supported_languages: list[str]
    stack_trace_formats: list[str]
    supported_verdicts: list[str]
    verification_actions: list[str]
    remediation_mode: str
    autonomous_patch_application: bool
    secret_redaction_enabled: bool


class StackTraceFrameResponse(BaseSchema):
    file_path: str
    line_number: int
    function_name: str
    code_context: str | None = None
    origin: str
    is_resolved: bool
    matched_symbol: str | None = None
    is_protected_file: bool = False
    resolution_note: str = ""


class DebuggingEvidenceResponse(BaseSchema):
    id: UUID
    evidence_type: str
    file_path: str | None = None
    symbol_name: str | None = None
    line_range: tuple[int, int] | None = None
    content: str
    confidence: float
    relevance_level: str
    provenance: str
    explanation: str
    metadata: dict = Field(default_factory=dict)


class RankedHypothesisResponse(BaseSchema):
    id: UUID
    title: str
    description: str
    verdict: str
    score: float
    confidence: float
    supporting_evidence_ids: list[UUID]
    contradicting_evidence_ids: list[UUID]
    affected_file: str | None = None
    affected_symbol: str | None = None
    reasoning_summary: str
    assumptions: list[str]
    ranking_rationale: str
    verification_steps: list[str]


class VerificationStepResponse(BaseSchema):
    id: UUID
    hypothesis_id: UUID
    action_type: str
    target: str
    command_preview: str | None = None
    is_executable: bool = False
    expected_outcome: str
    actual_outcome: str | None = None
    status: str
    duration_ms: float | None = None
    notes: str = ""


class FixProposalResponse(BaseSchema):
    id: UUID
    hypothesis_id: UUID
    target_file: str
    target_symbol: str | None = None
    defect_explanation: str
    diff_patch: str
    expected_behavior: str
    recommended_tests: list[str]
    validation_status: str
    validation_notes: list[str]
    safety_considerations: list[str]
    confidence: float


class DebuggingAnalysisResponse(BaseSchema):
    id: UUID
    organization_id: UUID
    status: str
    title: str
    exception_type: str
    summary: str
    started_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None
    localized_frames_count: int
    correlated_evidence_count: int
    hypotheses_count: int
    fix_proposals_count: int



