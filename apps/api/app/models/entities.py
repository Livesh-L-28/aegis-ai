from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.app.db.base import GUID, Base, TimestampMixin, UUIDPrimaryKeyMixin


class Organization(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    memberships: Mapped[list["Membership"]] = relationship(
        "Membership", back_populates="organization", cascade="all, delete-orphan"
    )
    teams: Mapped[list["Team"]] = relationship(
        "Team", back_populates="organization", cascade="all, delete-orphan"
    )
    projects: Mapped[list["Project"]] = relationship(
        "Project", back_populates="organization", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list["AuditEvent"]] = relationship(
        "AuditEvent", back_populates="organization", cascade="all, delete-orphan"
    )


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(255), unique=True, index=True, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Relationships
    memberships: Mapped[list["Membership"]] = relationship(
        "Membership", back_populates="user", cascade="all, delete-orphan"
    )


class Membership(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "memberships"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="VIEWER")

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="memberships")
    user: Mapped["User"] = relationship("User", back_populates="memberships")


class Team(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "teams"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="teams")


class Project(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "projects"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="projects")
    environments: Mapped[list["Environment"]] = relationship(
        "Environment", back_populates="project", cascade="all, delete-orphan"
    )


class Environment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "environments"

    project_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="environments")
    services: Mapped[list["Service"]] = relationship(
        "Service", back_populates="environment", cascade="all, delete-orphan"
    )


class Service(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "services"

    environment_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("environments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    repo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Relationships
    environment: Mapped["Environment"] = relationship("Environment", back_populates="services")


class AuditEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "audit_events"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor_user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    request_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    event_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Relationships
    organization: Mapped["Organization"] = relationship("Organization", back_populates="audit_events")


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "incidents"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(50), nullable=False, default="MEDIUM")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="OPEN")
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="MANUAL")
    service_name: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    incident_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Relationships
    investigations: Mapped[list["Investigation"]] = relationship(
        "Investigation", back_populates="incident", cascade="all, delete-orphan"
    )


class Investigation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "investigations"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    incident_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="CREATED")
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float | None] = mapped_column(nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    investigation_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", back_populates="investigations")
    evidence_items: Mapped[list["Evidence"]] = relationship(
        "Evidence", back_populates="investigation", cascade="all, delete-orphan"
    )
    hypotheses: Mapped[list["Hypothesis"]] = relationship(
        "Hypothesis", back_populates="investigation", cascade="all, delete-orphan"
    )
    reasoning_result: Mapped["ReasoningResult | None"] = relationship(
        "ReasoningResult", back_populates="investigation", uselist=False, cascade="all, delete-orphan"
    )


class Evidence(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "evidence"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    signal: Mapped[str] = mapped_column(String(100), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    structured_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    confidence: Mapped[float] = mapped_column(default=1.0, nullable=False)
    relevance_score: Mapped[float] = mapped_column(default=1.0, nullable=False)
    provenance: Mapped[str] = mapped_column(String(255), nullable=False)

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="evidence_items")


class Hypothesis(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "hypotheses"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="CANDIDATE")
    score: Mapped[float] = mapped_column(default=0.0, nullable=False)
    confidence: Mapped[float] = mapped_column(default=0.0, nullable=False)
    supporting_evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    contradicting_evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="hypotheses")


class ReasoningResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "reasoning_results"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    investigation_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False)
    affected_services: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    supporting_evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    contradicting_evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reasoning_steps: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    model_provider: Mapped[str] = mapped_column(String(100), nullable=False, default="mock")
    model_name: Mapped[str] = mapped_column(String(100), nullable=False, default="mock-reasoning-v1")
    prompt_version: Mapped[str] = mapped_column(String(50), nullable=False, default="v1")
    context_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="reasoning_result")


class AIPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_policies"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0")
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    rules: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class AIUsageRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_usage_records"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    operation: Mapped[str] = mapped_column(String(100), nullable=False)
    input_tokens: Mapped[int | None] = mapped_column(nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(nullable=True)
    total_tokens: Mapped[int | None] = mapped_column(nullable=True)
    estimated_cost: Mapped[float | None] = mapped_column(nullable=True)
    duration_ms: Mapped[float] = mapped_column(default=0.0, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="SUCCESS")
    usage_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


# --- Phase 6 Remediation Models ---
class Remediation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "remediations"

    incident_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    service_name: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    root_cause_reference: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    risk_level: Mapped[str] = mapped_column(String(50), nullable=False, default="MEDIUM")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="PROPOSED")
    actions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    blast_radius: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    validation_plan: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    rollback_plan: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    remediation_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    approvals: Mapped[list["RemediationApprovalRecord"]] = relationship(
        "RemediationApprovalRecord", back_populates="remediation", cascade="all, delete-orphan"
    )
    executions: Mapped[list["RemediationExecutionRecord"]] = relationship(
        "RemediationExecutionRecord", back_populates="remediation", cascade="all, delete-orphan"
    )


class RemediationApprovalRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "remediation_approvals"

    remediation_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("remediations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    approver_id: Mapped[str] = mapped_column(String(100), nullable=False)
    decision: Mapped[str] = mapped_column(String(50), nullable=False, default="APPROVED")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    policy_version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0")
    remediation_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Relationships
    remediation: Mapped["Remediation"] = relationship("Remediation", back_populates="approvals")


class RemediationExecutionRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "remediation_executions"

    remediation_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("remediations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    attempt: Mapped[int] = mapped_column(default=1, nullable=False)
    executor_id: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    environment: Mapped[str] = mapped_column(String(50), nullable=False, default="production-sim")
    target: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="PREFLIGHT")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    preflight_result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    validation_result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    rollback_result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    remediation: Mapped["Remediation"] = relationship("Remediation", back_populates="executions")


# --- Phase 7 Autonomy & Reliability Models ---
class AutonomyPolicyRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "autonomy_policies"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    environment: Mapped[str] = mapped_column(String(50), nullable=False, default="production-sim")
    service: Mapped[str] = mapped_column(String(100), nullable=False, default="*")
    autonomy_level: Mapped[str] = mapped_column(String(50), nullable=False, default="LEVEL_2_AUTO_EXECUTE_LOW_RISK")
    allowed_actions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    maximum_risk: Mapped[str] = mapped_column(String(50), nullable=False, default="LOW")
    max_blast_radius_services: Mapped[int] = mapped_column(default=1, nullable=False)
    require_rollback_plan: Mapped[bool] = mapped_column(default=True, nullable=False)
    require_validation_plan: Mapped[bool] = mapped_column(default=True, nullable=False)
    change_freeze_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.0")


class AgentRunEntity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "agent_runs"

    incident_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    service_name: Mapped[str] = mapped_column(String(100), nullable=False)
    state: Mapped[str] = mapped_column(String(50), nullable=False, default="CREATED")
    budget: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    tool_calls_count: Mapped[int] = mapped_column(default=0, nullable=False)
    iterations_count: Mapped[int] = mapped_column(default=0, nullable=False)
    total_cost_usd: Mapped[float] = mapped_column(default=0.0, nullable=False)
    total_tokens_consumed: Mapped[int] = mapped_column(default=0, nullable=False)
    remediation_id: Mapped[UUID | None] = mapped_column(GUID, nullable=True)
    autonomy_decision: Mapped[str | None] = mapped_column(String(50), nullable=True)
    outcome: Mapped[str] = mapped_column(Text, nullable=False, default="")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IncidentLearningEntity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "incident_learnings"

    incident_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    service_name: Mapped[str] = mapped_column(String(100), nullable=False)
    environment: Mapped[str] = mapped_column(String(50), nullable=False, default="production-sim")
    root_cause: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_summary: Mapped[str] = mapped_column(String(255), nullable=False)
    actions_taken: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    validated: Mapped[bool] = mapped_column(default=True, nullable=False)
    promoted_to_knowledge: Mapped[bool] = mapped_column(default=False, nullable=False)
    runbook_candidate: Mapped[bool] = mapped_column(default=False, nullable=False)
    proposed_runbook_content: Mapped[str] = mapped_column(Text, nullable=False, default="")





class ReviewSessionEntity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "review_sessions"

    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID | None] = mapped_column(
        GUID,
        ForeignKey("projects.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    repository_name: Mapped[str] = mapped_column(String(255), nullable=False)
    review_type: Mapped[str] = mapped_column(String(50), nullable=False, default="LOCAL")
    base_commit: Mapped[str | None] = mapped_column(String(40), nullable=True)
    head_commit: Mapped[str | None] = mapped_column(String(40), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="PENDING")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    total_findings: Mapped[int] = mapped_column(default=0, nullable=False)
    execution_time_seconds: Mapped[float] = mapped_column(default=0.0, nullable=False)
    cancellation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    review_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Relationships
    findings: Mapped[list["ReviewFindingEntity"]] = relationship(
        "ReviewFindingEntity",
        back_populates="session",
        cascade="all, delete-orphan",
    )


class ReviewFindingEntity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "review_findings"

    review_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("review_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    start_line: Mapped[int] = mapped_column(nullable=False)
    end_line: Mapped[int] = mapped_column(nullable=False)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    origin: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[float] = mapped_column(default=1.0, nullable=False)
    technical_evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    suggestion: Mapped[str | None] = mapped_column(Text, nullable=True)
    deduplication_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False, default="aegis_review")
    finding_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    session: Mapped["ReviewSessionEntity"] = relationship(
        "ReviewSessionEntity",
        back_populates="findings",
    )
