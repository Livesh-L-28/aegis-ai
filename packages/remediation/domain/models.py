"""Phase 6 Remediation Domain Models and Structured Proposals."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from packages.remediation.domain.enums import (
    ApprovalDecision,
    ExecutionStatus,
    RemediationActionType,
    RemediationStatus,
)
from packages.security.policy import AIRiskLevel


class RemediationAction(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    action_type: RemediationActionType
    target: str  # service, config key, container, repo
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: AIRiskLevel = AIRiskLevel.LOW
    timeout_seconds: int = 60
    preconditions: list[str] = Field(default_factory=list)
    validation_step: str = ""
    rollback_step: str = ""


class BlastRadiusReport(BaseModel):
    affected_services: list[str] = Field(default_factory=list)
    affected_dependencies: list[str] = Field(default_factory=list)
    affected_environments: list[str] = Field(default_factory=list)
    estimated_impact_description: str = ""


class ValidationPlan(BaseModel):
    metric_checks: list[dict[str, Any]] = Field(default_factory=list)
    health_endpoint: str | None = None
    telemetry_window_seconds: int = 30
    success_criteria: str = ""


class RollbackPlan(BaseModel):
    action_type: RemediationActionType
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 60
    verification_step: str = ""


class RemediationProposal(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    organization_id: UUID
    project_id: UUID | None = None
    environment_id: UUID | None = None
    service_id: UUID | None = None
    service_name: str

    title: str
    description: str

    root_cause_reference: str
    evidence_ids: list[str] = Field(default_factory=list)

    risk_level: AIRiskLevel = AIRiskLevel.MEDIUM
    status: RemediationStatus = RemediationStatus.PROPOSED

    actions: list[RemediationAction] = Field(default_factory=list)
    blast_radius: BlastRadiusReport = Field(default_factory=BlastRadiusReport)
    preconditions: list[str] = Field(default_factory=list)
    validation_plan: ValidationPlan = Field(default_factory=ValidationPlan)
    rollback_plan: RollbackPlan = Field(
        default_factory=lambda: RollbackPlan(
            action_type=RemediationActionType.ROLLBACK,
            target="",
            parameters={},
        )
    )

    model_provider: str = "mock"
    model_name: str = "mock-reasoner-v1"
    prompt_version: str = "v1"
    context_hash: str = ""

    remediation_hash: str = ""
    created_by: str = "aegis-remediation-engine"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None

    def compute_remediation_hash(self) -> str:
        """Deterministically hashes proposal actions, targets, parameters, and rollback plan."""
        payload = {
            "incident_id": str(self.incident_id),
            "service_name": self.service_name,
            "actions": [
                {
                    "type": a.action_type.value,
                    "target": a.target,
                    "params": a.parameters,
                    "risk": a.risk_level.value,
                }
                for a in self.actions
            ],
            "validation": self.validation_plan.model_dump(),
            "rollback": self.rollback_plan.model_dump(),
        }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class RemediationApproval(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    remediation_id: UUID
    organization_id: UUID
    approver_id: str
    decision: ApprovalDecision = ApprovalDecision.APPROVED
    reason: str = ""
    policy_version: str = "1.0"
    remediation_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime


class PreflightResult(BaseModel):
    passed: bool
    remediation_id: UUID
    remediation_hash: str
    target_exists: bool
    service_exists: bool
    schema_valid: bool
    rollback_available: bool
    approval_valid: bool
    hash_intact: bool
    details: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class RemediationExecution(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    remediation_id: UUID
    attempt: int = 1
    executor_id: str = "system"
    environment: str = "production-sim"
    target: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    status: ExecutionStatus = ExecutionStatus.PREFLIGHT
    preflight_result: PreflightResult | None = None
    validation_result: dict[str, Any] = Field(default_factory=dict)
    rollback_result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
