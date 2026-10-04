"""AI Policy Engine, Risk Levels, Data Classification, and Deny-by-Default Controls."""

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AIRiskLevel(StrEnum):
    READ_ONLY = "READ_ONLY"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DataClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    SECRET = "SECRET"


class PolicyDecisionResult(BaseModel):
    allowed: bool
    risk_level: AIRiskLevel
    data_classification: DataClassification
    reason: str
    requires_approval: bool = False
    policy_name: str = "default_enterprise_ai_policy"
    policy_version: str = "1.0"
    metadata: dict[str, Any] = Field(default_factory=dict)


class AIPolicyEngine:
    """Enforces fine-grained programmatic enterprise policies across AI reasoning requests and tools."""

    def __init__(self, policy_version: str = "1.0") -> None:
        self.policy_version = policy_version

    def classify_data(self, text: str) -> DataClassification:
        """Classify context sensitivity."""
        lower = text.lower()
        if any(k in lower for k in ("password", "secret_key", "bearer ", "private_key", "authorization:")):
            return DataClassification.SECRET
        if any(k in lower for k in ("pii", "user_id", "email", "customer", "ssn", "credit_card")):
            return DataClassification.SENSITIVE
        if any(k in lower for k in ("confidential", "internal", "runbook", "topology", "service", "cart-service")):
            return DataClassification.INTERNAL
        return DataClassification.PUBLIC


    def evaluate_reasoning_request(
        self,
        organization_id: UUID,
        model_name: str,
        provider_name: str,
        prompt: str,
        environment: str = "production-sim",
        custom_rules: dict[str, Any] | None = None,
    ) -> PolicyDecisionResult:
        """Evaluate if an AI reasoning operation is permitted under current policy."""
        data_class = self.classify_data(prompt)
        rules = custom_rules or {}

        # 1. Deny-by-default for SECRET data leaking into prompt without redaction
        if data_class == DataClassification.SECRET:
            return PolicyDecisionResult(
                allowed=False,
                risk_level=AIRiskLevel.CRITICAL,
                data_classification=data_class,
                reason="Context contains unredacted credentials or secrets; policy blocks execution.",
                policy_version=self.policy_version,
            )

        # 2. Provider whitelist check for sensitive data
        allowed_providers_for_sensitive = rules.get(
            "allowed_providers_for_sensitive", ["mock", "ollama", "openai-compatible"]
        )
        if data_class == DataClassification.SENSITIVE and provider_name not in allowed_providers_for_sensitive:
            return PolicyDecisionResult(
                allowed=False,
                risk_level=AIRiskLevel.HIGH,
                data_classification=data_class,
                reason=f"Provider '{provider_name}' is not authorized to process SENSITIVE tenant data.",
                policy_version=self.policy_version,
            )

        # 3. Model and provider whitelist check
        allowed_models = rules.get(
            "allowed_models",
            ["qwen2.5-coder:7b", "mock-v1", "mock-reasoner-v1", "aegis-fallback-mock", "gpt-4o-mini"],
        )
        if model_name not in allowed_models:

            return PolicyDecisionResult(
                allowed=False,
                risk_level=AIRiskLevel.HIGH,
                data_classification=data_class,
                reason=f"Model '{model_name}' is not permitted by model whitelist.",
                policy_version=self.policy_version,
            )

        # 4. Phase 5 reasoning operations are strictly READ_ONLY
        return PolicyDecisionResult(
            allowed=True,
            risk_level=AIRiskLevel.READ_ONLY,
            data_classification=data_class,
            reason="AI reasoning request meets READ_ONLY criteria and data classification boundaries.",
            requires_approval=False,
            policy_version=self.policy_version,
        )

    def evaluate_operation(self, risk_level: AIRiskLevel) -> PolicyDecisionResult:
        """Evaluate raw operational risk level for Phase 5 boundaries."""
        if risk_level in (AIRiskLevel.HIGH, AIRiskLevel.CRITICAL):
            return PolicyDecisionResult(
                allowed=False,
                risk_level=risk_level,
                data_classification=DataClassification.INTERNAL,
                reason=f"Operation with risk level '{risk_level.value}' is blocked in Phase 5.",
                policy_version=self.policy_version,
            )
        return PolicyDecisionResult(
            allowed=True,
            risk_level=risk_level,
            data_classification=DataClassification.INTERNAL,
            reason=f"Operation with risk level '{risk_level.value}' permitted under Phase 5.",
            policy_version=self.policy_version,
        )


    def evaluate_tool_request(
        self,
        tool_name: str,
        tool_risk_level: AIRiskLevel,
        is_read_only: bool,
        environment: str = "production-sim",
    ) -> PolicyDecisionResult:
        """Deny-by-default policy gate for tool execution requests."""
        # Phase 5 strictly permits only READ_ONLY tools
        if not is_read_only or tool_risk_level in (AIRiskLevel.HIGH, AIRiskLevel.CRITICAL):
            return PolicyDecisionResult(
                allowed=False,
                risk_level=tool_risk_level,
                data_classification=DataClassification.INTERNAL,
                reason=f"Tool '{tool_name}' with risk '{tool_risk_level.value}' is blocked; Phase 5 permits READ_ONLY tools only.",
                policy_version=self.policy_version,
            )

        return PolicyDecisionResult(
            allowed=True,
            risk_level=AIRiskLevel.READ_ONLY,
            data_classification=DataClassification.INTERNAL,
            reason=f"Read-only tool '{tool_name}' permitted under Phase 5 Trust Plane.",
            policy_version=self.policy_version,
        )


    def evaluate_remediation_proposal(
        self,
        risk_level: AIRiskLevel,
        environment: str = "production-sim",
        has_approval: bool = False,
        approver_count: int = 0,
        author_id: str | None = None,
        approver_id: str | None = None,
    ) -> PolicyDecisionResult:
        """Evaluates whether a Phase 6 remediation proposal is permitted to execute.

        - CRITICAL: Blocked by default.
        - HIGH: Requires authorized human approval; separation of duties (author != approver).
        - MEDIUM: Requires at least 1 human approval.
        - LOW / READ_ONLY: Allowed if preflight passes.
        """
        # 1. Critical operations are always blocked
        if risk_level == AIRiskLevel.CRITICAL:
            return PolicyDecisionResult(
                allowed=False,
                risk_level=risk_level,
                data_classification=DataClassification.INTERNAL,
                reason="CRITICAL risk remediations (e.g. destructive database changes) are blocked by policy.",
                policy_version=self.policy_version,
            )

        # 2. Separation of duties: Author cannot approve their own high-risk remediation
        if (
            risk_level in (AIRiskLevel.MEDIUM, AIRiskLevel.HIGH)
            and has_approval
            and author_id
            and approver_id
            and author_id == approver_id
        ):
            return PolicyDecisionResult(
                allowed=False,
                risk_level=risk_level,
                data_classification=DataClassification.INTERNAL,
                reason="Separation of duties violation: Remediation author cannot approve their own proposal.",
                policy_version=self.policy_version,
            )

        # 3. Check approval requirements
        if risk_level in (AIRiskLevel.MEDIUM, AIRiskLevel.HIGH) and (not has_approval or approver_count < 1):
            return PolicyDecisionResult(
                allowed=False,
                risk_level=risk_level,
                data_classification=DataClassification.INTERNAL,
                requires_approval=True,
                reason=f"Remediation requires explicit human approval before execution (Risk: {risk_level.value}).",
                policy_version=self.policy_version,
            )

        return PolicyDecisionResult(
            allowed=True,
            risk_level=risk_level,
            data_classification=DataClassification.INTERNAL,
            requires_approval=False,
            reason=f"Remediation policy validated for environment '{environment}' at risk '{risk_level.value}'.",
            policy_version=self.policy_version,
        )


default_policy_engine = AIPolicyEngine()

