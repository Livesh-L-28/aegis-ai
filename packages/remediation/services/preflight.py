"""Phase 6 Preflight Validator: Verifies environments, targets, schema, and approval integrity."""

from datetime import UTC, datetime

from packages.remediation.domain.models import (
    PreflightResult,
    RemediationApproval,
    RemediationProposal,
)
from packages.remediation.domain.registry import (
    RemediationActionRegistry,
    default_action_registry,
)
from packages.security.policy import AIRiskLevel, default_policy_engine


class PreflightValidator:
    """Preflight validation engine executed immediately prior to sandbox execution."""

    def __init__(
        self,
        registry: RemediationActionRegistry = default_action_registry,
    ) -> None:
        self.registry = registry
        self.policy_engine = default_policy_engine

    def validate_preflight(
        self,
        proposal: RemediationProposal,
        approval: RemediationApproval | None = None,
        environment: str = "production-sim",
    ) -> PreflightResult:
        errors: list[str] = []
        details: dict = {}

        # 1. Target and Service check
        service_exists = bool(proposal.service_name and proposal.service_name.strip())
        if not service_exists:
            errors.append("Target service name is undefined.")

        target_exists = all(bool(a.target and a.target.strip()) for a in proposal.actions)
        if not target_exists:
            errors.append("One or more actions have missing target resource.")

        # 2. Schema check on each action
        schemas_valid = True
        for action in proposal.actions:
            valid, msg = self.registry.validate_action(action.action_type, action.parameters)
            if not valid:
                schemas_valid = False
                errors.append(f"Action '{action.action_type.value}' schema invalid: {msg}")

        # 3. Rollback availability check for MEDIUM/HIGH actions
        rollback_available = bool(
            proposal.rollback_plan and proposal.rollback_plan.target and proposal.rollback_plan.action_type
        )
        if proposal.risk_level in (AIRiskLevel.MEDIUM, AIRiskLevel.HIGH) and not rollback_available:
            errors.append("Rollback plan is required for MEDIUM/HIGH risk remediations.")

        # 4. Hash integrity check
        current_hash = proposal.compute_remediation_hash()
        hash_intact = proposal.remediation_hash == current_hash
        if not hash_intact:
            errors.append("Remediation proposal hash mismatch; content was modified.")

        # 5. Approval validation
        approval_valid = True
        if proposal.risk_level in (AIRiskLevel.MEDIUM, AIRiskLevel.HIGH):
            if not approval:
                approval_valid = False
                errors.append("Human approval is required for this risk level.")
            else:
                now = datetime.now(UTC)
                exp = approval.expires_at if approval.expires_at.tzinfo else approval.expires_at.replace(tzinfo=UTC)
                if now > exp:
                    approval_valid = False
                    errors.append("Approval has expired.")
                if approval.remediation_hash != current_hash:
                    approval_valid = False
                    errors.append("Approval was granted for a different remediation version (hash mismatch).")

        passed = len(errors) == 0
        details["action_count"] = len(proposal.actions)
        details["risk_level"] = proposal.risk_level.value
        details["environment"] = environment

        return PreflightResult(
            passed=passed,
            remediation_id=proposal.id,
            remediation_hash=current_hash,
            target_exists=target_exists,
            service_exists=service_exists,
            schema_valid=schemas_valid,
            rollback_available=rollback_available,
            approval_valid=approval_valid,
            hash_intact=hash_intact,
            details=details,
            errors=errors,
        )


default_preflight_validator = PreflightValidator()
