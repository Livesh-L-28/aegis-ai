"""Phase 6 Remediation Risk Engine and Blast Radius Analysis."""

from packages.remediation.domain.enums import RemediationActionType
from packages.remediation.domain.models import BlastRadiusReport, RemediationAction
from packages.remediation.domain.registry import (
    RemediationActionRegistry,
    default_action_registry,
)
from packages.security.policy import AIRiskLevel

_RISK_ORDER = {
    AIRiskLevel.READ_ONLY: 1,
    AIRiskLevel.LOW: 2,
    AIRiskLevel.MEDIUM: 3,
    AIRiskLevel.HIGH: 4,
    AIRiskLevel.CRITICAL: 5,
}

_ACTION_BASE_RISKS: dict[RemediationActionType, AIRiskLevel] = {
    RemediationActionType.SERVICE_RESTART: AIRiskLevel.LOW,
    RemediationActionType.CACHE_INVALIDATION: AIRiskLevel.LOW,
    RemediationActionType.CONFIG_CHANGE: AIRiskLevel.MEDIUM,
    RemediationActionType.SCALING: AIRiskLevel.MEDIUM,
    RemediationActionType.CODE_PATCH: AIRiskLevel.HIGH,
    RemediationActionType.DEPLOYMENT: AIRiskLevel.HIGH,
    RemediationActionType.ROLLBACK: AIRiskLevel.HIGH,
}


class RemediationRiskEngine:
    """Calculates server-side immutable risk levels and computes architectural blast radius.

    AI proposals cannot downgrade risk. Max action risk governs total proposal risk.
    """

    def __init__(self, action_registry: RemediationActionRegistry = default_action_registry) -> None:
        self.registry = action_registry

    def evaluate_proposal_risk(
        self,
        actions: list[RemediationAction],
        environment: str = "production-sim",
    ) -> AIRiskLevel:
        """Determines final risk as MAX(all individual action calculated risks)."""
        if not actions:
            return AIRiskLevel.READ_ONLY

        max_risk = AIRiskLevel.READ_ONLY
        for action in actions:
            action_risk = self.evaluate_action_risk(action, environment)
            action.risk_level = action_risk
            if _RISK_ORDER[action_risk] > _RISK_ORDER[max_risk]:
                max_risk = action_risk

        return max_risk

    def evaluate_action_risk(
        self,
        action: RemediationAction,
        environment: str = "production-sim",
    ) -> AIRiskLevel:
        base_risk = _ACTION_BASE_RISKS.get(action.action_type, AIRiskLevel.HIGH)

        # Destructive or production environment escalation
        params = action.parameters
        if params.get("drop_database") or params.get("truncate_table") or params.get("destructive"):
            return AIRiskLevel.CRITICAL

        if environment == "production" and base_risk == AIRiskLevel.MEDIUM:
            # Escalate configuration mutations in live production to HIGH
            return AIRiskLevel.HIGH

        return base_risk

    def calculate_blast_radius(
        self,
        service_name: str,
        dependencies: list[str] | None = None,
        environment: str = "production-sim",
    ) -> BlastRadiusReport:
        deps = dependencies or []
        affected = [service_name]
        for d in deps:
            if d not in affected:
                affected.append(d)

        return BlastRadiusReport(
            affected_services=affected,
            affected_dependencies=deps,
            affected_environments=[environment],
            estimated_impact_description=(
                f"Remediation target '{service_name}' affects {len(affected)} services and dependencies: {', '.join(affected)}."
            ),
        )


default_risk_engine = RemediationRiskEngine()
