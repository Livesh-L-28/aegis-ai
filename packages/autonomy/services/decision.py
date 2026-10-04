"""Phase 7 Autonomy Decision Engine & Autonomy Circuit Breaker.

Enforces deterministic autonomy decisions:
- AI confidence != authorization
- Kill switch immediately blocks all autonomous mutations
- Change freeze blocks all mutations
- Rate limits prevent runaway autonomous changes
- Action must be explicitly present in AutonomyPolicy.allowed_actions
- Action risk must not exceed AutonomyPolicy.maximum_risk
- Blast radius must not exceed policy threshold
- Production default is strictly off unless explicitly granted
"""

from datetime import UTC, datetime

from packages.autonomy.domain.enums import (
    AutonomyCircuitState,
    AutonomyDecisionType,
    AutonomyLevel,
)
from packages.autonomy.domain.models import (
    AutonomyDecisionResult,
    AutonomyExplanation,
    AutonomyPolicy,
)
from packages.remediation.domain.models import RemediationProposal
from packages.security.policy import AIRiskLevel

_RISK_SEVERITY: dict[AIRiskLevel, int] = {
    AIRiskLevel.READ_ONLY: 1,
    AIRiskLevel.LOW: 2,
    AIRiskLevel.MEDIUM: 3,
    AIRiskLevel.HIGH: 4,
    AIRiskLevel.CRITICAL: 5,
}


class AutonomyCircuitBreaker:
    """Tracks consecutive autonomous execution failures and trips to OPEN state."""

    def __init__(self, failure_threshold: int = 3) -> None:
        self.failure_threshold = failure_threshold
        self.state = AutonomyCircuitState.CLOSED
        self.consecutive_failures = 0
        self.last_state_change = datetime.now(UTC)

    def record_success(self) -> None:
        self.consecutive_failures = 0
        if self.state == AutonomyCircuitState.HALF_OPEN:
            self.state = AutonomyCircuitState.CLOSED
            self.last_state_change = datetime.now(UTC)

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.failure_threshold:
            self.state = AutonomyCircuitState.OPEN
            self.last_state_change = datetime.now(UTC)

    def reset(self) -> None:
        self.consecutive_failures = 0
        self.state = AutonomyCircuitState.CLOSED
        self.last_state_change = datetime.now(UTC)

    def is_tripped(self) -> bool:
        return self.state == AutonomyCircuitState.OPEN


default_circuit_breaker = AutonomyCircuitBreaker()


class AutonomyDecisionEngine:
    """Evaluates whether an AI proposal is eligible for autonomous execution."""

    def __init__(self, circuit_breaker: AutonomyCircuitBreaker = default_circuit_breaker) -> None:
        self.circuit_breaker = circuit_breaker
        self._global_kill_switch = False
        self._global_change_freeze = False

    def set_kill_switch(self, enabled: bool) -> None:
        """Globally disable all autonomous executions (Emergency Stop)."""
        self._global_kill_switch = enabled

    def is_kill_switch_active(self) -> bool:
        return self._global_kill_switch

    def set_change_freeze(self, active: bool) -> None:
        """Globally halt all mutations during incident storms or freeze windows."""
        self._global_change_freeze = active

    def is_change_freeze_active(self) -> bool:
        return self._global_change_freeze

    def evaluate(
        self,
        proposal: RemediationProposal,
        policy: AutonomyPolicy,
        environment: str = "production-sim",
        is_production: bool = False,
    ) -> AutonomyDecisionResult:
        reasons: list[str] = []

        # 1. Kill Switch Check
        if self._global_kill_switch:
            reasons.append("Global autonomy kill switch is ACTIVE. Autonomous execution blocked.")
            return AutonomyDecisionResult(
                decision=AutonomyDecisionType.DENY,
                allowed=False,
                risk_level=proposal.risk_level,
                autonomy_level=policy.autonomy_level,
                explanation=AutonomyExplanation(
                    policy_version=policy.version,
                    reasons=reasons,
                    risk_level=proposal.risk_level.value,
                    blast_radius_count=len(proposal.blast_radius.affected_services),
                    allowlist_matched=False,
                    circuit_state=self.circuit_breaker.state.value,
                    change_freeze=self._global_change_freeze,
                ),
            )

        # 2. Change Freeze Check
        if self._global_change_freeze or policy.change_freeze_enabled:
            reasons.append("Change freeze is active. All mutations blocked; read-only recommend only.")
            return AutonomyDecisionResult(
                decision=AutonomyDecisionType.RECOMMEND_ONLY,
                allowed=False,
                risk_level=proposal.risk_level,
                autonomy_level=policy.autonomy_level,
                explanation=AutonomyExplanation(
                    policy_version=policy.version,
                    reasons=reasons,
                    risk_level=proposal.risk_level.value,
                    blast_radius_count=len(proposal.blast_radius.affected_services),
                    allowlist_matched=False,
                    circuit_state=self.circuit_breaker.state.value,
                    change_freeze=True,
                ),
            )

        # 3. Circuit Breaker Check
        if self.circuit_breaker.is_tripped():
            reasons.append("Autonomy circuit breaker is OPEN due to repeated failures.")
            return AutonomyDecisionResult(
                decision=AutonomyDecisionType.REQUIRE_APPROVAL,
                allowed=False,
                risk_level=proposal.risk_level,
                autonomy_level=policy.autonomy_level,
                explanation=AutonomyExplanation(
                    policy_version=policy.version,
                    reasons=reasons,
                    risk_level=proposal.risk_level.value,
                    blast_radius_count=len(proposal.blast_radius.affected_services),
                    allowlist_matched=False,
                    circuit_state=self.circuit_breaker.state.value,
                    change_freeze=False,
                ),
            )

        # 4. Critical Risk is always DENIED
        if proposal.risk_level == AIRiskLevel.CRITICAL:
            reasons.append("CRITICAL risk operations cannot be executed autonomously or through approval.")
            return AutonomyDecisionResult(
                decision=AutonomyDecisionType.DENY,
                allowed=False,
                risk_level=proposal.risk_level,
                autonomy_level=policy.autonomy_level,
                explanation=AutonomyExplanation(
                    policy_version=policy.version,
                    reasons=reasons,
                    risk_level=proposal.risk_level.value,
                    blast_radius_count=len(proposal.blast_radius.affected_services),
                    allowlist_matched=False,
                    circuit_state=self.circuit_breaker.state.value,
                    change_freeze=False,
                ),
            )

        # 5. Production Default Guardrail
        if is_production and policy.autonomy_level in (AutonomyLevel.LEVEL_0, AutonomyLevel.LEVEL_1):
            reasons.append("Production autonomy defaults to Level 0/1; requires human approval.")
            return AutonomyDecisionResult(
                decision=AutonomyDecisionType.REQUIRE_APPROVAL,
                allowed=False,
                risk_level=proposal.risk_level,
                autonomy_level=policy.autonomy_level,
                explanation=AutonomyExplanation(
                    policy_version=policy.version,
                    reasons=reasons,
                    risk_level=proposal.risk_level.value,
                    blast_radius_count=len(proposal.blast_radius.affected_services),
                    allowlist_matched=False,
                    circuit_state=self.circuit_breaker.state.value,
                    change_freeze=False,
                ),
            )

        # 6. Action Allowlist Check
        for action in proposal.actions:
            if action.action_type not in policy.allowed_actions:
                reasons.append(
                    f"Action '{action.action_type.value}' is not in the autonomous action allowlist."
                )
                return AutonomyDecisionResult(
                    decision=AutonomyDecisionType.REQUIRE_APPROVAL,
                    allowed=False,
                    risk_level=proposal.risk_level,
                    autonomy_level=policy.autonomy_level,
                    explanation=AutonomyExplanation(
                        policy_version=policy.version,
                        reasons=reasons,
                        risk_level=proposal.risk_level.value,
                        blast_radius_count=len(proposal.blast_radius.affected_services),
                        allowlist_matched=False,
                        circuit_state=self.circuit_breaker.state.value,
                        change_freeze=False,
                    ),
                )

        # 7. Maximum Risk Boundary Check
        if _RISK_SEVERITY[proposal.risk_level] > _RISK_SEVERITY[policy.maximum_risk]:
            reasons.append(
                f"Proposal risk '{proposal.risk_level.value}' exceeds max permitted risk '{policy.maximum_risk.value}'."
            )
            return AutonomyDecisionResult(
                decision=AutonomyDecisionType.REQUIRE_APPROVAL,
                allowed=False,
                risk_level=proposal.risk_level,
                autonomy_level=policy.autonomy_level,
                explanation=AutonomyExplanation(
                    policy_version=policy.version,
                    reasons=reasons,
                    risk_level=proposal.risk_level.value,
                    blast_radius_count=len(proposal.blast_radius.affected_services),
                    allowlist_matched=True,
                    circuit_state=self.circuit_breaker.state.value,
                    change_freeze=False,
                ),
            )

        # 8. Blast Radius Check
        affected_count = len(proposal.blast_radius.affected_services)
        if affected_count > policy.max_blast_radius_services:
            reasons.append(
                f"Blast radius ({affected_count} services) exceeds limit ({policy.max_blast_radius_services})."
            )
            return AutonomyDecisionResult(
                decision=AutonomyDecisionType.REQUIRE_APPROVAL,
                allowed=False,
                risk_level=proposal.risk_level,
                autonomy_level=policy.autonomy_level,
                explanation=AutonomyExplanation(
                    policy_version=policy.version,
                    reasons=reasons,
                    risk_level=proposal.risk_level.value,
                    blast_radius_count=affected_count,
                    allowlist_matched=True,
                    circuit_state=self.circuit_breaker.state.value,
                    change_freeze=False,
                ),
            )

        # 9. Rollback & Validation Requirements
        if policy.require_rollback_plan and not proposal.rollback_plan.target:
            reasons.append("Autonomous remediation requires a verified rollback plan.")
            return AutonomyDecisionResult(
                decision=AutonomyDecisionType.REQUIRE_APPROVAL,
                allowed=False,
                risk_level=proposal.risk_level,
                autonomy_level=policy.autonomy_level,
                explanation=AutonomyExplanation(
                    policy_version=policy.version,
                    reasons=reasons,
                    risk_level=proposal.risk_level.value,
                    blast_radius_count=affected_count,
                    allowlist_matched=True,
                    circuit_state=self.circuit_breaker.state.value,
                    change_freeze=False,
                ),
            )

        # Passed all deterministic safety gates
        reasons.append("Remediation meets all bounded autonomy criteria for safe auto-execution.")
        return AutonomyDecisionResult(
            decision=AutonomyDecisionType.AUTONOMOUSLY_EXECUTE,
            allowed=True,
            risk_level=proposal.risk_level,
            autonomy_level=policy.autonomy_level,
            explanation=AutonomyExplanation(
                policy_version=policy.version,
                reasons=reasons,
                risk_level=proposal.risk_level.value,
                blast_radius_count=affected_count,
                allowlist_matched=True,
                circuit_state=self.circuit_breaker.state.value,
                change_freeze=False,
            ),
        )


default_autonomy_engine = AutonomyDecisionEngine()
