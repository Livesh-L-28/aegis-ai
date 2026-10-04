"""Phase 6 Remediation Planner: Converts verified root cause and evidence into structured proposals."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from packages.intelligence.reasoning.validator import StructuredReasoningOutput
from packages.remediation.domain.enums import (
    RemediationActionType,
    RemediationStatus,
)
from packages.remediation.domain.models import (
    RemediationAction,
    RemediationProposal,
    RollbackPlan,
    ValidationPlan,
)
from packages.remediation.domain.risk import RemediationRiskEngine, default_risk_engine
from packages.security.policy import AIRiskLevel


class RemediationPlanner:
    """Generates structured, verifiable remediation proposals based on evidence and root cause."""

    def __init__(self, risk_engine: RemediationRiskEngine = default_risk_engine) -> None:
        self.risk_engine = risk_engine

    def plan_remediation(
        self,
        incident_id: UUID,
        organization_id: UUID,
        service_name: str,
        reasoning_result: StructuredReasoningOutput,
        environment: str = "production-sim",
        dependencies: list[str] | None = None,
        actor_id: str = "aegis-remediation-engine",
        expires_in_hours: int = 24,
    ) -> RemediationProposal:
        """Constructs a typed RemediationProposal tailored to the incident's isolated root cause."""
        root_cause = reasoning_result.root_cause
        root_lower = root_cause.lower()

        actions: list[RemediationAction] = []
        validation_plan = ValidationPlan(
            metric_checks=[{"metric": "http_request_duration_seconds", "operator": "<", "threshold": 0.5}],
            health_endpoint=f"http://{service_name}:8000/health",
            telemetry_window_seconds=15,
            success_criteria="Service latency normalizes and error rates return to baseline",
        )
        rollback_plan: RollbackPlan

        # Canonical Action mapping by root cause
        if "redis" in root_lower or "cache" in root_lower:
            actions.append(
                RemediationAction(
                    action_type=RemediationActionType.CACHE_INVALIDATION,
                    target=service_name,
                    parameters={"service_name": service_name, "cache_key": "payment_ledger_*"},
                    risk_level=AIRiskLevel.LOW,
                    validation_step="Verify redis error counter stops incrementing",
                    rollback_step="None required for cache flush",
                )
            )
            actions.append(
                RemediationAction(
                    action_type=RemediationActionType.SERVICE_RESTART,
                    target=service_name,
                    parameters={"service_name": service_name, "grace_period_seconds": 5},
                    risk_level=AIRiskLevel.LOW,
                    validation_step="Verify container health check returns healthy",
                    rollback_step="Restart again if container unhealthy",
                )
            )
            rollback_plan = RollbackPlan(
                action_type=RemediationActionType.SERVICE_RESTART,
                target=service_name,
                parameters={"service_name": service_name},
                verification_step="Restart service to restore initial state",
            )
        elif "latency" in root_lower or "postgres" in root_lower or "database" in root_lower:
            actions.append(
                RemediationAction(
                    action_type=RemediationActionType.CONFIG_CHANGE,
                    target=service_name,
                    parameters={"service_name": service_name, "key": "db_query_timeout_ms", "value": 2000},
                    risk_level=AIRiskLevel.MEDIUM,
                    validation_step="Verify query latency metrics drop below 500ms",
                    rollback_step="Revert db_query_timeout_ms to default",
                )
            )
            rollback_plan = RollbackPlan(
                action_type=RemediationActionType.CONFIG_CHANGE,
                target=service_name,
                parameters={"service_name": service_name, "key": "db_query_timeout_ms", "value": 5000},
                verification_step="Verify database configuration reset",
            )
        elif "regression" in root_lower or "deployment" in root_lower or "v1.1" in root_lower:
            actions.append(
                RemediationAction(
                    action_type=RemediationActionType.ROLLBACK,
                    target=service_name,
                    parameters={"service_name": service_name, "target_version": "1.0.0"},
                    risk_level=AIRiskLevel.HIGH,
                    validation_step="Verify orders_failed_total decreases to 0",
                    rollback_step="Re-deploy target version 1.1.0 if rollback fails",
                )
            )
            rollback_plan = RollbackPlan(
                action_type=RemediationActionType.DEPLOYMENT,
                target=service_name,
                parameters={"service_name": service_name, "target_version": "1.1.0"},
                verification_step="Re-deploy original release",
            )
        else:
            # Default fallback safe restart
            actions.append(
                RemediationAction(
                    action_type=RemediationActionType.SERVICE_RESTART,
                    target=service_name,
                    parameters={"service_name": service_name, "grace_period_seconds": 10},
                    risk_level=AIRiskLevel.LOW,
                    validation_step="Verify service responds 200 on /health",
                    rollback_step="None",
                )
            )
            rollback_plan = RollbackPlan(
                action_type=RemediationActionType.SERVICE_RESTART,
                target=service_name,
                parameters={"service_name": service_name},
            )

        # Calculate server-side risk level and blast radius
        final_risk = self.risk_engine.evaluate_proposal_risk(actions, environment)
        blast_radius = self.risk_engine.calculate_blast_radius(service_name, dependencies, environment)

        now = datetime.now(UTC)
        proposal = RemediationProposal(
            incident_id=incident_id,
            organization_id=organization_id,
            service_name=service_name,
            title=f"Automated Remediation Plan for {service_name}",
            description=f"Remediation addressing root cause: '{root_cause}' with impact mitigation.",
            root_cause_reference=root_cause,
            evidence_ids=[str(e) for e in reasoning_result.supporting_evidence_ids],
            risk_level=final_risk,
            status=RemediationStatus.PROPOSED,
            actions=actions,
            blast_radius=blast_radius,
            validation_plan=validation_plan,
            rollback_plan=rollback_plan,
            created_by=actor_id,
            created_at=now,
            expires_at=now + timedelta(hours=expires_in_hours),
        )

        proposal.remediation_hash = proposal.compute_remediation_hash()
        return proposal


default_remediation_planner = RemediationPlanner()
