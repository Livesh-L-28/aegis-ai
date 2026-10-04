"""Phase 6 Controlled Sandbox Executor: Safe typed execution without shell execution."""

from datetime import UTC, datetime
from typing import Any

from packages.logging.logger import get_logger
from packages.remediation.domain.enums import (
    ExecutionStatus,
    RemediationActionType,
    RemediationStatus,
)
from packages.remediation.domain.models import (
    PreflightResult,
    RemediationAction,
    RemediationExecution,
    RemediationProposal,
)
from packages.remediation.domain.registry import (
    RemediationActionRegistry,
    default_action_registry,
)
from packages.security.llm_firewall.adapter import (
    FirewallDecisionAction,
    LLMFirewall,
    default_llm_firewall,
)
from packages.simulation.deployments import DeploymentEvent, deployment_registry
from packages.simulation.scenarios import FaultType, simulation_registry

logger = get_logger("aegis.remediation.executor")


class RemediationSandboxExecutor:
    """Executes validated remediation actions in a controlled sandbox without shell access.

    Translates typed actions into simulated environment mutations and restores health.
    """

    def __init__(
        self,
        registry: RemediationActionRegistry = default_action_registry,
        firewall: LLMFirewall = default_llm_firewall,
    ) -> None:
        self.registry = registry
        self.firewall = firewall

    async def execute_proposal(
        self,
        proposal: RemediationProposal,
        preflight: PreflightResult,
        dry_run: bool = False,
        executor_id: str = "system",
        environment: str = "production-sim",
    ) -> RemediationExecution:
        execution = RemediationExecution(
            remediation_id=proposal.id,
            executor_id=executor_id,
            environment=environment,
            target=proposal.service_name,
            preflight_result=preflight,
            status=ExecutionStatus.PREFLIGHT,
        )

        if not preflight.passed:
            execution.status = ExecutionStatus.FAILED
            execution.error = f"Preflight validation failed: {'; '.join(preflight.errors)}"
            proposal.status = RemediationStatus.FAILED
            return execution

        if dry_run:
            execution.status = ExecutionStatus.AUTHORIZED
            execution.completed_at = datetime.now(UTC)
            return execution

        execution.status = ExecutionStatus.EXECUTING
        proposal.status = RemediationStatus.EXECUTING

        results: list[dict[str, Any]] = []
        for action in proposal.actions:
            # 1. Gate: Firewall check on action parameters
            fw_res = self.firewall.inspect_tool_call(
                tool_name=action.action_type.value,
                arguments=action.parameters,
            )
            if not fw_res.allowed or fw_res.action == FirewallDecisionAction.BLOCK:
                execution.status = ExecutionStatus.FAILED
                execution.error = f"Action blocked by LLM Firewall: {fw_res.reason}"
                proposal.status = RemediationStatus.FAILED
                return execution

            # 2. Execute typed action in simulation environment
            try:
                res = await self._execute_typed_action(action, environment)
                results.append(res)
            except Exception as exc:
                logger.error("Action execution error on %s: %s", action.action_type, exc)
                execution.status = ExecutionStatus.FAILED
                execution.error = str(exc)
                proposal.status = RemediationStatus.FAILED
                return execution

        execution.validation_result = {"action_results": results}
        execution.status = ExecutionStatus.VALIDATING
        proposal.status = RemediationStatus.VALIDATING
        return execution

    async def _execute_typed_action(
        self,
        action: RemediationAction,
        environment: str,
    ) -> dict[str, Any]:
        """Maps typed remediation actions to realistic simulation runtime operations."""
        atype = action.action_type
        params = action.parameters

        if atype == RemediationActionType.SERVICE_RESTART:
            service = params.get("service_name", action.target)
            # In simulation, deactivates active ephemeral connection failures
            for scenario in simulation_registry.list_all():
                if (
                    scenario.enabled
                    and scenario.target_service == service
                    and scenario.fault_type in (FaultType.REDIS_FAILURE, FaultType.SERVICE_ERROR_RATE)
                ):
                    simulation_registry.deactivate(scenario.id)
            return {"action": "restart", "service": service, "status": "completed"}

        elif atype == RemediationActionType.CONFIG_CHANGE:
            service = params.get("service_name", action.target)
            key = params.get("key")
            value = params.get("value")
            # In simulation, deactivates latency faults
            for scenario in simulation_registry.list_all():
                if (
                    scenario.enabled
                    and scenario.target_service == service
                    and scenario.fault_type in (FaultType.DATABASE_LATENCY, FaultType.SERVICE_LATENCY)
                ):
                    simulation_registry.deactivate(scenario.id)
            return {"action": "config_change", "key": key, "value": value, "status": "completed"}

        elif atype == RemediationActionType.CACHE_INVALIDATION:
            service = params.get("service_name", action.target)
            cache_key = params.get("cache_key", "*")
            # Deactivate redis failure in simulation
            redis_scenario = simulation_registry.get("INC-002")
            if redis_scenario and redis_scenario.enabled:
                simulation_registry.deactivate("INC-002")
            return {"action": "cache_invalidation", "cache_key": cache_key, "status": "completed"}

        elif atype in (RemediationActionType.DEPLOYMENT, RemediationActionType.ROLLBACK):
            service = params.get("service_name", action.target)
            target_version = params.get("target_version", "1.0.0")
            # Record deployment event
            deployment_registry.record(
                DeploymentEvent(
                    service_name=service,
                    version=target_version,
                    environment=environment,
                    metadata={"remediation_action": atype.value},
                )
            )
            # If deployment regression is active, rollback deactivates it
            reg_scenario = simulation_registry.get("INC-005")
            if reg_scenario and reg_scenario.enabled:
                simulation_registry.deactivate("INC-005")
            return {"action": atype.value, "version": target_version, "status": "completed"}

        elif atype == RemediationActionType.CODE_PATCH:
            repo = params.get("repo_name", "aegis-core")
            branch = params.get("branch_name", "remediation-patch")
            return {"action": "code_patch", "repo": repo, "branch": branch, "status": "applied"}

        return {"action": atype.value, "status": "unhandled"}

    async def execute_rollback(
        self,
        proposal: RemediationProposal,
        environment: str = "production-sim",
    ) -> dict[str, Any]:
        """Rollback restores the service to baseline known-good state."""
        rb = proposal.rollback_plan
        action = RemediationAction(
            action_type=rb.action_type,
            target=rb.target or proposal.service_name,
            parameters=rb.parameters,
        )
        res = await self._execute_typed_action(action, environment)
        proposal.status = RemediationStatus.ROLLED_BACK
        return res


default_sandbox_executor = RemediationSandboxExecutor()
