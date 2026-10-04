"""Phase 6 Action Registry and Action Definitions."""

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

from packages.remediation.domain.enums import RemediationActionType
from packages.security.policy import AIRiskLevel


class ActionDefinition(BaseModel):
    action_type: RemediationActionType
    name: str
    description: str
    schema_definition: dict[str, Any] = Field(default_factory=dict)
    default_risk_level: AIRiskLevel = AIRiskLevel.MEDIUM
    allowed_environments: list[str] = Field(default_factory=lambda: ["production-sim", "development", "staging"])
    preconditions: list[str] = Field(default_factory=list)
    timeout_seconds: int = 60
    supports_rollback: bool = True


class RemediationActionRegistry:
    """Strict registry of permitted, typed remediation action schemas and handlers. Denies unknown actions."""

    def __init__(self) -> None:
        self._definitions: dict[RemediationActionType, ActionDefinition] = {}
        self._handlers: dict[RemediationActionType, Callable[..., Any]] = {}
        self._register_default_actions()

    def register_action(
        self,
        definition: ActionDefinition,
        handler: Callable[..., Any] | None = None,
    ) -> None:
        self._definitions[definition.action_type] = definition
        if handler:
            self._handlers[definition.action_type] = handler

    def get_definition(self, action_type: RemediationActionType) -> ActionDefinition | None:
        return self._definitions.get(action_type)

    def validate_action(self, action_type: RemediationActionType, parameters: dict[str, Any]) -> tuple[bool, str]:
        definition = self.get_definition(action_type)
        if not definition:
            return False, f"Action type '{action_type.value}' is not registered in RemediationActionRegistry (Deny-by-default)."

        # Validate required parameters
        required = definition.schema_definition.get("required", [])
        for field in required:
            if field not in parameters:
                return False, f"Missing required parameter '{field}' for action '{action_type.value}'."

        return True, "Valid action schema"

    def _register_default_actions(self) -> None:
        self.register_action(
            ActionDefinition(
                action_type=RemediationActionType.SERVICE_RESTART,
                name="Restart Service Instance",
                description="Gracefully restarts target service container or simulation instance to clear transient state.",
                schema_definition={
                    "type": "object",
                    "required": ["service_name"],
                    "properties": {
                        "service_name": {"type": "string"},
                        "grace_period_seconds": {"type": "integer"},
                    },
                },
                default_risk_level=AIRiskLevel.LOW,
            )
        )
        self.register_action(
            ActionDefinition(
                action_type=RemediationActionType.CONFIG_CHANGE,
                name="Update Runtime Configuration",
                description="Mutates typed service configuration parameter (e.g. database pool, timeout, cache ttl).",
                schema_definition={
                    "type": "object",
                    "required": ["service_name", "key", "value"],
                    "properties": {
                        "service_name": {"type": "string"},
                        "key": {"type": "string"},
                        "value": {"type": "any"},
                    },
                },
                default_risk_level=AIRiskLevel.MEDIUM,
            )
        )
        self.register_action(
            ActionDefinition(
                action_type=RemediationActionType.DEPLOYMENT,
                name="Deploy Service Version",
                description="Rolls forward service to target validated release version.",
                schema_definition={
                    "type": "object",
                    "required": ["service_name", "target_version"],
                    "properties": {
                        "service_name": {"type": "string"},
                        "target_version": {"type": "string"},
                    },
                },
                default_risk_level=AIRiskLevel.HIGH,
            )
        )
        self.register_action(
            ActionDefinition(
                action_type=RemediationActionType.ROLLBACK,
                name="Rollback Service Release",
                description="Restores service to previous known-good deployment artifact.",
                schema_definition={
                    "type": "object",
                    "required": ["service_name", "target_version"],
                    "properties": {
                        "service_name": {"type": "string"},
                        "target_version": {"type": "string"},
                    },
                },
                default_risk_level=AIRiskLevel.HIGH,
            )
        )
        self.register_action(
            ActionDefinition(
                action_type=RemediationActionType.CODE_PATCH,
                name="Apply Controlled Code Patch",
                description="Applies validated unified diff patch via branch, pull request, and CI pipeline.",
                schema_definition={
                    "type": "object",
                    "required": ["repo_name", "diff", "branch_name"],
                    "properties": {
                        "repo_name": {"type": "string"},
                        "diff": {"type": "string"},
                        "branch_name": {"type": "string"},
                    },
                },
                default_risk_level=AIRiskLevel.HIGH,
            )
        )
        self.register_action(
            ActionDefinition(
                action_type=RemediationActionType.CACHE_INVALIDATION,
                name="Flush / Invalidate Cache Key",
                description="Evicts corrupt or stale cache entries from Redis cache.",
                schema_definition={
                    "type": "object",
                    "required": ["service_name", "cache_key"],
                    "properties": {
                        "service_name": {"type": "string"},
                        "cache_key": {"type": "string"},
                    },
                },
                default_risk_level=AIRiskLevel.LOW,
            )
        )


default_action_registry = RemediationActionRegistry()
