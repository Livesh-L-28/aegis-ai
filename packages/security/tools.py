"""Read-only Tool Gateway, Tool Registry, Tool Policy, and Deny-by-Default Validation."""

from collections.abc import Callable
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from packages.security.llm_firewall.adapter import (
    FirewallDecisionAction,
    LLMFirewall,
    default_llm_firewall,
)
from packages.security.policy import (
    AIPolicyEngine,
    AIRiskLevel,
    default_policy_engine,
)


class ToolDefinition(BaseModel):
    name: str
    description: str
    risk_level: AIRiskLevel = AIRiskLevel.READ_ONLY
    is_read_only: bool = True
    parameters_schema: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: float = 5.0
    enabled: bool = True


class ToolExecutionResult(BaseModel):
    tool_name: str
    allowed: bool
    status: str  # "SUCCESS" | "DENIED" | "FAILED"
    result: Any = None
    reason: str = ""
    risk_level: AIRiskLevel = AIRiskLevel.READ_ONLY
    duration_ms: float = 0.0


class ToolGateway:
    """Governed Tool Execution Gateway with Deny-by-Default validation, firewall inspection, and policy enforcement."""

    def __init__(
        self,
        firewall: LLMFirewall = default_llm_firewall,
        policy_engine: AIPolicyEngine = default_policy_engine,
    ) -> None:
        self.firewall = firewall
        self.policy_engine = policy_engine
        self._registry: dict[str, ToolDefinition] = {}
        self._handlers: dict[str, Callable[..., Any]] = {}
        self._register_default_read_only_tools()

    def register_tool(
        self,
        tool_def: ToolDefinition,
        handler: Callable[..., Any] | None = None,
    ) -> None:
        self._registry[tool_def.name] = tool_def
        if handler:
            self._handlers[tool_def.name] = handler
        elif hasattr(tool_def, "handler"):
            self._handlers[tool_def.name] = tool_def.handler

    def _register_default_read_only_tools(self) -> None:
        # Register safe conceptual read-only tools
        self.register_tool(
            ToolDefinition(
                name="get_service_metadata",
                description="Retrieve runtime service status and configuration metadata",
                risk_level=AIRiskLevel.READ_ONLY,
                is_read_only=True,
                parameters_schema={"type": "object", "required": ["service_name"], "properties": {"service_name": {"type": "string"}}},
            ),
            lambda service_name="order-service": {"service": service_name, "status": "active", "environment": "production-sim"},
        )
        self.register_tool(
            ToolDefinition(
                name="get_dependency_graph",
                description="Retrieve architectural dependency map for service",
                risk_level=AIRiskLevel.READ_ONLY,
                is_read_only=True,
                parameters_schema={"type": "object"},
            ),
            lambda: {"edges": ["order-service->postgres", "payment-service->redis"]},
        )

    async def execute_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        organization_id: UUID | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
    ) -> ToolExecutionResult:
        """Strict execution flow:

        1. Registry check (Unknown tools -> DENY)
        2. Policy Engine check (Write / Dangerous tools -> DENY)
        3. Schema validation check (Missing parameters -> DENY)
        4. LLM Firewall check (Malicious commands/arguments -> DENY)
        5. Safe execution
        """
        args = arguments or {}

        # 1. Deny unknown tools by default
        if tool_name not in self._registry or not self._registry[tool_name].enabled:
            return ToolExecutionResult(
                tool_name=tool_name,
                allowed=False,
                status="DENIED",
                reason=f"Tool '{tool_name}' is not registered or disabled (Deny-by-default).",
                risk_level=AIRiskLevel.CRITICAL,
            )

        tool_def = self._registry[tool_name]

        # 2. Programmatic Policy Engine evaluation
        policy_res = self.policy_engine.evaluate_tool_request(
            tool_name=tool_def.name,
            tool_risk_level=tool_def.risk_level,
            is_read_only=tool_def.is_read_only,
        )
        if not policy_res.allowed:
            return ToolExecutionResult(
                tool_name=tool_name,
                allowed=False,
                status="DENIED",
                reason=f"Policy violation: {policy_res.reason}",
                risk_level=tool_def.risk_level,
            )

        # 3. Schema validation
        required_params = tool_def.parameters_schema.get("required", [])
        for req in required_params:
            if req not in args:
                return ToolExecutionResult(
                    tool_name=tool_name,
                    allowed=False,
                    status="DENIED",
                    reason=f"Tool schema violation: missing required parameter '{req}'.",
                    risk_level=tool_def.risk_level,
                )

        # 4. LLM Firewall Inspection
        fw_res = self.firewall.inspect_tool_call(
            tool_name=tool_name,
            arguments=args,
            user_id=user_id,
            session_id=session_id,
        )
        if not fw_res.allowed or fw_res.action == FirewallDecisionAction.BLOCK:
            return ToolExecutionResult(
                tool_name=tool_name,
                allowed=False,
                status="DENIED",
                reason=f"Firewall block: {fw_res.reason}",
                risk_level=tool_def.risk_level,
            )

        # 5. Safe read-only execution
        handler = self._handlers.get(tool_name)
        if not handler:
            return ToolExecutionResult(
                tool_name=tool_name,
                allowed=False,
                status="DENIED",
                reason=f"No handler configured for tool '{tool_name}'.",
                risk_level=tool_def.risk_level,
            )

        try:
            output = handler(**args)
            return ToolExecutionResult(
                tool_name=tool_name,
                allowed=True,
                status="SUCCESS",
                result=output,
                reason="Tool executed successfully within Trust Plane boundaries.",
                risk_level=tool_def.risk_level,
            )
        except Exception as exc:
            return ToolExecutionResult(
                tool_name=tool_name,
                allowed=True,
                status="FAILED",
                reason=f"Tool execution encountered runtime error: {exc}",
                risk_level=tool_def.risk_level,
            )



default_tool_gateway = ToolGateway()
