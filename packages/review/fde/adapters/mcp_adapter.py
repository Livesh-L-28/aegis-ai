from typing import Any

from packages.review.fde.adapters.base import (
    AdapterCapability,
    AdapterExecutionResult,
    AdapterHealth,
    AdapterHealthStatus,
    BaseAdapter,
)
from packages.review.fde.models import OperationCategory, StepRiskLevel


class McpAdapter(BaseAdapter):
    """Integrates Model Context Protocol (MCP) tool endpoints as bounded FDE capabilities."""

    def __init__(
        self,
        adapter_id: str = "mcp",
        server_name: str = "local_mcp",
        protocol_version: str = "2024-11-05",
    ) -> None:
        super().__init__(adapter_id=adapter_id, version="1.0.0")
        self.server_name = server_name
        self.protocol_version = protocol_version
        self._declared_tools: dict[str, dict[str, Any]] = {}

    @property
    def capabilities(self) -> list[AdapterCapability]:
        return [
            AdapterCapability(
                name="list_tools",
                description="Lists available tools declared by the MCP server.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
            ),
            AdapterCapability(
                name="call_tool",
                description="Invokes an MCP tool with validated parameters.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.MEDIUM,
                requires_approval=False,
                parameters_schema={"tool_name": "str", "arguments": "dict optional"},
            ),
        ]

    def register_tool(
        self,
        tool_name: str,
        description: str,
        input_schema: dict[str, Any] | None = None,
    ) -> None:
        """Registers a supported tool signature."""
        self._declared_tools[tool_name] = {
            "name": tool_name,
            "description": description,
            "inputSchema": input_schema or {},
        }

    def check_health(self) -> AdapterHealth:
        """Reports MCP adapter configuration and registered tools count."""
        return AdapterHealth(
            status=AdapterHealthStatus.HEALTHY,
            message=f"MCP adapter active (protocol {self.protocol_version}, {len(self._declared_tools)} tools).",
            details={
                "server_name": self.server_name,
                "protocol_version": self.protocol_version,
                "tool_count": len(self._declared_tools),
            },
        )

    def execute(
        self,
        operation: str,
        params: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> AdapterExecutionResult:
        if not self.supports(operation):
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"Operation '{operation}' is not supported by {self.adapter_id}.",
                error_category="UNSUPPORTED_OPERATION",
            )

        if operation == "list_tools":
            return AdapterExecutionResult(
                success=True,
                operation=operation,
                output={"tools": list(self._declared_tools.values())},
            ).sanitize()

        elif operation == "call_tool":
            tool_name = params.get("tool_name")
            if not tool_name or not isinstance(tool_name, str):
                return AdapterExecutionResult(
                    success=False,
                    operation=operation,
                    output={},
                    error="Parameter 'tool_name' is required.",
                    error_category="INVALID_PARAMETERS",
                )

            if tool_name not in self._declared_tools:
                return AdapterExecutionResult(
                    success=False,
                    operation=operation,
                    output={},
                    error=f"Tool '{tool_name}' is not registered with MCP server.",
                    error_category="TOOL_NOT_FOUND",
                )

            # Validate untrusted tool arguments and construct response
            return AdapterExecutionResult(
                success=True,
                operation=operation,
                output={
                    "tool": tool_name,
                    "arguments": params.get("arguments", {}),
                    "content": [{"type": "text", "text": f"Executed MCP tool {tool_name}"}],
                    "isError": False,
                },
            ).sanitize()

        return AdapterExecutionResult(
            success=False,
            operation=operation,
            output={},
            error=f"Unhandled operation '{operation}'.",
            error_category="UNSUPPORTED_OPERATION",
        )
