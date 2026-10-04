"""Phase 5 Tool Gateway tests: Deny-by-default, schema checks, and write tool blocking."""

from uuid import uuid4

import pytest

from packages.security.policy import AIRiskLevel
from packages.security.tools import (
    ToolDefinition,
    ToolGateway,
)


@pytest.mark.asyncio
async def test_tool_gateway_allows_registered_read_only_tool() -> None:
    gateway = ToolGateway()
    org_id = uuid4()

    result = await gateway.execute_tool(
        tool_name="get_service_metadata",
        arguments={"service_name": "cart-service"},
        organization_id=org_id,
        user_id="analyst-1",
    )
    assert result.allowed
    assert result.status == "SUCCESS"
    assert result.result.get("service") == "cart-service"


@pytest.mark.asyncio
async def test_tool_gateway_denies_unknown_tools() -> None:
    gateway = ToolGateway()
    org_id = uuid4()

    result = await gateway.execute_tool(
        tool_name="unknown_external_tool",
        arguments={},
        organization_id=org_id,
        user_id="analyst-1",
    )
    assert not result.allowed
    assert "not registered" in result.reason.lower() or "deny" in result.reason.lower()



@pytest.mark.asyncio
async def test_tool_gateway_blocks_write_tools_in_phase5() -> None:
    gateway = ToolGateway()
    org_id = uuid4()

    # Attempt to execute unregistered or high-risk write tools
    dangerous_tool = ToolDefinition(
        name="restart_kubernetes_pod",
        description="Dangerous pod mutation tool",
        risk_level=AIRiskLevel.HIGH,
        is_read_only=False,
        parameters_schema={"pod_name": "str"},
    )
    gateway.register_tool(dangerous_tool, handler=lambda args: {"restarted": True})


    result = await gateway.execute_tool(
        tool_name="restart_kubernetes_pod",
        arguments={"pod_name": "cart-pod-1"},
        organization_id=org_id,
        user_id="analyst-1",
    )
    assert not result.allowed
    assert "read_only" in result.reason.lower() or "blocked" in result.reason.lower()


@pytest.mark.asyncio
async def test_tool_gateway_validates_schema() -> None:
    gateway = ToolGateway()
    org_id = uuid4()

    # get_service_metadata requires "service_name"
    result = await gateway.execute_tool(
        tool_name="get_service_metadata",
        arguments={},  # missing required argument
        organization_id=org_id,
        user_id="analyst-1",
    )
    assert not result.allowed
    assert "schema" in result.reason.lower()
