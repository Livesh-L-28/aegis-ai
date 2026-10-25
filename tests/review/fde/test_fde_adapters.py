"""Contract and security tests for LogicFalcon FDE Adapters."""

import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from packages.review.fde.adapters import (
    AdapterHealthStatus,
    AdapterRegistry,
    AwsAdapter,
    DockerAdapter,
    HttpAdapter,
    McpAdapter,
    PostgresAdapter,
)
from packages.review.fde.models import OperationCategory, StepRiskLevel

# ==============================================================================
# 1. HttpAdapter Tests
# ==============================================================================


def test_http_adapter_capabilities_and_health() -> None:
    adapter = HttpAdapter(default_timeout=5.0, verify_ssl=True)
    health = adapter.check_health()
    assert health.status == AdapterHealthStatus.HEALTHY
    assert adapter.supports("http_get")
    assert adapter.supports("http_post")
    assert adapter.supports("http_health_check")
    assert not adapter.supports("http_delete")

    # POST must require approval and be marked as consequential mutation
    post_cap = adapter.get_capability("http_post")
    assert post_cap is not None
    assert post_cap.requires_approval is True
    assert post_cap.operation_category == OperationCategory.CONSEQUENTIAL_MUTATION
    assert post_cap.risk_level == StepRiskLevel.HIGH


def test_http_adapter_invalid_scheme_and_parameters() -> None:
    adapter = HttpAdapter()
    res = adapter.execute("http_get", {"url": "ftp://example.com/file"})
    assert not res.success
    assert res.error_category == "INVALID_SCHEME"

    res_missing = adapter.execute("http_get", {})
    assert not res_missing.success
    assert res_missing.error_category == "INVALID_PARAMETERS"


def test_http_adapter_get_success_and_redaction() -> None:
    adapter = HttpAdapter()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b'{"token": "ghp_1234567890abcdef1234567890abcdef12"}'
    mock_resp.text = '{"token": "ghp_1234567890abcdef1234567890abcdef12"}'
    mock_resp.headers = {"Authorization": "Bearer secret_token_value", "Content-Type": "application/json"}

    with patch("httpx.Client.get", return_value=mock_resp):
        res = adapter.execute("http_get", {"url": "https://api.example.com/data"})
        assert res.success
        assert res.output["headers"]["Authorization"] == "[REDACTED]"
        assert "ghp_1234567890" not in str(res.output["body"])
        assert "[REDACTED" in str(res.output["body"])


def test_http_adapter_response_too_large() -> None:
    adapter = HttpAdapter()
    oversized = b"A" * (600 * 1024)  # 600 KB exceeds 512 KB limit

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = oversized

    with patch("httpx.Client.get", return_value=mock_resp):
        res = adapter.execute("http_get", {"url": "https://api.example.com/huge"})
        assert not res.success
        assert res.error_category == "RESPONSE_TOO_LARGE"


# ==============================================================================
# 2. DockerAdapter Tests
# ==============================================================================


def test_docker_adapter_unsafe_identifier_rejection() -> None:
    adapter = DockerAdapter()

    # Shell injection attempt in container_id
    res = adapter.execute("inspect_container", {"container_id": "test; rm -rf /"})
    assert not res.success
    assert res.error_category == "UNSAFE_IDENTIFIER"

    # Whitespace injection
    res2 = adapter.execute("container_logs", {"container_id": "app container"})
    assert not res2.success
    assert res2.error_category == "UNSAFE_IDENTIFIER"


def test_docker_adapter_health_check_parsing() -> None:
    adapter = DockerAdapter()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"Status": "running", "Health": {"Status": "healthy"}, "Running": true, "ExitCode": 0}',
            stderr="",
        )
        res = adapter.execute("container_health", {"container_id": "web-service"})
        assert res.success
        assert res.output["health_status"] == "healthy"

    # Unhealthy container
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout='{"Status": "unhealthy", "Health": {"Status": "unhealthy"}, "Running": true, "ExitCode": 1}', stderr="")
        res = adapter.execute("container_health", {"container_id": "web-service"})
        assert not res.success
        assert res.error_category == "UNHEALTHY_CONTAINER"


def test_docker_adapter_subprocess_timeout() -> None:
    adapter = DockerAdapter()
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["docker"], timeout=5.0)):
        res = adapter.execute("container_logs", {"container_id": "api_server"})
        assert not res.success
        assert res.error_category == "TIMEOUT"


# ==============================================================================
# 3. PostgresAdapter Tests
# ==============================================================================


def test_postgres_adapter_credential_masking() -> None:
    secret_url = "postgresql://admin:super_secret_password_123@db.internal:5432/production"
    adapter = PostgresAdapter(connection_url=secret_url)

    masked = adapter._mask_url(secret_url)
    assert "super_secret_password_123" not in masked
    assert "admin:[REDACTED]@db.internal:5432/production" in masked


def test_postgres_adapter_safe_identifier_check() -> None:
    adapter = PostgresAdapter(connection_url="postgresql://user:pass@localhost:5432/db")

    # SQL injection in table name
    res = adapter.execute("check_table_exists", {"table_name": "users; DROP TABLE users;"})
    assert not res.success
    assert res.error_category == "INVALID_IDENTIFIER"


@pytest.mark.asyncio
async def test_postgres_adapter_connection_and_table_queries() -> None:
    adapter = PostgresAdapter(connection_url="postgresql://user:pass@localhost:5432/db")

    # Mock asyncpg connection
    mock_conn = AsyncMock()
    mock_conn.fetchrow.return_value = {"alive": 1}
    mock_conn.fetchval.return_value = True

    with patch("asyncpg.connect", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = mock_conn

        res_conn = await adapter.execute_async("check_connection", {})
        assert res_conn.success
        assert res_conn.output["alive"] is True

        res_tbl = await adapter.execute_async("check_table_exists", {"table_name": "users", "schema": "public"})
        assert res_tbl.success
        assert res_tbl.output["exists"] is True


# ==============================================================================
# 4. McpAdapter & AwsAdapter Tests
# ==============================================================================


def test_mcp_adapter_tool_registration_and_execution() -> None:
    adapter = McpAdapter(server_name="test_server")
    adapter.register_tool("check_disk_space", "Checks free disk space on server", {"type": "object"})

    list_res = adapter.execute("list_tools", {})
    assert list_res.success
    tools = list_res.output["tools"]
    assert len(tools) == 1
    assert tools[0]["name"] == "check_disk_space"

    call_res = adapter.execute("call_tool", {"tool_name": "check_disk_space", "arguments": {}})
    assert call_res.success
    assert call_res.output["tool"] == "check_disk_space"

    call_unknown = adapter.execute("call_tool", {"tool_name": "nonexistent_tool"})
    assert not call_unknown.success
    assert call_unknown.error_category == "TOOL_NOT_FOUND"


def test_aws_adapter_graceful_missing_boto3() -> None:
    adapter = AwsAdapter()
    with patch.object(adapter, "_is_boto3_available", return_value=False):
        health = adapter.check_health()
        assert health.status == AdapterHealthStatus.UNAVAILABLE
        assert "not installed" in health.message

        res = adapter.execute("describe_ecs_services", {})
        assert not res.success
        assert res.error_category == "OPTIONAL_DEPENDENCY_MISSING"


# ==============================================================================
# 5. AdapterRegistry Tests
# ==============================================================================


def test_adapter_registry_lifecycle() -> None:
    registry = AdapterRegistry()
    http_adapter = HttpAdapter()
    docker_adapter = DockerAdapter()

    registry.register(http_adapter)
    registry.register(docker_adapter)

    assert registry.list_adapters() == ["docker", "http"]
    assert registry.get("http") is http_adapter
    assert registry.get("docker") is docker_adapter

    found = registry.find_capability("http_get")
    assert found is not None
    ad, cap = found
    assert ad.adapter_id == "http"
    assert cap.name == "http_get"

    found_docker = registry.find_capability("container_logs")
    assert found_docker is not None
    assert found_docker[0].adapter_id == "docker"

    assert registry.find_capability("nonexistent_op") is None

    # Check health reporting across all adapters
    health_reports = registry.check_all_health()
    assert "http" in health_reports
    assert "docker" in health_reports

    registry.cleanup_all()
    assert len(registry.list_adapters()) == 0
