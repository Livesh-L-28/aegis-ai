"""Safe Docker CLI adapter for LogicFalcon FDE with argument array execution and bounded timeouts."""

import json
import re
import subprocess
import time
from typing import Any

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.fde.adapters.base import (
    AdapterCapability,
    AdapterExecutionResult,
    AdapterHealth,
    AdapterHealthStatus,
    BaseAdapter,
)
from packages.review.fde.models import OperationCategory, StepRiskLevel


class DockerAdapter(BaseAdapter):
    """Executes bounded, safe Docker commands via non-shell subprocesses."""

    # Restrict container names/IDs to safe characters
    SAFE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]+$")
    MAX_OUTPUT_BYTES = 256 * 1024  # 256 KB
    DEFAULT_TIMEOUT_SECONDS = 5.0
    MAX_TIMEOUT_SECONDS = 30.0

    def __init__(self, adapter_id: str = "docker") -> None:
        super().__init__(adapter_id=adapter_id, version="1.0.0")

    @property
    def capabilities(self) -> list[AdapterCapability]:
        return [
            AdapterCapability(
                name="docker_version",
                description="Checks Docker engine and CLI version.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
            ),
            AdapterCapability(
                name="list_containers",
                description="Lists currently running or all containers.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"all": "bool optional"},
            ),
            AdapterCapability(
                name="inspect_container",
                description="Inspects container state, network, and configuration.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"container_id": "str"},
            ),
            AdapterCapability(
                name="container_health",
                description="Checks container health check status and exit code.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"container_id": "str"},
            ),
            AdapterCapability(
                name="container_logs",
                description="Fetches recent logs for a container with secret redaction.",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"container_id": "str", "tail": "int optional"},
            ),
            AdapterCapability(
                name="start_container",
                description="Starts a stopped container.",
                operation_category=OperationCategory.REVERSIBLE_MUTATION,
                risk_level=StepRiskLevel.MEDIUM,
                requires_approval=True,
                parameters_schema={"container_id": "str"},
            ),
            AdapterCapability(
                name="stop_container",
                description="Stops a running container.",
                operation_category=OperationCategory.REVERSIBLE_MUTATION,
                risk_level=StepRiskLevel.MEDIUM,
                requires_approval=True,
                parameters_schema={"container_id": "str", "timeout": "int optional"},
            ),
            AdapterCapability(
                name="restart_container",
                description="Restarts an existing container.",
                operation_category=OperationCategory.REVERSIBLE_MUTATION,
                risk_level=StepRiskLevel.MEDIUM,
                requires_approval=True,
                parameters_schema={"container_id": "str", "timeout": "int optional"},
            ),
        ]

    def check_health(self) -> AdapterHealth:
        """Probes Docker daemon responsiveness via bounded non-shell subprocess."""
        start_time = time.perf_counter()
        try:
            res = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=4.0,
                shell=False,
            )
            elapsed = (time.perf_counter() - start_time) * 1000
            if res.returncode == 0:
                ver = res.stdout.strip()
                return AdapterHealth(
                    status=AdapterHealthStatus.HEALTHY,
                    message=f"Docker daemon is responsive (version {ver}).",
                    latency_ms=elapsed,
                    details={"server_version": ver},
                )
            clean_err = redact_secrets_in_text(res.stderr.strip()[:200])
            return AdapterHealth(
                status=AdapterHealthStatus.DEGRADED,
                message=f"Docker command failed with code {res.returncode}: {clean_err}",
                latency_ms=elapsed,
            )
        except FileNotFoundError:
            return AdapterHealth(
                status=AdapterHealthStatus.UNAVAILABLE,
                message="Docker executable not found on host PATH.",
            )
        except subprocess.TimeoutExpired:
            return AdapterHealth(
                status=AdapterHealthStatus.UNAVAILABLE,
                message="Docker daemon timed out after 4.0s.",
            )
        except Exception as e:
            return AdapterHealth(
                status=AdapterHealthStatus.UNAVAILABLE,
                message=f"Docker health check failed: {e}",
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

        container_id = params.get("container_id")
        if operation not in ("docker_version", "list_containers"):
            if not container_id or not isinstance(container_id, str):
                return AdapterExecutionResult(
                    success=False,
                    operation=operation,
                    output={},
                    error="Parameter 'container_id' is required.",
                    error_category="INVALID_PARAMETERS",
                )
            if not self.SAFE_NAME_REGEX.match(container_id):
                return AdapterExecutionResult(
                    success=False,
                    operation=operation,
                    output={},
                    error=f"Invalid container identifier '{container_id}'. Only alphanumeric and ._- characters allowed.",
                    error_category="UNSAFE_IDENTIFIER",
                )

        timeout = min(float(params.get("timeout", self.DEFAULT_TIMEOUT_SECONDS)), self.MAX_TIMEOUT_SECONDS)

        # Build safe argument list
        cmd: list[str] = ["docker"]
        if operation == "docker_version":
            cmd.extend(["version", "--format", "{{json .}}"])
        elif operation == "list_containers":
            cmd.extend(["ps", "--format", "{{json .}}"])
            if params.get("all"):
                cmd.append("-a")
        elif operation == "inspect_container":
            cmd.extend(["inspect", container_id])  # type: ignore[list-item]
        elif operation == "container_health":
            cmd.extend(["inspect", "--format", "{{json .State}}", container_id])  # type: ignore[list-item]
        elif operation == "container_logs":
            tail_lines = min(int(params.get("tail", 100)), 500)
            cmd.extend(["logs", "--tail", str(tail_lines), container_id])  # type: ignore[list-item]
        elif operation == "start_container":
            cmd.extend(["start", container_id])  # type: ignore[list-item]
        elif operation == "stop_container":
            cmd.extend(["stop", container_id])  # type: ignore[list-item]
        elif operation == "restart_container":
            cmd.extend(["restart", container_id])  # type: ignore[list-item]
        else:
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"Unhandled operation '{operation}'.",
                error_category="UNSUPPORTED_OPERATION",
            )

        start_time = time.perf_counter()
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )
            elapsed = time.perf_counter() - start_time

            stdout = res.stdout[: self.MAX_OUTPUT_BYTES]
            stderr = res.stderr[: self.MAX_OUTPUT_BYTES]

            if res.returncode != 0:
                clean_err = redact_secrets_in_text(stderr.strip())
                return AdapterExecutionResult(
                    success=False,
                    operation=operation,
                    output={"stderr": clean_err, "exit_code": res.returncode},
                    error=f"Docker command failed with exit code {res.returncode}: {clean_err}",
                    error_category="DOCKER_COMMAND_ERROR",
                    execution_time_seconds=elapsed,
                ).sanitize()

            # Process output based on operation
            parsed_output: Any = stdout
            if operation in ("docker_version", "inspect_container", "container_health"):
                try:
                    parsed_output = json.loads(stdout)
                except Exception:
                    parsed_output = stdout

            # Special verification for container_health
            if operation == "container_health" and isinstance(parsed_output, dict):
                status_str = parsed_output.get("Status", "unknown")
                health_obj = parsed_output.get("Health", {})
                health_status = health_obj.get("Status", status_str)
                is_healthy = health_status in ("healthy", "running")
                return AdapterExecutionResult(
                    success=is_healthy,
                    operation=operation,
                    output={
                        "container_id": container_id,
                        "status": status_str,
                        "health_status": health_status,
                        "running": parsed_output.get("Running", False),
                        "exit_code": parsed_output.get("ExitCode", 0),
                    },
                    error=None if is_healthy else f"Container state is '{status_str}' (health: '{health_status}').",
                    error_category=None if is_healthy else "UNHEALTHY_CONTAINER",
                    execution_time_seconds=elapsed,
                ).sanitize()

            return AdapterExecutionResult(
                success=True,
                operation=operation,
                output=parsed_output,
                execution_time_seconds=elapsed,
            ).sanitize()

        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - start_time
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"Docker subprocess timed out after {timeout:.1f}s.",
                error_category="TIMEOUT",
                execution_time_seconds=elapsed,
            ).sanitize()
        except FileNotFoundError:
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error="Docker CLI not found on host PATH.",
                error_category="EXECUTABLE_NOT_FOUND",
            ).sanitize()
        except Exception as e:
            elapsed = time.perf_counter() - start_time
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error=f"Docker execution error: {e}",
                error_category="EXECUTION_ERROR",
                execution_time_seconds=elapsed,
            ).sanitize()
