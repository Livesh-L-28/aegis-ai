"""System environment adapter for LogicFalcon FDE."""

import os
import socket
import sys
import time
from typing import Any

from packages.review.fde.adapters.base import (
    AdapterCapability,
    AdapterExecutionResult,
    AdapterHealth,
    AdapterHealthStatus,
    BaseAdapter,
)
from packages.review.fde.models import (
    OperationCategory,
    StepRiskLevel,
)


class SystemAdapter(BaseAdapter):
    """Safe, read-only system and runtime probe adapter."""

    def __init__(self) -> None:
        super().__init__(adapter_id="system", version="1.0.0")

    @property
    def capabilities(self) -> list[AdapterCapability]:
        return [
            AdapterCapability(
                name="probe_runtime",
                description="Probe active Python runtime version and architecture",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
            ),
            AdapterCapability(
                name="check_runtime",
                description="Verify active Python environment meets requirements",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
            ),
            AdapterCapability(
                name="probe_port",
                description="Probe local TCP port binding availability",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
            ),
            AdapterCapability(
                name="verify_port",
                description="Verify localhost binding availability for declared port",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
            ),
            AdapterCapability(
                name="check_env",
                description="Probe presence of required environment variable names (redacting values)",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
            ),
        ]

    def check_health(self) -> AdapterHealth:
        return AdapterHealth(
            status=AdapterHealthStatus.HEALTHY,
            message="System adapter active and operational",
        )

    def execute(
        self,
        operation: str,
        params: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> AdapterExecutionResult:
        start_time = time.perf_counter()

        if operation in ("probe_runtime", "check_runtime"):
            v = sys.version_info
            is_compatible = v >= (3, 12)
            return AdapterExecutionResult(
                success=is_compatible,
                operation=operation,
                output={"version": f"{v.major}.{v.minor}.{v.micro}", "compatible": is_compatible},
                execution_time_seconds=time.perf_counter() - start_time,
            )

        elif operation in ("probe_port", "verify_port"):
            target_str = str(params.get("target", params.get("port", 8080)))
            target_port_str = target_str.split(":")[-1] if ":" in target_str else target_str
            try:
                port = int(target_port_str)
            except ValueError:
                return AdapterExecutionResult(
                    success=False,
                    operation=operation,
                    output=None,
                    error=f"Invalid port specification: '{target_str}'",
                    execution_time_seconds=time.perf_counter() - start_time,
                )

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                is_bound = s.connect_ex(("127.0.0.1", port)) == 0

            return AdapterExecutionResult(
                success=True,
                operation=operation,
                output={"port": port, "is_bound": is_bound},
                execution_time_seconds=time.perf_counter() - start_time,
            )

        elif operation == "check_env":
            var_name = str(params.get("variable", params.get("target", "")))
            present = var_name in os.environ
            return AdapterExecutionResult(
                success=present,
                operation=operation,
                output={"variable": var_name, "present": present},
                execution_time_seconds=time.perf_counter() - start_time,
            )

        else:
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output=None,
                error=f"Unsupported system operation: '{operation}'",
                execution_time_seconds=time.perf_counter() - start_time,
            )
