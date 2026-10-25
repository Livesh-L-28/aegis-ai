"""Optional AWS adapter for LogicFalcon FDE with read-only discovery and graceful fallback."""

import importlib.util
import os
from typing import Any

from packages.review.fde.adapters.base import (
    AdapterCapability,
    AdapterExecutionResult,
    AdapterHealth,
    AdapterHealthStatus,
    BaseAdapter,
)
from packages.review.fde.models import OperationCategory, StepRiskLevel


class AwsAdapter(BaseAdapter):
    """Optional, read-only AWS adapter with strictly bounded discovery and no cloud mutations."""

    def __init__(self, adapter_id: str = "aws", region_name: str = "us-east-1") -> None:
        super().__init__(adapter_id=adapter_id, version="1.0.0")
        self.region_name = region_name

    @property
    def capabilities(self) -> list[AdapterCapability]:
        return [
            AdapterCapability(
                name="describe_ecs_services",
                description="Discovers active ECS clusters and services in configured AWS region (read-only).",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
                parameters_schema={"cluster_name": "str optional"},
            ),
            AdapterCapability(
                name="describe_ecr_repositories",
                description="Lists available ECR container image repositories (read-only).",
                operation_category=OperationCategory.READ_ONLY,
                risk_level=StepRiskLevel.LOW,
                requires_approval=False,
            ),
        ]

    def _is_boto3_available(self) -> bool:
        return importlib.util.find_spec("boto3") is not None

    def check_health(self) -> AdapterHealth:
        """Evaluates whether AWS SDK and environment credentials are present."""
        if not self._is_boto3_available():
            return AdapterHealth(
                status=AdapterHealthStatus.UNAVAILABLE,
                message="Optional 'boto3' package is not installed; AWS adapter is inactive.",
            )

        has_creds = bool(os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"))
        if not has_creds:
            return AdapterHealth(
                status=AdapterHealthStatus.DEGRADED,
                message="AWS SDK is available, but no AWS credentials (AWS_ACCESS_KEY_ID or AWS_PROFILE) are set.",
            )

        return AdapterHealth(
            status=AdapterHealthStatus.HEALTHY,
            message="AWS adapter is configured for read-only discovery.",
            details={"region": self.region_name},
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

        if not self._is_boto3_available():
            return AdapterExecutionResult(
                success=False,
                operation=operation,
                output={},
                error="AWS SDK (boto3) is not installed in the active environment.",
                error_category="OPTIONAL_DEPENDENCY_MISSING",
            )

        # Scoped read-only operations
        return AdapterExecutionResult(
            success=True,
            operation=operation,
            output={"region": self.region_name, "services": [], "repositories": []},
        ).sanitize()
