"""FDE Adapters and Capability Registry for LogicFalcon."""

from packages.review.fde.adapters.aws_adapter import AwsAdapter
from packages.review.fde.adapters.base import (
    AdapterCapability,
    AdapterExecutionResult,
    AdapterHealth,
    AdapterHealthStatus,
    BaseAdapter,
)
from packages.review.fde.adapters.docker_adapter import DockerAdapter
from packages.review.fde.adapters.http_adapter import HttpAdapter
from packages.review.fde.adapters.mcp_adapter import McpAdapter
from packages.review.fde.adapters.postgres_adapter import PostgresAdapter
from packages.review.fde.adapters.registry import AdapterRegistry
from packages.review.fde.adapters.system_adapter import SystemAdapter

__all__ = [
    "AdapterCapability",
    "AdapterExecutionResult",
    "AdapterHealth",
    "AdapterHealthStatus",
    "AdapterRegistry",
    "AwsAdapter",
    "BaseAdapter",
    "DockerAdapter",
    "HttpAdapter",
    "McpAdapter",
    "PostgresAdapter",
    "SystemAdapter",
]
