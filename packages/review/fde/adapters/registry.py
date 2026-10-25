"""Capability registry for LogicFalcon FDE adapters."""

import contextlib

from packages.review.fde.adapters.base import (
    AdapterCapability,
    AdapterHealth,
    AdapterHealthStatus,
    BaseAdapter,
)


class AdapterRegistry:
    """Central registry and lookup broker for FDE adapters and capabilities."""

    def __init__(self) -> None:
        self._adapters: dict[str, BaseAdapter] = {}

    def register(self, adapter: BaseAdapter) -> None:
        """Registers an adapter instance."""
        self._adapters[adapter.adapter_id] = adapter

    def unregister(self, adapter_id: str) -> BaseAdapter | None:
        """Unregisters and cleans up an adapter."""
        adapter = self._adapters.pop(adapter_id, None)
        if adapter:
            adapter.cleanup()
        return adapter

    def get(self, adapter_id: str) -> BaseAdapter | None:
        """Retrieves an adapter by identifier."""
        return self._adapters.get(adapter_id)

    def list_adapters(self) -> list[str]:
        """Lists all registered adapter IDs."""
        return sorted(self._adapters.keys())

    def find_capability(self, operation: str) -> tuple[BaseAdapter, AdapterCapability] | None:
        """Discovers which adapter provides the specified operation capability."""
        for adapter in self._adapters.values():
            cap = adapter.get_capability(operation)
            if cap:
                return adapter, cap
        return None

    def check_all_health(self) -> dict[str, AdapterHealth]:
        """Runs health checks across all registered adapters."""
        health_reports: dict[str, AdapterHealth] = {}
        for adapter_id, adapter in self._adapters.items():
            try:
                health_reports[adapter_id] = adapter.check_health()
            except Exception as e:
                health_reports[adapter_id] = AdapterHealth(
                    status=AdapterHealthStatus.UNAVAILABLE,
                    message=f"Health probe raised unhandled exception: {e}",
                )
        return health_reports

    def cleanup_all(self) -> None:
        """Safely cleans up all registered adapters."""
        for adapter in self._adapters.values():
            with contextlib.suppress(Exception):
                adapter.cleanup()
        self._adapters.clear()
