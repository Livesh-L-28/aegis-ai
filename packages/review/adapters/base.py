"""Base protocol and interfaces for static analysis adapters."""

from abc import ABC, abstractmethod
from typing import Any

from packages.review.domain.models import ReviewFinding


class StaticAnalysisAdapter(ABC):
    """Abstract base class for all deterministic static analysis adapters."""

    is_subprocess_isolated: bool = False
    is_pure_ast_analyzer: bool = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the static analysis tool."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if the tool is installed and eligible to run safely."""
        pass

    @abstractmethod
    def analyze_file(
        self,
        file_path: str,
        content: str,
        options: dict[str, Any] | None = None,
    ) -> list[ReviewFinding]:
        """Performs static analysis on a single file's content and returns normalized findings."""
        pass


class AnalyzerRegistry:
    """Formal registry allowing custom static analysis adapters and rules to be registered and validated."""

    def __init__(self) -> None:
        self._adapters: dict[str, StaticAnalysisAdapter] = {}

    def register(self, adapter: StaticAnalysisAdapter) -> None:
        """Registers a new static analysis adapter with interface validation."""
        if not isinstance(adapter, StaticAnalysisAdapter):
            raise TypeError(f"Adapter must inherit from StaticAnalysisAdapter, got {type(adapter)}")
        name = adapter.name
        if not name or not isinstance(name, str):
            raise ValueError("Adapter name must be a non-empty string.")
        self._adapters[name] = adapter

    def get(self, name: str) -> StaticAnalysisAdapter | None:
        """Retrieves a registered adapter by name."""
        return self._adapters.get(name)

    def list_adapters(self) -> list[str]:
        """Returns sorted names of all registered adapters."""
        return sorted(self._adapters.keys())

    def get_all(self) -> list[StaticAnalysisAdapter]:
        """Returns list of all registered adapter instances."""
        return list(self._adapters.values())

    def unregister(self, name: str) -> bool:
        """Unregisters an adapter by name."""
        if name in self._adapters:
            del self._adapters[name]
            return True
        return False


# Global default adapter registry
global_analyzer_registry = AnalyzerRegistry()

