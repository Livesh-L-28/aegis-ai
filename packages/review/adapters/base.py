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
