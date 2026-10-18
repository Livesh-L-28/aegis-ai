"""Interface-only TypeScript adapter specification.

Status: UNSUPPORTED IN MILESTONE 1.
In accordance with platform safety constraints, TypeScript AST parsing and analysis
remain unsupported until a genuine, host-isolated, non-executing AST parser is implemented.
This stub defines the extension interface only and does not perform active analysis.
"""

from typing import Any

from packages.review.adapters.base import StaticAnalysisAdapter
from packages.review.domain.models import ReviewFinding


class TypeScriptLanguageAdapter(StaticAnalysisAdapter):
    """Interface-only contract for future non-executing TypeScript AST analysis."""

    STATUS: str = "UNSUPPORTED_IN_MILESTONE_1"

    @property
    def name(self) -> str:
        return "typescript_stub"

    def is_available(self) -> bool:
        # Explicitly unsupported in Milestone 1
        return False

    def analyze_file(
        self,
        file_path: str,
        content: str,
        options: dict[str, Any] | None = None,
    ) -> list[ReviewFinding]:
        # Strictly read-only no-op: does not execute external scripts or claim mock analysis
        return []
