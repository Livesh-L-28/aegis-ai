"""AEGIS AI — Enterprise-grade AI Engineering, Automated Code Review & Autonomous Debugging Platform.

Public API exports for library consumers and integrations.
"""

try:
    from packages.intelligence.debugging.service import AutonomousDebuggingService
except (ImportError, ModuleNotFoundError):
    class AutonomousDebuggingService:  # type: ignore[no-redef]
        """Autonomous debugging service requires the full AEGIS AI platform backend.

        This feature is unavailable in the standalone LogicFalcon CLI/SDK distribution.
        """

        def __init__(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError(
                "AutonomousDebuggingService requires the optional AEGIS AI platform backend (apps.api). "
                "It is not available in the standalone LogicFalcon CLI/SDK distribution."
            )

from packages.review.cli import build_parser, run_cli
from packages.review.domain.models import FindingSeverity, ReviewReport
from packages.review.engine import LocalReviewEngine, ReviewConfig

__version__ = "0.1.1"

__all__ = [
    "AutonomousDebuggingService",
    "FindingSeverity",
    "LocalReviewEngine",
    "ReviewConfig",
    "ReviewReport",
    "__version__",
    "build_parser",
    "run_cli",
]
