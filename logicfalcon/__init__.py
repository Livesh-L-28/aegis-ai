"""LogicFalcon — Fast, precise engineering intelligence. Powered by AEGIS AI.

LogicFalcon is an AI-powered software engineering intelligence platform for
evidence-grounded code review, repository analysis, change-impact assessment,
root-cause analysis, and safe fix proposals. Powered by AEGIS AI.
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

__version__ = "0.1.0"
__product__ = "LogicFalcon"
__tagline__ = "Fast, precise engineering intelligence."
__platform__ = "AEGIS AI"

__all__ = [
    "AutonomousDebuggingService",
    "FindingSeverity",
    "LocalReviewEngine",
    "ReviewConfig",
    "ReviewReport",
    "__platform__",
    "__product__",
    "__tagline__",
    "__version__",
    "build_parser",
    "run_cli",
]
