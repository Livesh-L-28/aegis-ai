"""AEGIS AI Repository Intelligence & Code Review Engine."""

from packages.review.cli import build_parser, run_cli
from packages.review.domain.models import (
    AffectedArtifacts,
    ChangedFile,
    ChangedSymbol,
    DiffChangeType,
    DiffHunk,
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    GitDiffSummary,
    ReviewFinding,
    ReviewReport,
    ReviewSession,
    ReviewStatus,
    ReviewType,
    SourceLocation,
    ValidationStatus,
)
from packages.review.engine import LocalReviewEngine, ReviewConfig

__all__ = [
    "AffectedArtifacts",
    "ChangedFile",
    "ChangedSymbol",
    "DiffChangeType",
    "DiffHunk",
    "FindingCategory",
    "FindingOrigin",
    "FindingSeverity",
    "GitDiffSummary",
    "LocalReviewEngine",
    "ReviewConfig",
    "ReviewFinding",
    "ReviewReport",
    "ReviewSession",
    "ReviewStatus",
    "ReviewType",
    "SourceLocation",
    "ValidationStatus",
    "build_parser",
    "run_cli",
]
