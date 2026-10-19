"""Programmatic Python SDK for LogicFalcon (Powered by AEGIS AI).

Provides high-level programmatic access for automated code reviews, diff inspections,
remediation verification, and safe patch applications.
"""

from pathlib import Path

from packages.review.domain.models import (
    FindingSeverity,
    ProposedFix,
    ReviewFinding,
    ReviewReport,
)
from packages.review.engine import LocalReviewEngine, ReviewConfig
from packages.review.fix_engine import (
    FixApplicationResult,
    RemediationVerificationResult,
    ReviewFixEngine,
)
from packages.review.validator import FindingValidator

__all__ = [
    "FindingSeverity",
    "FindingValidator",
    "FixApplicationResult",
    "LocalReviewEngine",
    "ProposedFix",
    "RemediationVerificationResult",
    "ReviewConfig",
    "ReviewFinding",
    "ReviewFixEngine",
    "ReviewReport",
    "apply_fix",
    "review",
    "review_diff",
    "verify_fix",
]


def review(
    repo: str | Path = ".",
    base: str | None = None,
    staged: bool = False,
    unstaged: bool = False,
    severity_threshold: str = "ERROR",
    config: ReviewConfig | None = None,
) -> ReviewReport:
    """Executes a code review on a repository or working tree diff.

    Args:
        repo: Path to target repository root.
        base: Git commit or branch ref to compare against (e.g. 'origin/main').
        staged: If True, reviews only staged (cached) Git changes.
        unstaged: If True, reviews only unstaged working tree changes.
        severity_threshold: Minimum severity to trigger failure.
        config: Custom ReviewConfig options.

    Returns:
        ReviewReport containing findings, affected artifacts, and execution metrics.
    """
    repo_path = Path(repo).resolve()
    engine_config = config or ReviewConfig()
    engine = LocalReviewEngine(repo_root=repo_path, config=engine_config)

    report = engine.review_local_git_diff(
        base_ref=base,
        staged=staged,
        unstaged=unstaged,
    )

    validator = FindingValidator(repo_root=repo_path)
    verified, _ = validator.validate(report.findings)
    report.findings = verified
    return report


def review_diff(
    diff_text: str,
    repo_root: str | Path = ".",
    config: ReviewConfig | None = None,
) -> ReviewReport:
    """Synchronously reviews a raw unified Git diff string.

    Args:
        diff_text: Unified git diff formatted text.
        repo_root: Path to repository root for context and validation.
        config: Custom ReviewConfig options.

    Returns:
        ReviewReport containing findings and analysis metadata.
    """
    repo_path = Path(repo_root).resolve()
    engine_config = config or ReviewConfig()
    engine = LocalReviewEngine(repo_root=repo_path, config=engine_config)
    report = engine.review_diff(diff_text=diff_text)

    diff_summary = engine.diff_parser.parse(diff_text)
    validator = FindingValidator(repo_root=repo_path)
    verified, _ = validator.validate(report.findings, diff_summary=diff_summary)
    report.findings = verified
    return report


def apply_fix(
    fix: ProposedFix,
    approved: bool = False,
    repo_root: str | Path = ".",
    dry_run: bool = False,
    validate_syntax: bool = True,
    create_backup: bool = True,
) -> FixApplicationResult:
    """Safely applies a proposed remediation fix to disk.

    Args:
        fix: ProposedFix object to apply.
        approved: Explicit developer confirmation (required if dry_run=False).
        repo_root: Target repository root.
        dry_run: If True, returns unified diff preview without modifying disk.
        validate_syntax: If True, checks python syntax before writing.
        create_backup: If True, creates a .bak copy before modifying.

    Returns:
        FixApplicationResult with execution status and diff.
    """
    repo_path = Path(repo_root).resolve()
    fix_engine = ReviewFixEngine(repo_root=repo_path)
    return fix_engine.apply_fix(
        fix=fix,
        approved=approved,
        dry_run=dry_run,
        validate_syntax=validate_syntax,
        create_backup=create_backup,
    )


def verify_fix(
    fixes: list[ProposedFix],
    repo_root: str | Path = ".",
    run_tests: bool = True,
    run_linters: bool = True,
    test_command: list[str] | None = None,
    lint_command: list[str] | None = None,
) -> RemediationVerificationResult:
    """Applies fixes in an isolated workspace and runs real tests and linters.

    Args:
        fixes: List of ProposedFix objects to verify.
        repo_root: Target repository root.
        run_tests: Whether to execute tests in the isolated workspace.
        run_linters: Whether to execute linters in the isolated workspace.
        test_command: Custom test command list (e.g. ['pytest', 'tests/']).
        lint_command: Custom linter command list (e.g. ['ruff', 'check', '.']).

    Returns:
        RemediationVerificationResult indicating whether the fix passed QA.
    """
    repo_path = Path(repo_root).resolve()
    fix_engine = ReviewFixEngine(repo_root=repo_path)
    return fix_engine.verify_remediation(
        fixes=fixes,
        run_tests=run_tests,
        run_linters=run_linters,
        test_command=test_command,
        lint_command=lint_command,
    )
