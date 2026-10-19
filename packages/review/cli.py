"""Command-line interface for AEGIS AI Code Review."""

import argparse
import sys
from pathlib import Path
from typing import NoReturn

from packages.review.domain.models import FindingSeverity, ReviewReport
from packages.review.engine import LocalReviewEngine, ReviewConfig

SEVERITY_WEIGHTS: dict[FindingSeverity, int] = {
    FindingSeverity.INFO: 0,
    FindingSeverity.WARNING: 1,
    FindingSeverity.ERROR: 2,
    FindingSeverity.CRITICAL: 3,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logicfalcon review",
        description="LogicFalcon — Repository Intelligence & Automated Code Review CLI (Powered by AEGIS AI)",
    )
    parser.add_argument(
        "--repo",
        type=str,
        default=".",
        help="Path to the repository root directory (default: current directory).",
    )
    parser.add_argument(
        "--base",
        type=str,
        default=None,
        help="Base Git commit or branch reference to compare against (e.g., 'main', 'origin/main').",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format: human-readable 'text' table or machine-readable 'json' (default: text).",
    )
    parser.add_argument(
        "--changed-only",
        action="store_true",
        help="Restrict analysis output strictly to lines changed within the diff.",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=["INFO", "WARNING", "ERROR", "CRITICAL"],
        default="ERROR",
        help="Minimum finding severity that triggers a non-zero exit code (default: ERROR).",
    )
    parser.add_argument(
        "--enable-ai",
        action="store_true",
        help="Enable repository-aware AI analysis in addition to deterministic static rules.",
    )
    parser.add_argument(
        "--enable-tools",
        action="store_true",
        help="Enable external deterministic linters (e.g., Ruff) if installed.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-file analysis timeout in seconds (default: 10.0).",
    )
    return parser


def format_text_report(report: ReviewReport, changed_only: bool = False) -> str:
    lines = [
        "=" * 78,
        "🦅  LogicFalcon — Repository Intelligence & Code Review Report (Powered by AEGIS AI)",
        "=" * 78,
        f"Repository:   {report.repository_path}",
        f"Base Commit:  {report.base_commit or 'HEAD'}",
        f"Head Commit:  {report.head_commit or 'Working Tree'}",
        f"Files Scanned:{len(report.files_reviewed)}",
        f"Total Findings: {len(report.findings)}",
        f"Duration:     {report.execution_time_seconds}s",
        "-" * 78,
    ]

    if report.affected_artifacts.affected_tests:
        lines.append(f"Potentially Affected Tests ({len(report.affected_artifacts.affected_tests)}):")
        for test_file in report.affected_artifacts.affected_tests[:10]:
            lines.append(f"  • {test_file}")
        if len(report.affected_artifacts.affected_tests) > 10:
            lines.append(f"  ... and {len(report.affected_artifacts.affected_tests) - 10} more")
        lines.append("-" * 78)

    if not report.findings:
        lines.append("✅ No quality, reliability, or security findings detected.")
        lines.append("=" * 78)
        return "\n".join(lines)

    lines.append(f"{'SEV':<10} {'LOCATION':<32} {'RULE':<12} {'MESSAGE'}")
    lines.append("-" * 78)

    for f in report.findings:
        loc = f"{f.location.file_path}:{f.location.start_line}"
        if len(loc) > 30:
            loc = "..." + loc[-27:]
        lines.append(f"{f.severity.value:<10} {loc:<32} {f.rule_id:<12} {f.title}")
        if f.technical_evidence:
            lines.append(f"           Evidence: {f.technical_evidence}")
        if f.suggestion:
            lines.append(f"           Fix:      {f.suggestion}")
        lines.append("")

    lines.append("=" * 78)
    return "\n".join(lines)


def run_cli(args: list[str] | None = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(args)

    repo_path = Path(parsed.repo).resolve()
    if not repo_path.exists():
        sys.stderr.write(f"Error: Repository path '{repo_path}' does not exist.\n")
        return 2

    config = ReviewConfig(
        max_file_size_bytes=1_000_000,
        per_file_timeout_seconds=parsed.timeout,
        enable_external_tools=parsed.enable_tools,
        enable_ai_review=parsed.enable_ai,
    )
    engine = LocalReviewEngine(repo_root=repo_path, config=config)

    try:
        report = engine.review_local_git_diff(base_ref=parsed.base)
    except Exception as e:
        sys.stderr.write(f"Review execution failure: {e}\n")
        return 2

    if parsed.format == "json":
        sys.stdout.write(report.model_dump_json(indent=2) + "\n")
    else:
        sys.stdout.write(format_text_report(report, changed_only=parsed.changed_only) + "\n")

    # Evaluate exit code against severity threshold
    threshold_weight = SEVERITY_WEIGHTS[FindingSeverity(parsed.severity_threshold)]
    has_blocking_violations = any(
        SEVERITY_WEIGHTS[f.severity] >= threshold_weight for f in report.findings
    )

    return 1 if has_blocking_violations else 0


def main() -> NoReturn:
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
