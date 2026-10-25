"""Deterministic, secure report generator for LogicFalcon historical intelligence."""

import contextlib
import os
from pathlib import Path

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.history.models import (
    EngineeringTrendReport,
    PolicyEvaluationResult,
    RepositorySnapshot,
    SnapshotComparison,
    TechnicalDebtEstimate,
)
from packages.review.security.path_validation import validate_contained_path


class HistoryReportGenerator:
    """Generates Markdown, JSON, and Text reports for snapshots, comparisons, trends, and policies."""

    @classmethod
    def snapshot_to_markdown(cls, snapshot: RepositorySnapshot) -> str:
        """Formats a single snapshot as an evidence-rich Markdown document."""
        m = snapshot.metrics
        meta = snapshot.metadata

        lines: list[str] = [
            f"# LogicFalcon — Repository Health Snapshot ({meta.repo_name or 'Local Repository'})",
            "",
            "> **Historical Intelligence Report**  ",
            f"> Snapshot ID: `{snapshot.id}` | Revision: `{meta.revision or 'N/A'}` | State: `{meta.git_state}`  ",
            f"> Captured: {meta.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')} | LogicFalcon v{meta.logicfalcon_version}",
            "",
            "---",
            "",
            "## 1. Executive Summary & Health Overview",
            "",
            "| Metric | Measured Value | Unit / Status |",
            "| :--- | :--- | :--- |",
            f"| **Architecture Health Score** | **{m.health_score:.1f} / 100** | Health Index |",
            f"| **Technical Debt Points** | **{m.tech_debt_points:.1f} pts** | Normalized Effort |",
            f"| **Total Active Findings** | **{len(snapshot.findings)}** | Detected Defects |",
            f"| **Circular Dependency Cycles** | **{m.cycle_count}** | Architectural Risk |",
            f"| **Boundary Violations** | **{m.boundary_violations_count}** | Layer Isolation |",
            f"| **Coupling Hotspots** | **{m.hotspot_count}** | High Instability Modules |",
            f"| **Scan Coverage** | **{meta.scan_coverage:.1%}** | ({meta.parsed_files}/{max(1, meta.discovered_files)} files) |",
            "",
            "---",
            "",
            "## 2. Findings Severity Breakdown",
            "",
        ]

        if m.severity_distribution:
            lines.append("| Severity | Count |")
            lines.append("| :--- | :--- |")
            for sev, count in sorted(m.severity_distribution.items()):
                lines.append(f"| `{sev}` | {count} |")
            lines.append("")
        else:
            lines.append("*No static code review findings detected.*")
            lines.append("")

        if snapshot.findings:
            lines.append("### Active Findings Excerpt (Top 10)")
            lines.append("")
            lines.append("| Rule | Severity | Location | Title | Message |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for f in snapshot.findings[:10]:
                lines.append(f"| `{f.rule_id}` | `{f.severity}` | `{f.file_path}:{f.start_line}` | {f.title} | {f.message} |")
            lines.append("")

        if snapshot.limitations:
            lines.append("---")
            lines.append("## 3. Analysis Limitations & Coverage Gaps")
            lines.append("")
            for lim in snapshot.limitations:
                lines.append(f"- ⚠️ {lim}")
            lines.append("")

        return redact_secrets_in_text("\n".join(lines))

    @classmethod
    def comparison_to_markdown(cls, comparison: SnapshotComparison) -> str:
        """Formats a revision comparison and regression analysis as Markdown."""
        lines: list[str] = [
            "# LogicFalcon — Revision Health Comparison & Regression Report",
            "",
            f"> Base Snapshot: `{comparison.from_snapshot_id}` (Rev: `{comparison.from_revision or 'base'}`)  ",
            f"> Target Snapshot: `{comparison.to_snapshot_id}` (Rev: `{comparison.to_revision or 'target'}`)  ",
            f"> Evaluation Time: {comparison.to_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "---",
            "",
            "## 1. Delta Summary",
            "",
            "| Metric | Delta | Direction |",
            "| :--- | :--- | :--- |",
            f"| **Health Score Delta** | {comparison.health_score_delta:+.1f} pts | {'🟢 Improved' if comparison.health_score_delta > 0 else '🔴 Deteriorated' if comparison.health_score_delta < 0 else '⚪ Stable'} |",
            f"| **Technical Debt Delta** | {comparison.tech_debt_delta:+.1f} pts | {'🟢 Reduced' if comparison.tech_debt_delta < 0 else '🔴 Increased' if comparison.tech_debt_delta > 0 else '⚪ Stable'} |",
            f"| **New Findings** | +{len(comparison.new_findings)} | {'🔴 Regressions' if comparison.new_findings else '🟢 None'} |",
            f"| **Resolved Findings** | -{len(comparison.resolved_findings)} | {'🟢 Fixed' if comparison.resolved_findings else '⚪ None'} |",
            f"| **Reopened Findings** | {len(comparison.reopened_findings)} | {'🔴 Regressions' if comparison.reopened_findings else '⚪ None'} |",
            f"| **Uncertain Findings** | {len(comparison.uncertain_findings)} | ⚠️ Missing Scan Evidence |",
            "",
        ]

        if comparison.detected_regressions:
            lines.append("---")
            lines.append("## 2. 🚨 Detected Engineering Regressions")
            lines.append("")
            for reg in comparison.detected_regressions:
                lines.append(f"- ❌ **Regression**: {reg}")
            lines.append("")

        if comparison.new_findings:
            lines.append("---")
            lines.append("## 3. Newly Introduced Findings")
            lines.append("")
            lines.append("| Rule | Severity | Location | Title |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for f in comparison.new_findings:
                lines.append(f"| `{f.rule_id}` | `{f.severity}` | `{f.file_path}:{f.start_line}` | {f.title} |")
            lines.append("")

        if comparison.resolved_findings:
            lines.append("---")
            lines.append("## 4. Confirmed Resolved Findings")
            lines.append("")
            lines.append("| Rule | Severity | Location | Title |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for f in comparison.resolved_findings:
                lines.append(f"| `{f.rule_id}` | `{f.severity}` | `{f.file_path}:{f.start_line}` | {f.title} |")
            lines.append("")

        if comparison.comparability_notes:
            lines.append("---")
            lines.append("## 5. Comparability & Scan Caveats")
            lines.append("")
            for note in comparison.comparability_notes:
                lines.append(f"- 📌 {note}")
            lines.append("")

        return redact_secrets_in_text("\n".join(lines))

    @classmethod
    def trends_to_markdown(cls, report: EngineeringTrendReport) -> str:
        """Formats historical trend analysis as Markdown."""
        lines: list[str] = [
            f"# LogicFalcon — Longitudinal Engineering Trends ({report.repository_name})",
            "",
            "> **Historical Trend Intelligence**  ",
            f"> Sampled Snapshots: **{report.sample_count}** across **{report.time_span_days} days**  ",
            f"> Health Trajectory: **{report.health_direction.value}** | Debt Trajectory: **{report.debt_direction.value}**",
            "",
            "---",
            "",
            "## 1. Longitudinal Overview",
            "",
            f"- **Debt Velocity**: `{report.debt_velocity:+.1f} points/snapshot`",
            f"- **Net Findings Delta**: `{report.net_findings_delta:+d} findings`",
            "",
            "### Summary Commentary:",
            "",
        ]
        for c in report.summary_commentary:
            lines.append(f"- {c}")
        lines.append("")

        if report.trend_points:
            lines.append("---")
            lines.append("## 2. Historical Snapshot Timeline")
            lines.append("")
            lines.append("| Snapshot ID | Date | Revision | Health Score | Tech Debt | Findings | Cycles |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for tp in report.trend_points:
                short_id = tp.snapshot_id[:8]
                dt_str = tp.timestamp.strftime("%Y-%m-%d %H:%M")
                rev_str = tp.revision[:7] if tp.revision else "N/A"
                lines.append(
                    f"| `{short_id}` | {dt_str} | `{rev_str}` | {tp.health_score:.1f} | {tp.tech_debt_points:.1f} | {tp.total_findings} | {tp.cycle_count} |"
                )
            lines.append("")

        if report.recurring_rule_ids:
            lines.append("---")
            lines.append("## 3. Recurring Defects Across Revisions")
            lines.append("")
            lines.append("| Rule Identifier | Occurrence Frequency across Snapshots |")
            lines.append("| :--- | :--- |")
            for r, freq in report.recurring_rule_ids:
                lines.append(f"| `{r}` | {freq} snapshot(s) |")
            lines.append("")

        return redact_secrets_in_text("\n".join(lines))

    @classmethod
    def policy_to_markdown(cls, result: PolicyEvaluationResult) -> str:
        """Formats engineering policy gate evaluation as Markdown."""
        status_badge = "🟢 PASSED" if result.passed else "🔴 FAILED (BLOCKING)"
        lines: list[str] = [
            "# LogicFalcon — Engineering Policy Gate Evaluation",
            "",
            f"> **Status: {status_badge}** | Rules Evaluated: {result.rules_evaluated}  ",
            f"> Suggested Exit Code: `{result.suggested_exit_code}`",
            "",
            "---",
            "",
        ]

        if result.violations:
            lines.append("## 🚨 Blocking Policy Violations")
            lines.append("")
            lines.append("| Rule ID | Condition | Actual | Threshold | Violation Message |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for v in result.violations:
                lines.append(f"| `{v.rule_id}` | `{v.condition}` | {v.actual_value:.1f} | {v.threshold_value:.1f} | {v.message} |")
            lines.append("")

        if result.warnings:
            lines.append("## ⚠️ Policy Warnings (Non-Blocking)")
            lines.append("")
            lines.append("| Rule ID | Condition | Actual | Threshold | Warning Message |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for w in result.warnings:
                lines.append(f"| `{w.rule_id}` | `{w.condition}` | {w.actual_value:.1f} | {w.threshold_value:.1f} | {w.message} |")
            lines.append("")

        if result.passed and not result.warnings:
            lines.append("All configured engineering policy gates passed cleanly without warnings.")
            lines.append("")

        return redact_secrets_in_text("\n".join(lines))

    @classmethod
    def debt_to_markdown(cls, estimate: TechnicalDebtEstimate) -> str:
        """Formats technical debt breakdown as Markdown."""
        lines: list[str] = [
            "# LogicFalcon — Technical Debt Assessment",
            "",
            f"> **Total Technical Debt: {estimate.total_points:.1f} points**",
            "",
            "---",
            "",
            "## 1. Severity Distribution Breakdown",
            "",
            "| Severity | Debt Points | Contribution |",
            "| :--- | :--- | :--- |",
        ]
        for sev, pts in sorted(estimate.severity_breakdown.items(), key=lambda x: x[1], reverse=True):
            pct = (pts / max(0.1, estimate.total_points)) * 100
            lines.append(f"| `{sev}` | {pts:.1f} pts | {pct:.1f}% |")
        lines.append("")

        if estimate.category_breakdown:
            lines.append("## 2. Category Distribution Breakdown")
            lines.append("")
            lines.append("| Category | Debt Points | Contribution |")
            lines.append("| :--- | :--- | :--- |")
            for cat, pts in sorted(estimate.category_breakdown.items(), key=lambda x: x[1], reverse=True):
                pct = (pts / max(0.1, estimate.total_points)) * 100
                lines.append(f"| `{cat}` | {pts:.1f} pts | {pct:.1f}% |")
            lines.append("")

        if estimate.top_debt_files:
            lines.append("## 3. Top Debt Module Hotspots")
            lines.append("")
            lines.append("| Module File Path | Debt Points |")
            lines.append("| :--- | :--- |")
            for fp, pts in estimate.top_debt_files:
                lines.append(f"| `{fp}` | {pts:.1f} pts |")
            lines.append("")

        lines.append("---")
        lines.append("## 4. Estimation Assumptions")
        lines.append("")
        for a in estimate.assumptions:
            lines.append(f"- {a}")
        lines.append("")

        return redact_secrets_in_text("\n".join(lines))

    @classmethod
    def write_to_file(
        cls,
        rendered_content: str,
        target_path: str | Path,
        repo_root: str | Path | None = None,
    ) -> Path:
        """Safely writes report content to disk with path containment checks and overwrite defenses."""
        target_p = Path(target_path)
        target_path_str = str(target_path)

        # 1. Source code file overwrite defense
        suffix = target_p.suffix.lower()
        if suffix in (".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".rs", ".java"):
            raise PermissionError(
                f"Refusing to write report to source code file '{target_p.name}'. "
                "Reports must use report extensions (.md, .json, .txt)."
            )

        # 2. Path containment check
        if repo_root is not None:
            resolved_root = Path(repo_root).resolve()
            if target_p.is_absolute():
                resolved_target = target_p.resolve()
                try:
                    if not resolved_target.is_relative_to(resolved_root):
                        raise PermissionError(f"Rejected report path outside repository: '{target_path_str}'")
                    target_p = resolved_target
                except (ValueError, AttributeError):
                    raise PermissionError(f"Rejected report path outside repository: '{target_path_str}'") from None
            else:
                contained = validate_contained_path(resolved_root, target_path_str)
                if contained is None:
                    raise PermissionError(f"Rejected report path outside repository: '{target_path_str}'")
                target_p = contained

        target_p.parent.mkdir(parents=True, exist_ok=True)

        # 3. Atomic write via .tmp
        tmp_target = target_p.with_suffix(f"{target_p.suffix}.tmp")
        try:
            tmp_target.write_text(rendered_content, encoding="utf-8")
            os.replace(tmp_target, target_p)
        finally:
            if tmp_target.exists():
                with contextlib.suppress(OSError):
                    tmp_target.unlink()

        return target_p
