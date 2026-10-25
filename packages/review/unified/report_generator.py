"""Deterministic, secure report generator for Unified Engineering Intelligence."""

import os
from pathlib import Path

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.security.path_validation import validate_contained_path
from packages.review.unified.models import UnifiedIntelligenceReport


class UnifiedReportGenerator:
    """Renders Unified Engineering Intelligence reports in Markdown, JSON, and Text formats."""

    def __init__(self, report: UnifiedIntelligenceReport) -> None:
        self.report = report

    def to_json(self, indent: int = 2) -> str:
        """Serializes report to schema-stable, secret-redacted JSON."""
        return redact_secrets_in_text(self.report.model_dump_json(indent=indent))

    def to_text(self) -> str:
        """Generates concise plain-text summary suitable for CLI output."""
        rep = self.report
        lines: list[str] = [
            "🦅  LogicFalcon — Unified Engineering Intelligence Report",
            "=" * 70,
            f"Repository: {rep.repository_path} (ID: {rep.repository_id[:12]}...)",
            f"Revision: {rep.revision or 'working-tree'}",
            f"Execution Time: {rep.execution_time_seconds:.2f}s",
            "",
            "Core Engineering Metrics:",
            f"  - Review Findings: {rep.review_findings_count} (Critical: {rep.review_severity_counts.get('CRITICAL', 0)}, High: {rep.review_severity_counts.get('HIGH', 0)})",
            f"  - Architecture Score: {rep.architecture_score:.1f}/100 (Cycles: {rep.circular_dependency_count}, Boundary Violations: {rep.boundary_violations_count})",
            f"  - Change Impact Risk: {rep.impact_risk_level} (Score: {rep.impact_risk_score:.1f}/100)",
            f"  - Predictive Tests Selected: {rep.recommended_tests_count}",
            f"  - Technical Debt: {rep.technical_debt_points:.1f} pts (Trend: {rep.history_trend_direction})",
            f"  - Engineering Policy Gate: {'PASSED' if rep.policy_passed else 'FAILED (BLOCKING)'} ({rep.policy_violations_count} violation(s))",
            "",
            f"Prioritized Recommendations ({len(rep.recommendations)}):",
        ]

        for i, rec in enumerate(rep.recommendations, 1):
            lines.append(f"  {i}. [{rec.priority.value}] {rec.title} ({rec.id})")
            lines.append(f"     Action: {rec.suggested_action}")
            if rec.suggested_tests:
                lines.append(f"     Tests: {', '.join(rec.suggested_tests[:3])}")

        return redact_secrets_in_text("\n".join(lines))

    def to_markdown(self) -> str:
        """Generates comprehensive, beautifully formatted Markdown report."""
        rep = self.report
        policy_badge = "🟢 **PASSED**" if rep.policy_passed else "🔴 **FAILED (BLOCKING)**"

        lines: list[str] = [
            "# 🦅 LogicFalcon — Unified Engineering Intelligence Report",
            "",
            f"> **Repository:** `{rep.repository_path}` | **Revision:** `{rep.revision or 'working-tree'}`  ",
            f"> **Report ID:** `{rep.id}` | **Generated:** `{rep.created_at.isoformat()}`  ",
            f"> **Engineering Policy Gate:** {policy_badge}",
            "",
            "---",
            "",
            "## 1. Executive Summary & Quality Dashboard",
            "",
            "| Intelligence Metric | Measured Value | Health Indicator |",
            "| :--- | :--- | :--- |",
            f"| **Review Security & Quality Findings** | `{rep.review_findings_count}` issues | {'🟢 Clean' if rep.review_findings_count == 0 else '🟡 Action Needed' if rep.review_severity_counts.get('CRITICAL', 0) == 0 else '🔴 Critical Attention'} |",
            f"| **Architecture Health Score** | `{rep.architecture_score:.1f} / 100` | {'🟢 Optimal' if rep.architecture_score >= 80 else '🟡 Modularity Risk' if rep.architecture_score >= 60 else '🔴 Severe Degradation'} |",
            f"| **Circular Dependency Cycles** | `{rep.circular_dependency_count}` cycles | {'🟢 Zero' if rep.circular_dependency_count == 0 else '🔴 Cycles Detected'} |",
            f"| **Layer Boundary Violations** | `{rep.boundary_violations_count}` violations | {'🟢 Compliant' if rep.boundary_violations_count == 0 else '🔴 Boundary Breaches'} |",
            f"| **Change Impact Risk Level** | `{rep.impact_risk_level}` (`{rep.impact_risk_score:.1f}/100`) | {'🟢 Low Risk' if rep.impact_risk_score < 30 else '🟡 Medium Risk' if rep.impact_risk_score < 60 else '🔴 High Risk'} |",
            f"| **Predictive Tests Selected** | `{rep.recommended_tests_count}` tests | Target verification set |",
            f"| **Technical Debt Points** | `{rep.technical_debt_points:.1f} pts` | Trend: `{rep.history_trend_direction}` |",
            f"| **Engineering Policy Gate** | `{policy_badge}` | `{rep.policy_violations_count}` policy violation(s) |",
            "",
            "---",
            "",
            f"## 2. Evidence-Based Prioritized Recommendations ({len(rep.recommendations)})",
            "",
        ]

        if not rep.recommendations:
            lines.append("No active recommendations. Repository satisfies all engineering quality baselines.")
        else:
            for rec in rep.recommendations:
                p_icon = "🔴" if rec.priority.value in ("CRITICAL", "HIGH") else "🟡" if rec.priority.value == "MEDIUM" else "🔵"
                lines.append(f"### {p_icon} [{rec.priority.value}] {rec.title}")
                lines.append(f"**ID:** `{rec.id}` | **Category:** `{rec.category.value}` | **Confidence:** `{int(rec.confidence * 100)}%`\n")
                lines.append(f"**Rationale:** {rec.rationale}\n")

                if rec.supporting_evidence:
                    lines.append("**Supporting Evidence:**")
                    for ev in rec.supporting_evidence:
                        lines.append(f"- {ev}")
                    lines.append("")

                if rec.affected_files:
                    lines.append(f"**Affected Files:** `{', '.join(rec.affected_files[:6])}`\n")

                lines.append(f"**Suggested Action:** {rec.suggested_action}\n")

                if rec.suggested_tests:
                    lines.append(f"**Recommended Tests:** `{', '.join(rec.suggested_tests)}`\n")

                if rec.acceptance_criteria:
                    lines.append("**Acceptance Criteria:**")
                    for ac in rec.acceptance_criteria:
                        lines.append(f"- [ ] {ac}")
                    lines.append("")

                lines.append("---")
                lines.append("")

        if rep.recommended_tests:
            lines.append("## 3. Predictive Test Selection Candidates")
            lines.append("")
            lines.append("Target test candidates determined from static change-impact propagation:")
            for t in rep.recommended_tests:
                lines.append(f"- `{t}`")
            lines.append("")

        if rep.limitations:
            lines.append("## 4. Analysis Limitations & Boundary Constraints")
            lines.append("")
            for lim in rep.limitations:
                lines.append(f"- ⚠️ {lim}")
            lines.append("")

        return redact_secrets_in_text("\n".join(lines))

    @classmethod
    def write_report(
        cls,
        output_path: str | Path,
        content: str,
        repo_root: str | Path | None = None,
        allow_overwrite: bool = True,
    ) -> Path:
        """Safely writes report to disk enforcing path containment, source-file overwrite refusal, and atomic writing."""
        target_p = Path(output_path)
        target_path_str = str(output_path)

        # 1. Reject source code overwrites
        forbidden_extensions = {".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".rs", ".c", ".cpp", ".java"}
        if target_p.suffix.lower() in forbidden_extensions:
            raise PermissionError(f"Refusing to write report to source code file: {target_p.name}")

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
        else:
            target_p = target_p.resolve()

        if target_p.exists() and not allow_overwrite:
            raise FileExistsError(f"Report file already exists: {target_p}")

        target_p.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target_p.with_suffix(f"{target_p.suffix}.tmp")

        redacted_content = redact_secrets_in_text(content)
        tmp_path.write_text(redacted_content, encoding="utf-8")
        os.replace(tmp_path, target_p)
        return target_p
