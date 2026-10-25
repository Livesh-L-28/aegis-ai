from pathlib import Path
from typing import Any

from packages.review.domain.models import FindingSeverity, ReviewReport
from packages.review.history.models import (
    EngineeringTrendReport,
    SnapshotComparison,
    TechnicalDebtEstimate,
)
from packages.review.impact.models import ChangeImpactReport, ImpactRiskLevel
from packages.review.unified.models import (
    RecommendationCategory,
    RecommendationPriority,
    UnifiedRecommendation,
)


class RecommendationSynthesizer:
    """Synthesizes evidence-grounded recommendations across static analysis engines."""

    @classmethod
    def synthesize(
        cls,
        review_report: ReviewReport | None = None,
        architecture_report: Any = None,
        impact_report: ChangeImpactReport | None = None,
        history_comparison: SnapshotComparison | None = None,
        trend_report: EngineeringTrendReport | None = None,
        debt_estimate: TechnicalDebtEstimate | None = None,
    ) -> list[UnifiedRecommendation]:
        """Builds a deterministic, deduplicated list of prioritized engineering recommendations."""
        recommendations: list[UnifiedRecommendation] = []

        # 1. Security & Quality Review Findings
        if review_report and review_report.findings:
            cls._synthesize_review_recommendations(review_report, recommendations)

        # 2. Architecture Cycles & Boundary Violations
        if architecture_report:
            cls._synthesize_architecture_recommendations(architecture_report, recommendations)

        # 3. Change Impact & Predictive Test Selection
        if impact_report:
            cls._synthesize_impact_recommendations(impact_report, recommendations)

        # 4. Historical Regressions & Reopened Findings
        if history_comparison:
            cls._synthesize_history_comparison_recommendations(history_comparison, recommendations)

        # 5. Longitudinal Trends & Chronic Recurring Defects
        if trend_report:
            cls._synthesize_trend_recommendations(trend_report, recommendations)

        # 6. Technical Debt Hotspots
        if debt_estimate:
            cls._synthesize_debt_recommendations(debt_estimate, recommendations)

        # 7. Deduplicate by ID and sort deterministically
        seen_ids: set[str] = set()
        deduped: list[UnifiedRecommendation] = []
        for rec in recommendations:
            if rec.id not in seen_ids:
                seen_ids.add(rec.id)
                deduped.append(rec)

        priority_order = {
            RecommendationPriority.CRITICAL: 0,
            RecommendationPriority.HIGH: 1,
            RecommendationPriority.MEDIUM: 2,
            RecommendationPriority.LOW: 3,
            RecommendationPriority.INFORMATIONAL: 4,
        }

        deduped.sort(
            key=lambda r: (
                priority_order.get(r.priority, 5),
                -r.confidence,
                r.id,
            )
        )
        return deduped

    @classmethod
    def _synthesize_review_recommendations(
        cls,
        report: ReviewReport,
        recommendations: list[UnifiedRecommendation],
    ) -> None:
        """Synthesizes recommendations from active code review findings."""
        # Group by rule_id
        by_rule: dict[str, list[Any]] = {}
        for finding in report.findings:
            by_rule.setdefault(finding.rule_id, []).append(finding)

        for rule_id, findings in sorted(by_rule.items(), key=lambda x: x[0]):
            highest_sev = findings[0].severity
            for f in findings[1:]:
                if f.severity == FindingSeverity.CRITICAL:
                    highest_sev = FindingSeverity.CRITICAL
                elif f.severity == FindingSeverity.ERROR and highest_sev != FindingSeverity.CRITICAL:
                    highest_sev = FindingSeverity.ERROR
                elif f.severity == FindingSeverity.WARNING and highest_sev not in (FindingSeverity.CRITICAL, FindingSeverity.ERROR):
                    highest_sev = FindingSeverity.WARNING

            if highest_sev == FindingSeverity.CRITICAL:
                priority = RecommendationPriority.CRITICAL
            elif highest_sev == FindingSeverity.ERROR:
                priority = RecommendationPriority.HIGH
            elif highest_sev == FindingSeverity.WARNING:
                priority = RecommendationPriority.MEDIUM
            else:
                priority = RecommendationPriority.LOW

            affected_files = sorted(
                {
                    f.location.file_path
                    if hasattr(f, "location") and f.location
                    else getattr(f, "file_path", "")
                    for f in findings
                }
            )
            components = sorted(
                {
                    f.metadata.get("re_component")
                    for f in findings
                    if f.metadata and f.metadata.get("re_component")
                }
            )

            rec_id = f"REC-SEC-{rule_id}"
            title = f"Remediate {len(findings)} {highest_sev.value} finding(s) for rule {rule_id}"
            rationale = (
                f"Rule {rule_id} detected {len(findings)} instance(s) of potential security or "
                f"reliability violations across {len(affected_files)} file(s)."
            )

            evidence = []
            for f in findings[:5]:
                loc_fp = f.location.file_path if hasattr(f, "location") and f.location else getattr(f, "file_path", "")
                loc_line = f.location.start_line if hasattr(f, "location") and f.location else getattr(f, "line_number", 1)
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                evidence.append(f"[{sev_val}] {loc_fp}:{loc_line} - {f.message}")

            if len(findings) > 5:
                evidence.append(f"... and {len(findings) - 5} additional instance(s).")

            suggested_action = (
                f"Inspect and replace flagged patterns for {rule_id} in {', '.join(affected_files[:3])}. "
                "Ensure safe alternatives, parameterized inputs, or defensive sanitizers are used."
            )

            suggested_tests = [
                f"tests/test_{Path(f).stem}.py" for f in affected_files[:3] if Path(f).stem
            ]

            acceptance = [
                f"Static analysis report confirms zero active {rule_id} findings.",
                "Automated test suite executes successfully with no regressions.",
            ]

            recommendations.append(
                UnifiedRecommendation(
                    id=rec_id,
                    priority=priority,
                    category=RecommendationCategory.SECURITY,
                    title=title,
                    rationale=rationale,
                    supporting_evidence=evidence,
                    affected_components=components,
                    affected_files=affected_files,
                    suggested_action=suggested_action,
                    suggested_tests=suggested_tests,
                    acceptance_criteria=acceptance,
                    confidence=1.0,
                )
            )

    @classmethod
    def _synthesize_architecture_recommendations(
        cls,
        arch_report: Any,
        recommendations: list[UnifiedRecommendation],
    ) -> None:
        """Synthesizes recommendations from architectural analysis."""
        cycles = getattr(arch_report, "cycles", [])
        if cycles:
            rec_id = "REC-ARCH-CYCLES"
            cycle_paths = [getattr(c, "display_path", getattr(c, "path_str", str(c))) for c in cycles[:4]]
            affected = sorted({node for c in cycles for node in getattr(c, "modules", getattr(c, "cycle_nodes", []))})

            recommendations.append(
                UnifiedRecommendation(
                    id=rec_id,
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.ARCHITECTURE,
                    title=f"Resolve {len(cycles)} circular import dependenc{'y' if len(cycles) == 1 else 'ies'}",
                    rationale=(
                        f"Detected {len(cycles)} direct or transitive circular module dependency cycle(s). "
                        "Cycles increase coupling instability, complicate testing, and risk runtime import errors."
                    ),
                    supporting_evidence=[f"Cycle: {cp}" for cp in cycle_paths],
                    affected_components=["DependencyGraph"],
                    affected_files=affected[:8],
                    suggested_action=(
                        "Invert dependencies using interfaces, extract shared types into leaf modules, "
                        "or replace direct imports with dependency injection."
                    ),
                    suggested_tests=["tests/review/test_architecture_and_cycles.py"],
                    acceptance_criteria=[
                        "Architecture analyzer reports 0 circular dependencies.",
                        "Repository architecture health score recovers without cycles deduction.",
                    ],
                    confidence=1.0,
                )
            )

        boundary_violations = getattr(arch_report, "boundary_violations", [])
        if boundary_violations:
            rec_id = "REC-ARCH-BOUNDARIES"
            affected_files = sorted(
                {
                    getattr(v, "source_file", getattr(v, "source_module", "source"))
                    for v in boundary_violations
                }
            )
            evidence = [
                f"Forbidden cross-tier import: {getattr(v, 'source_file', getattr(v, 'source_module', 'source'))} -> {getattr(v, 'target_module', getattr(v, 'target_file', 'target'))} ({getattr(v, 'rule_name', 'boundary_rule')})"
                for v in boundary_violations[:5]
            ]

            recommendations.append(
                UnifiedRecommendation(
                    id=rec_id,
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.ARCHITECTURE,
                    title=f"Fix {len(boundary_violations)} architectural tier boundary violation(s)",
                    rationale=(
                        f"Found {len(boundary_violations)} layer boundary violation(s) violating clean architecture "
                        "separation of concerns (e.g. domain importing infrastructure or presentation)."
                    ),
                    supporting_evidence=evidence,
                    affected_components=["ArchitecturePolicy"],
                    affected_files=affected_files,
                    suggested_action=(
                        "Refactor illegal imports to adhere to layer definitions. Use domain events, "
                        "ports/adapters, or service interfaces."
                    ),
                    suggested_tests=[],
                    acceptance_criteria=[
                        "Zero boundary violations reported by logicfalcon architecture.",
                    ],
                    confidence=1.0,
                )
            )

    @classmethod
    def _synthesize_impact_recommendations(
        cls,
        impact_report: ChangeImpactReport,
        recommendations: list[UnifiedRecommendation],
    ) -> None:
        """Synthesizes recommendations from change impact analysis."""
        if impact_report.recommended_tests:
            rec_id = "REC-TEST-PREDICTIVE"
            risk = impact_report.risk_level
            priority = (
                RecommendationPriority.CRITICAL
                if risk == ImpactRiskLevel.CRITICAL
                else RecommendationPriority.HIGH
                if risk == ImpactRiskLevel.HIGH
                else RecommendationPriority.MEDIUM
            )

            test_files = [t.test_file for t in impact_report.recommended_tests]
            cs = impact_report.change_set
            evidence = [
                f"Risk Level: {risk.value} (Score: {impact_report.risk_score}/100)",
                f"Modified files: {len(cs.modified_paths)}, Changed symbols: {len(cs.changed_symbols)}",
                f"Total impacted entities: {len(impact_report.impacted_entities)}",
            ]

            recommendations.append(
                UnifiedRecommendation(
                    id=rec_id,
                    priority=priority,
                    category=RecommendationCategory.TEST_SELECTION,
                    title=f"Execute predictive test suite ({len(test_files)} candidate test(s))",
                    rationale=(
                        f"Static change-impact analysis scored this change set at risk level {risk.value} "
                        f"({impact_report.risk_score}/100). Executing targeted tests verifies downstream dependents."
                    ),
                    supporting_evidence=evidence,
                    affected_components=sorted({e.component_name for e in impact_report.impacted_entities if e.component_name}),
                    affected_files=sorted(cs.modified_paths),
                    suggested_action=f"Run predictive tests: pytest {' '.join(test_files[:5])}",
                    suggested_tests=test_files,
                    acceptance_criteria=[
                        f"All {len(test_files)} predictive tests execute and pass.",
                    ],
                    confidence=0.95,
                )
            )

    @classmethod
    def _synthesize_history_comparison_recommendations(
        cls,
        comp: SnapshotComparison,
        recommendations: list[UnifiedRecommendation],
    ) -> None:
        """Synthesizes recommendations from revision comparisons."""
        if comp.reopened_findings:
            rec_id = "REC-REG-REOPENED"
            affected = sorted({f.file_path for f in comp.reopened_findings})
            evidence = []
            for f in comp.reopened_findings[:5]:
                line_no = getattr(f, "start_line", getattr(f, "line_number", 1))
                evidence.append(f"Reopened finding: [{f.severity}] {f.rule_id} in {f.file_path}:{line_no}")

            recommendations.append(
                UnifiedRecommendation(
                    id=rec_id,
                    priority=RecommendationPriority.CRITICAL,
                    category=RecommendationCategory.REGRESSION,
                    title=f"Investigate {len(comp.reopened_findings)} reopened defect regression(s)",
                    rationale=(
                        f"Detected {len(comp.reopened_findings)} finding(s) that were previously resolved in "
                        "prior revisions but have re-emerged in the current change."
                    ),
                    supporting_evidence=evidence,
                    affected_components=[],
                    affected_files=affected,
                    suggested_action="Review commit diff for accidental rollback of prior security/bug fixes.",
                    suggested_tests=[],
                    acceptance_criteria=[
                        "Reopened defects are re-resolved and regression unit tests added.",
                    ],
                    confidence=1.0,
                )
            )

        if comp.detected_regressions:
            rec_id = "REC-REG-METRIC-DROP"
            recommendations.append(
                UnifiedRecommendation(
                    id=rec_id,
                    priority=RecommendationPriority.HIGH,
                    category=RecommendationCategory.REGRESSION,
                    title="Remediate detected engineering regressions",
                    rationale="Revision comparison identified negative engineering metric transitions.",
                    supporting_evidence=comp.detected_regressions,
                    affected_components=[],
                    affected_files=[],
                    suggested_action="Address metric drops before merging revision.",
                    suggested_tests=[],
                    acceptance_criteria=["Zero blocking regressions detected."],
                    confidence=0.9,
                )
            )

    @classmethod
    def _synthesize_trend_recommendations(
        cls,
        trends: EngineeringTrendReport,
        recommendations: list[UnifiedRecommendation],
    ) -> None:
        """Synthesizes recommendations from longitudinal trends."""
        if trends.recurring_rule_ids:
            rec_id = "REC-DEBT-RECURRING"
            top_recurring = trends.recurring_rule_ids[:3]
            evidence = [f"Rule {r_id}: observed in {cnt} historical snapshot(s)" for r_id, cnt in top_recurring]

            recommendations.append(
                UnifiedRecommendation(
                    id=rec_id,
                    priority=RecommendationPriority.MEDIUM,
                    category=RecommendationCategory.TECHNICAL_DEBT,
                    title="Implement preventative linter rules for recurring defect patterns",
                    rationale=(
                        f"Longitudinal history shows chronic recurrence of rules: "
                        f"{', '.join(r_id for r_id, _ in top_recurring)}."
                    ),
                    supporting_evidence=evidence,
                    affected_components=[],
                    affected_files=[],
                    suggested_action="Configure pre-commit hooks or automated IDE QuickFix rules for recurring patterns.",
                    suggested_tests=[],
                    acceptance_criteria=[
                        "Recurring rule frequency decreases across subsequent snapshots.",
                    ],
                    confidence=0.85,
                )
            )

    @classmethod
    def _synthesize_debt_recommendations(
        cls,
        debt: TechnicalDebtEstimate,
        recommendations: list[UnifiedRecommendation],
    ) -> None:
        """Synthesizes recommendations from technical debt assessment."""
        if debt.top_debt_files:
            rec_id = "REC-DEBT-HOTSPOTS"
            top_files = debt.top_debt_files[:3]
            evidence = [f"{path}: {score} debt points" for path, score in top_files]

            recommendations.append(
                UnifiedRecommendation(
                    id=rec_id,
                    priority=RecommendationPriority.MEDIUM,
                    category=RecommendationCategory.TECHNICAL_DEBT,
                    title=f"Refactor top technical debt hotspots ({len(top_files)} files)",
                    rationale="Concentrated technical debt in key files compounds maintenance cost and defect density.",
                    supporting_evidence=evidence,
                    affected_components=[],
                    affected_files=[path for path, _ in top_files],
                    suggested_action="Modularize large files and decouple complex routines into single-responsibility units.",
                    suggested_tests=[],
                    acceptance_criteria=[
                        "Total technical debt score reduced by at least 20%.",
                    ],
                    confidence=0.85,
                )
            )
