"""Orchestrator for LogicFalcon Unified Engineering Intelligence."""

import hashlib
import time
from pathlib import Path

from packages.review.analyzer.architecture import ArchitectureAnalyzer
from packages.review.engine import LocalReviewEngine, ReviewConfig
from packages.review.history.engine import HistoricalIntelligenceEngine
from packages.review.impact.engine import ChangeImpactEngine
from packages.review.reverse_engineering.engine import ReverseEngineeringEngine
from packages.review.unified.models import UnifiedIntelligenceReport
from packages.review.unified.recommendations import RecommendationSynthesizer


class UnifiedIntelligenceEngine:
    """Coordinates code review, architecture analysis, impact analysis, and historical tracking."""

    def __init__(
        self,
        repo_root: str | Path = ".",
        history_db_path: str | Path | None = None,
        max_files: int = 500,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.history_db_path = history_db_path
        self.max_files = max_files

        # Privacy-conscious repository identity
        self.repo_id = hashlib.sha256(str(self.repo_root).encode("utf-8")).hexdigest()

    def analyze(
        self,
        staged: bool = False,
        unstaged: bool = False,
        base_revision: str | None = None,
        target_revision: str | None = None,
        explicit_files: list[str] | None = None,
        save_history: bool = False,
        revision: str | None = None,
        policy_config_path: str | Path | None = None,
    ) -> UnifiedIntelligenceReport:
        """Executes a unified analysis pass across all intelligence pillars."""
        start_time = time.monotonic()
        limitations: list[str] = []

        # 1. Reverse Engineering Intelligence (provides inventory, routes, models)
        re_engine = ReverseEngineeringEngine(
            repo_root=self.repo_root,
            max_files=self.max_files,
        )
        try:
            re_report = re_engine.analyze()
        except Exception as e:
            re_report = None
            limitations.append(f"Reverse engineering engine encountered an error: {e}")

        # 2. Architecture & Dependency Health Analysis
        arch_analyzer = ArchitectureAnalyzer(repo_root=self.repo_root)
        try:
            arch_report = arch_analyzer.analyze(files=explicit_files)
        except Exception as e:
            arch_report = None
            limitations.append(f"Architecture analyzer encountered an error: {e}")

        # 3. Change Impact Intelligence & Predictive Test Selection
        impact_engine = ChangeImpactEngine(
            repo_root=self.repo_root,
            max_entities=300,
        )
        try:
            impact_report = impact_engine.analyze(
                base_rev=base_revision,
                target_rev=target_revision or "HEAD",
                staged=staged,
                unstaged=unstaged,
                explicit_files=explicit_files,
                re_report=re_report,
            )
        except Exception as e:
            impact_report = None
            limitations.append(f"Change impact analysis encountered an error: {e}")

        # 4. Deterministic Code Review
        review_config = ReviewConfig(
            include_re_context=True,
            enable_ai_review=False,
        )
        review_engine = LocalReviewEngine(repo_root=self.repo_root, config=review_config)
        try:
            if explicit_files:
                review_report = review_engine.review_files(explicit_files)
            elif staged:
                review_report = review_engine.review_local_git_diff(staged=True)
            elif unstaged:
                review_report = review_engine.review_local_git_diff(unstaged=True)
            elif base_revision:
                review_report = review_engine.review_local_git_diff(base_ref=base_revision)
            else:
                review_report = review_engine.review_local_git_diff()
        except Exception as e:
            review_report = None
            limitations.append(f"Local review engine encountered an error: {e}")

        # 5. Historical Tracking & Regression Analytics
        from packages.review.history.debt import TechnicalDebtEstimator

        history_engine = HistoricalIntelligenceEngine(
            repo_root=self.repo_root,
            db_path=self.history_db_path,
        )
        history_comparison = None
        trend_report = None
        debt_estimate = None
        policy_result = None

        try:
            # Capture snapshot
            snapshot = history_engine.capture_snapshot(
                revision=revision,
                save=save_history,
                max_files=self.max_files,
            )
            debt_estimate = TechnicalDebtEstimator.estimate(
                findings=snapshot.findings,
                metrics=snapshot.metrics,
            )

            if save_history:
                recent_snaps = history_engine.storage.list_snapshots(limit=2)
                if len(recent_snaps) >= 2:
                    history_comparison = history_engine.compare_snapshots(
                        from_id_or_rev=str(recent_snaps[1].id),
                        to_id_or_rev=str(recent_snaps[0].id),
                    )
                    policy_result = history_engine.evaluate_policy(
                        config_path=policy_config_path,
                        comparison=history_comparison,
                        snapshot=snapshot,
                    )
                trend_report = history_engine.analyze_trends(limit=10)
        except Exception as e:
            limitations.append(f"Historical intelligence subsystem encountered an error: {e}")

        # 6. Evidence-Based Recommendation Synthesis
        recommendations = RecommendationSynthesizer.synthesize(
            review_report=review_report,
            architecture_report=arch_report,
            impact_report=impact_report,
            history_comparison=history_comparison,
            trend_report=trend_report,
            debt_estimate=debt_estimate,
        )

        # 7. Aggregate Findings and Metrics
        total_findings = len(review_report.findings) if review_report else 0
        sev_counts: dict[str, int] = {}
        if review_report:
            for f in review_report.findings:
                sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        arch_score = getattr(arch_report, "health_score", 100.0) if arch_report else 100.0
        cycles_count = len(getattr(arch_report, "cycles", [])) if arch_report else 0
        boundary_count = len(getattr(arch_report, "boundary_violations", [])) if arch_report else 0

        tot_files = re_report.inventory.total_files if re_report and re_report.inventory else 0
        tot_routes = re_report.api_inventory.total_routes if re_report and re_report.api_inventory else 0
        tot_models = re_report.data_model_inventory.total_models if re_report and re_report.data_model_inventory else 0

        impact_risk = impact_report.risk_level.value if impact_report else "LOW"
        impact_score = impact_report.risk_score if impact_report else 0.0
        recommended_tests = [t.test_file for t in impact_report.recommended_tests] if impact_report else []

        trend_dir = trend_report.health_direction.value if trend_report else "STABLE"
        debt_pts = debt_estimate.total_points if debt_estimate else 0.0

        pol_passed = policy_result.passed if policy_result else True
        pol_violations = len(policy_result.violations) if policy_result else 0

        execution_time = time.monotonic() - start_time

        return UnifiedIntelligenceReport(
            repository_path=str(self.repo_root),
            repository_id=self.repo_id,
            revision=revision,
            execution_time_seconds=execution_time,
            review_findings_count=total_findings,
            review_severity_counts=sev_counts,
            architecture_score=arch_score,
            circular_dependency_count=cycles_count,
            boundary_violations_count=boundary_count,
            total_files=tot_files,
            total_routes=tot_routes,
            total_models=tot_models,
            impact_risk_level=impact_risk,
            impact_risk_score=impact_score,
            recommended_tests_count=len(recommended_tests),
            recommended_tests=recommended_tests,
            history_trend_direction=trend_dir,
            technical_debt_points=debt_pts,
            policy_passed=pol_passed,
            policy_violations_count=pol_violations,
            recommendations=recommendations,
            limitations=limitations,
        )
