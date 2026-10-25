"""Orchestrator for Change Impact Intelligence and Predictive Test Selection."""

import time
from pathlib import Path

from packages.review.analyzer.dependency_graph import DependencyGraph
from packages.review.domain.models import ReviewFinding, ReviewReport
from packages.review.impact.change_detector import ChangeSetDetector
from packages.review.impact.models import (
    ChangeImpactReport,
    ChangeSet,
    ImpactAnalysisLimitation,
)
from packages.review.impact.propagator import ImpactPropagator
from packages.review.impact.scorer import ImpactScorer
from packages.review.impact.test_selector import PredictiveTestSelector
from packages.review.reverse_engineering.engine import ReverseEngineeringEngine
from packages.review.reverse_engineering.models import ReverseEngineeringReport


class ChangeImpactEngine:
    """Coordinates change detection, dependency propagation, risk scoring, and test selection."""

    def __init__(
        self,
        repo_root: str | Path,
        dependency_graph: DependencyGraph | None = None,
        max_depth: int = 5,
        max_entities: int = 500,
        conservative_tests: bool = False,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.dep_graph = dependency_graph or DependencyGraph(self.repo_root)
        self.max_depth = max_depth
        self.max_entities = max_entities
        self.conservative_tests = conservative_tests
        self.detector = ChangeSetDetector(self.repo_root)
        self.scorer = ImpactScorer()

    def analyze(
        self,
        change_set: ChangeSet | None = None,
        base_rev: str | None = None,
        target_rev: str | None = None,
        staged: bool = False,
        unstaged: bool = False,
        explicit_files: list[str] | None = None,
        re_report: ReverseEngineeringReport | None = None,
        run_re: bool = True,
        findings_by_file: dict[str, list[ReviewFinding]] | None = None,
    ) -> ChangeImpactReport:
        """Executes complete change impact analysis and predictive test selection."""
        start_time = time.perf_counter()
        limitations: list[ImpactAnalysisLimitation] = []

        # 1. Acquire change set
        cs = change_set
        if cs is None:
            if explicit_files is not None:
                cs = self.detector.from_explicit_files(explicit_files)
            elif base_rev is not None:
                cs = self.detector.from_revisions(base_rev=base_rev, target_rev=target_rev or "HEAD")
            else:
                cs = self.detector.from_working_tree(staged=staged, unstaged=unstaged)

        # 2. Reverse Engineering Intelligence (optional / on-demand)
        resolved_re_report = re_report
        if resolved_re_report is None and run_re:
            try:
                re_engine = ReverseEngineeringEngine(repo_root=self.repo_root)
                resolved_re_report = re_engine.analyze()
            except Exception as e:
                limitations.append(
                    ImpactAnalysisLimitation(
                        category="re_analysis_error",
                        file_path="repository_root",
                        description=f"Reverse engineering reconnaissance failed: {e}",
                    )
                )

        # 3. Propagate impact through dependency & call graphs
        propagator = ImpactPropagator(
            repo_root=self.repo_root,
            dependency_graph=self.dep_graph,
            re_report=resolved_re_report,
            max_depth=self.max_depth,
            max_entities=self.max_entities,
        )
        entities, prop_limitations = propagator.propagate(cs)
        limitations.extend(prop_limitations)

        # 4. Score entities and evaluate change risk
        self.scorer.score_entities(entities, findings_by_file=findings_by_file)
        risk_level, risk_score, risk_reasons = self.scorer.evaluate_change_risk(cs, entities)

        # 5. Select recommended tests
        test_selector = PredictiveTestSelector(
            repo_root=self.repo_root,
            dependency_graph=self.dep_graph,
            conservative_mode=self.conservative_tests,
        )
        recommended_tests = test_selector.select_tests(cs, entities)

        elapsed = time.perf_counter() - start_time
        return ChangeImpactReport(
            repository_path=str(self.repo_root),
            execution_time_seconds=round(elapsed, 4),
            change_set=cs,
            impacted_entities=entities,
            recommended_tests=recommended_tests,
            risk_level=risk_level,
            risk_score=risk_score,
            risk_reasons=risk_reasons,
            limitations=limitations,
            metadata={
                "max_depth": self.max_depth,
                "conservative_tests": self.conservative_tests,
                "re_intelligence_active": resolved_re_report is not None,
            },
        )

    def analyze_with_review(
        self,
        base_rev: str | None = None,
        target_rev: str | None = None,
        staged: bool = False,
        unstaged: bool = False,
        explicit_files: list[str] | None = None,
    ) -> tuple[ChangeImpactReport, ReviewReport]:
        """Runs change impact analysis alongside LocalReviewEngine, correlating findings with impact."""
        from packages.review.engine import LocalReviewEngine, ReviewConfig

        # First run review on the target changes
        review_config = ReviewConfig(include_re_context=True)
        review_engine = LocalReviewEngine(repo_root=self.repo_root, config=review_config)

        if explicit_files:
            review_report = review_engine.review_files(file_paths=explicit_files)
        else:
            review_report = review_engine.review_local_git_diff(
                staged=staged,
                unstaged=unstaged,
                base_ref=base_rev,
            )

        # Map findings by file
        findings_by_file: dict[str, list[ReviewFinding]] = {}
        for f in review_report.findings:
            findings_by_file.setdefault(f.location.file_path, []).append(f)

        # Execute change impact analysis with correlated findings
        impact_report = self.analyze(
            base_rev=base_rev,
            target_rev=target_rev,
            staged=staged,
            unstaged=unstaged,
            explicit_files=explicit_files,
            findings_by_file=findings_by_file,
        )

        # Attach impact summary to review report metadata without altering finding severities
        review_report.metadata["impact_analysis"] = {
            "risk_level": impact_report.risk_level.value,
            "risk_score": impact_report.risk_score,
            "impacted_entities_count": len(impact_report.impacted_entities),
            "recommended_tests_count": len(impact_report.recommended_tests),
        }

        return impact_report, review_report
