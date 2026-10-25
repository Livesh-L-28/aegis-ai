"""Unit tests for Unified Engineering Intelligence models and recommendation synthesis."""

from datetime import UTC, datetime
from typing import Any

from packages.review.domain.models import (
    BoundaryViolation,
    DependencyCycle,
    FindingCategory,
    FindingOrigin,
    FindingSeverity,
    ReviewFinding,
    SourceLocation,
)
from packages.review.history.models import (
    EngineeringTrendReport,
    SnapshotComparison,
    SnapshotFinding,
    TechnicalDebtEstimate,
    TrendDirection,
)
from packages.review.impact.models import (
    ChangeImpactReport,
    ChangeSet,
    ConfidenceCategory,
    ImpactedEntity,
    ImpactRiskLevel,
    ImpactType,
)
from packages.review.impact.models import (
    TestImpactCandidate as _TestImpactCandidate,
)
from packages.review.unified.models import (
    RecommendationCategory,
    RecommendationPriority,
    UnifiedIntelligenceReport,
    UnifiedRecommendation,
)
from packages.review.unified.recommendations import RecommendationSynthesizer


def test_unified_recommendation_and_report_models() -> None:
    rec = UnifiedRecommendation(
        id="REC-TEST-001",
        priority=RecommendationPriority.CRITICAL,
        category=RecommendationCategory.SECURITY,
        title="Test Critical Security Recommendation",
        rationale="Testing rationale",
        supporting_evidence=["Evidence 1", "Evidence 2"],
        affected_components=["Core"],
        affected_files=["app/main.py"],
        suggested_action="Patch vulnerable call",
        suggested_tests=["tests/test_main.py"],
        acceptance_criteria=["Zero findings"],
        confidence=0.95,
        known_limitations=[],
    )
    assert rec.priority == RecommendationPriority.CRITICAL
    assert rec.category == RecommendationCategory.SECURITY

    rep = UnifiedIntelligenceReport(
        repository_path="/fake/repo",
        repository_id="fake-hash",
        recommendations=[rec],
    )
    assert rep.schema_version == "1.0.0"
    assert len(rep.recommendations) == 1
    assert rep.recommendations[0].id == "REC-TEST-001"


def test_recommendation_synthesizer_from_review_findings() -> None:
    f_crit = ReviewFinding(
        rule_id="SEC-001",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.CRITICAL,
        title="Dynamic Code Execution",
        message="Unsafe eval() usage detected",
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="src/eval_handler.py", start_line=42, end_line=42),
        tool_name="ast_security",
        metadata={"re_component": "Handlers"},
    )
    f_high = ReviewFinding(
        rule_id="SEC-003",
        category=FindingCategory.SECURITY,
        severity=FindingSeverity.ERROR,
        title="Hardcoded Secret",
        message="API token literal detected",
        origin=FindingOrigin.STATIC_ANALYSIS,
        location=SourceLocation(file_path="src/config.py", start_line=10, end_line=10),
        tool_name="ast_security",
    )
    class DummyReviewReport:
        def __init__(self, findings_list: list[Any]) -> None:
            self.findings = findings_list

    recs = RecommendationSynthesizer.synthesize(review_report=DummyReviewReport([f_crit, f_high]))  # type: ignore[arg-type]
    assert len(recs) == 2

    # Prioritization check: CRITICAL must precede HIGH
    assert recs[0].priority == RecommendationPriority.CRITICAL
    assert recs[0].id == "REC-SEC-SEC-001"
    assert "src/eval_handler.py" in recs[0].affected_files
    assert "Handlers" in recs[0].affected_components

    assert recs[1].priority == RecommendationPriority.HIGH
    assert recs[1].id == "REC-SEC-SEC-003"


def test_recommendation_synthesizer_from_architecture_cycles_and_boundaries() -> None:
    class DummyArchReport:
        def __init__(self) -> None:
            self.cycles = [
                DependencyCycle(
                    modules=["src/a.py", "src/b.py"],
                    length=2,
                    display_path="src/a.py -> src/b.py -> src/a.py",
                )
            ]
            self.boundary_violations = [
                BoundaryViolation(
                    source_module="domain.order",
                    source_file="domain/order.py",
                    target_module="adapters.db",
                    rule_name="domain_cannot_import_adapters",
                    description="Domain cannot import adapters",
                )
            ]
            self.health_score = 75.0

    recs = RecommendationSynthesizer.synthesize(architecture_report=DummyArchReport())
    rec_ids = {r.id for r in recs}
    assert "REC-ARCH-CYCLES" in rec_ids
    assert "REC-ARCH-BOUNDARIES" in rec_ids

    cycle_rec = next(r for r in recs if r.id == "REC-ARCH-CYCLES")
    assert cycle_rec.priority == RecommendationPriority.HIGH
    assert cycle_rec.category == RecommendationCategory.ARCHITECTURE
    assert any("src/a.py -> src/b.py" in ev for ev in cycle_rec.supporting_evidence)


def test_recommendation_synthesizer_from_impact_and_tests() -> None:
    cs = ChangeSet(
        modified_paths=["src/models.py"],
        added_paths=[],
        deleted_paths=[],
        renamed_paths=[],
        changed_symbols=[],
        total_added_lines=10,
        total_deleted_lines=2,
    )
    impact_rep = ChangeImpactReport(
        repository_path="/fake/repo",
        change_set=cs,
        impacted_entities=[
            ImpactedEntity(
                file_path="src/service.py",
                symbol_name="get_user",
                impact_type=ImpactType.DIRECT_DEPENDENCY,
                depth=1,
                impact_score=60.0,
                component_name="Services",
            )
        ],
        recommended_tests=[
            _TestImpactCandidate(
                test_file="tests/test_service.py",
                associated_target="src/service.py",
                confidence=ConfidenceCategory.HIGH,
                selection_reason="direct dependent",
            )
        ],
        risk_level=ImpactRiskLevel.HIGH,
        risk_score=70.0,
        execution_time_seconds=0.1,
    )

    recs = RecommendationSynthesizer.synthesize(impact_report=impact_rep)
    assert len(recs) == 1
    rec = recs[0]
    assert rec.id == "REC-TEST-PREDICTIVE"
    assert rec.priority == RecommendationPriority.HIGH
    assert rec.category == RecommendationCategory.TEST_SELECTION
    assert "tests/test_service.py" in rec.suggested_tests


def test_recommendation_synthesizer_from_history_reopened_and_trends() -> None:
    f_reopened = SnapshotFinding(
        fingerprint="fp-reopened",
        rule_id="SEC-004",
        category="SECURITY",
        severity="HIGH",
        file_path="src/auth.py",
        start_line=10,
        message="Insecure deserialization",
    )
    now = datetime.now(UTC)
    comp = SnapshotComparison(
        from_snapshot_id="s1",
        to_snapshot_id="s2",
        from_timestamp=now,
        to_timestamp=now,
        reopened_findings=[f_reopened],
    )
    trends = EngineeringTrendReport(
        repository_name="repo",
        sample_count=5,
        time_span_days=10.0,
        recurring_rule_ids=[("SEC-004", 4), ("ARCH-001", 3)],
        health_direction=TrendDirection.DETERIORATING,
    )
    debt = TechnicalDebtEstimate(
        total_points=45.0,
        top_debt_files=[("src/huge.py", 25.0)],
    )

    recs = RecommendationSynthesizer.synthesize(
        history_comparison=comp,
        trend_report=trends,
        debt_estimate=debt,
    )
    rec_ids = {r.id for r in recs}
    assert "REC-REG-REOPENED" in rec_ids
    assert "REC-DEBT-RECURRING" in rec_ids
    assert "REC-DEBT-HOTSPOTS" in rec_ids

    reopened_rec = next(r for r in recs if r.id == "REC-REG-REOPENED")
    assert reopened_rec.priority == RecommendationPriority.CRITICAL
    assert reopened_rec.category == RecommendationCategory.REGRESSION
