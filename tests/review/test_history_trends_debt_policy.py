"""Unit tests for trend analytics, technical debt estimation, and engineering policy gates."""

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from packages.review.history.comparator import SnapshotComparator
from packages.review.history.debt import TechnicalDebtEstimator
from packages.review.history.models import (
    GitState,
    PolicyMode,
    PolicyRule,
    RepositoryMetrics,
    RepositorySnapshot,
    SnapshotFinding,
    SnapshotMetadata,
    TrendDirection,
)
from packages.review.history.policy import EngineeringPolicyEvaluator
from packages.review.history.trends import TrendAnalyzer


def make_snapshot_at(
    days_ago: int,
    health_score: float,
    debt_points: float,
    findings: list[SnapshotFinding] | None = None,
    cycles: int = 0,
) -> RepositorySnapshot:
    dt = datetime.now(UTC) - timedelta(days=days_ago)
    meta = SnapshotMetadata(
        schema_version="1.0",
        created_at=dt,
        repo_name="trend-repo",
        revision=f"rev-{days_ago}d",
        git_state=GitState.CLEAN,
    )
    metrics = RepositoryMetrics(
        health_score=health_score,
        tech_debt_points=debt_points,
        cycle_count=cycles,
        file_count=10,
    )
    return RepositorySnapshot(
        id=uuid4(),
        metadata=meta,
        metrics=metrics,
        findings=findings or [],
    )


def test_trend_analyzer_trajectory_improving_and_deteriorating() -> None:
    # 1. Improving trajectory: health increases, debt decreases
    snaps_improving = [
        make_snapshot_at(days_ago=10, health_score=75.0, debt_points=50.0),
        make_snapshot_at(days_ago=5, health_score=82.0, debt_points=35.0),
        make_snapshot_at(days_ago=0, health_score=90.0, debt_points=20.0),
    ]

    report = TrendAnalyzer.analyze(snaps_improving)
    assert report.sample_count == 3
    assert report.health_direction == TrendDirection.IMPROVING
    assert report.debt_direction == TrendDirection.IMPROVING
    assert report.debt_velocity < 0  # Debt is shrinking
    assert report.time_span_days >= 9.9

    # 2. Deteriorating trajectory: health drops, debt increases
    snaps_deteriorating = [
        make_snapshot_at(days_ago=10, health_score=92.0, debt_points=15.0),
        make_snapshot_at(days_ago=0, health_score=80.0, debt_points=45.0),
    ]
    report_bad = TrendAnalyzer.analyze(snaps_deteriorating)
    assert report_bad.health_direction == TrendDirection.DETERIORATING
    assert report_bad.debt_direction == TrendDirection.DETERIORATING
    assert report_bad.debt_velocity > 0


def test_trend_analyzer_recurring_defects_counter() -> None:
    f1 = SnapshotFinding(
        fingerprint="fp1", rule_id="SEC-001", category="SECURITY", severity="HIGH",
        file_path="src/a.py", start_line=1,
    )
    f2 = SnapshotFinding(
        fingerprint="fp2", rule_id="ARCH-001", category="ARCHITECTURE", severity="HIGH",
        file_path="src/b.py", start_line=5,
    )

    snaps = [
        make_snapshot_at(days_ago=3, health_score=85.0, debt_points=20.0, findings=[f1]),
        make_snapshot_at(days_ago=2, health_score=85.0, debt_points=20.0, findings=[f1, f2]),
        make_snapshot_at(days_ago=1, health_score=85.0, debt_points=20.0, findings=[f1]),
    ]

    rep = TrendAnalyzer.analyze(snaps)
    recurring_rules = dict(rep.recurring_rule_ids)
    assert recurring_rules["SEC-001"] == 3
    assert recurring_rules["ARCH-001"] == 1


def test_technical_debt_point_weights_and_breakdowns() -> None:
    f_crit = SnapshotFinding(
        fingerprint="fp-c", rule_id="SEC-001", category="SECURITY", severity="CRITICAL",
        file_path="src/auth.py", start_line=10,
    )
    f_high = SnapshotFinding(
        fingerprint="fp-h", rule_id="SEC-002", category="SECURITY", severity="HIGH",
        file_path="src/auth.py", start_line=20,
    )
    f_med = SnapshotFinding(
        fingerprint="fp-m", rule_id="REL-002", category="RELIABILITY", severity="MEDIUM",
        file_path="src/client.py", start_line=30,
    )

    metrics = RepositoryMetrics(
        cycle_count=2,  # 2 * 5.0 = 10.0 pts
        boundary_violations_count=1,  # 1 * 4.0 = 4.0 pts
        hotspot_count=1,  # 1 * 2.5 = 2.5 pts
    )

    debt = TechnicalDebtEstimator.estimate(
        findings=[f_crit, f_high, f_med],
        metrics=metrics,
    )

    # 20.0 (CRIT) + 8.0 (HIGH) + 3.0 (MED) = 31.0 pts from findings
    # 10.0 + 4.0 + 2.5 = 16.5 pts from architecture
    # Total = 47.5 pts
    assert debt.total_points == 47.5
    assert debt.severity_breakdown["CRITICAL"] == 20.0
    assert debt.severity_breakdown["HIGH"] == 8.0
    assert debt.severity_breakdown["MEDIUM"] == 3.0
    assert debt.category_breakdown["ARCHITECTURE_CYCLES"] == 10.0

    # File hotspots
    top_files = dict(debt.top_debt_files)
    assert top_files["src/auth.py"] == 28.0  # 20 + 8


def test_engineering_policy_gate_blocking_violation() -> None:
    f_new_crit = SnapshotFinding(
        fingerprint="fp-new-crit", rule_id="SEC-001", category="SECURITY", severity="CRITICAL",
        file_path="src/login.py", start_line=10,
    )

    base_snap = make_snapshot_at(days_ago=1, health_score=95.0, debt_points=10.0)
    target_snap = make_snapshot_at(days_ago=0, health_score=90.0, debt_points=30.0, findings=[f_new_crit])

    comp = SnapshotComparator.compare(base_snapshot=base_snap, target_snapshot=target_snap)

    rules = [
        PolicyRule(
            id="POL-001",
            condition="max_new_critical_findings",
            threshold=0.0,
            mode=PolicyMode.BLOCKING,
        ),
    ]

    evaluator = EngineeringPolicyEvaluator(rules=rules)
    result = evaluator.evaluate_comparison(comp)

    assert result.passed is False
    assert result.is_blocking_failure is True
    assert result.suggested_exit_code == 1
    assert len(result.violations) == 1
    assert result.violations[0].rule_id == "POL-001"


def test_engineering_policy_gate_warning_mode_passes() -> None:
    base_snap = make_snapshot_at(days_ago=1, health_score=90.0, debt_points=10.0)
    target_snap = make_snapshot_at(days_ago=0, health_score=80.0, debt_points=25.0)  # Health dropped 10 pts

    comp = SnapshotComparator.compare(base_snapshot=base_snap, target_snapshot=target_snap)

    rules = [
        PolicyRule(
            id="POL-WARN",
            condition="max_health_score_drop",
            threshold=5.0,
            mode=PolicyMode.WARNING,  # Warning does not block!
        ),
    ]

    evaluator = EngineeringPolicyEvaluator(rules=rules)
    result = evaluator.evaluate_comparison(comp)

    assert result.passed is True  # Passed because warning is non-blocking
    assert result.is_blocking_failure is False
    assert result.suggested_exit_code == 0
    assert len(result.warnings) == 1
    assert result.warnings[0].rule_id == "POL-WARN"


def test_engineering_policy_evaluator_from_json_config() -> None:
    config_dict = {
        "rules": [
            {
                "id": "CI-GATE-01",
                "condition": "max_new_cycles",
                "threshold": 0.0,
                "mode": "BLOCKING",
            }
        ]
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        tf.write(json.dumps(config_dict))
        tf.flush()
        config_path = tf.name

    evaluator = EngineeringPolicyEvaluator.from_config_file(config_path)
    assert len(evaluator.rules) == 1
    assert evaluator.rules[0].id == "CI-GATE-01"
    Path(config_path).unlink(missing_ok=True)
