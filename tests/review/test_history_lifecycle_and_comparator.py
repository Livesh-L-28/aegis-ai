"""Unit tests for finding lifecycle tracking, false-resolution defense, and revision comparison."""

from datetime import UTC, datetime
from uuid import uuid4

from packages.review.history.comparator import SnapshotComparator
from packages.review.history.lifecycle import FindingLifecycleTracker
from packages.review.history.models import (
    FindingLifecycleState,
    GitState,
    RepositoryMetrics,
    RepositorySnapshot,
    SnapshotFinding,
    SnapshotMetadata,
)


def make_finding(
    fingerprint: str,
    rule_id: str = "SEC-001",
    file_path: str = "src/app.py",
    severity: str = "HIGH",
    start_line: int = 15,
) -> SnapshotFinding:
    return SnapshotFinding(
        fingerprint=fingerprint,
        rule_id=rule_id,
        category="SECURITY",
        severity=severity,
        file_path=file_path,
        start_line=start_line,
        title=f"Finding {rule_id}",
        message="Vulnerability details",
        evidence_snippet="dangerous_call()",
        confidence=1.0,
        resolution_state=FindingLifecycleState.NEW,
    )


def test_lifecycle_new_unchanged_changed_transitions() -> None:
    f_persistent = make_finding(fingerprint="fp-persistent", rule_id="SEC-001", file_path="src/a.py", severity="HIGH")
    f_modified_prior = make_finding(fingerprint="fp-modified", rule_id="SEC-002", file_path="src/b.py", severity="MEDIUM")
    f_modified_curr = make_finding(fingerprint="fp-modified", rule_id="SEC-002", file_path="src/b.py", severity="CRITICAL")
    f_new = make_finding(fingerprint="fp-new", rule_id="SEC-003", file_path="src/c.py", severity="LOW")

    prior = [f_persistent, f_modified_prior]
    curr = [f_persistent, f_modified_curr, f_new]
    parsed_files = {"src/a.py", "src/b.py", "src/c.py"}

    enriched, transitions = FindingLifecycleTracker.compute_lifecycle(
        prior_findings=prior,
        current_findings=curr,
        current_parsed_files=parsed_files,
    )
    assert len(transitions) == 3
    states_by_fp = {f.fingerprint: f.resolution_state for f in enriched}
    assert states_by_fp["fp-persistent"] == FindingLifecycleState.UNCHANGED
    assert states_by_fp["fp-modified"] == FindingLifecycleState.CHANGED
    assert states_by_fp["fp-new"] == FindingLifecycleState.NEW


def test_lifecycle_reopened_detection() -> None:
    f_reopened = make_finding(fingerprint="fp-reopened", rule_id="SEC-004", file_path="src/auth.py")
    prior: list[SnapshotFinding] = []
    curr = [f_reopened]
    parsed_files = {"src/auth.py"}

    # Pass fp-reopened in historical_resolved_fingerprints
    enriched, _ = FindingLifecycleTracker.compute_lifecycle(
        prior_findings=prior,
        current_findings=curr,
        current_parsed_files=parsed_files,
        historical_resolved_fingerprints={"fp-reopened"},
    )

    assert enriched[0].resolution_state == FindingLifecycleState.REOPENED


def test_lifecycle_false_resolution_defense_for_skipped_and_unparsed_files() -> None:
    f_resolved = make_finding(fingerprint="fp-fixed", rule_id="SEC-001", file_path="src/fixed.py")
    f_skipped = make_finding(fingerprint="fp-skipped", rule_id="SEC-002", file_path="src/huge_file.py")
    f_unparsed = make_finding(fingerprint="fp-unparsed", rule_id="SEC-003", file_path="src/missing.py")

    prior = [f_resolved, f_skipped, f_unparsed]
    curr: list[SnapshotFinding] = []  # None present in current scan
    parsed_files = {"src/fixed.py"}  # Only fixed.py was parsed
    skipped_files = {"src/huge_file.py"}  # huge_file.py was skipped

    _, transitions = FindingLifecycleTracker.compute_lifecycle(
        prior_findings=prior,
        current_findings=curr,
        current_parsed_files=parsed_files,
        current_skipped_files=skipped_files,
    )

    trans_by_fp = {t.fingerprint: t for t in transitions}

    # 1. Genuine fix: file was parsed, finding absent -> RESOLVED (is_confirmed=True)
    assert trans_by_fp["fp-fixed"].current_state == FindingLifecycleState.RESOLVED
    assert trans_by_fp["fp-fixed"].is_confirmed is True

    # 2. File was skipped: DO NOT mark resolved! -> UNCERTAIN (is_confirmed=False)
    assert trans_by_fp["fp-skipped"].current_state == FindingLifecycleState.UNCERTAIN
    assert trans_by_fp["fp-skipped"].is_confirmed is False
    assert "skipped" in trans_by_fp["fp-skipped"].transition_reason.lower()

    # 3. File was not parsed at all -> UNCERTAIN (is_confirmed=False)
    assert trans_by_fp["fp-unparsed"].current_state == FindingLifecycleState.UNCERTAIN
    assert trans_by_fp["fp-unparsed"].is_confirmed is False


def test_snapshot_comparator_deltas_and_regressions() -> None:
    # Base snapshot
    f_base = make_finding(fingerprint="fp-1", severity="MEDIUM")
    meta_base = SnapshotMetadata(
        schema_version="1.0",
        logicfalcon_version="0.1.2",
        created_at=datetime.now(UTC),
        repo_name="demo",
        revision="rev-base",
        git_state=GitState.CLEAN,
        scan_coverage=1.0,
    )
    metrics_base = RepositoryMetrics(
        file_count=10,
        cycle_count=0,
        boundary_violations_count=0,
        health_score=92.0,
        tech_debt_points=10.0,
    )
    base_snap = RepositorySnapshot(
        id=uuid4(),
        metadata=meta_base,
        metrics=metrics_base,
        findings=[f_base],
    )

    # Target snapshot: introduces a CRITICAL finding, a circular dependency, and health drop
    f_crit_new = make_finding(fingerprint="fp-2", severity="CRITICAL", rule_id="SEC-002", file_path="src/login.py")
    meta_target = SnapshotMetadata(
        schema_version="1.0",
        logicfalcon_version="0.1.2",
        created_at=datetime.now(UTC),
        repo_name="demo",
        revision="rev-target",
        git_state=GitState.CLEAN,
        scan_coverage=1.0,
    )
    metrics_target = RepositoryMetrics(
        file_count=11,
        cycle_count=1,
        boundary_violations_count=0,
        health_score=80.0,
        tech_debt_points=35.0,
    )
    target_snap = RepositorySnapshot(
        id=uuid4(),
        metadata=meta_target,
        metrics=metrics_target,
        findings=[f_base, f_crit_new],
    )

    comp = SnapshotComparator.compare(base_snapshot=base_snap, target_snapshot=target_snap)

    assert comp.is_comparable is True
    assert len(comp.new_findings) == 1
    assert comp.new_findings[0].fingerprint == "fp-2"
    assert len(comp.persistent_findings) == 1
    assert comp.health_score_delta == -12.0
    assert comp.tech_debt_delta == 25.0
    assert comp.metric_deltas["cycle_count"] == 1.0

    # Verify detected regressions
    assert any("CRITICAL" in reg for reg in comp.detected_regressions)
    assert any("circular dependency" in reg for reg in comp.detected_regressions)
    assert any("dropped" in reg for reg in comp.detected_regressions)


def test_snapshot_comparator_coverage_drop_incomparability_warning() -> None:
    meta_base = SnapshotMetadata(
        schema_version="1.0",
        created_at=datetime.now(UTC),
        scan_coverage=0.95,
    )
    meta_target = SnapshotMetadata(
        schema_version="1.0",
        created_at=datetime.now(UTC),
        scan_coverage=0.40,  # Severe coverage drop
    )
    base_snap = RepositorySnapshot(
        id=uuid4(),
        metadata=meta_base,
        metrics=RepositoryMetrics(),
        findings=[],
    )
    target_snap = RepositorySnapshot(
        id=uuid4(),
        metadata=meta_target,
        metrics=RepositoryMetrics(),
        findings=[],
    )

    comp = SnapshotComparator.compare(base_snapshot=base_snap, target_snapshot=target_snap)
    assert comp.is_comparable is False
    assert any("coverage" in note.lower() for note in comp.comparability_notes)
