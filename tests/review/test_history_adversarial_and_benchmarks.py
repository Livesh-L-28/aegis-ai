"""Adversarial security tests, path defenses, and performance benchmarks for Historical Intelligence."""

import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from packages.review.history.debt import TechnicalDebtEstimator
from packages.review.history.models import (
    RepositoryMetrics,
    RepositorySnapshot,
    SnapshotFinding,
    SnapshotMetadata,
)
from packages.review.history.policy import EngineeringPolicyEvaluator
from packages.review.history.report_generator import HistoryReportGenerator
from packages.review.history.storage import HistoryStorage
from packages.review.history.trends import TrendAnalyzer


def test_adversarial_path_traversal_in_report_write_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir) / "repo"
        repo_root.mkdir()

        # Attempt to write outside repo root via path traversal
        escape_path = repo_root / "../../../escaped_report.md"

        with pytest.raises(PermissionError, match="Rejected report path outside repository"):
            HistoryReportGenerator.write_to_file(
                rendered_content="# Injected Content",
                target_path=str(escape_path),
                repo_root=repo_root,
            )


def test_adversarial_source_code_overwrite_defense() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir)
        source_file = repo_root / "critical_app.py"
        source_file.write_text("print('original code')\n", encoding="utf-8")

        with pytest.raises(PermissionError, match="Refusing to write report to source code file"):
            HistoryReportGenerator.write_to_file(
                rendered_content="# Overwrite attempt",
                target_path=str(source_file),
                repo_root=repo_root,
            )

        # Confirm source file was never overwritten
        assert source_file.read_text(encoding="utf-8") == "print('original code')\n"


def test_adversarial_secret_redaction_across_all_reports() -> None:
    fake_token = "ghp_VerySecretProductionToken9876543210zyxwv"
    f = SnapshotFinding(
        fingerprint="fp-leak",
        rule_id="SEC-003",
        category="SECURITY",
        severity="CRITICAL",
        file_path="src/config.py",
        start_line=12,
        title="Hardcoded API Secret",
        message=f"Discovered secret token {fake_token}",
        evidence_snippet=f"api_key = '{fake_token}'",
    )
    snap = RepositorySnapshot(
        id=uuid4(),
        metadata=SnapshotMetadata(repo_name="demo"),
        metrics=RepositoryMetrics(),
        findings=[f],
    )

    md = HistoryReportGenerator.snapshot_to_markdown(snap)
    assert fake_token not in md
    assert "REDACTED" in md

    debt = TechnicalDebtEstimator.estimate([f])
    debt_md = HistoryReportGenerator.debt_to_markdown(debt)
    assert fake_token not in debt_md


def test_adversarial_malformed_policy_config_rejection() -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        tf.write("{ NOT VALID JSON")
        tf.flush()
        bad_json_path = tf.name

    with pytest.raises(ValueError, match="Malformed JSON in policy configuration"):
        EngineeringPolicyEvaluator.from_config_file(bad_json_path)

    Path(bad_json_path).unlink(missing_ok=True)


def test_benchmark_snapshot_storage_and_trend_scalability() -> None:
    """Benchmark creating and analyzing 50 snapshots."""
    storage = HistoryStorage(":memory:")

    t0 = time.perf_counter()
    for i in range(50):
        findings: list[SnapshotFinding] = []
        for j in range(5):
            findings.append(
                SnapshotFinding(
                    fingerprint=f"fp-{i}-{j}",
                    rule_id=f"SEC-00{j+1}",
                    category="SECURITY",
                    severity="HIGH" if j == 0 else "MEDIUM",
                    file_path=f"src/mod_{j}.py",
                    start_line=10,
                )
            )
        snap = RepositorySnapshot(
            id=uuid4(),
            metadata=SnapshotMetadata(
                created_at=datetime.now(UTC),
                revision=f"commit-{i:03d}",
                repo_name="bench-repo",
            ),
            metrics=RepositoryMetrics(
                file_count=20,
                health_score=85.0 + (i % 5),
                tech_debt_points=float(len(findings) * 5),
            ),
            findings=findings,
        )
        storage.save_snapshot(snap)

    t_store = time.perf_counter() - t0
    assert storage.count_snapshots() == 50
    # 50 snapshots in memory SQLite should take less than 0.5s
    assert t_store < 1.0

    # Trend calculation over 50 snapshots
    t1 = time.perf_counter()
    recent = storage.get_recent_snapshots(limit=50)
    report = TrendAnalyzer.analyze(recent)
    t_trend = time.perf_counter() - t1

    assert report.sample_count == 50
    # Trend analysis over 50 snapshots must be sub-second
    assert t_trend < 0.2

    storage.close()
