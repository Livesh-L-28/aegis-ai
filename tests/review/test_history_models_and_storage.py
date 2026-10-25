"""Unit tests for Historical Intelligence models and SQLite persistence storage."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from packages.review.history.models import (
    FindingLifecycleState,
    GitState,
    RepositoryMetrics,
    RepositorySnapshot,
    SnapshotFinding,
    SnapshotMetadata,
)
from packages.review.history.storage import CURRENT_SCHEMA_VERSION, HistoryStorage


def create_sample_snapshot(
    repo_name: str = "demo-repo",
    revision: str = "rev-001",
    health_score: float = 95.0,
    findings_count: int = 2,
    secret_in_snippet: str | None = None,
) -> RepositorySnapshot:
    """Helper to generate deterministic synthetic snapshots."""
    findings: list[SnapshotFinding] = []
    for i in range(findings_count):
        snippet = f"token = '{secret_in_snippet}'" if secret_in_snippet else "def example(): pass"
        findings.append(
            SnapshotFinding(
                fingerprint=f"fp-00{i+1}",
                rule_id=f"SEC-00{i+1}",
                category="SECURITY",
                severity="CRITICAL" if i == 0 else "MEDIUM",
                file_path=f"src/module_{i+1}.py",
                start_line=10 + i,
                title=f"Sample Vulnerability {i+1}",
                message=f"Suspicious pattern in module_{i+1}",
                evidence_snippet=snippet,
                confidence=1.0,
                resolution_state=FindingLifecycleState.NEW,
                first_seen_rev=revision,
                last_seen_rev=revision,
            )
        )

    meta = SnapshotMetadata(
        schema_version="1.0",
        logicfalcon_version="0.1.2",
        created_at=datetime.now(UTC),
        repo_name=repo_name,
        repo_path_hash="a1b2c3d4",
        revision=revision,
        git_state=GitState.CLEAN,
        discovered_files=10,
        parsed_files=10,
        skipped_files=0,
        scan_coverage=1.0,
        config_fingerprint="test-config-fp",
    )

    metrics = RepositoryMetrics(
        file_count=10,
        symbol_count=45,
        total_lines_of_code=1200,
        graph_nodes=10,
        graph_edges=18,
        cycle_count=0,
        boundary_violations_count=0,
        health_score=health_score,
        tech_debt_points=float(findings_count * 10),
    )

    return RepositorySnapshot(
        id=uuid4(),
        metadata=meta,
        metrics=metrics,
        findings=findings,
    )


def test_history_storage_initialization_and_migration() -> None:
    storage = HistoryStorage(":memory:")
    assert storage.count_snapshots() == 0

    # Verify schema migrations table
    conn = storage._get_connection()
    row = conn.execute("SELECT version FROM schema_migrations WHERE version = ?", (CURRENT_SCHEMA_VERSION,)).fetchone()
    assert row is not None
    assert row["version"] == CURRENT_SCHEMA_VERSION
    storage.close()


def test_history_storage_save_and_retrieve_by_id() -> None:
    storage = HistoryStorage(":memory:")
    snap = create_sample_snapshot(revision="abc1234", health_score=88.5, findings_count=3)
    storage.save_snapshot(snap)

    assert storage.count_snapshots() == 1

    retrieved = storage.get_snapshot(snap.id)
    assert retrieved is not None
    assert retrieved.id == snap.id
    assert retrieved.metadata.revision == "abc1234"
    assert retrieved.metrics.health_score == 88.5
    assert len(retrieved.findings) == 3
    assert retrieved.findings[0].fingerprint == "fp-001"
    storage.close()


def test_history_storage_retrieve_by_revision_and_latest() -> None:
    storage = HistoryStorage(":memory:")
    snap1 = create_sample_snapshot(revision="commit-alpha", health_score=90.0)
    snap2 = create_sample_snapshot(revision="commit-beta", health_score=85.0)

    storage.save_snapshot(snap1)
    storage.save_snapshot(snap2)

    by_rev = storage.get_snapshot_by_revision("commit-alpha")
    assert by_rev is not None
    assert by_rev.id == snap1.id

    latest = storage.get_latest_snapshot()
    assert latest is not None
    assert latest.metadata.revision in ("commit-alpha", "commit-beta")
    storage.close()


def test_history_storage_list_summaries() -> None:
    storage = HistoryStorage(":memory:")
    for i in range(5):
        s = create_sample_snapshot(revision=f"rev-00{i}", health_score=80.0 + i)
        storage.save_snapshot(s)

    summaries = storage.list_snapshots(limit=3, offset=0)
    assert len(summaries) == 3
    assert summaries[0].file_count == 10
    assert summaries[0].health_score >= 80.0
    storage.close()


def test_history_storage_secret_redaction_on_save() -> None:
    storage = HistoryStorage(":memory:")
    fake_token = "ghp_FakeGitHubSecretToken1234567890abcdef"
    snap = create_sample_snapshot(secret_in_snippet=fake_token)
    storage.save_snapshot(snap)

    retrieved = storage.get_snapshot(snap.id)
    assert retrieved is not None
    assert fake_token not in retrieved.findings[0].evidence_snippet
    assert "[REDACTED_API_KEY]" in retrieved.findings[0].evidence_snippet or "REDACTED" in retrieved.findings[0].evidence_snippet
    storage.close()


def test_history_storage_pruning() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "test_history.db"
        storage = HistoryStorage(db_file)

        for i in range(10):
            s = create_sample_snapshot(revision=f"rev-{i}")
            storage.save_snapshot(s)

        assert storage.count_snapshots() == 10

        # Keep only the last 4 snapshots
        pruned_count = storage.prune_snapshots(keep_last_n=4)
        assert pruned_count == 6
        assert storage.count_snapshots() == 4

        storage.close()
