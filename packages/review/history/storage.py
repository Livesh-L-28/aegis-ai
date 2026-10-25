"""Local-first, revision-aware persistent storage for LogicFalcon historical intelligence."""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.history.models import (
    FindingLifecycleState,
    RepositoryMetrics,
    RepositorySnapshot,
    SnapshotFinding,
    SnapshotMetadata,
    SnapshotSummary,
)

CURRENT_SCHEMA_VERSION = 1


class HistoryStorage:
    """Safe, revision-aware persistent snapshot storage backed by SQLite."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        if str(db_path) == ":memory:":
            self.db_path = ":memory:"
        else:
            resolved = Path(db_path).resolve()
            resolved.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(resolved)
        self._conn: sqlite3.Connection | None = None
        self.initialize()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                timeout=10.0,
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            # Enable WAL mode and foreign key enforcement
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
        return self._conn

    def initialize(self) -> None:
        """Initializes database schema and runs versioned migrations."""
        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    logicfalcon_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    repo_name TEXT NOT NULL,
                    repo_path_hash TEXT NOT NULL,
                    revision TEXT,
                    git_state TEXT NOT NULL,
                    config_fingerprint TEXT NOT NULL,
                    discovered_files INTEGER NOT NULL,
                    parsed_files INTEGER NOT NULL,
                    skipped_files INTEGER NOT NULL,
                    scan_coverage REAL NOT NULL,
                    total_findings INTEGER NOT NULL,
                    health_score REAL NOT NULL,
                    tech_debt_score REAL NOT NULL,
                    metrics_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    limitations_json TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshot_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    start_line INTEGER NOT NULL,
                    end_line INTEGER,
                    symbol_name TEXT,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    evidence_snippet TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    resolution_state TEXT NOT NULL,
                    first_seen_snapshot_id TEXT,
                    last_seen_snapshot_id TEXT,
                    first_seen_rev TEXT,
                    last_seen_rev TEXT,
                    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
                );
                """
            )
            # Create query indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_snapshots_created_at ON snapshots(created_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_snapshots_revision ON snapshots(revision);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_snapshot_id ON snapshot_findings(snapshot_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON snapshot_findings(fingerprint);")

            # Record migration version
            conn.execute(
                """
                INSERT OR IGNORE INTO schema_migrations (version, applied_at)
                VALUES (?, ?)
                """,
                (CURRENT_SCHEMA_VERSION, datetime.now(UTC).isoformat()),
            )

    def save_snapshot(self, snapshot: RepositorySnapshot) -> None:
        """Persists a complete repository snapshot in an atomic transaction."""
        conn = self._get_connection()
        meta = snapshot.metadata
        metrics = snapshot.metrics
        snap_id = str(snapshot.id)

        meta_json = json.dumps(
            {
                "analyzer_versions": meta.analyzer_versions,
                "enabled_analyzers": meta.enabled_analyzers,
                "metadata": meta.metadata,
            }
        )
        limitations_json = json.dumps(snapshot.limitations)
        metrics_json = json.dumps(metrics.model_dump())

        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO snapshots (
                    id, schema_version, logicfalcon_version, created_at,
                    repo_name, repo_path_hash, revision, git_state,
                    config_fingerprint, discovered_files, parsed_files, skipped_files,
                    scan_coverage, total_findings, health_score, tech_debt_score,
                    metrics_json, metadata_json, limitations_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snap_id,
                    meta.schema_version,
                    meta.logicfalcon_version,
                    meta.created_at.isoformat(),
                    meta.repo_name,
                    meta.repo_path_hash,
                    meta.revision,
                    meta.git_state.value if hasattr(meta.git_state, "value") else str(meta.git_state),
                    meta.config_fingerprint,
                    meta.discovered_files,
                    meta.parsed_files,
                    meta.skipped_files,
                    meta.scan_coverage,
                    len(snapshot.findings),
                    metrics.health_score,
                    metrics.tech_debt_points,
                    metrics_json,
                    meta_json,
                    limitations_json,
                ),
            )

            # Insert findings with secret redaction
            conn.execute("DELETE FROM snapshot_findings WHERE snapshot_id = ?", (snap_id,))
            for f in snapshot.findings:
                clean_snippet = redact_secrets_in_text(f.evidence_snippet)
                clean_msg = redact_secrets_in_text(f.message)
                conn.execute(
                    """
                    INSERT INTO snapshot_findings (
                        snapshot_id, fingerprint, rule_id, category, severity,
                        file_path, start_line, end_line, symbol_name, title, message,
                        evidence_snippet, confidence, resolution_state,
                        first_seen_snapshot_id, last_seen_snapshot_id, first_seen_rev, last_seen_rev
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snap_id,
                        f.fingerprint,
                        f.rule_id,
                        f.category,
                        f.severity,
                        f.file_path,
                        f.start_line,
                        f.end_line,
                        f.symbol_name,
                        f.title,
                        clean_msg,
                        clean_snippet,
                        f.confidence,
                        f.resolution_state.value if hasattr(f.resolution_state, "value") else str(f.resolution_state),
                        f.first_seen_snapshot_id,
                        f.last_seen_snapshot_id,
                        f.first_seen_rev,
                        f.last_seen_rev,
                    ),
                )

    def get_snapshot(self, snapshot_id: UUID | str) -> RepositorySnapshot | None:
        """Retrieves a full snapshot by ID."""
        conn = self._get_connection()
        snap_id = str(snapshot_id)
        row = conn.execute("SELECT * FROM snapshots WHERE id = ?", (snap_id,)).fetchone()
        if not row:
            return None
        return self._hydrate_snapshot(row)

    def get_snapshot_by_revision(self, revision: str) -> RepositorySnapshot | None:
        """Retrieves the most recent snapshot matching a specific Git revision hash/ref."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM snapshots WHERE revision = ? ORDER BY created_at DESC LIMIT 1",
            (revision,),
        ).fetchone()
        if not row:
            return None
        return self._hydrate_snapshot(row)

    def get_latest_snapshot(self) -> RepositorySnapshot | None:
        """Retrieves the most recently created repository snapshot."""
        conn = self._get_connection()
        row = conn.execute("SELECT * FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
        if not row:
            return None
        return self._hydrate_snapshot(row)

    def list_snapshots(self, limit: int = 50, offset: int = 0) -> list[SnapshotSummary]:
        """Returns paginated snapshot summaries for history listing."""
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT id, created_at, repo_name, revision, git_state,
                   discovered_files, total_findings, health_score, tech_debt_score
            FROM snapshots
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        summaries: list[SnapshotSummary] = []
        for r in cursor.fetchall():
            summaries.append(
                SnapshotSummary(
                    id=UUID(r["id"]),
                    created_at=datetime.fromisoformat(r["created_at"]),
                    repo_name=r["repo_name"],
                    revision=r["revision"],
                    git_state=r["git_state"],
                    file_count=r["discovered_files"],
                    total_findings=r["total_findings"],
                    health_score=r["health_score"],
                    tech_debt_points=r["tech_debt_score"],
                )
            )
        return summaries

    def get_recent_snapshots(self, limit: int = 20) -> list[RepositorySnapshot]:
        """Returns the most recent full snapshots in chronological ascending order."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT * FROM snapshots ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        rows = cursor.fetchall()
        # Return in ascending chronological order for trend calculation
        snapshots = [self._hydrate_snapshot(r) for r in reversed(rows)]
        return snapshots

    def delete_snapshot(self, snapshot_id: UUID | str) -> bool:
        """Deletes a specific snapshot and its associated findings."""
        conn = self._get_connection()
        snap_id = str(snapshot_id)
        with conn:
            cursor = conn.execute("DELETE FROM snapshots WHERE id = ?", (snap_id,))
            return cursor.rowcount > 0

    def prune_snapshots(self, keep_last_n: int = 50, older_than_days: int | None = None) -> int:
        """Safely prunes older snapshots beyond retention limits."""
        conn = self._get_connection()
        total_deleted = 0
        with conn:
            if older_than_days is not None:
                cutoff_dt = datetime.now(UTC).timestamp() - (older_than_days * 86400)
                cutoff_iso = datetime.fromtimestamp(cutoff_dt, tz=UTC).isoformat()
                cursor = conn.execute("DELETE FROM snapshots WHERE created_at < ?", (cutoff_iso,))
                total_deleted += cursor.rowcount

            # Keep only the last N
            if keep_last_n > 0:
                rows = conn.execute(
                    "SELECT id FROM snapshots ORDER BY created_at DESC LIMIT -1 OFFSET ?",
                    (keep_last_n,),
                ).fetchall()
                for r in rows:
                    conn.execute("DELETE FROM snapshots WHERE id = ?", (r["id"],))
                    total_deleted += 1

        return total_deleted

    def count_snapshots(self) -> int:
        """Returns the total number of stored snapshots."""
        conn = self._get_connection()
        row = conn.execute("SELECT COUNT(*) AS cnt FROM snapshots").fetchone()
        return int(row["cnt"]) if row else 0

    def _hydrate_snapshot(self, row: sqlite3.Row) -> RepositorySnapshot:
        conn = self._get_connection()
        snap_id = row["id"]
        meta_dict = json.loads(row["metadata_json"])
        metrics_dict = json.loads(row["metrics_json"])
        limitations = json.loads(row["limitations_json"])

        meta = SnapshotMetadata(
            schema_version=row["schema_version"],
            logicfalcon_version=row["logicfalcon_version"],
            created_at=datetime.fromisoformat(row["created_at"]),
            repo_name=row["repo_name"],
            repo_path_hash=row["repo_path_hash"],
            revision=row["revision"],
            git_state=row["git_state"],
            analyzer_versions=meta_dict.get("analyzer_versions", {}),
            enabled_analyzers=meta_dict.get("enabled_analyzers", []),
            config_fingerprint=row["config_fingerprint"],
            discovered_files=row["discovered_files"],
            parsed_files=row["parsed_files"],
            skipped_files=row["skipped_files"],
            scan_coverage=row["scan_coverage"],
            limitations=limitations,
            metadata=meta_dict.get("metadata", {}),
        )

        metrics = RepositoryMetrics(**metrics_dict)

        # Hydrate findings
        finding_rows = conn.execute(
            "SELECT * FROM snapshot_findings WHERE snapshot_id = ? ORDER BY file_path, start_line",
            (snap_id,),
        ).fetchall()

        findings: list[SnapshotFinding] = []
        for fr in finding_rows:
            findings.append(
                SnapshotFinding(
                    fingerprint=fr["fingerprint"],
                    rule_id=fr["rule_id"],
                    category=fr["category"],
                    severity=fr["severity"],
                    file_path=fr["file_path"],
                    start_line=fr["start_line"],
                    end_line=fr["end_line"],
                    symbol_name=fr["symbol_name"],
                    title=fr["title"],
                    message=fr["message"],
                    evidence_snippet=fr["evidence_snippet"],
                    confidence=fr["confidence"],
                    resolution_state=FindingLifecycleState(fr["resolution_state"]),
                    first_seen_snapshot_id=fr["first_seen_snapshot_id"],
                    last_seen_snapshot_id=fr["last_seen_snapshot_id"],
                    first_seen_rev=fr["first_seen_rev"],
                    last_seen_rev=fr["last_seen_rev"],
                )
            )

        return RepositorySnapshot(
            id=UUID(snap_id),
            metadata=meta,
            metrics=metrics,
            findings=findings,
            limitations=limitations,
        )

    def close(self) -> None:
        """Closes the underlying SQLite connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
