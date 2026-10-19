"""Tests for Alembic migration 0007_engineering_evidence_graph upgrade and downgrade integrity."""

import importlib
from typing import Any

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine

mig_0006 = importlib.import_module("apps.api.app.db.migrations.versions.0006_code_review_engine")
mig_0007 = importlib.import_module("apps.api.app.db.migrations.versions.0007_engineering_evidence_graph")


def test_migration_0007_metadata() -> None:
    assert mig_0007.revision == "0007_engineering_evidence_graph"
    assert mig_0007.down_revision == "0006_code_review_engine"


def test_migration_0007_upgrade_downgrade_cycle() -> None:
    # Use disposable in-memory SQLite engine
    engine = create_engine("sqlite:///:memory:")

    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn)
        op = Operations(ctx)

        # 1. First run prerequisite tables from prior migrations (organizations, projects, review_sessions, review_findings)
        with op.batch_alter_table("dummy") as _:
            pass

        # Apply 0006 upgrade so review_sessions and review_findings exist
        # We need organizations and projects first
        conn.exec_driver_sql(
            "CREATE TABLE organizations (id CHAR(36) PRIMARY KEY, name VARCHAR(255), slug VARCHAR(100), created_at TIMESTAMP, updated_at TIMESTAMP)"
        )
        conn.exec_driver_sql(
            "CREATE TABLE projects (id CHAR(36) PRIMARY KEY, organization_id CHAR(36), name VARCHAR(255), slug VARCHAR(100), created_at TIMESTAMP, updated_at TIMESTAMP)"
        )

        # Set alembic op context
        mig_0006.op = op  # type: ignore[attr-defined]
        mig_0006.upgrade()

        # 2. Test 0007 upgrade
        mig_0007.op = op  # type: ignore[attr-defined]
        mig_0007.upgrade()

        # Verify tables created
        inspector = sa_inspect(conn)
        table_names = set(inspector.get_table_names())
        assert "repositories" in table_names
        assert "repository_revisions" in table_names
        assert "source_file_nodes" in table_names
        assert "code_symbol_nodes" in table_names
        assert "code_dependency_edges" in table_names
        assert "engineering_evidence_records" in table_names

        # 3. Test 0007 downgrade
        mig_0007.downgrade()
        table_names_after = set(sa_inspect(conn).get_table_names())
        assert "repositories" not in table_names_after
        assert "repository_revisions" not in table_names_after
        assert "source_file_nodes" not in table_names_after
        assert "code_symbol_nodes" not in table_names_after
        assert "code_dependency_edges" not in table_names_after
        assert "engineering_evidence_records" not in table_names_after


def sa_inspect(conn: Any) -> Any:
    from sqlalchemy import inspect
    return inspect(conn)
