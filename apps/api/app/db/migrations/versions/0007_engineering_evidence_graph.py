"""0007_engineering_evidence_graph: Add repositories, revisions, source_files, symbols, dependencies, and evidence records

Revision ID: 0007_engineering_evidence_graph
Revises: 0006_code_review_engine
Create Date: 2026-10-18 16:30:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_engineering_evidence_graph"
down_revision: str | None = "0006_code_review_engine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. repositories table
    op.create_table(
        "repositories",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "project_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False, index=True),
        sa.Column("default_branch", sa.String(100), nullable=False, server_default="main"),
        sa.Column("repo_url", sa.String(500), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("project_id", "slug", name="uq_repositories_project_slug"),
    )

    # 2. repository_revisions table
    op.create_table(
        "repository_revisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "repository_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("repositories.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("commit_sha", sa.String(40), nullable=False, index=True),
        sa.Column("parent_shas", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("author", sa.String(255), nullable=False, server_default="unknown"),
        sa.Column(
            "committed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("commit_message", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("repository_id", "commit_sha", name="uq_revisions_repo_commit"),
    )

    # 3. source_file_nodes table
    op.create_table(
        "source_file_nodes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "repository_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("repositories.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "revision_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("repository_revisions.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("file_path", sa.String(1024), nullable=False, index=True),
        sa.Column("classification", sa.String(50), nullable=False, server_default="SOURCE"),
        sa.Column("language", sa.String(50), nullable=False, server_default="python"),
        sa.Column("content_hash", sa.String(64), nullable=False, index=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("revision_id", "file_path", name="uq_source_files_revision_path"),
    )

    # 4. code_symbol_nodes table
    op.create_table(
        "code_symbol_nodes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "file_node_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("source_file_nodes.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("name", sa.String(255), nullable=False, index=True),
        sa.Column("qualified_name", sa.String(500), nullable=False, index=True),
        sa.Column("symbol_type", sa.String(50), nullable=False, server_default="FUNCTION"),
        sa.Column("start_line", sa.Integer(), nullable=False),
        sa.Column("end_line", sa.Integer(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False, server_default=""),
        sa.Column("docstring_summary", sa.Text(), nullable=True),
        sa.Column("embedding", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
    )

    # 5. code_dependency_edges table
    op.create_table(
        "code_dependency_edges",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "repository_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("repositories.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "revision_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("repository_revisions.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("source_file_path", sa.String(1024), nullable=False, index=True),
        sa.Column("target_module", sa.String(500), nullable=False, index=True),
        sa.Column("imported_symbols", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("edge_type", sa.String(50), nullable=False, server_default="IMPORT"),
        sa.Column("source_symbol", sa.String(255), nullable=True),
        sa.Column("target_symbol", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_code_dependency_edges_rev_target",
        "code_dependency_edges",
        ["revision_id", "target_module"],
    )
    op.create_index(
        "ix_code_dependency_edges_rev_source",
        "code_dependency_edges",
        ["revision_id", "source_file_path"],
    )

    # 6. engineering_evidence_records table
    op.create_table(
        "engineering_evidence_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "repository_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("repositories.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column(
            "revision_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("repository_revisions.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column("evidence_type", sa.String(50), nullable=False, index=True),
        sa.Column("provenance_source", sa.String(100), nullable=False, index=True),
        sa.Column("file_path", sa.String(1024), nullable=True, index=True),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("end_line", sa.Integer(), nullable=True),
        sa.Column("symbol_name", sa.String(255), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("structured_payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("content_hash", sa.String(64), nullable=False, index=True),
        sa.Column("validation_status", sa.String(50), nullable=False, server_default="UNVERIFIED"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
    )

    # 7. Add foreign keys to review_sessions
    with op.batch_alter_table("review_sessions") as batch_op:
        batch_op.add_column(
            sa.Column(
                "repository_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey(
                    "repositories.id",
                    ondelete="SET NULL",
                    name="fk_review_sessions_repository_id",
                ),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "revision_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey(
                    "repository_revisions.id",
                    ondelete="SET NULL",
                    name="fk_review_sessions_revision_id",
                ),
                nullable=True,
            )
        )
        batch_op.create_index("ix_review_sessions_repository_id", ["repository_id"])
        batch_op.create_index("ix_review_sessions_revision_id", ["revision_id"])

    # 8. Add foreign key to review_findings
    with op.batch_alter_table("review_findings") as batch_op:
        batch_op.add_column(
            sa.Column(
                "evidence_record_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey(
                    "engineering_evidence_records.id",
                    ondelete="SET NULL",
                    name="fk_review_findings_evidence_record_id",
                ),
                nullable=True,
            )
        )
        batch_op.create_index("ix_review_findings_evidence_record_id", ["evidence_record_id"])


def downgrade() -> None:
    with op.batch_alter_table("review_findings") as batch_op:
        batch_op.drop_index("ix_review_findings_evidence_record_id")
        batch_op.drop_column("evidence_record_id")

    with op.batch_alter_table("review_sessions") as batch_op:
        batch_op.drop_index("ix_review_sessions_revision_id")
        batch_op.drop_index("ix_review_sessions_repository_id")
        batch_op.drop_column("revision_id")
        batch_op.drop_column("repository_id")

    op.drop_table("engineering_evidence_records")
    op.drop_table("code_dependency_edges")
    op.drop_table("code_symbol_nodes")
    op.drop_table("source_file_nodes")
    op.drop_table("repository_revisions")
    op.drop_table("repositories")
