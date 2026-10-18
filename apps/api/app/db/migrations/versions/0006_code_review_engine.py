"""0006_code_review_engine: Add review_sessions and review_findings tables

Revision ID: 0006_code_review_engine
Revises: 0005_phase7_autonomy_reliability
Create Date: 2026-10-18 10:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006_code_review_engine"
down_revision: str | None = "0005_phase7_autonomy_reliability"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. review_sessions table
    op.create_table(
        "review_sessions",
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
            sa.ForeignKey("projects.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column("repository_name", sa.String(255), nullable=False),
        sa.Column("review_type", sa.String(50), nullable=False, server_default="LOCAL"),
        sa.Column("base_commit", sa.String(40), nullable=True),
        sa.Column("head_commit", sa.String(40), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="PENDING"),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("total_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("execution_time_seconds", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("cancellation_reason", sa.Text(), nullable=True),
        sa.Column("review_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
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

    # 2. review_findings table
    op.create_table(
        "review_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "review_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("review_sessions.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("file_path", sa.String(1024), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=False),
        sa.Column("end_line", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(100), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(50), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("origin", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("technical_evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("suggestion", sa.Text(), nullable=True),
        sa.Column("deduplication_hash", sa.String(64), nullable=False, index=True),
        sa.Column("tool_name", sa.String(100), nullable=False, server_default="aegis_review"),
        sa.Column("finding_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
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


def downgrade() -> None:
    op.drop_table("review_findings")
    op.drop_table("review_sessions")
