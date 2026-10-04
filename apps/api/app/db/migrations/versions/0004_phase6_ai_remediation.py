"""0004_phase6_ai_remediation: Add remediations, approvals, and executions tables

Revision ID: 0004_phase6_ai_remediation
Revises: 0003_phase5_ai_trust_reliability
Create Date: 2026-10-03 14:35:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_phase6_ai_remediation"
down_revision: str | None = "0003_phase5_ai_trust_reliability"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. remediations table
    op.create_table(
        "remediations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("service_name", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("root_cause_reference", sa.Text(), nullable=False),
        sa.Column(
            "evidence_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("risk_level", sa.String(length=50), nullable=False, server_default="MEDIUM"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="PROPOSED"),
        sa.Column(
            "actions",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "blast_radius",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "validation_plan",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "rollback_plan",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("remediation_hash", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(length=100), nullable=False, server_default="system"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_remediations_incident_id", "remediations", ["incident_id"])
    op.create_index("ix_remediations_organization_id", "remediations", ["organization_id"])

    # 2. remediation_approvals table
    op.create_table(
        "remediation_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "remediation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("approver_id", sa.String(length=100), nullable=False),
        sa.Column("decision", sa.String(length=50), nullable=False, server_default="APPROVED"),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("policy_version", sa.String(length=50), nullable=False, server_default="1.0"),
        sa.Column("remediation_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_remediation_approvals_remediation_id", "remediation_approvals", ["remediation_id"])
    op.create_index("ix_remediation_approvals_organization_id", "remediation_approvals", ["organization_id"])

    # 3. remediation_executions table
    op.create_table(
        "remediation_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "remediation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("executor_id", sa.String(length=100), nullable=False, server_default="system"),
        sa.Column("environment", sa.String(length=50), nullable=False, server_default="production-sim"),
        sa.Column("target", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="PREFLIGHT"),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "preflight_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "validation_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "rollback_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_remediation_executions_remediation_id", "remediation_executions", ["remediation_id"])
    op.create_index("ix_remediation_executions_organization_id", "remediation_executions", ["organization_id"])


def downgrade() -> None:
    op.drop_table("remediation_executions")
    op.drop_table("remediation_approvals")
    op.drop_table("remediations")
