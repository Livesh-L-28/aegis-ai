"""0005_phase7_autonomy_reliability: Add autonomy_policies, agent_runs, and incident_learnings tables

Revision ID: 0005_phase7_autonomy_reliability
Revises: 0004_phase6_ai_remediation
Create Date: 2026-10-03 15:00:00.000000
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_phase7_autonomy_reliability"
down_revision: str | None = "0004_phase6_ai_remediation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. autonomy_policies table
    op.create_table(
        "autonomy_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("environment", sa.String(length=50), nullable=False, server_default="production-sim"),
        sa.Column("service", sa.String(length=100), nullable=False, server_default="*"),
        sa.Column(
            "autonomy_level",
            sa.String(length=50),
            nullable=False,
            server_default="LEVEL_2_AUTO_EXECUTE_LOW_RISK",
        ),
        sa.Column(
            "allowed_actions",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("maximum_risk", sa.String(length=50), nullable=False, server_default="LOW"),
        sa.Column("max_blast_radius_services", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("require_rollback_plan", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("require_validation_plan", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("change_freeze_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("version", sa.String(length=50), nullable=False, server_default="1.0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )

    # 2. agent_runs table
    op.create_table(
        "agent_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
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
        sa.Column("service_name", sa.String(length=100), nullable=False),
        sa.Column("state", sa.String(length=50), nullable=False, server_default="CREATED"),
        sa.Column(
            "budget",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("tool_calls_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("iterations_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_cost_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("total_tokens_consumed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("remediation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("autonomy_decision", sa.String(length=50), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=False, server_default=""),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )

    # 3. incident_learnings table
    op.create_table(
        "incident_learnings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "incident_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
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
        sa.Column("service_name", sa.String(length=100), nullable=False),
        sa.Column("environment", sa.String(length=50), nullable=False, server_default="production-sim"),
        sa.Column("root_cause", sa.Text(), nullable=False),
        sa.Column("remediation_summary", sa.String(length=255), nullable=False),
        sa.Column(
            "actions_taken",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("validated", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("promoted_to_knowledge", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("runbook_candidate", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("proposed_runbook_content", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("incident_learnings")
    op.drop_table("agent_runs")
    op.drop_table("autonomy_policies")
