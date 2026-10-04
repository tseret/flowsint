"""Autonomous passive investigation agent runs."""

import sqlalchemy as sa
from alembic import op

revision = "20261003_agent_runs"
down_revision = "20261002_case_workspace"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "sketch_id",
            sa.Uuid(),
            sa.ForeignKey("sketches.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "owner_id", sa.Uuid(), sa.ForeignKey("profiles.id", ondelete="SET NULL")
        ),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("seed_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("max_steps", sa.Integer(), nullable=False),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("report", sa.Text()),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_agent_runs_sketch_id", "agent_runs", ["sketch_id"])


def downgrade() -> None:
    op.drop_table("agent_runs")
