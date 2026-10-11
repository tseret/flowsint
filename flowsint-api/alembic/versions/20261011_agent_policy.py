"""Persist investigation boundaries and the explored frontier."""

import sqlalchemy as sa
from alembic import op

revision = "20261011_agent_policy"
down_revision = "20261004_agent_run_started"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_runs",
        sa.Column("policy", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "agent_runs",
        sa.Column("frontier", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("agent_runs", "frontier")
    op.drop_column("agent_runs", "policy")
