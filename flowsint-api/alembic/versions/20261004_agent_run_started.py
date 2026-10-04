"""Record when an agent run actually started, to detect runs lost with their worker."""

import sqlalchemy as sa
from alembic import op

revision = "20261004_agent_run_started"
down_revision = "20261003_agent_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_runs", sa.Column("started_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("agent_runs", "started_at")
