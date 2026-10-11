"""Persist enrichment summaries separately from legacy result details."""

import sqlalchemy as sa
from alembic import op

revision = "20261002_scan_summary"
down_revision = "c7d1f0a92b3e"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("summary", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "summary")
