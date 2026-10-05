"""add_enricher_to_scans

Revision ID: d2a7c4e9b1f0
Revises: c7d1f0a92b3e
Create Date: 2026-10-05 00:00:00.000000

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d2a7c4e9b1f0"
down_revision: Union[str, None] = "c7d1f0a92b3e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Pre-existing scans keep enricher=NULL; the graph falls back to node provenance.
    op.add_column("scans", sa.Column("enricher", sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scans", "enricher")
