"""merge scans enricher and agent run

Revision ID: 06ec274dd75d
Revises: 20261004_agent_run_started, d2a7c4e9b1f0
Create Date: 2026-10-05 10:52:54.182819

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '06ec274dd75d'
down_revision: Union[str, None] = ('20261004_agent_run_started', 'd2a7c4e9b1f0')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
