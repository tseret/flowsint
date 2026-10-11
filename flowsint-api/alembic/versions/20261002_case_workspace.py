"""Persistent case collaboration and optimistic analysis versions."""

import sqlalchemy as sa
from alembic import op

revision = "20261002_case_workspace"
down_revision = "20261002_scan_summary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analyses",
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_table(
        "case_items",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.Uuid(),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "author_id", sa.Uuid(), sa.ForeignKey("profiles.id", ondelete="SET NULL")
        ),
        sa.Column(
            "assignee_id", sa.Uuid(), sa.ForeignKey("profiles.id", ondelete="SET NULL")
        ),
        sa.Column(
            "reviewer_id", sa.Uuid(), sa.ForeignKey("profiles.id", ondelete="SET NULL")
        ),
        sa.Column(
            "sketch_id", sa.Uuid(), sa.ForeignKey("sketches.id", ondelete="CASCADE")
        ),
        sa.Column("target_kind", sa.String()),
        sa.Column("target_id", sa.String()),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("assessment", sa.Text(), nullable=False, server_default=""),
        sa.Column("decision", sa.String(), nullable=False, server_default="pending"),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
    )
    op.create_index(
        "ix_case_items_investigation_id", "case_items", ["investigation_id"]
    )
    op.create_table(
        "case_activity",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.Uuid(),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "actor_id", sa.Uuid(), sa.ForeignKey("profiles.id", ondelete="SET NULL")
        ),
        sa.Column("actor_name", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("item_id", sa.Uuid()),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
    )
    op.create_index(
        "ix_case_activity_investigation_id", "case_activity", ["investigation_id"]
    )


def downgrade() -> None:
    op.drop_table("case_activity")
    op.drop_table("case_items")
    op.drop_column("analyses", "version")
