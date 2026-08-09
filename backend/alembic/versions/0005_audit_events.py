"""Add append-only security and mutation audit events.

Revision ID: 0005_audit_events
Revises: 0004_resource_ownership
Create Date: 2026-08-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_audit_events"
down_revision: str | None = "0004_resource_ownership"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("request_id", sa.String(length=36), nullable=False),
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=192), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("method", sa.String(length=8), nullable=False),
        sa.Column("route", sa.String(length=256), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id"),
    )
    for column_name in (
        "action",
        "created_at",
        "outcome",
        "principal_id",
        "resource_id",
        "resource_type",
    ):
        op.create_index(
            f"ix_audit_events_{column_name}", "audit_events", [column_name]
        )


def downgrade() -> None:
    for column_name in (
        "resource_type",
        "resource_id",
        "principal_id",
        "outcome",
        "created_at",
        "action",
    ):
        op.drop_index(f"ix_audit_events_{column_name}", table_name="audit_events")
    op.drop_table("audit_events")
