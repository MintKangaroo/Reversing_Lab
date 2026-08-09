"""Add principal-owned, content-addressed memory region artifacts.

Revision ID: 0006_memory_region_artifacts
Revises: 0005_audit_events
Create Date: 2026-08-09
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006_memory_region_artifacts"
down_revision: str | None = "0005_audit_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "memory_region_artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("owner_id", sa.String(length=128), nullable=False),
        sa.Column("memory_dump_id", sa.String(length=36), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("start_address", sa.BigInteger(), nullable=False),
        sa.Column("end_address", sa.BigInteger(), nullable=False),
        sa.Column("architecture", sa.String(length=16), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("storage_path", sa.String(length=1024), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["memory_dump_id"], ["memory_dumps.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "owner_id",
            "memory_dump_id",
            "pid",
            "start_address",
            "architecture",
            "content_sha256",
            name="uq_memory_region_artifact_content",
        ),
    )
    for column_name in (
        "content_sha256",
        "memory_dump_id",
        "owner_id",
        "pid",
    ):
        op.create_index(
            f"ix_memory_region_artifacts_{column_name}",
            "memory_region_artifacts",
            [column_name],
        )


def downgrade() -> None:
    for column_name in ("pid", "owner_id", "memory_dump_id", "content_sha256"):
        op.drop_index(
            f"ix_memory_region_artifacts_{column_name}",
            table_name="memory_region_artifacts",
        )
    op.drop_table("memory_region_artifacts")
