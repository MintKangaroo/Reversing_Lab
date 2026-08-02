"""Scope persisted analysis resources to authenticated principals.

Revision ID: 0004_resource_ownership
Revises: 0003_64_bit_values
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_resource_ownership"
down_revision: str | None = "0003_64_bit_values"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OWNER_TABLES = (
    "challenge_attempts",
    "user_annotations",
    "bookmarks",
    "analysis_artifacts",
    "analysis_jobs",
    "memory_dumps",
    "dynamic_analysis_runs",
    "ctf_workspaces",
)

_OWNER_UNIQUES = {
    "user_annotations": (
        "uq_annotation_target",
        ("owner_id", "binary_sha256", "address", "kind"),
        ("binary_sha256", "address", "kind"),
    ),
    "bookmarks": (
        "uq_bookmark_target",
        ("owner_id", "binary_sha256", "address"),
        ("binary_sha256", "address"),
    ),
    "analysis_artifacts": (
        "uq_artifact_content",
        ("owner_id", "binary_sha256", "kind", "content_sha256"),
        ("binary_sha256", "kind", "content_sha256"),
    ),
}


def _add_owner(table_name: str) -> None:
    op.add_column(
        table_name,
        sa.Column(
            "owner_id",
            sa.String(length=128),
            server_default="local",
            nullable=False,
        ),
    )
    constraint = _OWNER_UNIQUES.get(table_name)
    with op.batch_alter_table(table_name) as batch_op:
        if constraint is not None:
            name, owned_columns, _ = constraint
            batch_op.drop_constraint(name, type_="unique")
            batch_op.create_unique_constraint(name, owned_columns)
        batch_op.alter_column(
            "owner_id",
            existing_type=sa.String(length=128),
            existing_nullable=False,
            server_default=None,
        )
    op.create_index(f"ix_{table_name}_owner_id", table_name, ["owner_id"])


def _drop_owner(table_name: str) -> None:
    op.drop_index(f"ix_{table_name}_owner_id", table_name=table_name)
    constraint = _OWNER_UNIQUES.get(table_name)
    with op.batch_alter_table(table_name) as batch_op:
        if constraint is not None:
            name, _, legacy_columns = constraint
            batch_op.drop_constraint(name, type_="unique")
            batch_op.create_unique_constraint(name, legacy_columns)
        batch_op.drop_column("owner_id")


def upgrade() -> None:
    op.create_table(
        "binary_access",
        sa.Column("owner_id", sa.String(length=128), nullable=False),
        sa.Column("binary_sha256", sa.String(length=64), nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["binary_sha256"], ["binaries.sha256"]),
        sa.PrimaryKeyConstraint("owner_id", "binary_sha256"),
    )
    op.execute(
        sa.text(
            "INSERT INTO binary_access "
            "(owner_id, binary_sha256, filename, created_at) "
            "SELECT 'local', sha256, filename, created_at FROM binaries"
        )
    )

    op.execute(sa.text("UPDATE projects SET owner_id = 'local' WHERE owner_id IS NULL"))
    with op.batch_alter_table("projects") as batch_op:
        batch_op.alter_column(
            "owner_id",
            existing_type=sa.String(length=128),
            existing_nullable=True,
            nullable=False,
        )

    for table_name in _OWNER_TABLES:
        _add_owner(table_name)


def downgrade() -> None:
    for table_name in reversed(_OWNER_TABLES):
        _drop_owner(table_name)

    with op.batch_alter_table("projects") as batch_op:
        batch_op.alter_column(
            "owner_id",
            existing_type=sa.String(length=128),
            existing_nullable=False,
            nullable=True,
        )
    op.drop_table("binary_access")
