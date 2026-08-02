"""Use portable 64-bit storage for sizes and virtual addresses.

Revision ID: 0003_64_bit_values
Revises: 0002_project_ownership
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_64_bit_values"
down_revision: str | None = "0002_project_ownership"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = (
    ("binaries", "size", False),
    ("analysis_artifacts", "size", False),
    ("memory_dumps", "size", False),
    ("user_annotations", "address", False),
    ("bookmarks", "address", False),
    ("ctf_notes", "address", True),
)


def _alter_values(source: sa.TypeEngine, target: sa.TypeEngine) -> None:
    dialect = op.get_bind().dialect.name
    for table_name, column_name, nullable in _COLUMNS:
        dialect_options = {}
        if dialect == "postgresql":
            dialect_options["postgresql_using"] = (
                f"{column_name}::{target.compile(dialect=op.get_bind().dialect)}"
            )
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.alter_column(
                column_name,
                existing_type=source,
                type_=target,
                existing_nullable=nullable,
                **dialect_options,
            )


def upgrade() -> None:
    _alter_values(sa.Integer(), sa.BigInteger())


def downgrade() -> None:
    _alter_values(sa.BigInteger(), sa.Integer())
