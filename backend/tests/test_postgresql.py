"""PostgreSQL migration and repository contract checks.

The module is skipped in the normal SQLite test suite. CI supplies an isolated
PostgreSQL service and ``RLAB_TEST_POSTGRES_URL``.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import BigInteger, create_engine, inspect, text
from sqlalchemy.orm import Session

from reversing_lab.database.models import BinaryRecord
from reversing_lab.database.repository import (
    AnnotationRepository,
    BookmarkRepository,
    CtfWorkspaceRepository,
    ProjectRepository,
)
from reversing_lab.errors import BinaryNotFoundError

_DATABASE_URL = os.getenv("RLAB_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _DATABASE_URL,
    reason="RLAB_TEST_POSTGRES_URL is required for PostgreSQL contracts.",
)


def test_postgresql_schema_and_64_bit_repository_roundtrip() -> None:
    engine = create_engine(_DATABASE_URL)
    inspector = inspect(engine)
    for table_name, column_name in (
        ("binaries", "size"),
        ("analysis_artifacts", "size"),
        ("memory_dumps", "size"),
        ("user_annotations", "address"),
        ("bookmarks", "address"),
        ("ctf_notes", "address"),
    ):
        columns = {
            column["name"]: column for column in inspector.get_columns(table_name)
        }
        assert isinstance(columns[column_name]["type"], BigInteger)

    with engine.connect() as connection:
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
    assert revision == "0003_64_bit_values"

    digest = "f" * 64
    virtual_address = 0x1_4000_1000
    with Session(engine) as session:
        session.add(
            BinaryRecord(
                sha256=digest,
                filename="postgres-contract.elf",
                binary_format="ELF",
                size=3_000_000_000,
                storage_path=f"/isolated/{digest}",
            )
        )
        session.commit()

        annotation = AnnotationRepository(session).upsert(
            digest, virtual_address, "comment", "64-bit address"
        )
        bookmark = BookmarkRepository(session).upsert(
            digest, virtual_address + 1, "entry", "PostgreSQL round-trip"
        )
        projects = ProjectRepository(session)
        project = projects.create("PostgreSQL contract", owner_id="analyst-one")
        projects.add_sample(project.id, digest, owner_id="analyst-one")
        with pytest.raises(BinaryNotFoundError):
            projects.get(project.id, owner_id="analyst-two")

        workspaces = CtfWorkspaceRepository(session)
        workspace = workspaces.create(
            "64-bit CrackMe",
            "safe contract fixture",
            "reversing",
            "test",
            digest,
            {"file identification": True},
        )
        note = workspaces.add_note(
            workspace.id, "address", "high virtual address", virtual_address + 2
        )

        assert annotation.address == virtual_address
        assert bookmark.address == virtual_address + 1
        assert projects.sample_hashes(project.id, "analyst-one") == [digest]
        assert note.address == virtual_address + 2

    engine.dispose()
