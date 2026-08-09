"""PostgreSQL migration and repository contract checks.

The module is skipped in the normal SQLite test suite. CI supplies an isolated
PostgreSQL service and ``RLAB_TEST_POSTGRES_URL``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import BigInteger, create_engine, inspect, text
from sqlalchemy.orm import Session

from reversing_lab.config import get_settings
from reversing_lab.database.models import BinaryAccessRecord, BinaryRecord
from reversing_lab.database.repository import (
    AnnotationRepository,
    AuditRepository,
    BinaryRepository,
    BookmarkRepository,
    CtfWorkspaceRepository,
    ProjectRepository,
)
from reversing_lab.database.retention import RetentionRepository
from reversing_lab.errors import BinaryNotFoundError

_DATABASE_URL = os.getenv("RLAB_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not _DATABASE_URL,
    reason="RLAB_TEST_POSTGRES_URL is required for PostgreSQL contracts.",
)


def test_postgresql_schema_and_64_bit_repository_roundtrip(tmp_path: Path) -> None:
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
    assert revision == "0005_audit_events"

    for table_name in (
        "projects",
        "challenge_attempts",
        "user_annotations",
        "bookmarks",
        "analysis_artifacts",
        "analysis_jobs",
        "memory_dumps",
        "dynamic_analysis_runs",
        "ctf_workspaces",
    ):
        columns = {
            column["name"]: column for column in inspector.get_columns(table_name)
        }
        assert columns["owner_id"]["nullable"] is False
    assert inspector.get_pk_constraint("binary_access")["constrained_columns"] == [
        "owner_id",
        "binary_sha256",
    ]

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
        session.flush()
        session.add_all(
            [
                BinaryAccessRecord(
                    owner_id=owner_id,
                    binary_sha256=digest,
                    filename="postgres-contract.elf",
                )
                for owner_id in ("analyst-one", "analyst-two")
            ]
        )
        session.commit()

        annotation = AnnotationRepository(
            session, "analyst-one", False
        ).upsert(
            digest, virtual_address, "comment", "64-bit address"
        )
        bookmark = BookmarkRepository(session, "analyst-one", False).upsert(
            digest, virtual_address + 1, "entry", "PostgreSQL round-trip"
        )
        second_annotation = AnnotationRepository(
            session, "analyst-two", False
        ).upsert(digest, virtual_address, "comment", "isolated overlay")
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
        assert annotation.id != second_annotation.id
        assert AnnotationRepository(session, "analyst-one", False).list(
            digest
        )[0].value == "64-bit address"
        assert AnnotationRepository(session, "analyst-two", False).list(
            digest
        )[0].value == "isolated overlay"
        assert projects.sample_hashes(project.id, "analyst-one") == [digest]
        assert note.address == virtual_address + 2

        AuditRepository(session).record(
            request_id="00000000-0000-0000-0000-000000000001",
            principal_id="analyst-one",
            role="analyst",
            action="POST /api/projects",
            resource_type="projects",
            resource_id=project.id,
            method="POST",
            route="/api/projects",
            status_code=201,
            outcome="succeeded",
        )
        audit_items, audit_total = AuditRepository(
            session, "analyst-one", False
        ).list(offset=0, limit=10)
        assert audit_total == 1
        assert audit_items[0].details_json == "{}"

        settings = get_settings()
        previous_storage = settings.storage_dir
        settings.storage_dir = tmp_path / "postgres-storage"
        try:
            first_repo = BinaryRepository(session, "binary-owner-one", False)
            first = first_repo.save(
                b"postgresql binary grant contract", "owner-one.elf", "ELF"
            )
            second_repo = BinaryRepository(session, "binary-owner-two", False)
            second = second_repo.save(
                b"postgresql binary grant contract", "owner-two.elf", "ELF"
            )
            assert first.sha256 == second.sha256
            assert first_repo.display_filename(first.sha256) == "owner-one.elf"
            assert second_repo.display_filename(second.sha256) == "owner-two.elf"
        finally:
            settings.storage_dir = previous_storage

        preview = RetentionRepository(session, "analyst-one").preview(True)
        assert preview["counts"]["annotations"] == 1
        retained = RetentionRepository(session, "analyst-one").purge(True)
        assert retained["deleted_counts"]["projects"] == 1
        assert retained["binary_records_deleted"] == 0
        assert AnnotationRepository(session, "analyst-two", False).list(
            digest
        )[0].value == "isolated overlay"

    engine.dispose()
