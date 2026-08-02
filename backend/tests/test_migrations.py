"""Alembic baseline, downgrade, drift, and existing-SQLite compatibility."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

from reversing_lab.database.models import Base, BinaryRecord, UserAnnotationRecord
from reversing_lab.database.migrate import bootstrap_database


def _config(database_path: Path) -> Config:
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    return config


def test_fresh_database_upgrade_has_no_metadata_drift(tmp_path: Path) -> None:
    database = tmp_path / "fresh.db"
    config = _config(database)
    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{database}")
    tables = set(inspect(engine).get_table_names())
    assert tables == set(Base.metadata.tables) | {"alembic_version"}
    for table_name, table in Base.metadata.tables.items():
        migrated = {column["name"] for column in inspect(engine).get_columns(table_name)}
        assert migrated == set(table.columns.keys())
    command.check(config)

    command.downgrade(config, "base")
    assert set(inspect(engine).get_table_names()) == {"alembic_version"}


def test_existing_create_all_database_can_be_stamped_without_data_loss(
    tmp_path: Path,
) -> None:
    database = tmp_path / "existing.db"
    engine = create_engine(f"sqlite:///{database}")
    Base.metadata.create_all(engine)
    digest = "a" * 64
    virtual_address = 0x1_4000_1000
    with Session(engine) as session:
        session.add(
            BinaryRecord(
                sha256=digest,
                filename="existing.elf",
                binary_format="ELF",
                size=3_000_000_000,
                storage_path=f"data/binaries/{digest}",
            )
        )
        session.add(
            UserAnnotationRecord(
                binary_sha256=digest,
                address=virtual_address,
                kind="comment",
                value="preserve a high virtual address",
            )
        )
        session.commit()

    assert bootstrap_database(f"sqlite:///{database}") == "stamped-and-upgraded"
    config = _config(database)
    command.check(config)

    with Session(engine) as session:
        preserved = session.scalar(
            select(BinaryRecord).where(BinaryRecord.sha256 == digest)
        )
        assert preserved is not None
        assert preserved.filename == "existing.elf"
        assert preserved.size == 3_000_000_000
        annotation = session.scalar(
            select(UserAnnotationRecord).where(
                UserAnnotationRecord.binary_sha256 == digest
            )
        )
        assert annotation is not None
        assert annotation.address == virtual_address
    assert inspect(engine).get_table_names().count("alembic_version") == 1


def test_bootstrap_refuses_partial_unversioned_schema(tmp_path: Path) -> None:
    database = tmp_path / "partial.db"
    engine = create_engine(f"sqlite:///{database}")
    BinaryRecord.__table__.create(engine)

    with pytest.raises(RuntimeError, match="Refusing to stamp"):
        bootstrap_database(f"sqlite:///{database}")
    assert "alembic_version" not in inspect(engine).get_table_names()


def test_pre_ownership_legacy_schema_is_stamped_then_upgraded(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pre-owner.db"
    config = _config(database)
    command.upgrade(config, "0001_initial_schema")
    engine = create_engine(f"sqlite:///{database}")
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO projects "
                "(id, name, description, created_at, updated_at) "
                "VALUES (:id, :name, :description, :created_at, :updated_at)"
            ),
            {
                "id": "legacy-project",
                "name": "Legacy investigation",
                "description": "preserve me",
                "created_at": now,
                "updated_at": now,
            },
        )
        connection.execute(text("DROP TABLE alembic_version"))

    assert bootstrap_database(f"sqlite:///{database}") == "stamped-and-upgraded"
    columns = {item["name"] for item in inspect(engine).get_columns("projects")}
    assert "owner_id" in columns
    with engine.connect() as connection:
        name = connection.scalar(
            text("SELECT name FROM projects WHERE id = 'legacy-project'")
        )
    assert name == "Legacy investigation"
