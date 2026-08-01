"""Conservative Alembic bootstrap for fresh and legacy development databases."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from ..config import get_settings
from .models import Base


def _alembic_config(database_url: str) -> Config:
    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "alembic"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _validate_legacy_schema(database_url: str) -> None:
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        actual_tables = set(inspector.get_table_names())
        expected_tables = set(Base.metadata.tables)
        if actual_tables != expected_tables:
            missing = sorted(expected_tables - actual_tables)
            unexpected = sorted(actual_tables - expected_tables)
            raise RuntimeError(
                "Refusing to stamp an unversioned database with schema drift: "
                f"missing={missing}, unexpected={unexpected}."
            )
        for name, table in Base.metadata.tables.items():
            actual_columns = {
                column["name"] for column in inspector.get_columns(name)
            }
            expected_columns = set(table.columns.keys())
            if actual_columns != expected_columns:
                raise RuntimeError(
                    "Refusing to stamp an unversioned database with column drift "
                    f"in {name!r}: missing={sorted(expected_columns - actual_columns)}, "
                    f"unexpected={sorted(actual_columns - expected_columns)}."
                )
    finally:
        engine.dispose()


def bootstrap_database(database_url: str | None = None) -> str:
    """Migrate a fresh/versioned DB or safely baseline an exact legacy schema."""
    url = database_url or get_settings().database_url
    engine = create_engine(url)
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    config = _alembic_config(url)
    if "alembic_version" in tables or not tables:
        command.upgrade(config, "head")
        return "upgraded"

    _validate_legacy_schema(url)
    command.stamp(config, "head")
    command.upgrade(config, "head")
    return "stamped-and-upgraded"


def main() -> None:
    result = bootstrap_database()
    print(f"Database schema {result}.")


if __name__ == "__main__":
    main()
