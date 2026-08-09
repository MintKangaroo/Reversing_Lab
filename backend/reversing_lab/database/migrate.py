"""Conservative Alembic bootstrap for fresh and legacy development databases."""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from sqlalchemy import BigInteger, create_engine, inspect

from alembic import command

from ..config import get_settings
from .models import Base

_OWNED_TABLES = {
    "challenge_attempts",
    "user_annotations",
    "bookmarks",
    "analysis_artifacts",
    "analysis_jobs",
    "memory_dumps",
    "dynamic_analysis_runs",
    "ctf_workspaces",
}
_PORTABLE_BIGINT_COLUMNS = {
    ("binaries", "size"),
    ("analysis_artifacts", "size"),
    ("memory_dumps", "size"),
    ("user_annotations", "address"),
    ("bookmarks", "address"),
    ("ctf_notes", "address"),
}


def _alembic_config(database_url: str) -> Config:
    backend_root = Path(__file__).resolve().parents[2]
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "alembic"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _legacy_revision(database_url: str) -> str:
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        actual_tables = set(inspector.get_table_names())
        expected_tables = set(Base.metadata.tables)
        pre_audit_tables = expected_tables - {"audit_events"}
        pre_ownership_tables = pre_audit_tables - {"binary_access"}
        if (
            actual_tables != expected_tables
            and actual_tables != pre_audit_tables
            and actual_tables != pre_ownership_tables
        ):
            missing = sorted(pre_ownership_tables - actual_tables)
            unexpected = sorted(actual_tables - expected_tables)
            raise RuntimeError(
                "Refusing to stamp an unversioned database with schema drift: "
                f"missing={missing}, unexpected={unexpected}."
            )

        audit_events_present = actual_tables == expected_tables
        resource_ownership_present = frozenset(actual_tables) in {
            frozenset(expected_tables),
            frozenset(pre_audit_tables),
        }
        project_owner_present = True
        portable_bigints = True
        for name, table in Base.metadata.tables.items():
            if name not in actual_tables:
                continue
            inspected_columns = {
                column["name"]: column for column in inspector.get_columns(name)
            }
            actual_columns = set(inspected_columns)
            expected_columns = set(table.columns.keys())
            if not resource_ownership_present and name in _OWNED_TABLES:
                expected_columns.remove("owner_id")
            if (
                name == "projects"
                and actual_columns == expected_columns - {"owner_id"}
            ):
                project_owner_present = False
                continue
            if actual_columns != expected_columns:
                raise RuntimeError(
                    "Refusing to stamp an unversioned database with column drift "
                    f"in {name!r}: missing={sorted(expected_columns - actual_columns)}, "
                    f"unexpected={sorted(actual_columns - expected_columns)}."
                )
            for table_name, column_name in _PORTABLE_BIGINT_COLUMNS:
                if table_name == name and not isinstance(
                    inspected_columns[column_name]["type"], BigInteger
                ):
                    portable_bigints = False

        if audit_events_present:
            return "0005_audit_events"
        if resource_ownership_present:
            return "0004_resource_ownership"
        if not project_owner_present:
            return "0001_initial_schema"
        if portable_bigints:
            return "0003_64_bit_values"
        return "0002_project_ownership"
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

    revision = _legacy_revision(url)
    command.stamp(config, revision)
    command.upgrade(config, "head")
    return "stamped-and-upgraded"


def main() -> None:
    result = bootstrap_database()
    print(f"Database schema {result}.")


if __name__ == "__main__":
    main()
