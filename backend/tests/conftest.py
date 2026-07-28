"""Shared pytest fixtures."""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from . import fixtures


@pytest.fixture(scope="session")
def elf_bytes() -> bytes:
    return fixtures.sample_elf()


@pytest.fixture(scope="session")
def pe_bytes() -> bytes:
    return fixtures.sample_pe()


@pytest.fixture(scope="session")
def macho_bytes() -> bytes:
    return fixtures.sample_macho()


@pytest.fixture()
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    """A TestClient wired to an isolated, temporary database and storage directory."""
    monkeypatch.setenv("RLAB_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("RLAB_STORAGE_DIR", str(tmp_path / "storage"))

    # Rebuild config + database singletons so they pick up the temp paths.
    from reversing_lab import config
    from reversing_lab.database import session as db_session
    from reversing_lab.api import services

    config.get_settings.cache_clear()
    db_session._engine = None
    db_session._SessionFactory = None
    services.clear_cache()

    from fastapi.testclient import TestClient
    from reversing_lab.api.app import create_app

    with TestClient(create_app()) as client:
        yield client

    # Reset singletons so later tests get a clean slate.
    config.get_settings.cache_clear()
    db_session._engine = None
    db_session._SessionFactory = None
    importlib.invalidate_caches()
