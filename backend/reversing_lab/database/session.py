"""Database engine/session lifecycle.

A single lazily-created engine and session factory back the whole app. ``init_db``
creates tables and ensures the on-disk binary storage directory exists; it is called
once from the API's startup hook.
"""

from __future__ import annotations

import logging

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings, get_settings
from .models import Base

logger = logging.getLogger(__name__)

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


def _build_engine(settings: Settings) -> Engine:
    # ``check_same_thread`` is a SQLite-only knob required for FastAPI's threadpool.
    connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    return create_engine(settings.database_url, connect_args=connect_args, future=True)


def get_engine() -> Engine:
    """Return the process-wide engine, creating it on first use."""
    global _engine
    if _engine is None:
        _engine = _build_engine(get_settings())
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Return the process-wide session factory."""
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)
    return _SessionFactory


def init_db() -> None:
    """Create tables and the binary storage directory (idempotent)."""
    settings = get_settings()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=get_engine())
    logger.info("Database initialized at %s", settings.database_url)


def get_session() -> Session:
    """Open a new database session (caller is responsible for closing/committing)."""
    return get_session_factory()()
