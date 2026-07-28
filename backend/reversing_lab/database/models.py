"""SQLAlchemy ORM models.

Two tables:

* ``binaries`` — metadata for each uploaded sample, keyed by its SHA-256 (the natural
  identity of a binary). Raw bytes live on disk under ``storage_dir``; only the path
  and metadata are stored in the database.
* ``challenge_attempts`` — an append-only log of challenge submissions, for progress
  tracking and scoreboards.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class BinaryRecord(Base):
    """Metadata for an uploaded binary. The SHA-256 is the primary key."""

    __tablename__ = "binaries"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    binary_format: Mapped[str] = mapped_column(String(16), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class ChallengeAttempt(Base):
    """A single challenge submission (append-only)."""

    __tablename__ = "challenge_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    challenge_slug: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    submission: Mapped[str] = mapped_column(String(512), nullable=False)
    correct: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
