"""Repositories — the only code that reads/writes persistence.

Keeping all ORM/disk access behind repositories means the API and services depend on
narrow, testable interfaces rather than on SQLAlchemy sessions directly.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..errors import BinaryNotFoundError
from .models import BinaryRecord, ChallengeAttempt

logger = logging.getLogger(__name__)


class BinaryRepository:
    """Stores binary bytes on disk (by content hash) and metadata in the database."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._storage_dir: Path = get_settings().storage_dir

    def _path_for(self, sha256: str) -> Path:
        # The filename is the content hash: no user input reaches the filesystem path,
        # so path traversal is impossible by construction.
        return self._storage_dir / sha256

    def save(self, data: bytes, filename: str, binary_format: str) -> BinaryRecord:
        """Persist ``data`` and return its record, de-duplicating by content hash."""
        sha256 = hashlib.sha256(data).hexdigest()
        existing = self._session.get(BinaryRecord, sha256)
        if existing is not None:
            return existing

        self._storage_dir.mkdir(parents=True, exist_ok=True)
        path = self._path_for(sha256)
        path.write_bytes(data)

        record = BinaryRecord(
            sha256=sha256,
            filename=filename,
            binary_format=binary_format,
            size=len(data),
            storage_path=str(path),
        )
        self._session.add(record)
        self._session.commit()
        logger.info("Stored binary %s (%s, %d bytes)", sha256[:12], binary_format, len(data))
        return record

    def get(self, sha256: str) -> BinaryRecord:
        """Return the record for ``sha256`` or raise :class:`BinaryNotFoundError`."""
        record = self._session.get(BinaryRecord, sha256)
        if record is None:
            raise BinaryNotFoundError(f"No binary with id {sha256!r}.")
        return record

    def load_bytes(self, sha256: str) -> bytes:
        """Return the stored bytes for ``sha256`` or raise :class:`BinaryNotFoundError`."""
        record = self.get(sha256)
        path = Path(record.storage_path)
        if not path.is_file():
            raise BinaryNotFoundError(f"Backing file for {sha256!r} is missing.")
        return path.read_bytes()

    def list(self, limit: int = 100) -> list[BinaryRecord]:
        """Return the most recently uploaded binaries, newest first."""
        stmt = select(BinaryRecord).order_by(BinaryRecord.created_at.desc()).limit(limit)
        return list(self._session.scalars(stmt))


class ChallengeAttemptRepository:
    """Append-only log of challenge submissions."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def record(self, challenge_slug: str, submission: str, correct: bool) -> ChallengeAttempt:
        """Persist a submission attempt and return it."""
        attempt = ChallengeAttempt(
            challenge_slug=challenge_slug,
            submission=submission[:512],
            correct=correct,
        )
        self._session.add(attempt)
        self._session.commit()
        return attempt

    def solved_slugs(self) -> set[str]:
        """Return the set of challenge slugs that have at least one correct attempt."""
        stmt = select(ChallengeAttempt.challenge_slug).where(ChallengeAttempt.correct.is_(True))
        return set(self._session.scalars(stmt))
