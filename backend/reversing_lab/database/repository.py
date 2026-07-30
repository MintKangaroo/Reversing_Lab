"""Repositories — the only code that reads/writes persistence.

Keeping all ORM/disk access behind repositories means the API and services depend on
narrow, testable interfaces rather than on SQLAlchemy sessions directly.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..errors import BinaryNotFoundError
from .models import (
    AnalysisArtifactRecord,
    BinaryRecord,
    BookmarkRecord,
    ChallengeAttempt,
    ProjectRecord,
    ProjectSampleRecord,
    UserAnnotationRecord,
)

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


class ProjectRepository:
    """CRUD for analyst projects and their sample membership."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, name: str, description: str = "") -> ProjectRecord:
        project = ProjectRecord(id=str(uuid4()), name=name, description=description)
        self._session.add(project)
        self._session.commit()
        return project

    def list(self, limit: int = 100) -> list[ProjectRecord]:
        stmt = select(ProjectRecord).order_by(ProjectRecord.updated_at.desc()).limit(limit)
        return list(self._session.scalars(stmt))

    def get(self, project_id: str) -> ProjectRecord:
        project = self._session.get(ProjectRecord, project_id)
        if project is None:
            raise BinaryNotFoundError(f"No project with id {project_id!r}.")
        return project

    def update(
        self, project_id: str, name: str | None, description: str | None
    ) -> ProjectRecord:
        project = self.get(project_id)
        if name is not None:
            project.name = name
        if description is not None:
            project.description = description
        self._session.commit()
        return project

    def add_sample(self, project_id: str, binary_sha256: str) -> ProjectSampleRecord:
        self.get(project_id)
        if self._session.get(BinaryRecord, binary_sha256) is None:
            raise BinaryNotFoundError(f"No binary with id {binary_sha256!r}.")
        key = {"project_id": project_id, "binary_sha256": binary_sha256}
        existing = self._session.get(ProjectSampleRecord, key)
        if existing is not None:
            return existing
        membership = ProjectSampleRecord(**key)
        self._session.add(membership)
        self._session.commit()
        return membership

    def sample_hashes(self, project_id: str) -> list[str]:
        self.get(project_id)
        stmt = (
            select(ProjectSampleRecord.binary_sha256)
            .where(ProjectSampleRecord.project_id == project_id)
            .order_by(ProjectSampleRecord.added_at.desc())
        )
        return list(self._session.scalars(stmt))


class AnnotationRepository:
    """Persistent analyst overlays, kept separate from immutable analysis."""

    _ALLOWED_KINDS = {"function_name", "comment"}

    def __init__(self, session: Session) -> None:
        self._session = session

    def upsert(
        self, binary_sha256: str, address: int, kind: str, value: str
    ) -> UserAnnotationRecord:
        if kind not in self._ALLOWED_KINDS:
            raise ValueError(f"Unsupported annotation kind: {kind!r}.")
        stmt = select(UserAnnotationRecord).where(
            UserAnnotationRecord.binary_sha256 == binary_sha256,
            UserAnnotationRecord.address == address,
            UserAnnotationRecord.kind == kind,
        )
        record = self._session.scalar(stmt)
        if record is None:
            record = UserAnnotationRecord(
                binary_sha256=binary_sha256,
                address=address,
                kind=kind,
                value=value,
            )
            self._session.add(record)
        else:
            record.value = value
        self._session.commit()
        return record

    def list(
        self, binary_sha256: str, address: int | None = None
    ) -> list[UserAnnotationRecord]:
        stmt = select(UserAnnotationRecord).where(
            UserAnnotationRecord.binary_sha256 == binary_sha256
        )
        if address is not None:
            stmt = stmt.where(UserAnnotationRecord.address == address)
        return list(self._session.scalars(stmt.order_by(UserAnnotationRecord.address)))


class BookmarkRepository:
    """CRUD for sample address bookmarks."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def upsert(
        self, binary_sha256: str, address: int, label: str, note: str
    ) -> BookmarkRecord:
        stmt = select(BookmarkRecord).where(
            BookmarkRecord.binary_sha256 == binary_sha256,
            BookmarkRecord.address == address,
        )
        record = self._session.scalar(stmt)
        if record is None:
            record = BookmarkRecord(
                binary_sha256=binary_sha256,
                address=address,
                label=label,
                note=note,
            )
            self._session.add(record)
        else:
            record.label = label
            record.note = note
        self._session.commit()
        return record

    def list(self, binary_sha256: str) -> list[BookmarkRecord]:
        stmt = (
            select(BookmarkRecord)
            .where(BookmarkRecord.binary_sha256 == binary_sha256)
            .order_by(BookmarkRecord.address)
        )
        return list(self._session.scalars(stmt))

    def delete(self, binary_sha256: str, address: int) -> bool:
        result = self._session.execute(
            delete(BookmarkRecord).where(
                BookmarkRecord.binary_sha256 == binary_sha256,
                BookmarkRecord.address == address,
            )
        )
        self._session.commit()
        return bool(result.rowcount)


class ArtifactRepository:
    """Store derived bytes by their own hash and index metadata in SQL."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._storage_dir = get_settings().storage_dir.parent / "artifacts"

    def save(
        self,
        binary_sha256: str,
        kind: str,
        data: bytes,
        metadata: dict[str, object] | None = None,
    ) -> AnalysisArtifactRecord:
        content_sha256 = hashlib.sha256(data).hexdigest()
        stmt = select(AnalysisArtifactRecord).where(
            AnalysisArtifactRecord.binary_sha256 == binary_sha256,
            AnalysisArtifactRecord.kind == kind,
            AnalysisArtifactRecord.content_sha256 == content_sha256,
        )
        existing = self._session.scalar(stmt)
        if existing is not None:
            return existing
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        path = self._storage_dir / content_sha256
        if not path.exists():
            path.write_bytes(data)
        record = AnalysisArtifactRecord(
            id=str(uuid4()),
            binary_sha256=binary_sha256,
            kind=kind,
            content_sha256=content_sha256,
            size=len(data),
            storage_path=str(path),
            metadata_json=json.dumps(metadata or {}, sort_keys=True),
        )
        self._session.add(record)
        self._session.commit()
        return record

    def list(self, binary_sha256: str) -> list[AnalysisArtifactRecord]:
        stmt = (
            select(AnalysisArtifactRecord)
            .where(AnalysisArtifactRecord.binary_sha256 == binary_sha256)
            .order_by(AnalysisArtifactRecord.created_at.desc())
        )
        return list(self._session.scalars(stmt))
