"""Repositories — the only code that reads/writes persistence.

Keeping all ORM/disk access behind repositories means the API and services depend on
narrow, testable interfaces rather than on SQLAlchemy sessions directly.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..errors import BinaryNotFoundError
from .models import (
    DEFAULT_OWNER_ID,
    AnalysisArtifactRecord,
    AnalysisJobRecord,
    AuditEventRecord,
    BinaryAccessRecord,
    BinaryRecord,
    BookmarkRecord,
    ChallengeAttempt,
    CtfNoteRecord,
    CtfWorkspaceRecord,
    DynamicAnalysisRunRecord,
    MemoryDumpRecord,
    ProjectRecord,
    ProjectSampleRecord,
    UserAnnotationRecord,
)

logger = logging.getLogger(__name__)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class _OwnedRepository:
    """Shared principal scope for mutable repositories."""

    def __init__(
        self,
        session: Session,
        owner_id: str = DEFAULT_OWNER_ID,
        unrestricted: bool = True,
    ) -> None:
        self._session = session
        self._owner_id = owner_id
        self._unrestricted = unrestricted

    def _read_scope(self, statement, model):
        if self._unrestricted:
            return statement
        return statement.where(model.owner_id == self._owner_id)

    def _require_binary_access(self, sha256: str) -> None:
        if self._session.get(BinaryRecord, sha256) is None:
            raise BinaryNotFoundError(f"No binary with id {sha256!r}.")
        if self._unrestricted:
            return
        key = {"owner_id": self._owner_id, "binary_sha256": sha256}
        if self._session.get(BinaryAccessRecord, key) is None:
            raise BinaryNotFoundError(f"No binary with id {sha256!r}.")


class BinaryRepository(_OwnedRepository):
    """Stores binary bytes on disk (by content hash) and metadata in the database."""

    def __init__(
        self,
        session: Session,
        owner_id: str = DEFAULT_OWNER_ID,
        unrestricted: bool = True,
    ) -> None:
        super().__init__(session, owner_id, unrestricted)
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
            self._grant_access(sha256, filename)
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
        # No ORM relationship links these records, so make the FK insertion order
        # explicit for PostgreSQL instead of relying on unit-of-work sorting.
        self._session.flush()
        self._session.add(
            BinaryAccessRecord(
                owner_id=self._owner_id,
                binary_sha256=sha256,
                filename=filename,
            )
        )
        self._session.commit()
        logger.info("Stored binary %s (%s, %d bytes)", sha256[:12], binary_format, len(data))
        return record

    def _grant_access(self, sha256: str, filename: str) -> None:
        key = {"owner_id": self._owner_id, "binary_sha256": sha256}
        access = self._session.get(BinaryAccessRecord, key)
        if access is None:
            self._session.add(BinaryAccessRecord(**key, filename=filename))
        else:
            access.filename = filename
        self._session.commit()

    def display_filename(self, sha256: str) -> str:
        """Return the current principal's display name without leaking another owner's."""
        key = {"owner_id": self._owner_id, "binary_sha256": sha256}
        access = self._session.get(BinaryAccessRecord, key)
        if access is not None:
            return access.filename
        return self.get(sha256).filename

    def get(self, sha256: str) -> BinaryRecord:
        """Return the record for ``sha256`` or raise :class:`BinaryNotFoundError`."""
        if _SHA256.fullmatch(sha256) is None:
            raise BinaryNotFoundError("Binary identifier must be a lowercase SHA-256.")
        if self._unrestricted:
            record = self._session.get(BinaryRecord, sha256)
        else:
            stmt = (
                select(BinaryRecord)
                .join(
                    BinaryAccessRecord,
                    BinaryAccessRecord.binary_sha256 == BinaryRecord.sha256,
                )
                .where(
                    BinaryRecord.sha256 == sha256,
                    BinaryAccessRecord.owner_id == self._owner_id,
                )
            )
            record = self._session.scalar(stmt)
        if record is None:
            raise BinaryNotFoundError(f"No binary with id {sha256!r}.")
        return record

    def load_bytes(self, sha256: str) -> bytes:
        """Return the stored bytes for ``sha256`` or raise :class:`BinaryNotFoundError`."""
        record = self.get(sha256)
        path = self._path_for(sha256).resolve()
        storage_root = self._storage_dir.resolve()
        if path.parent != storage_root:
            raise BinaryNotFoundError(f"Backing file for {sha256!r} is outside storage.")
        if not path.is_file():
            raise BinaryNotFoundError(f"Backing file for {sha256!r} is missing.")
        return path.read_bytes()

    def list(self, limit: int = 100) -> list[BinaryRecord]:
        """Return the most recently uploaded binaries, newest first."""
        stmt = select(BinaryRecord)
        if not self._unrestricted:
            stmt = stmt.join(
                BinaryAccessRecord,
                BinaryAccessRecord.binary_sha256 == BinaryRecord.sha256,
            ).where(BinaryAccessRecord.owner_id == self._owner_id)
        stmt = stmt.order_by(BinaryRecord.created_at.desc()).limit(limit)
        return list(self._session.scalars(stmt))


class ChallengeAttemptRepository(_OwnedRepository):
    """Append-only log of challenge submissions."""

    def record(self, challenge_slug: str, submission: str, correct: bool) -> ChallengeAttempt:
        """Persist a submission attempt and return it."""
        attempt = ChallengeAttempt(
            owner_id=self._owner_id,
            challenge_slug=challenge_slug,
            submission=submission[:512],
            correct=correct,
        )
        self._session.add(attempt)
        self._session.commit()
        return attempt

    def solved_slugs(self) -> set[str]:
        """Return the set of challenge slugs that have at least one correct attempt."""
        stmt = select(ChallengeAttempt.challenge_slug).where(
            ChallengeAttempt.correct.is_(True)
        )
        stmt = self._read_scope(stmt, ChallengeAttempt)
        return set(self._session.scalars(stmt))


class AuditRepository:
    """Append-only request audit events with principal-scoped reads."""

    def __init__(
        self,
        session: Session,
        principal_id: str = DEFAULT_OWNER_ID,
        unrestricted: bool = True,
    ) -> None:
        self._session = session
        self._principal_id = principal_id
        self._unrestricted = unrestricted

    def record(
        self,
        *,
        request_id: str,
        principal_id: str,
        role: str,
        action: str,
        resource_type: str,
        resource_id: str | None,
        method: str,
        route: str,
        status_code: int,
        outcome: str,
    ) -> AuditEventRecord:
        record = AuditEventRecord(
            id=str(uuid4()),
            request_id=request_id,
            principal_id=principal_id[:128],
            role=role[:32],
            action=action[:192],
            resource_type=resource_type[:64],
            resource_id=resource_id[:128] if resource_id else None,
            method=method[:8],
            route=route[:256],
            status_code=status_code,
            outcome=outcome[:16],
            details_json="{}",
        )
        self._session.add(record)
        self._session.commit()
        return record

    def list(
        self,
        *,
        offset: int,
        limit: int,
        action: str | None = None,
        resource_type: str | None = None,
        outcome: str | None = None,
    ) -> tuple[list[AuditEventRecord], int]:
        filters = []
        if not self._unrestricted:
            filters.append(AuditEventRecord.principal_id == self._principal_id)
        if action is not None:
            filters.append(AuditEventRecord.action == action)
        if resource_type is not None:
            filters.append(AuditEventRecord.resource_type == resource_type)
        if outcome is not None:
            filters.append(AuditEventRecord.outcome == outcome)
        total = self._session.scalar(
            select(func.count()).select_from(AuditEventRecord).where(*filters)
        )
        statement = (
            select(AuditEventRecord)
            .where(*filters)
            .order_by(AuditEventRecord.created_at.desc(), AuditEventRecord.id.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(self._session.scalars(statement)), int(total or 0)


class ProjectRepository(_OwnedRepository):
    """CRUD for analyst projects and their sample membership."""

    def _project_scope(self, owner_id: str | None) -> str | None:
        if owner_id is not None:
            return owner_id
        return None if self._unrestricted else self._owner_id

    def create(
        self,
        name: str,
        description: str = "",
        owner_id: str | None = None,
    ) -> ProjectRecord:
        owner_id = owner_id or self._owner_id
        project = ProjectRecord(
            id=str(uuid4()), name=name, description=description, owner_id=owner_id
        )
        self._session.add(project)
        self._session.commit()
        return project

    def list(
        self, limit: int = 100, owner_id: str | None = None
    ) -> list[ProjectRecord]:
        owner_id = self._project_scope(owner_id)
        stmt = select(ProjectRecord)
        if owner_id is not None:
            stmt = stmt.where(ProjectRecord.owner_id == owner_id)
        stmt = stmt.order_by(ProjectRecord.updated_at.desc()).limit(limit)
        return list(self._session.scalars(stmt))

    def get(self, project_id: str, owner_id: str | None = None) -> ProjectRecord:
        owner_id = self._project_scope(owner_id)
        project = self._session.get(ProjectRecord, project_id)
        if project is None or (
            owner_id is not None and project.owner_id != owner_id
        ):
            raise BinaryNotFoundError(f"No project with id {project_id!r}.")
        return project

    def update(
        self,
        project_id: str,
        name: str | None,
        description: str | None,
        owner_id: str | None = None,
    ) -> ProjectRecord:
        project = self.get(project_id, owner_id)
        if name is not None:
            project.name = name
        if description is not None:
            project.description = description
        self._session.commit()
        return project

    def add_sample(
        self,
        project_id: str,
        binary_sha256: str,
        owner_id: str | None = None,
    ) -> ProjectSampleRecord:
        owner_id = self._project_scope(owner_id)
        self.get(project_id, owner_id)
        if self._session.get(BinaryRecord, binary_sha256) is None:
            raise BinaryNotFoundError(f"No binary with id {binary_sha256!r}.")
        if owner_id is not None:
            access_key = {
                "owner_id": owner_id,
                "binary_sha256": binary_sha256,
            }
            if self._session.get(BinaryAccessRecord, access_key) is None:
                raise BinaryNotFoundError(f"No binary with id {binary_sha256!r}.")
        key = {"project_id": project_id, "binary_sha256": binary_sha256}
        existing = self._session.get(ProjectSampleRecord, key)
        if existing is not None:
            return existing
        membership = ProjectSampleRecord(**key)
        self._session.add(membership)
        self._session.commit()
        return membership

    def sample_hashes(
        self, project_id: str, owner_id: str | None = None
    ) -> list[str]:
        self.get(project_id, owner_id)
        stmt = (
            select(ProjectSampleRecord.binary_sha256)
            .where(ProjectSampleRecord.project_id == project_id)
            .order_by(ProjectSampleRecord.added_at.desc())
        )
        return list(self._session.scalars(stmt))


class AnnotationRepository(_OwnedRepository):
    """Persistent analyst overlays, kept separate from immutable analysis."""

    _ALLOWED_KINDS = {"function_name", "comment"}

    def upsert(
        self, binary_sha256: str, address: int, kind: str, value: str
    ) -> UserAnnotationRecord:
        if kind not in self._ALLOWED_KINDS:
            raise ValueError(f"Unsupported annotation kind: {kind!r}.")
        self._require_binary_access(binary_sha256)
        stmt = select(UserAnnotationRecord).where(
            UserAnnotationRecord.owner_id == self._owner_id,
            UserAnnotationRecord.binary_sha256 == binary_sha256,
            UserAnnotationRecord.address == address,
            UserAnnotationRecord.kind == kind,
        )
        record = self._session.scalar(stmt)
        if record is None:
            record = UserAnnotationRecord(
                owner_id=self._owner_id,
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
        stmt = self._read_scope(stmt, UserAnnotationRecord)
        if address is not None:
            stmt = stmt.where(UserAnnotationRecord.address == address)
        return list(self._session.scalars(stmt.order_by(UserAnnotationRecord.address)))


class BookmarkRepository(_OwnedRepository):
    """CRUD for sample address bookmarks."""

    def upsert(
        self, binary_sha256: str, address: int, label: str, note: str
    ) -> BookmarkRecord:
        self._require_binary_access(binary_sha256)
        stmt = select(BookmarkRecord).where(
            BookmarkRecord.owner_id == self._owner_id,
            BookmarkRecord.binary_sha256 == binary_sha256,
            BookmarkRecord.address == address,
        )
        record = self._session.scalar(stmt)
        if record is None:
            record = BookmarkRecord(
                owner_id=self._owner_id,
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
        stmt = self._read_scope(stmt, BookmarkRecord)
        return list(self._session.scalars(stmt))

    def delete(self, binary_sha256: str, address: int) -> bool:
        statement = delete(BookmarkRecord).where(
            BookmarkRecord.owner_id == self._owner_id,
            BookmarkRecord.binary_sha256 == binary_sha256,
            BookmarkRecord.address == address,
        )
        result = self._session.execute(statement)
        self._session.commit()
        return bool(result.rowcount)


class ArtifactRepository(_OwnedRepository):
    """Store derived bytes by their own hash and index metadata in SQL."""

    def __init__(
        self,
        session: Session,
        owner_id: str = DEFAULT_OWNER_ID,
        unrestricted: bool = True,
    ) -> None:
        super().__init__(session, owner_id, unrestricted)
        self._storage_dir = get_settings().storage_dir.parent / "artifacts"

    def save(
        self,
        binary_sha256: str,
        kind: str,
        data: bytes,
        metadata: dict[str, object] | None = None,
    ) -> AnalysisArtifactRecord:
        self._require_binary_access(binary_sha256)
        content_sha256 = hashlib.sha256(data).hexdigest()
        stmt = select(AnalysisArtifactRecord).where(
            AnalysisArtifactRecord.owner_id == self._owner_id,
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
            owner_id=self._owner_id,
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
        stmt = self._read_scope(stmt, AnalysisArtifactRecord)
        return list(self._session.scalars(stmt))


class JobRepository(_OwnedRepository):
    """State transitions for DB-backed analysis jobs."""

    def create(self, kind: str, target_id: str) -> AnalysisJobRecord:
        record = AnalysisJobRecord(
            id=str(uuid4()),
            owner_id=self._owner_id,
            kind=kind,
            target_id=target_id,
            state="queued",
            progress=0,
            message="Queued",
        )
        self._session.add(record)
        self._session.commit()
        return record

    def get(self, job_id: str) -> AnalysisJobRecord:
        stmt = select(AnalysisJobRecord).where(AnalysisJobRecord.id == job_id)
        stmt = self._read_scope(stmt, AnalysisJobRecord)
        record = self._session.scalar(stmt)
        if record is None:
            raise BinaryNotFoundError(f"No analysis job with id {job_id!r}.")
        return record

    def list(self, limit: int = 100) -> list[AnalysisJobRecord]:
        stmt = (
            select(AnalysisJobRecord)
            .order_by(AnalysisJobRecord.created_at.desc())
            .limit(limit)
        )
        stmt = self._read_scope(stmt, AnalysisJobRecord)
        return list(self._session.scalars(stmt))

    def update(
        self,
        job_id: str,
        *,
        state: str | None = None,
        progress: int | None = None,
        message: str | None = None,
        error: str | None = None,
        result_ref: str | None = None,
    ) -> AnalysisJobRecord:
        record = self.get(job_id)
        if state is not None:
            record.state = state
            now = datetime.now(timezone.utc)
            if state == "running" and record.started_at is None:
                record.started_at = now
            if state in {"completed", "failed", "cancelled"}:
                record.finished_at = now
        if progress is not None:
            record.progress = max(0, min(100, progress))
        if message is not None:
            record.message = message[:512]
        if error is not None:
            record.error = error[:16_384]
        if result_ref is not None:
            record.result_ref = result_ref
        self._session.commit()
        return record

    def request_cancel(self, job_id: str) -> AnalysisJobRecord:
        record = self.get(job_id)
        if record.state not in {"completed", "failed", "cancelled"}:
            record.cancel_requested = True
            if record.state == "queued":
                record.state = "cancelled"
                record.message = "Cancelled before execution"
                record.finished_at = datetime.now(timezone.utc)
            self._session.commit()
        return record


class MemoryDumpRepository(_OwnedRepository):
    """Store memory dumps and compressed result references."""

    def __init__(
        self,
        session: Session,
        owner_id: str = DEFAULT_OWNER_ID,
        unrestricted: bool = True,
    ) -> None:
        super().__init__(session, owner_id, unrestricted)
        self._storage_dir = get_settings().storage_dir.parent / "memory"
        self._artifact_dir = get_settings().storage_dir.parent / "memory-artifacts"

    def save(self, data: bytes, filename: str, dump_format: str) -> MemoryDumpRecord:
        sha256 = hashlib.sha256(data).hexdigest()
        stmt = select(MemoryDumpRecord).where(
            MemoryDumpRecord.owner_id == self._owner_id,
            MemoryDumpRecord.sha256 == sha256,
        )
        existing = self._session.scalar(stmt)
        if existing is not None:
            return existing
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        path = self._storage_dir / sha256
        path.write_bytes(data)
        record = MemoryDumpRecord(
            id=str(uuid4()),
            owner_id=self._owner_id,
            sha256=sha256,
            filename=filename,
            size=len(data),
            dump_format=dump_format,
            storage_path=str(path),
        )
        self._session.add(record)
        self._session.commit()
        return record

    def get(self, dump_id: str) -> MemoryDumpRecord:
        stmt = select(MemoryDumpRecord).where(MemoryDumpRecord.id == dump_id)
        stmt = self._read_scope(stmt, MemoryDumpRecord)
        record = self._session.scalar(stmt)
        if record is None:
            raise BinaryNotFoundError(f"No memory dump with id {dump_id!r}.")
        return record

    def set_analysis(
        self, dump_id: str, data: bytes, provider: str
    ) -> MemoryDumpRecord:
        record = self.get(dump_id)
        digest = hashlib.sha256(data).hexdigest()
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        path = self._artifact_dir / f"{digest}.json.gz"
        if not path.exists():
            path.write_bytes(data)
        record.analysis_path = str(path)
        record.analysis_provider = provider
        self._session.commit()
        return record


class DynamicRunRepository(_OwnedRepository):
    """Persist dynamic-run policy and compressed event artifact references."""

    def __init__(
        self,
        session: Session,
        owner_id: str = DEFAULT_OWNER_ID,
        unrestricted: bool = True,
    ) -> None:
        super().__init__(session, owner_id, unrestricted)
        self._artifact_dir = get_settings().storage_dir.parent / "dynamic-artifacts"

    def create(
        self,
        run_id: str,
        job_id: str,
        binary_sha256: str,
        provider: str,
        policy: dict[str, object],
    ) -> DynamicAnalysisRunRecord:
        self._require_binary_access(binary_sha256)
        record = DynamicAnalysisRunRecord(
            id=run_id,
            owner_id=self._owner_id,
            job_id=job_id,
            binary_sha256=binary_sha256,
            provider=provider,
            policy_json=json.dumps(policy, sort_keys=True),
        )
        self._session.add(record)
        self._session.commit()
        return record

    def get(self, run_id: str) -> DynamicAnalysisRunRecord:
        stmt = select(DynamicAnalysisRunRecord).where(
            DynamicAnalysisRunRecord.id == run_id
        )
        stmt = self._read_scope(stmt, DynamicAnalysisRunRecord)
        record = self._session.scalar(stmt)
        if record is None:
            stmt = select(DynamicAnalysisRunRecord).where(
                DynamicAnalysisRunRecord.job_id == run_id
            )
            stmt = self._read_scope(stmt, DynamicAnalysisRunRecord)
            record = self._session.scalar(stmt)
        if record is None:
            raise BinaryNotFoundError(f"No dynamic analysis run with id {run_id!r}.")
        return record

    def set_result(self, run_id: str, data: bytes) -> DynamicAnalysisRunRecord:
        record = self.get(run_id)
        digest = hashlib.sha256(data).hexdigest()
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        path = self._artifact_dir / f"{digest}.json.gz"
        if not path.exists():
            path.write_bytes(data)
        record.result_path = str(path)
        self._session.commit()
        return record


class CtfWorkspaceRepository(_OwnedRepository):
    """CRUD for CTF investigation state and notes."""

    def create(
        self,
        title: str,
        description: str,
        category: str,
        difficulty: str,
        binary_sha256: str | None,
        checklist: dict[str, bool],
    ) -> CtfWorkspaceRecord:
        if binary_sha256:
            self._require_binary_access(binary_sha256)
        record = CtfWorkspaceRecord(
            id=str(uuid4()),
            owner_id=self._owner_id,
            title=title,
            description=description,
            category=category,
            difficulty=difficulty,
            binary_sha256=binary_sha256,
            checklist_json=json.dumps(checklist, sort_keys=True),
        )
        self._session.add(record)
        self._session.commit()
        return record

    def get(self, workspace_id: str) -> CtfWorkspaceRecord:
        stmt = select(CtfWorkspaceRecord).where(
            CtfWorkspaceRecord.id == workspace_id
        )
        stmt = self._read_scope(stmt, CtfWorkspaceRecord)
        record = self._session.scalar(stmt)
        if record is None:
            raise BinaryNotFoundError(f"No CTF workspace with id {workspace_id!r}.")
        return record

    def list(self, limit: int = 100) -> list[CtfWorkspaceRecord]:
        stmt = (
            select(CtfWorkspaceRecord)
            .order_by(CtfWorkspaceRecord.updated_at.desc())
            .limit(limit)
        )
        stmt = self._read_scope(stmt, CtfWorkspaceRecord)
        return list(self._session.scalars(stmt))

    def update(self, workspace_id: str, values: dict[str, object]) -> CtfWorkspaceRecord:
        record = self.get(workspace_id)
        linked_binary = values.get("binary_sha256")
        if isinstance(linked_binary, str):
            self._require_binary_access(linked_binary)
        scalar_fields = {"title", "description", "category", "difficulty", "binary_sha256"}
        json_fields = {
            "hypotheses": "hypotheses_json",
            "flag_candidates": "flag_candidates_json",
            "checklist": "checklist_json",
            "writeup_steps": "writeup_steps_json",
        }
        for key, value in values.items():
            if value is None:
                continue
            if key in scalar_fields:
                setattr(record, key, value)
            elif key in json_fields:
                setattr(record, json_fields[key], json.dumps(value, sort_keys=True))
        self._session.commit()
        return record

    def add_note(
        self, workspace_id: str, kind: str, content: str, address: int | None
    ) -> CtfNoteRecord:
        self.get(workspace_id)
        note = CtfNoteRecord(
            id=str(uuid4()),
            workspace_id=workspace_id,
            kind=kind,
            content=content,
            address=address,
        )
        self._session.add(note)
        self._session.commit()
        return note

    def notes(self, workspace_id: str) -> list[CtfNoteRecord]:
        self.get(workspace_id)
        stmt = (
            select(CtfNoteRecord)
            .where(CtfNoteRecord.workspace_id == workspace_id)
            .order_by(CtfNoteRecord.created_at)
        )
        return list(self._session.scalars(stmt))
