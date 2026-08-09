"""Explicit principal-owned data retention and safe filesystem reclamation."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..errors import RetentionConflictError
from .models import (
    AnalysisArtifactRecord,
    AnalysisJobRecord,
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

_ACTIVE_JOB_STATES = {"queued", "running"}


class RetentionRepository:
    """Preview and purge only the explicitly selected principal's owned data."""

    def __init__(self, session: Session, principal_id: str) -> None:
        self._session = session
        self._principal_id = principal_id

    def _count(self, model, *criteria) -> int:
        value = self._session.scalar(
            select(func.count()).select_from(model).where(*criteria)
        )
        return int(value or 0)

    def _owned_counts(self) -> dict[str, int]:
        project_ids = select(ProjectRecord.id).where(
            ProjectRecord.owner_id == self._principal_id
        )
        workspace_ids = select(CtfWorkspaceRecord.id).where(
            CtfWorkspaceRecord.owner_id == self._principal_id
        )
        return {
            "binary_access": self._count(
                BinaryAccessRecord,
                BinaryAccessRecord.owner_id == self._principal_id,
            ),
            "projects": self._count(
                ProjectRecord, ProjectRecord.owner_id == self._principal_id
            ),
            "project_samples": self._count(
                ProjectSampleRecord,
                ProjectSampleRecord.project_id.in_(project_ids),
            ),
            "annotations": self._count(
                UserAnnotationRecord,
                UserAnnotationRecord.owner_id == self._principal_id,
            ),
            "bookmarks": self._count(
                BookmarkRecord, BookmarkRecord.owner_id == self._principal_id
            ),
            "artifacts": self._count(
                AnalysisArtifactRecord,
                AnalysisArtifactRecord.owner_id == self._principal_id,
            ),
            "jobs": self._count(
                AnalysisJobRecord,
                AnalysisJobRecord.owner_id == self._principal_id,
            ),
            "memory_dumps": self._count(
                MemoryDumpRecord,
                MemoryDumpRecord.owner_id == self._principal_id,
            ),
            "dynamic_runs": self._count(
                DynamicAnalysisRunRecord,
                DynamicAnalysisRunRecord.owner_id == self._principal_id,
            ),
            "ctf_workspaces": self._count(
                CtfWorkspaceRecord,
                CtfWorkspaceRecord.owner_id == self._principal_id,
            ),
            "ctf_notes": self._count(
                CtfNoteRecord, CtfNoteRecord.workspace_id.in_(workspace_ids)
            ),
            "challenge_attempts": self._count(
                ChallengeAttempt,
                ChallengeAttempt.owner_id == self._principal_id,
            ),
        }

    def _active_jobs(self) -> int:
        return self._count(
            AnalysisJobRecord,
            AnalysisJobRecord.owner_id == self._principal_id,
            AnalysisJobRecord.state.in_(_ACTIVE_JOB_STATES),
        )

    def _orphanable_binaries(self) -> tuple[int, int]:
        owned_hashes = list(
            self._session.scalars(
                select(BinaryAccessRecord.binary_sha256).where(
                    BinaryAccessRecord.owner_id == self._principal_id
                )
            )
        )
        count = 0
        size = 0
        for sha256 in owned_hashes:
            access_count = self._count(
                BinaryAccessRecord,
                BinaryAccessRecord.binary_sha256 == sha256,
            )
            if access_count != 1:
                continue
            record = self._session.get(BinaryRecord, sha256)
            if record is not None:
                count += 1
                size += record.size
        return count, size

    def preview(self, include_binary_access: bool) -> dict[str, object]:
        orphanable_count, orphanable_bytes = self._orphanable_binaries()
        return {
            "principal_id": self._principal_id,
            "include_binary_access": include_binary_access,
            "required_confirmation": f"PURGE:{self._principal_id}",
            "counts": self._owned_counts(),
            "active_jobs": self._active_jobs(),
            "orphanable_binary_count": (
                orphanable_count if include_binary_access else 0
            ),
            "estimated_reclaimable_binary_bytes": (
                orphanable_bytes if include_binary_access else 0
            ),
            "audit_events_retained": True,
        }

    def purge(self, include_binary_access: bool) -> dict[str, object]:
        if self._active_jobs():
            raise RetentionConflictError(
                "Owned data cannot be purged while analysis jobs are queued or running."
            )

        before = self._owned_counts()
        project_ids = select(ProjectRecord.id).where(
            ProjectRecord.owner_id == self._principal_id
        )
        workspace_ids = select(CtfWorkspaceRecord.id).where(
            CtfWorkspaceRecord.owner_id == self._principal_id
        )
        artifacts = list(
            self._session.scalars(
                select(AnalysisArtifactRecord).where(
                    AnalysisArtifactRecord.owner_id == self._principal_id
                )
            )
        )
        dumps = list(
            self._session.scalars(
                select(MemoryDumpRecord).where(
                    MemoryDumpRecord.owner_id == self._principal_id
                )
            )
        )
        runs = list(
            self._session.scalars(
                select(DynamicAnalysisRunRecord).where(
                    DynamicAnalysisRunRecord.owner_id == self._principal_id
                )
            )
        )
        owned_hashes = list(
            self._session.scalars(
                select(BinaryAccessRecord.binary_sha256).where(
                    BinaryAccessRecord.owner_id == self._principal_id
                )
            )
        )

        candidates: list[tuple[str, str]] = []
        candidates.extend(("artifact", item.storage_path) for item in artifacts)
        for item in dumps:
            candidates.append(("memory", item.storage_path))
            if item.analysis_path:
                candidates.append(("memory-analysis", item.analysis_path))
        for item in runs:
            if item.result_path:
                candidates.append(("dynamic", item.result_path))

        self._execute_delete(
            delete(ProjectSampleRecord).where(
                ProjectSampleRecord.project_id.in_(project_ids)
            )
        )
        self._execute_delete(
            delete(CtfNoteRecord).where(CtfNoteRecord.workspace_id.in_(workspace_ids))
        )
        for model in (
            DynamicAnalysisRunRecord,
            AnalysisArtifactRecord,
            UserAnnotationRecord,
            BookmarkRecord,
            MemoryDumpRecord,
            CtfWorkspaceRecord,
            AnalysisJobRecord,
            ChallengeAttempt,
            ProjectRecord,
        ):
            self._execute_delete(
                delete(model).where(model.owner_id == self._principal_id)
            )
        if include_binary_access:
            self._execute_delete(
                delete(BinaryAccessRecord).where(
                    BinaryAccessRecord.owner_id == self._principal_id
                )
            )

        self._session.flush()
        deleted_binaries = 0
        if include_binary_access:
            for sha256 in owned_hashes:
                record = self._session.get(BinaryRecord, sha256)
                if record is None or self._binary_has_references(sha256):
                    continue
                candidates.append(("binary", record.storage_path))
                self._session.delete(record)
                deleted_binaries += 1
        self._session.flush()

        removable = [
            path
            for kind, path in candidates
            if not self._path_has_reference(kind, path)
        ]
        self._session.commit()
        files_removed, bytes_reclaimed, warnings = self._remove_files(removable)
        deleted_counts = dict(before)
        if not include_binary_access:
            deleted_counts["binary_access"] = 0
        return {
            "principal_id": self._principal_id,
            "include_binary_access": include_binary_access,
            "deleted_counts": deleted_counts,
            "binary_records_deleted": deleted_binaries,
            "files_removed": files_removed,
            "bytes_reclaimed": bytes_reclaimed,
            "audit_events_retained": True,
            "warnings": warnings,
        }

    def _execute_delete(self, statement) -> None:
        self._session.execute(
            statement.execution_options(synchronize_session=False)
        )

    def _binary_has_references(self, sha256: str) -> bool:
        checks = (
            self._count(
                BinaryAccessRecord,
                BinaryAccessRecord.binary_sha256 == sha256,
            ),
            self._count(
                ProjectSampleRecord,
                ProjectSampleRecord.binary_sha256 == sha256,
            ),
            self._count(
                UserAnnotationRecord,
                UserAnnotationRecord.binary_sha256 == sha256,
            ),
            self._count(
                BookmarkRecord, BookmarkRecord.binary_sha256 == sha256
            ),
            self._count(
                AnalysisArtifactRecord,
                AnalysisArtifactRecord.binary_sha256 == sha256,
            ),
            self._count(
                DynamicAnalysisRunRecord,
                DynamicAnalysisRunRecord.binary_sha256 == sha256,
            ),
            self._count(
                CtfWorkspaceRecord,
                CtfWorkspaceRecord.binary_sha256 == sha256,
            ),
        )
        return any(checks)

    def _path_has_reference(self, kind: str, path: str) -> bool:
        if kind == "artifact":
            return bool(
                self._count(
                    AnalysisArtifactRecord,
                    AnalysisArtifactRecord.storage_path == path,
                )
            )
        if kind == "memory":
            return bool(
                self._count(MemoryDumpRecord, MemoryDumpRecord.storage_path == path)
            )
        if kind == "memory-analysis":
            return bool(
                self._count(MemoryDumpRecord, MemoryDumpRecord.analysis_path == path)
            )
        if kind == "dynamic":
            return bool(
                self._count(
                    DynamicAnalysisRunRecord,
                    DynamicAnalysisRunRecord.result_path == path,
                )
            )
        return False

    @staticmethod
    def _remove_files(paths: list[str]) -> tuple[int, int, list[str]]:
        settings = get_settings()
        storage_parent = settings.storage_dir.parent
        allowed_roots = {
            settings.storage_dir.resolve(),
            (storage_parent / "artifacts").resolve(),
            (storage_parent / "memory").resolve(),
            (storage_parent / "memory-artifacts").resolve(),
            (storage_parent / "dynamic-artifacts").resolve(),
        }
        removed = 0
        reclaimed = 0
        warnings: list[str] = []
        for raw_path in sorted(set(paths)):
            path = Path(raw_path).resolve()
            if path.parent not in allowed_roots:
                warnings.append("Skipped a file outside configured storage roots.")
                continue
            try:
                if not path.is_file():
                    continue
                size = path.stat().st_size
                path.unlink()
                removed += 1
                reclaimed += size
            except OSError:
                warnings.append(f"Could not remove retained file {path.name!r}.")
        return removed, reclaimed, warnings
