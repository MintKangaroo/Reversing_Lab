"""FastAPI dependency-injection providers."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends
from sqlalchemy.orm import Session

from ..database import (
    AnnotationRepository,
    ArtifactRepository,
    AuditRepository,
    BinaryRepository,
    BookmarkRepository,
    ChallengeAttemptRepository,
    CtfWorkspaceRepository,
    DynamicRunRepository,
    JobRepository,
    MemoryDumpRepository,
    ProjectRepository,
    RetentionRepository,
)
from ..database.session import get_session_factory
from .auth import Principal, get_current_principal, resource_scope


def _owned(repository_type, session: Session, principal: Principal):
    owner_id, unrestricted = resource_scope(principal)
    return repository_type(session, owner_id, unrestricted)


def get_db() -> Iterator[Session]:
    """Yield a request-scoped database session, always closed afterwards."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def get_binary_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> BinaryRepository:
    """Provide a :class:`BinaryRepository` bound to the request session."""
    return _owned(BinaryRepository, session, principal)


def get_attempt_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> ChallengeAttemptRepository:
    """Provide a :class:`ChallengeAttemptRepository` bound to the request session."""
    return _owned(ChallengeAttemptRepository, session, principal)


def get_project_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> ProjectRepository:
    return _owned(ProjectRepository, session, principal)


def get_annotation_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> AnnotationRepository:
    return _owned(AnnotationRepository, session, principal)


def get_bookmark_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> BookmarkRepository:
    return _owned(BookmarkRepository, session, principal)


def get_artifact_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> ArtifactRepository:
    return _owned(ArtifactRepository, session, principal)


def get_audit_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> AuditRepository:
    return _owned(AuditRepository, session, principal)


def get_job_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> JobRepository:
    return _owned(JobRepository, session, principal)


def get_memory_dump_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> MemoryDumpRepository:
    return _owned(MemoryDumpRepository, session, principal)


def get_dynamic_run_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> DynamicRunRepository:
    return _owned(DynamicRunRepository, session, principal)


def get_ctf_workspace_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> CtfWorkspaceRepository:
    return _owned(CtfWorkspaceRepository, session, principal)


def get_retention_repository(
    session: Session = Depends(get_db),
    principal: Principal = Depends(get_current_principal),
) -> RetentionRepository:
    owner_id, _ = resource_scope(principal)
    return RetentionRepository(session, owner_id)
