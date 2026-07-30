"""FastAPI dependency-injection providers."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends
from sqlalchemy.orm import Session

from ..database import (
    AnnotationRepository,
    ArtifactRepository,
    BinaryRepository,
    BookmarkRepository,
    ChallengeAttemptRepository,
    CtfWorkspaceRepository,
    DynamicRunRepository,
    JobRepository,
    MemoryDumpRepository,
    ProjectRepository,
)
from ..database.session import get_session_factory


def get_db() -> Iterator[Session]:
    """Yield a request-scoped database session, always closed afterwards."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def get_binary_repository(session: Session = Depends(get_db)) -> BinaryRepository:
    """Provide a :class:`BinaryRepository` bound to the request session."""
    return BinaryRepository(session)


def get_attempt_repository(session: Session = Depends(get_db)) -> ChallengeAttemptRepository:
    """Provide a :class:`ChallengeAttemptRepository` bound to the request session."""
    return ChallengeAttemptRepository(session)


def get_project_repository(session: Session = Depends(get_db)) -> ProjectRepository:
    return ProjectRepository(session)


def get_annotation_repository(session: Session = Depends(get_db)) -> AnnotationRepository:
    return AnnotationRepository(session)


def get_bookmark_repository(session: Session = Depends(get_db)) -> BookmarkRepository:
    return BookmarkRepository(session)


def get_artifact_repository(session: Session = Depends(get_db)) -> ArtifactRepository:
    return ArtifactRepository(session)


def get_job_repository(session: Session = Depends(get_db)) -> JobRepository:
    return JobRepository(session)


def get_memory_dump_repository(session: Session = Depends(get_db)) -> MemoryDumpRepository:
    return MemoryDumpRepository(session)


def get_dynamic_run_repository(session: Session = Depends(get_db)) -> DynamicRunRepository:
    return DynamicRunRepository(session)


def get_ctf_workspace_repository(
    session: Session = Depends(get_db),
) -> CtfWorkspaceRepository:
    return CtfWorkspaceRepository(session)
