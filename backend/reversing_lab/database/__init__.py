"""Persistence: ORM models, session lifecycle, and repositories."""

from __future__ import annotations

from .models import (
    AnalysisArtifactRecord,
    AnalysisJobRecord,
    BinaryRecord,
    BookmarkRecord,
    ChallengeAttempt,
    DynamicAnalysisRunRecord,
    MemoryDumpRecord,
    ProjectRecord,
    ProjectSampleRecord,
    UserAnnotationRecord,
)
from .repository import (
    AnnotationRepository,
    ArtifactRepository,
    BinaryRepository,
    BookmarkRepository,
    ChallengeAttemptRepository,
    DynamicRunRepository,
    JobRepository,
    MemoryDumpRepository,
    ProjectRepository,
)
from .session import get_engine, get_session, get_session_factory, init_db

__all__ = [
    "AnnotationRepository",
    "AnalysisArtifactRecord",
    "AnalysisJobRecord",
    "ArtifactRepository",
    "BinaryRecord",
    "BinaryRepository",
    "BookmarkRecord",
    "BookmarkRepository",
    "ChallengeAttempt",
    "ChallengeAttemptRepository",
    "DynamicAnalysisRunRecord",
    "DynamicRunRepository",
    "JobRepository",
    "MemoryDumpRecord",
    "MemoryDumpRepository",
    "ProjectRecord",
    "ProjectRepository",
    "ProjectSampleRecord",
    "UserAnnotationRecord",
    "get_engine",
    "get_session",
    "get_session_factory",
    "init_db",
]
