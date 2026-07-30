"""Persistence: ORM models, session lifecycle, and repositories."""

from __future__ import annotations

from .models import (
    BinaryRecord,
    BookmarkRecord,
    ChallengeAttempt,
    ProjectRecord,
    ProjectSampleRecord,
    UserAnnotationRecord,
)
from .repository import (
    AnnotationRepository,
    BinaryRepository,
    BookmarkRepository,
    ChallengeAttemptRepository,
    ProjectRepository,
)
from .session import get_engine, get_session, get_session_factory, init_db

__all__ = [
    "AnnotationRepository",
    "BinaryRecord",
    "BinaryRepository",
    "BookmarkRecord",
    "BookmarkRepository",
    "ChallengeAttempt",
    "ChallengeAttemptRepository",
    "ProjectRecord",
    "ProjectRepository",
    "ProjectSampleRecord",
    "UserAnnotationRecord",
    "get_engine",
    "get_session",
    "get_session_factory",
    "init_db",
]
