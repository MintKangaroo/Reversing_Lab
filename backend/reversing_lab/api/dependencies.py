"""FastAPI dependency-injection providers."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends
from sqlalchemy.orm import Session

from ..database import BinaryRepository, ChallengeAttemptRepository
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
