"""Abstract challenge contract.

A challenge bundles static metadata with a deterministic :meth:`build` that produces a
downloadable artifact plus the solution flag. Determinism matters: the same challenge
always yields the same artifact and answer, so verification needs no per-instance
state and the catalog is reproducible across restarts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from functools import cached_property

from .models import (
    BuiltChallenge,
    ChallengeCategory,
    ChallengeView,
    Difficulty,
)

# All challenge flags share this recognizable wrapper.
FLAG_PREFIX = "RLAB{"
FLAG_SUFFIX = "}"


def make_flag(secret: str) -> str:
    """Wrap ``secret`` in the platform's flag format, e.g. ``RLAB{secret}``."""
    return f"{FLAG_PREFIX}{secret}{FLAG_SUFFIX}"


class AbstractChallenge(ABC):
    """Base class for all challenges."""

    slug: str
    title: str
    category: ChallengeCategory
    difficulty: Difficulty
    description: str
    hint: str
    artifact_filename: str

    @abstractmethod
    def build(self) -> BuiltChallenge:
        """Deterministically produce the artifact bytes and the solution flag."""
        raise NotImplementedError

    @cached_property
    def _built(self) -> BuiltChallenge:
        return self.build()

    @property
    def artifact(self) -> bytes:
        """The challenge's downloadable artifact bytes (built once, cached)."""
        return self._built.artifact

    @property
    def answer(self) -> str:
        """The solution flag (server-side only)."""
        return self._built.answer

    def view(self) -> ChallengeView:
        """Return client-safe metadata (never includes the answer)."""
        return ChallengeView(
            slug=self.slug,
            title=self.title,
            category=self.category,
            difficulty=self.difficulty,
            description=self.description,
            hint=self.hint,
            artifact_filename=self.artifact_filename,
            artifact_size=len(self.artifact),
        )
