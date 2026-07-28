"""Challenge catalog and verification service.

The catalog is a fixed, deterministically-built set of challenges. Because generation
is reproducible, verification needs no per-instance persistence: a submission is
compared, in constant time, against the freshly rebuilt answer. Persisting *attempts*
(for scoreboards/progress) is the database layer's job, not this module's.
"""

from __future__ import annotations

import hmac

from ..errors import ChallengeError
from .base import AbstractChallenge
from .generators import (
    Base64Challenge,
    CrackMeChallenge,
    HiddenStringChallenge,
    MalwareChallenge,
    PackingChallenge,
    XorChallenge,
)
from .models import ChallengeResult, ChallengeView

# Registration order defines catalog order (Open/Closed: add a class, nothing else).
_CHALLENGE_CLASSES: tuple[type[AbstractChallenge], ...] = (
    HiddenStringChallenge,
    XorChallenge,
    Base64Challenge,
    CrackMeChallenge,
    PackingChallenge,
    MalwareChallenge,
)


class ChallengeRegistry:
    """In-memory registry of the built challenge catalog."""

    def __init__(self, classes: tuple[type[AbstractChallenge], ...] = _CHALLENGE_CLASSES) -> None:
        self._by_slug: dict[str, AbstractChallenge] = {}
        for cls in classes:
            instance = cls()
            if instance.slug in self._by_slug:
                raise ChallengeError(f"Duplicate challenge slug: {instance.slug!r}.")
            self._by_slug[instance.slug] = instance

    def list_views(self) -> list[ChallengeView]:
        """Return client-safe metadata for every challenge, in catalog order."""
        return [challenge.view() for challenge in self._by_slug.values()]

    def get(self, slug: str) -> AbstractChallenge:
        """Return the challenge for ``slug`` or raise :class:`ChallengeError`."""
        try:
            return self._by_slug[slug]
        except KeyError as exc:
            raise ChallengeError(f"Unknown challenge: {slug!r}.") from exc

    def view(self, slug: str) -> ChallengeView:
        """Return client-safe metadata for a single challenge."""
        return self.get(slug).view()

    def artifact(self, slug: str) -> tuple[str, bytes]:
        """Return ``(filename, bytes)`` for the challenge's downloadable artifact."""
        challenge = self.get(slug)
        return challenge.artifact_filename, challenge.artifact

    def verify(self, slug: str, submission: str) -> ChallengeResult:
        """Check ``submission`` against the challenge's answer in constant time."""
        challenge = self.get(slug)
        # Trim incidental whitespace; the flag content itself never has edge whitespace.
        candidate = submission.strip()
        correct = hmac.compare_digest(candidate, challenge.answer)
        message = "Correct — well done!" if correct else "Incorrect. Keep analyzing and try again."
        return ChallengeResult(slug=slug, correct=correct, message=message)


# Process-wide singleton; building the catalog is cheap and done once.
_REGISTRY: ChallengeRegistry | None = None


def get_registry() -> ChallengeRegistry:
    """Return the shared challenge registry (built lazily on first use)."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = ChallengeRegistry()
    return _REGISTRY
