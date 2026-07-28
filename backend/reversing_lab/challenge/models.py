"""Challenge domain models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ChallengeCategory(str, Enum):
    """The skill each challenge exercises."""

    HIDDEN_STRING = "hidden_string"
    XOR = "xor"
    BASE64 = "base64"
    CRACKME = "crackme"
    PACKING = "packing_detection"
    MALWARE = "malware_analysis"


class Difficulty(str, Enum):
    """Relative difficulty, for ordering and UI badges."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


@dataclass(frozen=True, slots=True)
class BuiltChallenge:
    """The deterministic output of a challenge generator.

    ``answer`` is the solution flag and must never be serialized to a client; it lives
    only server-side, where :func:`verify` compares submissions against it.
    """

    artifact: bytes
    answer: str


@dataclass(frozen=True, slots=True)
class ChallengeView:
    """Client-safe challenge metadata (no answer, no artifact bytes)."""

    slug: str
    title: str
    category: ChallengeCategory
    difficulty: Difficulty
    description: str
    hint: str
    artifact_filename: str
    artifact_size: int


@dataclass(frozen=True, slots=True)
class ChallengeResult:
    """The outcome of verifying a submitted answer."""

    slug: str
    correct: bool
    message: str
