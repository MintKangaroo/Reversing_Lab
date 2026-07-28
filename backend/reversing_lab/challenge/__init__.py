"""Hands-on reverse-engineering challenges with server-side verification."""

from __future__ import annotations

from .models import (
    ChallengeCategory,
    ChallengeResult,
    ChallengeView,
    Difficulty,
)
from .registry import ChallengeRegistry, get_registry

__all__ = [
    "ChallengeCategory",
    "ChallengeRegistry",
    "ChallengeResult",
    "ChallengeView",
    "Difficulty",
    "get_registry",
]
