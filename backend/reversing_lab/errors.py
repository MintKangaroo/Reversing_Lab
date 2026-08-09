"""Domain exception hierarchy.

Every error the analysis core raises derives from :class:`ReversingLabError`, so the
API layer can translate the whole family into HTTP responses in one place
(:mod:`reversing_lab.api.errors`) without leaking library-specific exception types.
"""

from __future__ import annotations


class ReversingLabError(Exception):
    """Base class for all domain errors raised by the platform."""


class UnsupportedFormatError(ReversingLabError):
    """The uploaded bytes are not a recognized/supported executable format."""


class ParseError(ReversingLabError):
    """A binary could not be parsed (truncated, malformed, or corrupt structures)."""


class DisassemblyError(ReversingLabError):
    """Disassembly could not be performed (unknown architecture, no code, ...)."""


class ChallengeError(ReversingLabError):
    """A challenge could not be generated, found, or verified."""


class BinaryNotFoundError(ReversingLabError):
    """No stored binary matches the requested identifier."""


class IntegrationUnavailableError(ReversingLabError):
    """An external tool (radare2/Ghidra/Binary Ninja) was requested but is not installed."""


class RetentionConflictError(ReversingLabError):
    """Owned data cannot be purged while related work is active."""
