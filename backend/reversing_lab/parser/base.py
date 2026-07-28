"""Abstract parser contract and shared LIEF helpers.

Concrete parsers (ELF/PE/Mach-O) subclass :class:`AbstractBinaryParser` and are the
only place in the codebase that touches LIEF. Everything they produce is expressed in
terms of :mod:`reversing_lab.parser.models`.
"""

from __future__ import annotations

import hashlib
import logging
from abc import ABC, abstractmethod

import lief

from ..errors import ParseError
from .models import Architecture, BinaryFormat, BinaryInfo

logger = logging.getLogger(__name__)

# LIEF machine/CPU enum name -> normalized (Architecture, bits).
# Order matters: the most specific tokens are checked first so that, e.g.,
# "X86_64" is not shadowed by the "X86" substring rule.
_ARCH_TOKENS: tuple[tuple[str, Architecture, int], ...] = (
    ("X86_64", Architecture.X86_64, 64),
    ("AMD64", Architecture.X86_64, 64),
    ("AARCH64", Architecture.ARM64, 64),
    ("ARM64", Architecture.ARM64, 64),
    ("I386", Architecture.X86, 32),
    ("X86", Architecture.X86, 32),
    ("ARM", Architecture.ARM, 32),
    ("MIPS", Architecture.MIPS, 32),
    ("POWERPC", Architecture.PPC, 32),
    ("PPC", Architecture.PPC, 32),
)


def sha256_of(data: bytes) -> str:
    """Return the hex SHA-256 digest — the canonical identity of a binary."""
    return hashlib.sha256(data).hexdigest()


def normalize_arch(enum_name: str) -> tuple[Architecture, int]:
    """Map a LIEF architecture enum *name* to ``(Architecture, bits)``.

    Unknown machines degrade to ``(UNKNOWN, 0)`` rather than raising — the caller can
    still show headers/sections/strings even when disassembly is unavailable.
    """
    key = enum_name.rsplit(".", 1)[-1].upper()
    for token, arch, bits in _ARCH_TOKENS:
        if token in key:
            return (arch, bits)
    return (Architecture.UNKNOWN, 0)


class AbstractBinaryParser(ABC):
    """Base class for format-specific parsers.

    Subclasses implement :meth:`_parse`, which receives the already-parsed LIEF
    binary and the raw bytes and returns a :class:`BinaryInfo`. The public
    :meth:`parse` wraps that call with uniform error handling.
    """

    #: The format this parser handles; set by each subclass.
    binary_format: BinaryFormat

    def parse(self, data: bytes) -> BinaryInfo:
        """Parse ``data`` into a normalized :class:`BinaryInfo`.

        Any failure inside LIEF or the subclass is converted into a
        :class:`ParseError`, so callers never see a library-specific exception.
        """
        try:
            binary = lief.parse(list(data))
        except Exception as exc:  # LIEF raises a variety of native exceptions.
            raise ParseError(f"LIEF failed to parse the {self.binary_format.value} binary.") from exc

        if binary is None:
            raise ParseError(f"Not a valid {self.binary_format.value} binary.")

        try:
            return self._parse(binary, data)
        except ParseError:
            raise
        except Exception as exc:
            logger.exception("Unexpected error while normalizing %s binary", self.binary_format.value)
            raise ParseError(
                f"Failed to extract metadata from the {self.binary_format.value} binary."
            ) from exc

    @abstractmethod
    def _parse(self, binary: "lief.Binary", data: bytes) -> BinaryInfo:
        """Translate the LIEF binary into a :class:`BinaryInfo`. Implemented per format."""
        raise NotImplementedError
