"""Format detection → parser resolution → parse, in one entry point.

Consumers call :func:`parse_binary`; they never instantiate a concrete parser or
touch LIEF. Adding a new format is a matter of registering a parser here (Open/Closed).
"""

from __future__ import annotations

from ..errors import UnsupportedFormatError
from .base import AbstractBinaryParser
from .detect import detect_format
from .elf_parser import ElfParser
from .macho_parser import MachoParser
from .models import BinaryFormat, BinaryInfo
from .pe_parser import PeParser

# One shared, stateless parser instance per format.
_PARSERS: dict[BinaryFormat, AbstractBinaryParser] = {
    BinaryFormat.ELF: ElfParser(),
    BinaryFormat.PE: PeParser(),
    BinaryFormat.MACHO: MachoParser(),
}


def get_parser(fmt: BinaryFormat) -> AbstractBinaryParser:
    """Return the parser registered for ``fmt``."""
    try:
        return _PARSERS[fmt]
    except KeyError as exc:  # pragma: no cover - guarded by detect_format
        raise UnsupportedFormatError(f"No parser registered for format {fmt}.") from exc


def parse_binary(data: bytes) -> BinaryInfo:
    """Detect the format of ``data`` and return its normalized :class:`BinaryInfo`."""
    fmt = detect_format(data)
    return get_parser(fmt).parse(data)
