"""Format detection from magic bytes.

Detection is deliberately cheap and independent of the heavy parsers: it inspects
only the first handful of bytes so the API can reject unsupported uploads before
committing to a full parse.
"""

from __future__ import annotations

from ..errors import UnsupportedFormatError
from .models import BinaryFormat

# Mach-O magic numbers (32/64-bit, both endiannesses) and fat/universal archives.
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # MH_MAGIC (32-bit, big-endian layout)
    b"\xce\xfa\xed\xfe",  # MH_CIGAM (32-bit, little-endian)
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC (universal binary, big-endian)
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
}


def detect_format(data: bytes) -> BinaryFormat:
    """Return the :class:`BinaryFormat` of ``data`` or raise ``UnsupportedFormatError``.

    Only the leading bytes are examined; the caller is responsible for the full parse.
    """
    if len(data) < 4:
        raise UnsupportedFormatError("Input too small to contain a valid executable header.")

    if data[:4] == b"\x7fELF":
        return BinaryFormat.ELF

    if data[:4] in _MACHO_MAGICS:
        return BinaryFormat.MACHO

    # PE: "MZ" DOS stub, with a valid e_lfanew pointing at the "PE\0\0" signature.
    if data[:2] == b"MZ" and len(data) >= 0x40:
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if 0 <= e_lfanew <= len(data) - 4 and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            return BinaryFormat.PE

    raise UnsupportedFormatError(
        "Unrecognized format: expected an ELF, PE, or Mach-O executable."
    )
