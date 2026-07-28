"""ELF parser (LIEF-backed)."""

from __future__ import annotations

import lief

from .base import AbstractBinaryParser, normalize_arch, sha256_of
from .models import (
    Architecture,
    BinaryFormat,
    BinaryInfo,
    Export,
    Import,
    Section,
    Symbol,
)

# LIEF symbol TYPE enum name -> human label.
_SYM_KIND = {
    "FUNC": "function",
    "OBJECT": "object",
    "SECTION": "section",
    "FILE": "file",
    "GNU_IFUNC": "ifunc",
    "NOTYPE": "notype",
}
_SYM_BINDING = {"GLOBAL": "global", "LOCAL": "local", "WEAK": "weak"}


def _enum_label(value: object, mapping: dict[str, str], default: str) -> str:
    name = str(value).rsplit(".", 1)[-1].upper()
    return mapping.get(name, default)


class ElfParser(AbstractBinaryParser):
    """Normalizes ELF executables and shared objects."""

    binary_format = BinaryFormat.ELF

    def _parse(self, binary: "lief.ELF.Binary", data: bytes) -> BinaryInfo:
        arch, bits = normalize_arch(str(binary.header.machine_type))
        endianness = (
            "big" if str(binary.abstract.header.endianness).endswith("BIG") else "little"
        )

        sections = tuple(
            Section(
                name=section.name or "",
                virtual_address=int(section.virtual_address),
                size=int(section.size),
                offset=int(section.offset),
                entropy=round(float(section.entropy), 4),
                flags=tuple(
                    str(flag).rsplit(".", 1)[-1] for flag in section.flags_list
                ),
                contains_code=any(
                    "EXECINSTR" in str(flag) for flag in section.flags_list
                ),
            )
            for section in binary.sections
        )

        symbols = tuple(
            Symbol(
                name=symbol.name or "",
                value=int(symbol.value),
                size=int(symbol.size),
                kind=_enum_label(symbol.type, _SYM_KIND, "notype"),
                binding=_enum_label(symbol.binding, _SYM_BINDING, "local"),
                is_exported=bool(symbol.exported),
                is_imported=bool(symbol.imported),
            )
            for symbol in binary.symbols
            if symbol.name
        )

        libraries = tuple(str(lib) for lib in binary.libraries)
        sole_library = libraries[0] if len(libraries) == 1 else None
        imports = tuple(
            Import(name=symbol.name, library=sole_library, address=None)
            for symbol in binary.dynamic_symbols
            if symbol.imported and symbol.name
        )

        exports = tuple(
            Export(name=symbol.name, address=int(symbol.value))
            for symbol in binary.dynamic_symbols
            if symbol.exported and symbol.name
        )

        has_relro = any("RELRO" in str(seg.type) for seg in binary.segments)

        extra = {
            "elf_type": str(binary.header.file_type).rsplit(".", 1)[-1],
            "interpreter": binary.interpreter if binary.has_interpreter else "",
            "libraries": ", ".join(libraries),
        }

        return BinaryInfo(
            binary_format=BinaryFormat.ELF,
            architecture=arch,
            bits=bits,
            endianness=endianness,
            entry_point=int(binary.entrypoint),
            is_pie=bool(binary.is_pie),
            has_nx=bool(binary.has_nx),
            has_relro=has_relro,
            file_size=len(data),
            sha256=sha256_of(data),
            sections=sections,
            symbols=symbols,
            imports=imports,
            exports=exports,
            extra=extra,
        )
