"""Mach-O parser (LIEF-backed)."""

from __future__ import annotations

import lief

from .base import AbstractBinaryParser, normalize_arch, sha256_of
from .models import (
    BinaryFormat,
    BinaryInfo,
    Export,
    Import,
    Section,
    Symbol,
)


class MachoParser(AbstractBinaryParser):
    """Normalizes Mach-O executables and dynamic libraries (thin, single-arch)."""

    binary_format = BinaryFormat.MACHO

    def _parse(self, binary: "lief.MachO.Binary", data: bytes) -> BinaryInfo:
        arch, bits = normalize_arch(str(binary.header.cpu_type))

        sections: list[Section] = []
        for section in binary.sections:
            segment_name = getattr(section, "segment_name", "") or ""
            display = f"{segment_name},{section.name}" if segment_name else section.name
            flags = ("CODE",) if segment_name == "__TEXT" and section.name == "__text" else ()
            sections.append(
                Section(
                    name=display or "",
                    virtual_address=int(section.virtual_address),
                    size=int(section.size),
                    offset=int(section.offset),
                    entropy=round(max(float(section.entropy), 0.0), 4),
                    flags=flags,
                    contains_code=(section.name == "__text"),
                )
            )

        imported_names = {func.name for func in binary.imported_functions if func.name}
        exported_names = {func.name for func in binary.exported_functions if func.name}

        imports = tuple(
            Import(name=name, library=None, address=None) for name in sorted(imported_names)
        )
        exports = tuple(
            Export(name=func.name, address=int(func.address))
            for func in binary.exported_functions
            if func.name
        )

        symbols = tuple(
            Symbol(
                name=symbol.name or "",
                value=int(symbol.value),
                size=0,
                kind="function",
                binding="global",
                is_exported=symbol.name in exported_names,
                is_imported=symbol.name in imported_names,
            )
            for symbol in binary.symbols
            if symbol.name
        )

        libraries = tuple(lib.name for lib in binary.libraries) if binary.libraries else ()
        extra = {
            "mach_flags": ", ".join(str(f).rsplit(".", 1)[-1] for f in binary.header.flags_list),
            "libraries": ", ".join(libraries),
        }

        return BinaryInfo(
            binary_format=BinaryFormat.MACHO,
            architecture=arch,
            bits=bits,
            endianness="little",  # All modern Mach-O targets are little-endian.
            entry_point=int(binary.entrypoint),
            is_pie=bool(binary.is_pie),
            has_nx=bool(binary.has_nx),
            has_relro=False,  # Not a Mach-O concept.
            file_size=len(data),
            sha256=sha256_of(data),
            sections=tuple(sections),
            symbols=symbols,
            imports=imports,
            exports=exports,
            extra=extra,
        )
