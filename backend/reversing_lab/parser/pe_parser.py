"""PE parser (LIEF-backed)."""

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


class PeParser(AbstractBinaryParser):
    """Normalizes Windows PE (PE32 / PE32+) executables and DLLs."""

    binary_format = BinaryFormat.PE

    def _parse(self, binary: "lief.PE.Binary", data: bytes) -> BinaryInfo:
        def enum_name(value: object) -> str:
            """Normalize both named and integer-rendering LIEF enum bindings."""
            name = getattr(value, "name", None)
            return str(name) if name else str(value).rsplit(".", 1)[-1]

        arch, bits = normalize_arch(str(binary.header.machine))
        # PE stores an image base + RVAs; expose the absolute entry point.
        image_base = int(binary.optional_header.imagebase)
        entry_rva = int(binary.optional_header.addressof_entrypoint)

        sections = tuple(
            Section(
                name=section.name or "",
                virtual_address=image_base + int(section.virtual_address),
                size=int(section.virtual_size or section.size),
                offset=int(section.offset),
                entropy=round(max(float(section.entropy), 0.0), 4),
                flags=tuple(
                    enum_name(flag) for flag in section.characteristics_lists
                ),
                contains_code=any(
                    "MEM_EXECUTE" in enum_name(flag) or "CNT_CODE" in enum_name(flag)
                    for flag in section.characteristics_lists
                ),
            )
            for section in binary.sections
        )

        imports: list[Import] = []
        for entry in binary.imports:
            library = entry.name or None
            for func in entry.entries:
                imports.append(
                    Import(
                        name=func.name or f"ordinal_{func.ordinal}",
                        library=library,
                        address=int(func.iat_address) if func.iat_address else None,
                    )
                )

        exports: list[Export] = []
        if binary.has_exports:
            for func in binary.get_export().entries:
                exports.append(
                    Export(
                        name=func.name or f"ordinal_{func.ordinal}",
                        address=image_base + int(func.address),
                        ordinal=int(func.ordinal),
                    )
                )

        symbols = tuple(
            Symbol(
                name=symbol.name or "",
                value=int(symbol.value),
                size=0,
                kind="function" if symbol.name in {imp.name for imp in imports} else "symbol",
                binding="global",
                is_exported=any(exp.name == symbol.name for exp in exports),
                is_imported=any(imp.name == symbol.name for imp in imports),
            )
            for symbol in binary.symbols
            if symbol.name
        )

        dll_chars = {
            enum_name(characteristic)
            for characteristic in binary.optional_header.dll_characteristics_lists
        }

        extra = {
            "subsystem": enum_name(binary.optional_header.subsystem),
            "image_base": hex(image_base),
            "dll_characteristics": ", ".join(sorted(dll_chars)),
            "is_dll": str(binary.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)),
        }

        return BinaryInfo(
            binary_format=BinaryFormat.PE,
            architecture=arch,
            bits=bits,
            endianness="little",  # PE is always little-endian.
            entry_point=image_base + entry_rva,
            is_pie="DYNAMIC_BASE" in dll_chars,
            has_nx="NX_COMPAT" in dll_chars,
            has_relro=False,  # RELRO is an ELF concept; not applicable to PE.
            file_size=len(data),
            sha256=sha256_of(data),
            sections=sections,
            symbols=symbols,
            imports=tuple(imports),
            exports=tuple(exports),
            extra=extra,
        )
