"""ELF parser (LIEF-backed)."""

from __future__ import annotations

import lief

from .base import AbstractBinaryParser, normalize_arch, sha256_of
from .models import (
    BinaryFormat,
    BinaryInfo,
    Export,
    Import,
    Mitigations,
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
            mitigations=_elf_mitigations(binary),
            extra=extra,
        )


def _elf_mitigations(binary: "lief.ELF.Binary") -> Mitigations:
    """Best-effort ELF mitigation/provenance extraction. Never raises: fragile note or
    property decoding degrades to ``None``/defaults rather than failing the parse."""
    return Mitigations(
        stack_canary=_elf_has_stack_canary(binary),
        control_flow_guard=_elf_has_cet(binary),
        signed=None,  # ELF has no standard code-signing scheme.
        has_debug_info=_elf_has_debug_info(binary),
        build_id=_elf_build_id(binary),
        tls=_elf_has_tls(binary),
        overlay_size=_elf_overlay_size(binary),
    )


def _elf_symbol_names(binary: "lief.ELF.Binary") -> set[str]:
    names: set[str] = set()
    for attr in ("symbols", "dynamic_symbols"):
        try:
            names |= {s.name for s in getattr(binary, attr) if s.name}
        except Exception:  # noqa: BLE001 — hostile/odd binaries may fault on access.
            pass
    return names


def _elf_has_stack_canary(binary: "lief.ELF.Binary") -> bool:
    # -fstack-protector references the guard helper/global; either name confirms it.
    canary = {"__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie"}
    return bool(canary & _elf_symbol_names(binary))


def _elf_has_cet(binary: "lief.ELF.Binary") -> bool | None:
    # CET (IBT/SHSTK) is advertised via a GNU property note. Decoding the exact bits is
    # LIEF-version fragile, so detect the CET keywords in the property note and treat a
    # binary with no property note at all as "undetermined" rather than "absent".
    try:
        saw_property_note = False
        for note in binary.notes:
            if "PROPERTY" not in str(note.type):
                continue
            saw_property_note = True
            haystack = str(getattr(note, "properties", "")) + str(note)
            if any(tag in haystack.upper() for tag in ("IBT", "SHSTK", "CET")):
                return True
        return False if saw_property_note else None
    except Exception:  # noqa: BLE001
        return None


def _elf_has_debug_info(binary: "lief.ELF.Binary") -> bool:
    try:
        return any(s.name.startswith(".debug") for s in binary.sections if s.name)
    except Exception:  # noqa: BLE001
        return False


def _elf_build_id(binary: "lief.ELF.Binary") -> str | None:
    try:
        for note in binary.notes:
            if "BUILD_ID" not in str(note.type):
                continue
            return "".join(f"{b:02x}" for b in note.description)
    except Exception:  # noqa: BLE001
        return None
    return None


def _elf_has_tls(binary: "lief.ELF.Binary") -> bool:
    try:
        return any("TLS" in str(seg.type) for seg in binary.segments)
    except Exception:  # noqa: BLE001
        return False


def _elf_overlay_size(binary: "lief.ELF.Binary") -> int:
    try:
        return len(binary.overlay) if binary.has_overlay else 0
    except Exception:  # noqa: BLE001
        return 0
