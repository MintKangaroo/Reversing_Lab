"""Mach-O parser (LIEF-backed)."""

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
            mitigations=_macho_mitigations(binary, imported_names | exported_names),
            extra=extra,
        )


def _macho_mitigations(binary: "lief.MachO.Binary", symbol_names: set[str]) -> Mitigations:
    """Best-effort Mach-O mitigation/provenance extraction. Control Flow Guard and TLS
    have no reliable Mach-O signal here, so they stay ``None`` (not applicable /
    undetermined). Never raises: unusual binaries fall back to safe defaults."""
    canary = {"__stack_chk_fail", "__stack_chk_guard"}
    return Mitigations(
        stack_canary=bool(canary & symbol_names),
        control_flow_guard=None,
        signed=_macho_safe_bool(lambda: binary.has_code_signature),
        has_debug_info=_macho_has_dwarf(binary),
        build_id=_macho_uuid(binary),
        tls=None,
        overlay_size=_macho_safe_int(lambda: len(binary.overlay)),
    )


def _macho_uuid(binary: "lief.MachO.Binary") -> str | None:
    # LC_UUID is the Mach-O provenance anchor, mirrored to the same lowercase-hex form
    # used for ELF build ids and PE PDB GUIDs.
    try:
        if not binary.has_uuid:
            return None
        return "".join(f"{b:02x}" for b in binary.uuid)
    except Exception:  # noqa: BLE001 — odd binaries may fault on the UUID command.
        return None


def _macho_has_dwarf(binary: "lief.MachO.Binary") -> bool:
    try:
        return any(
            getattr(section, "segment_name", "") == "__DWARF" for section in binary.sections
        )
    except Exception:  # noqa: BLE001
        return False


def _macho_safe_bool(getter) -> bool:
    try:
        return bool(getter())
    except Exception:  # noqa: BLE001
        return False


def _macho_safe_int(getter) -> int:
    try:
        return int(getter())
    except Exception:  # noqa: BLE001
        return 0
