"""Minimal, self-contained ELF64 (x86-64) builder for challenge artifacts.

Challenge artifacts are *real* ELF binaries so learners can open them in every view
(header, sections, strings, hex, disassembly, CFG) — not opaque blobs. This builder
emits a valid, minimal ``ET_EXEC`` file with a single ``PT_LOAD`` segment and three
sections (``.text``, ``.rodata``, ``.shstrtab``). It intentionally supports only the
tiny subset needed to package challenges; it is not a general-purpose linker.

The produced binaries are static data only — the platform never executes them.
"""

from __future__ import annotations

import struct

# Base virtual address for the single PT_LOAD segment (typical non-PIE ET_EXEC base).
_VADDR_BASE = 0x400000
_EHDR_SIZE = 64
_PHDR_SIZE = 56
_SHDR_SIZE = 64
_TEXT_OFFSET = 0x1000  # Page-align the loadable content after the headers.

# ELF constants used below.
_ET_EXEC = 2
_EM_X86_64 = 0x3E
_PT_LOAD = 1
_PF_R, _PF_X = 0x4, 0x1
_SHT_PROGBITS, _SHT_STRTAB = 1, 3
_SHF_ALLOC, _SHF_EXEC = 0x2, 0x4


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_elf64(
    code: bytes,
    rodata: bytes = b"",
    entry_offset: int = 0,
    text_section_name: str = ".text",
) -> bytes:
    """Wrap ``code`` (and optional ``rodata``) into a minimal x86-64 ELF executable.

    ``entry_offset`` is the offset, in bytes, of the entry point within ``code``.
    ``text_section_name`` names the executable section (used by the packing challenge
    to embed a recognizable packer section name such as ``.UPX1``).
    Returns the complete ELF file as ``bytes``.
    """
    if not code:
        raise ValueError("code must contain at least one byte.")
    if "\x00" in text_section_name or not text_section_name:
        raise ValueError("text_section_name must be a non-empty, NUL-free string.")

    text_offset = _TEXT_OFFSET
    text_vaddr = _VADDR_BASE + text_offset
    rodata_offset = _align_up(text_offset + len(code), 16)
    rodata_vaddr = _VADDR_BASE + rodata_offset

    text_name_bytes = text_section_name.encode("ascii")
    shstr = b"\x00" + text_name_bytes + b"\x00.rodata\x00.shstrtab\x00"

    def name_offset(name: bytes) -> int:
        return shstr.index(b"\x00" + name + b"\x00") + 1

    body_end = rodata_offset + len(rodata)
    shstr_offset = _align_up(body_end, 16)
    section_header_offset = _align_up(shstr_offset + len(shstr), 16)
    section_count = 4  # null, .text, .rodata, .shstrtab

    total_size = section_header_offset + section_count * _SHDR_SIZE
    buf = bytearray(total_size)

    entry = text_vaddr + entry_offset
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # 64-bit, little-endian, SysV
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        buf,
        0,
        e_ident,
        _ET_EXEC,
        _EM_X86_64,
        1,  # e_version
        entry,
        _EHDR_SIZE,  # e_phoff
        section_header_offset,  # e_shoff
        0,  # e_flags
        _EHDR_SIZE,  # e_ehsize
        _PHDR_SIZE,  # e_phentsize
        1,  # e_phnum
        _SHDR_SIZE,  # e_shentsize
        section_count,  # e_shnum
        3,  # e_shstrndx (.shstrtab)
    )

    # One PT_LOAD segment mapping the whole file read+execute.
    load_size = section_header_offset
    struct.pack_into(
        "<IIQQQQQQ",
        buf,
        _EHDR_SIZE,
        _PT_LOAD,
        _PF_R | _PF_X,
        0,  # p_offset
        _VADDR_BASE,  # p_vaddr
        _VADDR_BASE,  # p_paddr
        load_size,  # p_filesz
        load_size,  # p_memsz
        0x1000,  # p_align
    )

    buf[text_offset : text_offset + len(code)] = code
    buf[rodata_offset : rodata_offset + len(rodata)] = rodata
    buf[shstr_offset : shstr_offset + len(shstr)] = shstr

    def write_section(
        index: int,
        name: int,
        sh_type: int,
        flags: int,
        addr: int,
        offset: int,
        size: int,
        align: int = 1,
    ) -> None:
        struct.pack_into(
            "<IIQQQQIIQQ",
            buf,
            section_header_offset + index * _SHDR_SIZE,
            name,
            sh_type,
            flags,
            addr,
            offset,
            size,
            0,  # sh_link
            0,  # sh_info
            align,
            0,  # sh_entsize
        )

    write_section(0, 0, 0, 0, 0, 0, 0)
    write_section(
        1, name_offset(text_name_bytes), _SHT_PROGBITS, _SHF_ALLOC | _SHF_EXEC,
        text_vaddr, text_offset, len(code), align=16,
    )
    write_section(
        2, name_offset(b".rodata"), _SHT_PROGBITS, _SHF_ALLOC,
        rodata_vaddr, rodata_offset, len(rodata), align=16,
    )
    write_section(
        3, name_offset(b".shstrtab"), _SHT_STRTAB, 0,
        0, shstr_offset, len(shstr), align=1,
    )

    return bytes(buf)


def emit_load_al(byte_values: bytes) -> bytes:
    """Emit ``mov al, imm8`` for each byte, then ``ret`` — a disassembly-readable stub.

    Used by the CrackMe challenge: the password's bytes appear as instruction
    immediates in the disassembly view.
    """
    code = bytearray()
    for value in byte_values:
        code += bytes([0xB0, value])  # mov al, imm8
    code += b"\xc3"  # ret
    return bytes(code)
