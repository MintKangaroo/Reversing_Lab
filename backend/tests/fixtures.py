"""Deterministic fixture binaries for the test suite.

Rather than checking in opaque binary blobs, we synthesize minimal-but-valid ELF, PE,
and Mach-O files at test time. Each is small, reproducible, and exercises the code
paths the parsers/disassembler care about.
"""

from __future__ import annotations

import struct

from reversing_lab.challenge.elfbuilder import build_elf64


def sample_elf() -> bytes:
    """A real x86-64 ELF whose entry function contains a conditional branch.

    Code (at 0x401000):
        cmp edi, 0xa        83 ff 0a
        jle +3              7e 03
        add eax, eax        01 c0
        ret                 c3
        add eax, 1          83 c0 01
        ret                 c3
    This produces a small diamond CFG, ideal for CFG tests.
    """
    code = bytes.fromhex("83ff0a") + bytes.fromhex("7e03") + bytes.fromhex("01c0") + b"\xc3" + bytes.fromhex("83c001") + b"\xc3"
    rodata = b"hello reversing lab\x00secret_marker\x00"
    return build_elf64(code=code, rodata=rodata)


def sample_pe() -> bytes:
    """A minimal 64-bit PE (PE32+) executable with a single ``.text`` section."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew

    machine, nsec, opt_size, chars = 0x8664, 1, 0xF0, 0x22
    coff = struct.pack("<HHIIIHH", machine, nsec, 0, 0, 0, opt_size, chars)

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)  # PE32+ magic
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, 0x1000)  # BaseOfCode
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<H", opt, 40, 6)  # MajorOSVersion
    struct.pack_into("<I", opt, 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)  # Subsystem = CUI
    struct.pack_into("<H", opt, 70, 0x8160)  # DllCharacteristics: NX|DYNAMIC_BASE|GUARD_CF
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes

    section = struct.pack(
        "<8sIIIIIIHHI", b".text", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    headers = (dos + b"PE\x00\x00" + coff + bytes(opt) + section).ljust(0x200, b"\x00")
    body = b"\xc3" * 0x200  # ret sled
    return bytes(headers + body)


def sample_macho() -> bytes:
    """A minimal thin 64-bit Mach-O executable (__TEXT/__text + LC_MAIN)."""
    MH_MAGIC_64, CPU_X86_64, CPU_SUB, MH_EXECUTE = 0xFEEDFACF, 0x01000007, 3, 2
    LC_SEGMENT_64, LC_MAIN = 0x19, 0x80000028

    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text", b"__TEXT", 0x1000, 1, 0x1000, 0, 0, 0, 0x80000400, 0, 0, 0,
    )
    seg_size = 72 + len(section)
    segment = (
        struct.pack(
            "<II16sQQQQiiII",
            LC_SEGMENT_64, seg_size, b"__TEXT", 0, 0x2000, 0, 0x1000, 7, 5, 1, 0,
        )
        + section
    )
    main = struct.pack("<IIQQ", LC_MAIN, 24, 0x1000, 0)
    ncmds, sizeofcmds = 2, len(segment) + len(main)
    header = struct.pack(
        "<IiiIIIII",
        MH_MAGIC_64, CPU_X86_64, CPU_SUB, MH_EXECUTE, ncmds, sizeofcmds, 0x00200085, 0,
    )
    return bytes((header + segment + main).ljust(0x1000, b"\x00") + b"\xc3" * 0x100)
