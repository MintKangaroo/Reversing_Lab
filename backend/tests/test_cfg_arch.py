"""Control-flow recovery on ARM, AArch64, and MIPS.

Each fixture is a hand-assembled function (verified to decode as commented) exercising
the control-flow classification that used to be x86-only: direct branch targets in the
architecture's own operand syntax, conditional fall-through, calls that Capstone also
tags as jumps (ARM ``bl``), and return idioms outside the ``return`` group
(ARM ``bx lr``, MIPS ``jr $ra``).
"""

from __future__ import annotations

from reversing_lab.disassembler import build_cfg
from reversing_lab.parser.models import Architecture, BinaryFormat, BinaryInfo, Section

_BASE = 0x1000


def _info(arch: Architecture, bits: int, endianness: str, code: bytes) -> BinaryInfo:
    section = Section(
        name=".text",
        virtual_address=_BASE,
        size=len(code),
        offset=0,
        entropy=0.0,
        flags=("x",),
        contains_code=True,
    )
    return BinaryInfo(
        binary_format=BinaryFormat.ELF,
        architecture=arch,
        bits=bits,
        endianness=endianness,
        entry_point=_BASE,
        is_pie=False,
        has_nx=True,
        has_relro=False,
        file_size=len(code),
        sha256="0" * 64,
        sections=(section,),
    )


def _kinds(cfg) -> list[str]:
    return [edge.kind for edge in cfg.typed_edges]


def _diamond_checks(cfg) -> None:
    # Entry block ends in a conditional branch: two successors, one taken + one
    # fall-through, and the direct target was recovered (no "indirect" edge).
    entry = cfg.blocks[0]
    assert len(entry.successors) == 2
    kinds = _kinds(cfg)
    assert "indirect" not in kinds
    assert "conditional" in kinds
    assert "fallthrough" in kinds
    assert kinds.count("return") == 2


def test_arm64_conditional_diamond_and_ret() -> None:
    # cmp w0,#0 ; b.eq 0x1010 ; mov w0,#1 ; ret ; mov w0,#2 ; ret
    code = bytes.fromhex(
        "1f000071" "60000054" "20008052" "c0035fd6" "40008052" "c0035fd6"
    )
    cfg = build_cfg(_info(Architecture.ARM64, 64, "little", code), code)
    _diamond_checks(cfg)
    # The taken edge points at the second arm at 0x1010.
    assert any(edge.target_address == 0x1010 for edge in cfg.typed_edges)


def test_arm32_conditional_diamond_with_bx_lr_return() -> None:
    # cmp r0,#0 ; beq 0x1010 ; mov r0,#1 ; bx lr ; mov r0,#2 ; bx lr
    code = bytes.fromhex(
        "000050e3" "0100000a" "0100a0e3" "1eff2fe1" "0200a0e3" "1eff2fe1"
    )
    cfg = build_cfg(_info(Architecture.ARM, 32, "little", code), code)
    _diamond_checks(cfg)  # bx lr must be recognized as a return, not an indirect jump.


def test_mips_conditional_diamond_with_jr_ra_return() -> None:
    # beqz $a0,0x1010 ; nop ; li $v0,1 ; jr $ra ; li $v0,2 ; jr $ra  (big-endian)
    code = bytes.fromhex(
        "10800003" "00000000" "24020001" "03e00008" "24020002" "03e00008"
    )
    cfg = build_cfg(_info(Architecture.MIPS, 32, "big", code), code)
    _diamond_checks(cfg)


def test_arm64_bl_is_a_call_not_a_branch() -> None:
    # bl 0x1008 ; ret ; ret  — bl is in Capstone's jump AND call groups.
    code = bytes.fromhex("02000094" "c0035fd6" "c0035fd6")
    cfg = build_cfg(_info(Architecture.ARM64, 64, "little", code), code)
    kinds = _kinds(cfg)
    # The bl produces a call edge to 0x1008, never a branch/indirect successor.
    assert "call" in kinds
    assert "indirect" not in kinds
    call_edges = [e for e in cfg.typed_edges if e.kind == "call"]
    assert any(e.target_address == 0x1008 for e in call_edges)
    # The entry block runs bl then falls through to ret in the same block: no successors.
    assert cfg.blocks[0].successors == ()


def test_mips_jal_records_a_call_edge() -> None:
    # jal 0x1010 ; nop ; jr $ra ; nop ; jr $ra  (big-endian) — jal has no Capstone
    # call/jump group, so it is recognized by mnemonic.
    code = bytes.fromhex(
        "0c000404" "00000000" "03e00008" "00000000" "03e00008"
    )
    cfg = build_cfg(_info(Architecture.MIPS, 32, "big", code), code)
    assert "call" in _kinds(cfg)
