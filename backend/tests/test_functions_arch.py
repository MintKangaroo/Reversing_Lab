"""Function inventory / call-graph recovery and the shared classifier on non-x86.

The function-recovery pass shares its branch/call/return classification with the CFG
builder (``disassembler.classify``); these cover the arch-specific paths that x86-only
logic used to miss — notably MIPS ``jal`` (no Capstone call group) call targets.
"""

from __future__ import annotations

from reversing_lab.analysis.functions import analyze_functions, build_call_graph
from reversing_lab.disassembler import classify
from reversing_lab.disassembler.disassembler import Instruction
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


def _insn(mnemonic: str, op_str: str, groups: tuple[str, ...]) -> Instruction:
    return Instruction(
        address=0, mnemonic=mnemonic, op_str=op_str, bytes_hex="", size=4, groups=groups
    )


def test_mips_jal_call_target_is_discovered_and_linked() -> None:
    # jal 0x1010 ; nop ; jr $ra ; nop ; jr $ra   (big-endian)
    # jal has no Capstone call/jump group, so first-operand + group-only logic missed it.
    code = bytes.fromhex("0c000404" "00000000" "03e00008" "00000000" "03e00008")
    functions = analyze_functions(_info(Architecture.MIPS, 32, "big", code), code)

    by_address = {function.address: function for function in functions}
    assert 0x1000 in by_address  # entry / caller
    assert 0x1010 in by_address  # jal target, discovered as a function candidate
    assert 0x1010 in by_address[0x1000].callees

    graph = build_call_graph(functions)
    assert any(
        edge.source == 0x1000 and edge.target == 0x1010 for edge in graph.edges
    )


def test_arm64_conditional_branch_counts_toward_complexity() -> None:
    # cmp w0,#0 ; b.eq 0x1010 ; mov w0,#1 ; ret ; mov w0,#2 ; ret
    code = bytes.fromhex(
        "1f000071" "60000054" "20008052" "c0035fd6" "40008052" "c0035fd6"
    )
    functions = analyze_functions(_info(Architecture.ARM64, 64, "little", code), code)
    entry = next(f for f in functions if f.address == 0x1000)
    # The recovered conditional branch is a decision point (b.eq target read as the
    # last operand) and the taken target opens another basic block.
    assert entry.cyclomatic_complexity >= 2
    assert entry.basic_block_count >= 2


def test_classify_normalizes_operand_syntax_and_idioms() -> None:
    # Direct targets across architectures (last operand, optional '#').
    assert classify.direct_target(_insn("jmp", "0x401000", ("jump",))) == 0x401000
    assert classify.direct_target(_insn("b", "#0x1010", ("jump",))) == 0x1010
    assert classify.direct_target(_insn("cbz", "w0, #0x18", ("jump",))) == 0x18
    assert classify.direct_target(_insn("beq", "$a0, $a1, 0x1024", ("jump",))) == 0x1024
    assert classify.direct_target(_insn("jmp", "rax", ("jump",))) is None

    # Calls that are also jumps (ARM bl) and calls Capstone does not group (MIPS jal).
    assert classify.is_call(_insn("bl", "#0x20", ("call", "jump"))) is True
    assert classify.is_jump(_insn("bl", "#0x20", ("call", "jump"))) is False
    assert classify.is_call(_insn("jal", "0x20", ("stdenc",))) is True

    # Return idioms outside the return group.
    assert classify.is_return(_insn("bx", "lr", ("jump",))) is True
    assert classify.is_return(_insn("jr", "$ra", ("jump",))) is True
    assert classify.is_return(_insn("jr", "$t9", ("jump",))) is False

    # Fall-through only for conditional branches; indirect jumps do not fall through.
    assert classify.falls_through(_insn("beq", "$a0, $a1, 0x24", ("jump",))) is True
    assert classify.falls_through(_insn("b", "#0x1010", ("jump",))) is False
    assert classify.is_unconditional_jump(_insn("jr", "$t9", ("jump",))) is True
