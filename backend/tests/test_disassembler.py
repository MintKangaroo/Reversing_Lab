"""Disassembler and CFG tests."""

from __future__ import annotations

import pytest

from reversing_lab.disassembler import build_cfg, disassemble
from reversing_lab.errors import DisassemblyError
from reversing_lab.parser import parse_binary


def test_disassemble_entry(elf_bytes: bytes) -> None:
    info = parse_binary(elf_bytes)
    result = disassemble(info, elf_bytes, address=info.entry_point, count=10)
    assert result.instruction_count > 0
    first = result.instructions[0]
    # Fixture entry is `cmp edi, 0xa`.
    assert first.mnemonic == "cmp"
    assert "edi" in first.op_str


def test_disassemble_count_limit(elf_bytes: bytes) -> None:
    info = parse_binary(elf_bytes)
    result = disassemble(info, elf_bytes, count=2)
    assert result.instruction_count <= 2


def test_cfg_diamond(elf_bytes: bytes) -> None:
    info = parse_binary(elf_bytes)
    cfg = build_cfg(info, elf_bytes, address=info.entry_point)
    # cmp/jle -> two arms -> (arms end in ret) : the fixture yields a small graph with
    # a conditional branch producing two successors from the entry block.
    entry_block = cfg.blocks[0]
    assert len(entry_block.successors) == 2
    # Every edge references valid block ids.
    ids = {block.id for block in cfg.blocks}
    for src, dst in cfg.edges:
        assert src in ids and dst in ids


def test_cfg_does_not_bleed_into_next_function(elf_bytes: bytes) -> None:
    info = parse_binary(elf_bytes)
    cfg = build_cfg(info, elf_bytes, address=info.entry_point)
    # Both arms terminate in `ret`; no block should have zero instructions, and the
    # function-extent heuristic should keep the graph small (<= 4 blocks here).
    assert all(block.instructions for block in cfg.blocks)
    assert len(cfg.blocks) <= 4


def test_disassemble_unknown_arch_raises(elf_bytes: bytes) -> None:
    info = parse_binary(elf_bytes)
    from dataclasses import replace
    from reversing_lab.parser.models import Architecture

    broken = replace(info, architecture=Architecture.UNKNOWN, bits=0)
    with pytest.raises(DisassemblyError):
        disassemble(broken, elf_bytes)
