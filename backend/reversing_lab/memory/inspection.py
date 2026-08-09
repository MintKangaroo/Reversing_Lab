"""Bounded Capstone disassembly for explicitly extracted memory-region bytes."""

from __future__ import annotations

from dataclasses import dataclass, field

import capstone as cs

from ..config import get_settings
from ..errors import DisassemblyError

_ENGINES: dict[str, tuple[int, int]] = {
    "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
    "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
}


@dataclass(frozen=True, slots=True)
class RegionInstruction:
    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    size: int
    groups: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class RegionDisassembly:
    start_address: int
    architecture: str
    instruction_count: int
    truncated: bool
    instructions: tuple[RegionInstruction, ...]


def disassemble_region(
    data: bytes,
    *,
    base_address: int,
    architecture: str,
    offset: int = 0,
    count: int = 200,
) -> RegionDisassembly:
    if architecture not in _ENGINES:
        raise DisassemblyError(
            f"Memory-region disassembly is not supported for {architecture!r}."
        )
    if offset < 0 or offset > len(data):
        raise DisassemblyError("Memory-region offset is outside the artifact.")
    if count < 1:
        raise DisassemblyError("Instruction count must be positive.")
    limit = min(count, get_settings().max_disassembly_instructions)
    capstone_arch, mode = _ENGINES[architecture]
    engine = cs.Cs(capstone_arch, mode)
    engine.detail = True
    engine.skipdata = True
    start_address = base_address + offset
    instructions: list[RegionInstruction] = []
    for instruction in engine.disasm(data[offset:], start_address):
        if len(instructions) >= limit:
            break
        instructions.append(
            RegionInstruction(
                address=instruction.address,
                mnemonic=instruction.mnemonic,
                op_str=instruction.op_str,
                bytes_hex=instruction.bytes.hex(),
                size=instruction.size,
                groups=tuple(instruction.group_name(group) for group in instruction.groups),
            )
        )
    consumed = sum(instruction.size for instruction in instructions)
    return RegionDisassembly(
        start_address=start_address,
        architecture=architecture,
        instruction_count=len(instructions),
        truncated=bool(instructions) and offset + consumed < len(data) and len(instructions) >= limit,
        instructions=tuple(instructions),
    )
