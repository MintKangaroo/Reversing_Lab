"""Capstone-backed disassembler.

Turns a code region of a parsed binary into a list of normalized
:class:`Instruction` records. Architecture/mode are resolved from the binary's
:class:`~reversing_lab.parser.models.BinaryInfo`, and the instruction count is bounded
by settings to keep adversarial inputs from exhausting CPU or memory.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import capstone as cs

from ..config import get_settings
from ..errors import DisassemblyError
from ..parser.models import Architecture, BinaryInfo, Section

logger = logging.getLogger(__name__)

# (Architecture, bits) -> (capstone arch, capstone base mode).
_CS_ARCH: dict[tuple[Architecture, int], tuple[int, int]] = {
    (Architecture.X86, 32): (cs.CS_ARCH_X86, cs.CS_MODE_32),
    (Architecture.X86_64, 64): (cs.CS_ARCH_X86, cs.CS_MODE_64),
    (Architecture.ARM, 32): (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
    (Architecture.ARM64, 64): (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
    (Architecture.MIPS, 32): (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32),
    (Architecture.PPC, 32): (cs.CS_ARCH_PPC, cs.CS_MODE_32),
}


@dataclass(frozen=True, slots=True)
class Instruction:
    """A single decoded instruction."""

    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    size: int
    groups: tuple[str, ...] = field(default_factory=tuple)

    @property
    def text(self) -> str:
        """Human-readable ``mnemonic op_str`` rendering."""
        return f"{self.mnemonic} {self.op_str}".strip()


@dataclass(frozen=True, slots=True)
class DisassemblyResult:
    """Disassembly of one code region."""

    start_address: int
    instruction_count: int
    truncated: bool
    instructions: tuple[Instruction, ...]


def _resolve_engine(info: BinaryInfo) -> cs.Cs:
    """Construct a configured Capstone engine for ``info`` or raise ``DisassemblyError``."""
    try:
        arch, mode = _CS_ARCH[(info.architecture, info.bits)]
    except KeyError as exc:
        raise DisassemblyError(
            f"Disassembly is not supported for {info.architecture.value}/{info.bits}-bit."
        ) from exc

    if info.endianness == "big":
        mode |= cs.CS_MODE_BIG_ENDIAN

    engine = cs.Cs(arch, mode)
    engine.detail = True  # Needed for control-flow group classification (CFG).
    engine.skipdata = True  # Never abort on undecodable bytes; emit a placeholder instead.
    return engine


def _code_section(info: BinaryInfo, address: int | None) -> Section:
    """Pick the section to disassemble: the one containing ``address`` else the entry's."""
    target = address if address is not None else info.entry_point
    for section in info.sections:
        if section.contains_code and section.virtual_address <= target < section.virtual_address + section.size:
            return section

    code_sections = [s for s in info.sections if s.contains_code and s.size > 0]
    if not code_sections:
        raise DisassemblyError("No executable section found to disassemble.")
    # Fall back to the first (typically .text / __text) executable section.
    return code_sections[0]


def disassemble(
    info: BinaryInfo,
    data: bytes,
    address: int | None = None,
    count: int | None = None,
) -> DisassemblyResult:
    """Disassemble a code region of ``data``.

    ``address`` selects the starting virtual address (defaults to the entry point);
    disassembly proceeds to the end of the containing executable section or until
    ``count`` instructions are produced, whichever comes first. The result is capped by
    ``settings.max_disassembly_instructions``.
    """
    settings = get_settings()
    engine = _resolve_engine(info)
    section = _code_section(info, address)

    start = address if address is not None else max(info.entry_point, section.virtual_address)
    if not (section.virtual_address <= start < section.virtual_address + section.size):
        start = section.virtual_address

    file_start = section.offset + (start - section.virtual_address)
    file_end = section.offset + section.size
    code = data[file_start:file_end]
    if not code:
        raise DisassemblyError("Selected code region is empty.")

    limit = settings.max_disassembly_instructions
    if count is not None:
        limit = min(limit, max(count, 0))

    instructions: list[Instruction] = []
    for insn in engine.disasm(code, start):
        if len(instructions) >= limit:
            break
        instructions.append(
            Instruction(
                address=insn.address,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes_hex=insn.bytes.hex(),
                size=insn.size,
                groups=tuple(insn.group_name(g) for g in insn.groups),
            )
        )

    truncated = len(instructions) >= limit
    return DisassemblyResult(
        start_address=start,
        instruction_count=len(instructions),
        truncated=truncated,
        instructions=tuple(instructions),
    )
