"""Control-flow-graph construction from a linear disassembly.

The classic three-step basic-block algorithm:

1. Disassemble the region linearly (bounded by ``settings.max_cfg_instructions``).
2. Compute *leaders* — the first instruction, every branch target, and every
   instruction that follows a branch/return.
3. Slice the instruction stream at leaders into basic blocks and connect them with
   fall-through and branch edges.

Only direct branches (with an immediate target the disassembler prints as ``0x...``)
produce edges; indirect branches (``jmp rax``) have no statically known target and are
recorded as block terminators without an outgoing edge.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import get_settings
from ..parser.models import BinaryInfo
from .disassembler import Instruction, _resolve_engine, _code_section

# Unconditional branch mnemonics across the architectures we support.
_UNCONDITIONAL = {"jmp", "b", "bal"}


@dataclass(frozen=True, slots=True)
class BasicBlock:
    """A maximal straight-line instruction sequence with a single entry/exit."""

    id: int
    start_address: int
    end_address: int  # address just past the last instruction
    instructions: tuple[Instruction, ...]
    successors: tuple[int, ...]  # ids of successor blocks


@dataclass(frozen=True, slots=True)
class ControlFlowGraph:
    """A function/region's basic blocks and the edges between them."""

    entry_address: int
    blocks: tuple[BasicBlock, ...]
    edges: tuple[tuple[int, int], ...]  # (from_block_id, to_block_id)
    truncated: bool


def _branch_target(insn: Instruction) -> int | None:
    """Return the immediate target of a direct branch, or ``None`` if not static."""
    operand = insn.op_str.strip()
    if operand.startswith("0x"):
        try:
            return int(operand, 16)
        except ValueError:
            return None
    return None


def _is_jump(insn: Instruction) -> bool:
    return "jump" in insn.groups


def _is_return(insn: Instruction) -> bool:
    return "ret" in insn.groups or "return" in insn.groups


def build_cfg(info: BinaryInfo, data: bytes, address: int | None = None) -> ControlFlowGraph:
    """Build the control-flow graph for the code region starting at ``address``.

    Defaults to the region beginning at the entry point. The instruction budget is
    bounded by ``settings.max_cfg_instructions``.
    """
    settings = get_settings()
    engine = _resolve_engine(info)
    section = _code_section(info, address)

    start = address if address is not None else max(info.entry_point, section.virtual_address)
    if not (section.virtual_address <= start < section.virtual_address + section.size):
        start = section.virtual_address

    file_start = section.offset + (start - section.virtual_address)
    code = data[file_start : section.offset + section.size]

    # Step 1: linear disassembly, bounded and scoped to a single function.
    # We stop at the first terminator (ret / unconditional jump) that lies at or
    # beyond every forward branch target seen so far — i.e. once no in-function code
    # path can still reach past it. This keeps the CFG from bleeding into the next
    # function while remaining purely static (no symbol boundaries required).
    instructions: list[Instruction] = []
    truncated = False
    max_forward_target = start
    for insn in engine.disasm(code, start):
        if len(instructions) >= settings.max_cfg_instructions:
            truncated = True
            break
        model = Instruction(
            address=insn.address,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            bytes_hex=insn.bytes.hex(),
            size=insn.size,
            groups=tuple(insn.group_name(g) for g in insn.groups),
        )
        instructions.append(model)

        if _is_jump(model):
            target = _branch_target(model)
            if target is not None and target > max_forward_target:
                max_forward_target = target

        next_address = model.address + model.size
        terminates = _is_return(model) or (
            _is_jump(model) and model.mnemonic in _UNCONDITIONAL
        )
        if terminates and next_address > max_forward_target:
            break

    if not instructions:
        return ControlFlowGraph(entry_address=start, blocks=(), edges=(), truncated=truncated)

    addresses = {insn.address for insn in instructions}
    lowest = instructions[0].address
    highest = instructions[-1].address + instructions[-1].size

    # Step 2: compute leaders.
    leaders: set[int] = {instructions[0].address}
    for index, insn in enumerate(instructions):
        next_address = insn.address + insn.size
        if _is_jump(insn):
            target = _branch_target(insn)
            if target is not None and lowest <= target < highest and target in addresses:
                leaders.add(target)
            # The instruction after any branch starts a new block (fall-through path).
            if next_address in addresses:
                leaders.add(next_address)
        elif _is_return(insn):
            if next_address in addresses:
                leaders.add(next_address)

    # Step 3: slice into blocks.
    sorted_leaders = sorted(leaders)
    leader_to_id = {addr: idx for idx, addr in enumerate(sorted_leaders)}
    block_instructions: dict[int, list[Instruction]] = {addr: [] for addr in sorted_leaders}

    current = sorted_leaders[0]
    for insn in instructions:
        if insn.address in leader_to_id:
            current = insn.address
        block_instructions[current].append(insn)

    blocks: list[BasicBlock] = []
    edges: list[tuple[int, int]] = []
    for addr in sorted_leaders:
        body = block_instructions[addr]
        if not body:
            continue
        block_id = leader_to_id[addr]
        last = body[-1]
        successors: list[int] = []

        if _is_return(last):
            pass  # No successors: control leaves the region.
        elif _is_jump(last):
            target = _branch_target(last)
            if target is not None and target in leader_to_id:
                successors.append(leader_to_id[target])
            if last.mnemonic not in _UNCONDITIONAL:
                # Conditional branch also falls through to the next block.
                fall = last.address + last.size
                if fall in leader_to_id:
                    successors.append(leader_to_id[fall])
        else:
            fall = last.address + last.size
            if fall in leader_to_id:
                successors.append(leader_to_id[fall])

        # De-duplicate while preserving order.
        seen: set[int] = set()
        ordered_successors = tuple(s for s in successors if not (s in seen or seen.add(s)))
        for succ in ordered_successors:
            edges.append((block_id, succ))

        blocks.append(
            BasicBlock(
                id=block_id,
                start_address=addr,
                end_address=body[-1].address + body[-1].size,
                instructions=tuple(body),
                successors=ordered_successors,
            )
        )

    return ControlFlowGraph(
        entry_address=start,
        blocks=tuple(blocks),
        edges=tuple(edges),
        truncated=truncated,
    )
