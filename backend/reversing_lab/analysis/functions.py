"""Bounded function discovery, xrefs, and direct-call graph recovery.

Function boundaries are not guaranteed to exist in stripped binaries. This module
therefore treats the entry point, verified function symbols, and in-image direct call
targets as candidates and labels the derived inventory as heuristic.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from ..config import get_settings
from ..disassembler.disassembler import Instruction, _resolve_engine
from ..errors import DisassemblyError
from ..parser.models import BinaryInfo, Section
from .models import (
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
    Evidence,
    FunctionAnalysis,
    ProvenanceKind,
)


@dataclass(frozen=True, slots=True)
class _Decoded:
    instruction: Instruction
    section: Section


def _direct_target(instruction: Instruction) -> int | None:
    operand = instruction.op_str.split(",", 1)[0].strip().lstrip("#")
    if not operand.startswith("0x"):
        return None
    try:
        return int(operand, 16)
    except ValueError:
        return None


def _contains(sections: tuple[Section, ...], address: int) -> bool:
    return any(
        section.contains_code
        and section.virtual_address <= address < section.virtual_address + section.size
        for section in sections
    )


def _decode_executable(info: BinaryInfo, data: bytes) -> tuple[list[_Decoded], bool]:
    settings = get_settings()
    engine = _resolve_engine(info)
    decoded: list[_Decoded] = []
    truncated = False

    for section in sorted(info.sections, key=lambda item: item.virtual_address):
        if not section.contains_code or section.size <= 0:
            continue
        start = max(section.offset, 0)
        end = min(len(data), section.offset + section.size)
        for insn in engine.disasm(data[start:end], section.virtual_address):
            if len(decoded) >= settings.max_function_scan_instructions:
                truncated = True
                return decoded, truncated
            decoded.append(
                _Decoded(
                    instruction=Instruction(
                        address=insn.address,
                        mnemonic=insn.mnemonic,
                        op_str=insn.op_str,
                        bytes_hex=insn.bytes.hex(),
                        size=insn.size,
                        groups=tuple(insn.group_name(group) for group in insn.groups),
                    ),
                    section=section,
                )
            )
    return decoded, truncated


def _function_symbols(info: BinaryInfo) -> dict[int, str]:
    return {
        symbol.value: symbol.name
        for symbol in info.symbols
        if symbol.kind in {"function", "ifunc"} and symbol.value > 0 and symbol.name
    }


def _stack_frame_size(instructions: list[Instruction]) -> int | None:
    """Recognize only an explicit `sub rsp/esp, immediate` stack allocation."""
    for instruction in instructions[:8]:
        if instruction.mnemonic != "sub":
            continue
        operands = [part.strip() for part in instruction.op_str.split(",")]
        if len(operands) != 2 or operands[0] not in {"rsp", "esp", "sp"}:
            continue
        try:
            return int(operands[1].lstrip("#"), 0)
        except ValueError:
            return None
    return None


def analyze_functions(info: BinaryInfo, data: bytes) -> tuple[FunctionAnalysis, ...]:
    """Recover a deterministic, bounded function inventory."""
    settings = get_settings()
    decoded, scan_truncated = _decode_executable(info, data)
    if not decoded:
        return ()

    symbols = _function_symbols(info)
    candidate_reasons: dict[int, str] = {}
    if _contains(info.sections, info.entry_point):
        candidate_reasons[info.entry_point] = "binary entry point"
    for address in symbols:
        if _contains(info.sections, address):
            candidate_reasons[address] = "function symbol"

    call_sites: dict[tuple[int, int], list[int]] = defaultdict(list)
    for item in decoded:
        instruction = item.instruction
        if "call" not in instruction.groups:
            continue
        target = _direct_target(instruction)
        if target is not None and _contains(info.sections, target):
            candidate_reasons.setdefault(target, "direct call target")

    candidates = sorted(candidate_reasons)[: settings.max_functions]
    inventory_truncated = scan_truncated or len(candidate_reasons) > len(candidates)
    if not candidates:
        return ()

    decoded_by_section: dict[int, list[Instruction]] = defaultdict(list)
    for item in decoded:
        decoded_by_section[item.section.virtual_address].append(item.instruction)

    function_bodies: dict[int, list[Instruction]] = {}
    for index, address in enumerate(candidates):
        section = next(
            section
            for section in info.sections
            if section.contains_code
            and section.virtual_address <= address < section.virtual_address + section.size
        )
        next_candidate = next(
            (
                other
                for other in candidates[index + 1 :]
                if section.virtual_address <= other < section.virtual_address + section.size
            ),
            section.virtual_address + section.size,
        )
        body = [
            instruction
            for instruction in decoded_by_section[section.virtual_address]
            if address <= instruction.address < next_candidate
        ][: settings.max_instructions_per_function]
        # Without a subsequent candidate, the first return is the safest conservative
        # boundary. Conditional branches may produce earlier returns, so keep decoding
        # through a return only when a known forward target still lies beyond it.
        max_forward = address
        bounded: list[Instruction] = []
        for instruction in body:
            bounded.append(instruction)
            if "jump" in instruction.groups:
                target = _direct_target(instruction)
                if target is not None:
                    max_forward = max(max_forward, target)
            if ("ret" in instruction.groups or "return" in instruction.groups) and (
                instruction.address + instruction.size > max_forward
            ):
                break
        function_bodies[address] = bounded

    callees: dict[int, set[int]] = defaultdict(set)
    callers: dict[int, set[int]] = defaultdict(set)
    for owner, body in function_bodies.items():
        for instruction in body:
            if "call" not in instruction.groups:
                continue
            target = _direct_target(instruction)
            if target in function_bodies:
                callees[owner].add(target)
                callers[target].add(owner)
                call_sites[(owner, target)].append(instruction.address)

    functions: list[FunctionAnalysis] = []
    for address in candidates:
        body = function_bodies[address]
        if not body:
            continue
        branch_count = sum(
            1
            for instruction in body
            if "jump" in instruction.groups and instruction.mnemonic not in {"jmp", "b", "br"}
        )
        block_starts = {address}
        for instruction in body:
            if "jump" in instruction.groups:
                target = _direct_target(instruction)
                if target is not None and address <= target < body[-1].address + body[-1].size:
                    block_starts.add(target)
                block_starts.add(instruction.address + instruction.size)
        reason = candidate_reasons[address]
        provenance = (
            ProvenanceKind.VERIFIED if reason == "function symbol" else ProvenanceKind.HEURISTIC
        )
        name = symbols.get(address) or ("entry" if address == info.entry_point else f"sub_{address:x}")
        functions.append(
            FunctionAnalysis(
                address=address,
                name=name,
                demangled_name=None,
                size=max(0, body[-1].address + body[-1].size - address),
                call_count=sum(len(call_sites[(caller, address)]) for caller in callers[address]),
                callers=tuple(sorted(callers[address])),
                callees=tuple(sorted(callees[address])),
                cyclomatic_complexity=max(1, branch_count + 1),
                basic_block_count=max(1, len(block_starts)),
                instruction_count=len(body),
                stack_frame_size=_stack_frame_size(body),
                return_type=None,
                is_thunk=len(body) <= 2
                and bool(body)
                and body[-1].mnemonic in {"jmp", "b", "br"},
                confidence=0.95 if provenance is ProvenanceKind.VERIFIED else 0.7,
                provenance=provenance,
                evidence=(
                    Evidence(
                        source="function-discovery",
                        address=address,
                        function_address=address,
                        message=f"Candidate created from {reason}.",
                        provenance=provenance,
                    ),
                ),
                truncated=inventory_truncated
                or len(body) >= settings.max_instructions_per_function,
            )
        )
    return tuple(functions)


def get_function(
    functions: tuple[FunctionAnalysis, ...], address: int
) -> FunctionAnalysis:
    """Return the exact function or the function containing `address`."""
    exact = next((function for function in functions if function.address == address), None)
    if exact is not None:
        return exact
    containing = next(
        (
            function
            for function in functions
            if function.address <= address < function.address + function.size
        ),
        None,
    )
    if containing is None:
        raise DisassemblyError(f"No recovered function contains address 0x{address:x}.")
    return containing


def build_call_graph(
    functions: tuple[FunctionAnalysis, ...],
    root_address: int | None = None,
    depth: int = 3,
) -> CallGraph:
    """Build a depth-bounded graph from recovered direct calls."""
    settings = get_settings()
    by_address = {function.address: function for function in functions}
    selected: set[int]
    truncated = False

    if root_address is None:
        selected = set(by_address)
    else:
        root = get_function(functions, root_address).address
        selected = {root}
        queue = deque([(root, 0)])
        while queue:
            current, current_depth = queue.popleft()
            if current_depth >= depth:
                continue
            for callee in by_address[current].callees:
                if callee in by_address and callee not in selected:
                    selected.add(callee)
                    queue.append((callee, current_depth + 1))

    ordered = sorted(selected)
    if len(ordered) > settings.max_call_graph_nodes:
        ordered = ordered[: settings.max_call_graph_nodes]
        selected = set(ordered)
        truncated = True

    nodes = tuple(
        CallGraphNode(
            address=address,
            name=by_address[address].user_name or by_address[address].name,
            is_library=by_address[address].is_library,
            is_entry=by_address[address].name == "entry",
            suspicious_score=by_address[address].suspicious_score,
            provenance=by_address[address].provenance,
        )
        for address in ordered
    )
    edges = tuple(
        CallGraphEdge(
            source=function.address,
            target=callee,
            recursive=function.address == callee,
        )
        for function in functions
        if function.address in selected
        for callee in function.callees
        if callee in selected
    )
    return CallGraph(
        nodes=nodes,
        edges=edges,
        root_address=root_address,
        truncated=truncated,
    )
