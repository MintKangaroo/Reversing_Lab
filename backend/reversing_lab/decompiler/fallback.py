"""Conservative, architecture-light pseudo-C generation.

The generator translates only simple, recognizable instruction shapes. Unknown
operations remain address-linked comments instead of invented source semantics.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from ..analysis import analyze_functions, get_function
from ..analysis.models import ProvenanceKind
from ..disassembler import disassemble
from ..parser import parse_binary
from .base import (
    DecompileOptions,
    DecompiledFunction,
    DecompiledParameter,
    DecompiledVariable,
    SourceMapEntry,
)

_ARG_REGISTERS = {
    "rdi": "arg0",
    "edi": "arg0",
    "rcx": "arg0",
    "ecx": "arg0",
    "rsi": "arg1",
    "esi": "arg1",
    "rdx": "arg2",
    "edx": "arg2",
    "r8": "arg3",
    "r8d": "arg3",
    "r9": "arg4",
    "r9d": "arg4",
}
_RETURN_REGISTERS = {"rax", "eax", "x0", "r0"}
_CONDITIONS = {
    "je": "==",
    "jz": "==",
    "jne": "!=",
    "jnz": "!=",
    "jg": ">",
    "jnle": ">",
    "jge": ">=",
    "jnl": ">=",
    "jl": "<",
    "jnge": "<",
    "jle": "<=",
    "jng": "<=",
    "ja": ">",
    "jae": ">=",
    "jb": "<",
    "jbe": "<=",
}


def _operand_name(operand: str) -> str:
    cleaned = operand.strip().replace(" ", "")
    if cleaned in _ARG_REGISTERS:
        return _ARG_REGISTERS[cleaned]
    if cleaned in _RETURN_REGISTERS:
        return "result"
    if re.fullmatch(r"[re]?[abcds][xiplh]|r(?:1[0-5]|[0-9])[dwb]?", cleaned):
        return f"reg_{cleaned}"
    return cleaned


def _integer(value: str) -> str | None:
    candidate = value.strip().lstrip("#")
    try:
        parsed = int(candidate, 0)
    except ValueError:
        return None
    return hex(parsed) if parsed >= 10 else str(parsed)


class FallbackPseudoCAdapter:
    name = "pseudo_c"

    def is_available(self) -> bool:
        return True

    def decompile_function(
        self, binary_path: Path, address: int, options: DecompileOptions
    ) -> DecompiledFunction:
        started = time.monotonic()
        data = binary_path.read_bytes()
        info = parse_binary(data)
        functions = analyze_functions(info, data)
        function = get_function(functions, address)
        result = disassemble(
            info,
            data,
            address=function.address,
            count=max(function.instruction_count, 1),
        )

        referenced_args: set[str] = set()
        variables: dict[str, DecompiledVariable] = {}
        body: list[tuple[str, int, float]] = []
        labels = {
            target
            for instruction in result.instructions
            if "jump" in instruction.groups
            for target in [_integer(instruction.op_str)]
            if target is not None
        }
        previous_compare: tuple[str, str] | None = None

        for instruction in result.instructions:
            address_label = hex(instruction.address)
            if address_label in labels:
                body.append((f"label_{instruction.address:x}:", instruction.address, 0.9))

            operands = [part.strip() for part in instruction.op_str.split(",") if part.strip()]
            for operand in operands:
                register = operand.replace(" ", "")
                if register in _ARG_REGISTERS:
                    referenced_args.add(_ARG_REGISTERS[register])

            if instruction.mnemonic in {"push", "pop", "leave", "endbr64", "nop"}:
                body.append((f"/* {instruction.text} */", instruction.address, 0.95))
            elif (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and operands[0] in {"rbp", "ebp"}
                and operands[1] in {"rsp", "esp"}
            ):
                body.append(("/* establish stack frame */", instruction.address, 0.98))
            elif instruction.mnemonic == "sub" and len(operands) == 2 and operands[0] in {"rsp", "esp"}:
                size = _integer(operands[1])
                if size is not None:
                    variable = DecompiledVariable(
                        name="local_frame",
                        type_name=None,
                        storage=f"stack[{size}]",
                        confidence=0.8,
                        provenance=ProvenanceKind.INFERRED,
                    )
                    variables[variable.name] = variable
                    body.append((f"/* reserve {size} bytes for stack locals */", instruction.address, 0.8))
                else:
                    body.append((f"/* {instruction.text} */", instruction.address, 0.5))
            elif instruction.mnemonic in {"cmp", "test"} and len(operands) == 2:
                previous_compare = (_operand_name(operands[0]), _operand_name(operands[1]))
                body.append((f"/* flags = {previous_compare[0]} ? {previous_compare[1]} */", instruction.address, 0.75))
            elif instruction.mnemonic in _CONDITIONS:
                target = _integer(instruction.op_str)
                if target is not None:
                    condition = (
                        f"{previous_compare[0]} {_CONDITIONS[instruction.mnemonic]} "
                        f"{previous_compare[1]}"
                        if previous_compare
                        else "/* inferred condition */"
                    )
                    body.append((f"if ({condition}) goto label_{int(target, 0):x};", instruction.address, 0.7))
                else:
                    body.append((f"/* indirect conditional branch: {instruction.text} */", instruction.address, 0.4))
            elif instruction.mnemonic in {"jmp", "b"}:
                target = _integer(instruction.op_str)
                if target is not None:
                    destination = int(target, 0)
                    prefix = "/* loop candidate */ " if destination <= instruction.address else ""
                    body.append((f"{prefix}goto label_{destination:x};", instruction.address, 0.75))
                else:
                    body.append((f"/* indirect branch candidate: {instruction.text} */", instruction.address, 0.4))
            elif "call" in instruction.groups:
                target = _integer(instruction.op_str)
                callee = f"sub_{int(target, 0):x}" if target is not None else "indirect_call"
                body.append((f"{callee}();", instruction.address, 0.78 if target else 0.35))
            elif instruction.mnemonic in {"xor", "add", "sub", "rol", "ror"} and len(operands) == 2:
                operator = {"xor": "^=", "add": "+=", "sub": "-=", "rol": "/* rol */", "ror": "/* ror */"}[instruction.mnemonic]
                left, right = _operand_name(operands[0]), _operand_name(operands[1])
                if instruction.mnemonic in {"rol", "ror"}:
                    body.append((f"{operator} {left}, {right};", instruction.address, 0.55))
                else:
                    body.append((f"{left} {operator} {right};", instruction.address, 0.72))
            elif instruction.mnemonic == "mov" and len(operands) == 2:
                left, right = _operand_name(operands[0]), _operand_name(operands[1])
                body.append((f"{left} = {right};", instruction.address, 0.65))
            elif "ret" in instruction.groups or "return" in instruction.groups:
                body.append(("return result; /* return register value inferred */", instruction.address, 0.62))
            else:
                body.append((f"/* {instruction.text} */", instruction.address, 0.35))

        parameters = tuple(
            DecompiledParameter(
                name=name,
                type_name=None,
                storage="calling-convention register",
                confidence=0.55,
                provenance=ProvenanceKind.INFERRED,
            )
            for name in sorted(referenced_args)
        )
        parameter_text = ", ".join(f"uintptr_t /* inferred */ {item.name}" for item in parameters)
        lines = [
            "/* Estimated pseudo-C. This is not the original source code. */",
            f"uintptr_t /* inferred */ {function.name}({parameter_text or 'void'}) {{",
        ]
        source_map: list[SourceMapEntry] = []
        for text, instruction_address, confidence in body:
            lines.append(f"    {text}" if not text.startswith("label_") else text)
            source_map.append(
                SourceMapEntry(
                    line=len(lines),
                    address_start=instruction_address,
                    address_end=instruction_address
                    + next(
                        item.size
                        for item in result.instructions
                        if item.address == instruction_address
                    ),
                    confidence=confidence,
                    provenance=ProvenanceKind.INFERRED,
                )
            )
        lines.append("}")

        return DecompiledFunction(
            function_address=function.address,
            function_name=function.name,
            language="C-like",
            code="\n".join(lines),
            warnings=(
                "Fallback pseudo-C is a conservative instruction translation, not recovered original source.",
                "Types, variables, conditions, and function boundaries are inferred and may be incorrect.",
            ),
            confidence=0.48,
            variables=tuple(variables.values()),
            parameters=parameters,
            return_type=None,
            source_map=tuple(source_map),
            provider=self.name,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )
