"""Function discovery and direct call graph fixtures."""

from __future__ import annotations

import pytest

from reversing_lab.analysis import analyze_functions, build_call_graph, get_function
from reversing_lab.challenge.elfbuilder import build_elf64
from reversing_lab.errors import DisassemblyError
from reversing_lab.parser import parse_binary


@pytest.fixture()
def call_fixture() -> bytes:
    # entry @ 0x401000: call 0x401006; ret
    # sub_401006: ret
    return build_elf64(code=bytes.fromhex("e801000000c3c3"))


def test_discovers_entry_and_direct_call_target(call_fixture: bytes) -> None:
    info = parse_binary(call_fixture)
    functions = analyze_functions(info, call_fixture)
    assert [function.address for function in functions] == [0x401000, 0x401006]
    assert functions[0].name == "entry"
    assert functions[0].callees == (0x401006,)
    assert functions[1].callers == (0x401000,)
    assert functions[1].call_count == 1


def test_call_graph_has_static_edge(call_fixture: bytes) -> None:
    info = parse_binary(call_fixture)
    graph = build_call_graph(analyze_functions(info, call_fixture))
    assert {node.address for node in graph.nodes} == {0x401000, 0x401006}
    assert [(edge.source, edge.target, edge.kind) for edge in graph.edges] == [
        (0x401000, 0x401006, "static")
    ]


def test_get_function_accepts_contained_address(call_fixture: bytes) -> None:
    info = parse_binary(call_fixture)
    functions = analyze_functions(info, call_fixture)
    assert get_function(functions, 0x401002).address == 0x401000
    with pytest.raises(DisassemblyError):
        get_function(functions, 0xDEADBEEF)
