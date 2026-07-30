"""Typed CFG metadata and evidence-linked program flow summary."""

from __future__ import annotations

from reversing_lab.analysis import summarize_program_flow
from reversing_lab.challenge.elfbuilder import build_elf64
from reversing_lab.disassembler import build_cfg
from reversing_lab.parser import parse_binary


def _loop_fixture() -> bytes:
    # inc eax; cmp eax, 3; jl 0x401000; ret
    return build_elf64(
        code=bytes.fromhex("ffc083f8037cf9c3"),
        rodata=b"invalid input\x00",
    )


def test_cfg_has_typed_edges_loop_and_dominator() -> None:
    data = _loop_fixture()
    cfg = build_cfg(parse_binary(data), data)
    assert cfg.loop_headers == (0,)
    assert cfg.blocks[0].is_loop_header is True
    assert cfg.blocks[1].immediate_dominator == 0
    kinds = {edge.kind for edge in cfg.typed_edges}
    assert {"conditional", "fallthrough", "return"} <= kinds
    assert cfg.unreachable_blocks == ()


def test_flow_summary_links_addresses_and_limitations() -> None:
    data = _loop_fixture()
    info = parse_binary(data)
    summary = summarize_program_flow(info, data)
    assert summary.entry_point == 0x401000
    assert summary.stages[0].title == "Entry Point"
    assert summary.stages[0].evidence[0].address == 0x401000
    assert any(stage.id == "validation" for stage in summary.stages)
    assert summary.major_branches
    assert summary.failure_paths
    assert summary.limitations


def test_flow_summary_api(api_client) -> None:
    upload = api_client.post(
        "/api/binaries", files={"file": ("loop.elf", _loop_fixture())}
    )
    sha256 = upload.json()["sha256"]
    response = api_client.get(f"/api/binaries/{sha256}/flow-summary")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["entry_point"] == 0x401000
    assert body["stages"][0]["evidence"][0]["provenance"] == "verified"
    cfg = api_client.get(f"/api/binaries/{sha256}/cfg").json()
    assert cfg["typed_edges"]
    assert cfg["loop_headers"] == [0]
