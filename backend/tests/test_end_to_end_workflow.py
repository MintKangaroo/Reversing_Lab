"""Safe end-to-end analyst workflow across the public API."""

from __future__ import annotations

from .fixtures import sample_elf


def test_safe_static_analysis_workflow(api_client) -> None:
    uploaded = api_client.post(
        "/api/binaries", files={"file": ("authorized-ctf.elf", sample_elf())}
    )
    assert uploaded.status_code == 201
    sha256 = uploaded.json()["sha256"]

    info = api_client.get(f"/api/binaries/{sha256}/info")
    assert info.status_code == 200
    assert info.json()["entry_point"] > 0

    inventory = api_client.get(f"/api/binaries/{sha256}/functions?limit=100")
    assert inventory.status_code == 200
    assert inventory.json()["items"]
    address = inventory.json()["items"][0]["address"]

    disassembly = api_client.get(
        f"/api/binaries/{sha256}/functions/{address}/disassembly"
    )
    assert disassembly.status_code == 200
    assert disassembly.json()["instructions"]

    decompiled = api_client.get(
        f"/api/binaries/{sha256}/functions/{address}/decompile"
        "?provider=pseudo_c"
    )
    assert decompiled.status_code == 200
    assert decompiled.json()["code"]
    assert decompiled.json()["provenance"] == "inferred"

    cfg = api_client.get(f"/api/binaries/{sha256}/functions/{address}/cfg")
    assert cfg.status_code == 200
    assert cfg.json()["blocks"]
    callgraph = api_client.get(f"/api/binaries/{sha256}/callgraph")
    assert callgraph.status_code == 200
    assert callgraph.json()["nodes"]

    findings = api_client.get(f"/api/binaries/{sha256}/findings")
    assert findings.status_code == 200
    assert isinstance(findings.json(), list)

    annotation = api_client.post(
        f"/api/binaries/{sha256}/annotations",
        json={
            "address": address,
            "kind": "comment",
            "value": "Reviewed against the safe generated fixture.",
        },
    )
    assert annotation.status_code == 200
    assert annotation.json()["value"].startswith("Reviewed")

    report = api_client.get(
        f"/api/binaries/{sha256}/report?format=markdown"
    )
    assert report.status_code == 200
    assert "Reviewed against the safe generated fixture." in report.text
    assert "## 16. Recommended Next Steps" in report.text
