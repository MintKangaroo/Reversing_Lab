"""JSON, Markdown, and escaped HTML report contracts."""

from __future__ import annotations

from .fixtures import sample_elf


def test_report_exports_all_required_sections(api_client) -> None:
    uploaded = api_client.post(
        "/api/binaries", files={"file": ("report.elf", sample_elf())}
    ).json()
    sha256 = uploaded["sha256"]
    api_client.post(
        f"/api/binaries/{sha256}/annotations",
        json={
            "address": 0x401000,
            "kind": "comment",
            "value": "<script>alert('report')</script>",
        },
    )

    response = api_client.get(f"/api/binaries/{sha256}/report?format=json")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "1.0"
    assert body["hashes"]["sha256"] == sha256
    assert body["sample_metadata"]["entry_point_hex"].startswith("0x")
    assert body["decompiled_snippets"][0]["provider"] == "pseudo_c"
    assert body["dynamic_timeline"]["status"] == "not_linked"
    assert body["memory_findings"]["status"] == "not_linked"
    assert len(body) == 18

    markdown = api_client.get(
        f"/api/binaries/{sha256}/report?format=markdown"
    )
    assert markdown.status_code == 200
    assert "## 16. Recommended Next Steps" in markdown.text
    assert "not recovered original source code" in markdown.text

    html = api_client.get(f"/api/binaries/{sha256}/report?format=html")
    assert html.status_code == 200
    assert "<!doctype html>" in html.text
    assert "<script>alert" not in html.text
    assert "&lt;script&gt;alert" in html.text


def test_report_format_is_allowlisted(api_client) -> None:
    sha256 = api_client.post(
        "/api/binaries", files={"file": ("report.elf", sample_elf())}
    ).json()["sha256"]
    response = api_client.get(
        f"/api/binaries/{sha256}/report?format=../../etc/passwd"
    )
    assert response.status_code == 422
