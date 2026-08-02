"""Sandbox readiness, disabled defaults, mock provider, and event pagination."""

from __future__ import annotations

import time

from reversing_lab.dynamic import MockSandboxProvider, SandboxReadiness

from .fixtures import sample_elf


def _upload(client) -> str:
    response = client.post(
        "/api/binaries", files={"file": ("authorized.elf", sample_elf())}
    )
    return response.json()["sha256"]


def _wait(client, run_id: str, timeout: float = 4.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/dynamic-analysis/{run_id}").json()
        if body["job"]["state"] in {"completed", "failed", "cancelled"}:
            return body
        time.sleep(0.03)
    raise AssertionError("dynamic job did not finish")


def test_dynamic_analysis_is_disabled_by_default(api_client) -> None:
    sha256 = _upload(api_client)
    readiness = api_client.get(
        f"/api/dynamic-analysis/readiness?binary_sha256={sha256}"
    )
    assert readiness.status_code == 200
    body = readiness.json()
    assert body["ready"] is False
    assert body["provider_configured"] is False
    assert body["isolated_worker_available"] is False
    assert "Docker alone" in body["warning"]

    blocked = api_client.post(
        "/api/dynamic-analysis",
        json={"binary_sha256": sha256, "acknowledged": True},
    )
    assert blocked.status_code == 409
    assert blocked.json()["detail"]["reasons"]


def test_mock_provider_never_executes_and_returns_control_event(
    api_client, monkeypatch
) -> None:
    from reversing_lab.api.routes import dynamic

    class ReadyMock(MockSandboxProvider):
        def readiness(self, *, sample_path_validated, user_acknowledged):
            reasons = () if sample_path_validated and user_acknowledged else ("not ready",)
            return SandboxReadiness(
                provider="mock",
                provider_configured=True,
                isolated_worker_available=True,
                resource_limits_configured=True,
                timeout_configured=True,
                network_policy_configured=True,
                writable_workspace_configured=True,
                sample_path_validated=sample_path_validated,
                user_acknowledged=user_acknowledged,
                ready=not reasons,
                reasons=reasons,
                warning="Mock provider never executes samples.",
            )

    monkeypatch.setattr(dynamic, "get_sandbox_provider", lambda: ReadyMock())
    sha256 = _upload(api_client)
    started = api_client.post(
        "/api/dynamic-analysis",
        json={"binary_sha256": sha256, "acknowledged": True},
    )
    assert started.status_code == 202, started.text
    run_id = started.json()["id"]
    completed = _wait(api_client, run_id)
    assert completed["job"]["state"] == "completed", completed
    assert completed["policy"]["network"] == "blocked"
    assert completed["policy"]["privileged"] is False
    assert completed["policy"]["host_mounts"] is False
    assert completed["policy"]["docker_socket"] is False

    events = api_client.get(
        f"/api/dynamic-analysis/{run_id}/events?event_type=analysis_control"
    )
    assert events.status_code == 200, events.text
    body = events.json()
    assert body["items"][0]["operation"] == "mock_no_execution"
    assert body["items"][0]["result"] == "not_executed"
    assert "process creation" in body["unavailable_events"]
    assert api_client.get(
        f"/api/dynamic-analysis/{run_id}/artifacts"
    ).json() == []


def test_dynamic_request_requires_explicit_ack(api_client) -> None:
    sha256 = _upload(api_client)
    response = api_client.post(
        "/api/dynamic-analysis",
        json={"binary_sha256": sha256, "acknowledged": False},
    )
    assert response.status_code == 422
