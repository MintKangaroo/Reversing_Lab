"""Prometheus metrics endpoint and the in-process registry."""

from __future__ import annotations

from reversing_lab import metrics


def test_metrics_endpoint_exposes_request_and_job_series(api_client) -> None:
    metrics.reset()
    api_client.get("/api/health")

    response = api_client.get("/api/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "version=0.0.4" in response.headers["content-type"]

    body = response.text
    assert "# TYPE rlab_http_requests_total counter" in body
    assert 'rlab_http_requests_total{method="GET",route="/api/health",status="200"}' in body
    assert "# TYPE rlab_http_request_duration_seconds histogram" in body
    assert 'le="+Inf"' in body
    assert "rlab_http_request_duration_seconds_sum" in body
    assert "rlab_http_request_duration_seconds_count" in body
    assert "# TYPE rlab_active_jobs gauge" in body
    assert "rlab_active_jobs 0" in body
    assert "rlab_max_concurrent_jobs" in body


def test_metrics_can_be_disabled(api_client, monkeypatch) -> None:
    from reversing_lab import config

    monkeypatch.setenv("RLAB_METRICS_ENABLED", "false")
    config.get_settings.cache_clear()
    try:
        response = api_client.get("/api/metrics")
        assert response.status_code == 404
    finally:
        config.get_settings.cache_clear()


def test_registry_histogram_is_cumulative_with_sum_and_count() -> None:
    metrics.reset()
    metrics.record_request("GET", "/api/x", 200, 0.001)
    metrics.record_request("GET", "/api/x", 200, 0.2)

    rendered = metrics.render(active_jobs=0, max_jobs=2)
    lines = rendered.splitlines()

    def value(prefix: str) -> float:
        for line in lines:
            if line.startswith(prefix):
                return float(line.rsplit(" ", 1)[1])
        raise AssertionError(f"missing series: {prefix}")

    # 0.001s falls in the first bucket; both requests are under the +Inf bucket.
    assert value('rlab_http_request_duration_seconds_bucket{method="GET",route="/api/x",le="0.005"}') == 1
    assert value('rlab_http_request_duration_seconds_bucket{method="GET",route="/api/x",le="+Inf"}') == 2
    assert value('rlab_http_request_duration_seconds_count{method="GET",route="/api/x"}') == 2
    assert abs(value('rlab_http_request_duration_seconds_sum{method="GET",route="/api/x"}') - 0.201) < 1e-9


def test_metrics_is_public_when_auth_enabled(tmp_path, monkeypatch) -> None:
    import hashlib

    from fastapi.testclient import TestClient

    from reversing_lab import config
    from reversing_lab.api import services
    from reversing_lab.database import session as db_session

    digest = hashlib.sha256(b"secret-key").hexdigest()
    monkeypatch.setenv("RLAB_DATABASE_URL", f"sqlite:///{tmp_path / 'auth.db'}")
    monkeypatch.setenv("RLAB_STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("RLAB_AUTH_MODE", "api_key")
    monkeypatch.setenv("RLAB_AUTH_API_KEY_HASHES", f'{{"{digest}":"a:analyst"}}')
    config.get_settings.cache_clear()
    db_session._engine = None
    db_session._SessionFactory = None
    services.clear_cache()

    from reversing_lab.api.app import create_app

    try:
        with TestClient(create_app()) as client:
            # No Authorization header — still reachable, like /api/health.
            assert client.get("/api/metrics").status_code == 200
            assert client.get("/api/health/ready").status_code == 200
    finally:
        config.get_settings.cache_clear()
        db_session._engine = None
        db_session._SessionFactory = None
