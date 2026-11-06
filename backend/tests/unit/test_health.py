import logging

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.logging import JsonLogFormatter
from app.main import create_app


def test_liveness_response_uses_standard_envelope(tmp_path) -> None:
    app = create_app()
    app.state.settings.log_dir = tmp_path
    client = TestClient(app)

    response = client.get(
        "/api/v1/health/live",
        headers={"X-Request-ID": "test-request-id"},
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "test-request-id"
    payload = response.json()
    assert payload["success"] is True
    assert payload["message"] == "Service is live"
    assert payload["request_id"] == "test-request-id"
    assert payload["data"]["service"] == "cloudguest-backend"


def test_unknown_route_uses_standard_error_envelope() -> None:
    client = TestClient(create_app())

    response = client.get("/missing")

    assert response.status_code == 404
    payload = response.json()
    assert payload["success"] is False
    assert payload["message"] == "Not Found"
    assert payload["data"] == {}
    assert payload["request_id"]



class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_production_on_default_secrets_still_boots_and_says_so(tmp_path) -> None:
    """The api container boots through Settings after running migrations. A
    guard that raised here would crash-loop a deploy whose .env nobody has
    checked -- so it must log, and the app must still come up."""
    app = create_app(Settings(environment="production", log_dir=tmp_path))
    # create_app's configure_logging replaces the root handlers (pytest's
    # caplog included), so listen on the module logger directly.
    handler = _ListHandler()
    main_logger = logging.getLogger("app.main")
    main_logger.addHandler(handler)
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/health/live")
    finally:
        main_logger.removeHandler(handler)

    assert response.status_code == 200
    critical = [
        r
        for r in handler.records
        if r.levelno == logging.CRITICAL
        and r.getMessage() == "secret_at_public_default"
    ]
    assert {r.env_var for r in critical} == {
        "CLOUDGUEST_JWT_SECRET_KEY",
        "CLOUDGUEST_ROUTER_ENCRYPTION_KEY",
        "CLOUDGUEST_NETWORK_INTEGRATION_ENCRYPTION_KEY",
        "CLOUDGUEST_MFA_ENCRYPTION_KEY",
    }
    for record in critical:
        assert "aW5zZWN1cmU" not in JsonLogFormatter().format(record)
    # Strict mode is off by default, and unset payment webhook secrets
    # (their endpoints refuse every event) are named at startup too.
    warnings = {
        r.getMessage() for r in handler.records if r.levelno == logging.WARNING
    }
    assert "strict_production_secrets_disabled" in warnings
    assert "payment_webhook_secret_unset" in warnings


def test_local_boot_logs_no_secret_warning(tmp_path) -> None:
    app = create_app(Settings(environment="local", log_dir=tmp_path))
    handler = _ListHandler()
    main_logger = logging.getLogger("app.main")
    main_logger.addHandler(handler)
    try:
        with TestClient(app):
            pass
    finally:
        main_logger.removeHandler(handler)
    assert not [r for r in handler.records if r.levelno == logging.CRITICAL]


# Security review 2026-11-06, L9: unauthenticated probes answer up/down only.


async def test_readiness_reports_status_without_timings_or_errors(
    monkeypatch,
) -> None:
    from app.api.v1.health import routes

    class _Broken:
        async def __aenter__(self):
            raise ConnectionRefusedError("db host 10.0.0.5:5432")

        async def __aexit__(self, *exc):
            return False

    class _Redis:
        async def ping(self):
            return True

    monkeypatch.setattr(routes, "SessionLocal", lambda: _Broken())
    monkeypatch.setattr(routes, "redis_client", _Redis())

    database = await routes._database_status()
    redis = await routes._redis_status(1.0)

    assert database.model_dump() == {
        "status": "unavailable",
        "latency_ms": None,
        "error": None,
    }
    assert redis.model_dump() == {"status": "ok", "latency_ms": None, "error": None}


def test_system_version_does_not_disclose_the_interpreter() -> None:
    client = TestClient(create_app())

    response = client.get("/api/v1/system/version")

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["python_version"] is None
    assert data["api_version"] == "v1"
