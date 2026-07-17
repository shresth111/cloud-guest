from fastapi.testclient import TestClient

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

