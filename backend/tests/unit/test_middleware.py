from fastapi.testclient import TestClient

from app.main import create_app


def test_security_headers_are_applied() -> None:
    client = TestClient(create_app())

    response = client.get("/api/v1/health/live")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "X-Execution-Time-MS" in response.headers

