"""Unit tests for ``app.middleware.rate_limit.RateLimitMiddleware``: only
the curated auth/public/guest-facing path prefixes are limited, requests
under the cap pass through, and the (max+1)th request within the window
gets a 429 with a real ``Retry-After`` header.

Follows this project's "no cross-test-file fake" convention (see
``tests/unit/test_analytics_reports.py``'s own module docstring) -- a
small, self-contained ``FakeRedis`` mirroring ``tests/unit/test_auth.py``'s
identical INCR/EXPIRE/TTL shape, not imported across files.
"""

from __future__ import annotations

from fastapi import FastAPI
from starlette.testclient import TestClient

from app.middleware.rate_limit import RateLimitMiddleware


class FakeRedis:
    """Minimal async in-memory stand-in for ``redis.asyncio.Redis``."""

    def __init__(self) -> None:
        self._store: dict[str, int] = {}
        self._ttl: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        current = self._store.get(key, 0) + 1
        self._store[key] = current
        return current

    async def expire(self, key: str, seconds: int) -> None:
        self._ttl[key] = seconds

    async def ttl(self, key: str) -> int:
        return self._ttl.get(key, -1)


def _make_client(
    *, max_requests: int = 3, window_seconds: int = 60
) -> tuple[TestClient, FakeRedis]:
    app = FastAPI()

    @app.get("/api/v1/auth/login")
    async def login():
        return {"ok": True}

    @app.get("/api/v1/monitoring/dashboard")
    async def dashboard():
        return {"ok": True}

    redis = FakeRedis()
    app.add_middleware(
        RateLimitMiddleware,
        redis=redis,
        max_requests=max_requests,
        window_seconds=window_seconds,
    )
    return TestClient(app), redis


def test_requests_under_the_cap_pass_through() -> None:
    client, _redis = _make_client(max_requests=3)

    for _ in range(3):
        response = client.get("/api/v1/auth/login")
        assert response.status_code == 200


def test_request_over_the_cap_returns_429_with_retry_after() -> None:
    client, _redis = _make_client(max_requests=2)

    client.get("/api/v1/auth/login")
    client.get("/api/v1/auth/login")
    response = client.get("/api/v1/auth/login")

    assert response.status_code == 429
    assert "Retry-After" in response.headers
    assert response.json()["success"] is False


def test_unlisted_path_is_never_rate_limited() -> None:
    client, _redis = _make_client(max_requests=1)

    for _ in range(5):
        response = client.get("/api/v1/monitoring/dashboard")
        assert response.status_code == 200


def test_bucket_is_keyed_per_path_not_globally() -> None:
    """A cap on ``/auth/login`` must not also throttle
    ``/otp/request`` -- each rate-limited prefix gets its own bucket."""
    app = FastAPI()

    @app.get("/api/v1/auth/login")
    async def login():
        return {"ok": True}

    @app.get("/api/v1/otp/request")
    async def otp_request():
        return {"ok": True}

    redis = FakeRedis()
    app.add_middleware(
        RateLimitMiddleware, redis=redis, max_requests=1, window_seconds=60
    )
    client = TestClient(app)

    assert client.get("/api/v1/auth/login").status_code == 200
    assert client.get("/api/v1/auth/login").status_code == 429
    assert client.get("/api/v1/otp/request").status_code == 200
