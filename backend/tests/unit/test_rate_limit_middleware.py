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

import uuid

from fastapi import FastAPI
from starlette.testclient import TestClient

from app.middleware.rate_limit import RateLimitMiddleware


class FakeRedis:
    """Minimal async in-memory stand-in for ``redis.asyncio.Redis``."""

    def __init__(self) -> None:
        self._store: dict[str, int] = {}
        self._ttl: dict[str, int] = {}
        self.fail = False

    @property
    def keys(self) -> list[str]:
        return list(self._store)

    async def incr(self, key: str) -> int:
        if self.fail:
            raise ConnectionError("redis down")
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


# ============================================================================
# Design spec §5 S8 -- /captive-portal/resolve is not keyed on the shared
# NAT egress IP
# ============================================================================

RESOLVE = "/api/v1/captive-portal/resolve"
VENUE_A = "11111111-1111-1111-1111-111111111111"
VENUE_B = "22222222-2222-2222-2222-222222222222"


def _make_resolve_client(
    *, resolve_max_requests: int = 3, max_requests: int = 3
) -> tuple[TestClient, FakeRedis]:
    app = FastAPI()

    @app.get(RESOLVE)
    async def resolve():
        return {"ok": True}

    redis = FakeRedis()
    app.add_middleware(
        RateLimitMiddleware,
        redis=redis,
        max_requests=max_requests,
        window_seconds=60,
        resolve_max_requests=resolve_max_requests,
    )
    return TestClient(app), redis


def test_two_venues_behind_one_egress_ip_do_not_share_a_bucket() -> None:
    """The reported bug, inverted into its cleanest observable form: the
    old key was ``(client_ip, path)``, so *everything* arriving from one
    address shared one bucket. TestClient sends every request from the
    same client host, so under the old keying the second venue would
    already be throttled by the first venue's traffic."""
    client, _redis = _make_resolve_client(resolve_max_requests=2)

    assert client.get(RESOLVE, params={"location_id": VENUE_A}).status_code == 200
    assert client.get(RESOLVE, params={"location_id": VENUE_A}).status_code == 200
    assert client.get(RESOLVE, params={"location_id": VENUE_A}).status_code == 429

    # A different venue, same egress IP, still under its own cap.
    assert client.get(RESOLVE, params={"location_id": VENUE_B}).status_code == 200


def test_a_busy_venue_is_not_throttled_at_the_old_device_sized_cap() -> None:
    """A café's twenty simultaneous arrivals all leave through one NAT
    address. At the old device-sized cap they 429'd each other off the
    WiFi they were joining; at a venue-sized cap they do not."""
    client, _redis = _make_resolve_client(resolve_max_requests=600)

    for _ in range(120):
        response = client.get(RESOLVE, params={"location_id": VENUE_A})
        assert response.status_code == 200


def test_rotating_the_venue_id_does_not_escape_the_limit() -> None:
    """The attack the client-controlled key opens up. The venue component
    comes from a query parameter, so an attacker can mint a fresh bucket
    per request -- every one of these calls sails past the venue bucket.
    The per-IP ceiling is what stops it being unbounded: rotation buys a
    bounded ``_RESOLVE_IP_CEILING_MULTIPLIER`` times the venue cap, not
    infinity."""
    from app.middleware.rate_limit import _RESOLVE_IP_CEILING_MULTIPLIER

    cap = 3
    ceiling = cap * _RESOLVE_IP_CEILING_MULTIPLIER
    client, _redis = _make_resolve_client(resolve_max_requests=cap)

    codes = [
        client.get(RESOLVE, params={"location_id": str(uuid.uuid4())}).status_code
        for _ in range(ceiling + 2)
    ]
    assert codes[:ceiling] == [200] * ceiling, "rotation must clear the venue bucket"
    assert codes[ceiling:] == [429, 429], "but must not clear the per-IP ceiling"


def test_the_ip_ceiling_sits_above_the_venue_cap_not_at_it() -> None:
    """If the two were equal, then behind a venue's NAT -- where one IP
    *is* one venue -- the IP bucket would always bind first and the venue
    keying would be decorative. This is the property that makes the venue
    bucket the control that actually governs legitimate traffic."""
    from app.middleware.rate_limit import _RESOLVE_IP_CEILING_MULTIPLIER

    assert _RESOLVE_IP_CEILING_MULTIPLIER > 1


def test_a_crafted_venue_id_cannot_forge_another_bucket_key() -> None:
    """The parameter is attacker-controlled and lands in a Redis key.
    Interpolated raw, a value containing ``:`` could collide with -- or
    forge -- keys in another namespace. Normalizing through ``uuid.UUID``
    means an unparseable value never reaches a key at all."""
    client, redis = _make_resolve_client(resolve_max_requests=50)

    client.get(
        RESOLVE, params={"location_id": "x:rate_limit:portal_resolve:ip:1.2.3.4"}
    )

    assert not any("x:rate_limit" in key for key in redis.keys)
    # Unparseable scope -> IP bucket only, never a venue bucket.
    assert not any("portal_resolve:venue" in key for key in redis.keys)
    assert any("portal_resolve:ip" in key for key in redis.keys)


def test_organization_id_is_used_when_no_location_id_is_given() -> None:
    client, redis = _make_resolve_client(resolve_max_requests=50)

    client.get(RESOLVE, params={"organization_id": VENUE_A})

    assert any(f"portal_resolve:venue:org:{VENUE_A}" in key for key in redis.keys)


def test_location_id_wins_when_both_are_supplied() -> None:
    """Matches the endpoint's own most-specific-wins resolution, so the
    limiter and the endpoint agree on what one venue is."""
    client, redis = _make_resolve_client(resolve_max_requests=50)

    client.get(RESOLVE, params={"organization_id": VENUE_B, "location_id": VENUE_A})

    assert any(f"portal_resolve:venue:loc:{VENUE_A}" in key for key in redis.keys)
    assert not any("venue:org" in key for key in redis.keys)


def test_a_tripped_venue_bucket_still_counts_against_the_ip_bucket() -> None:
    """Every bucket is incremented even once one is known to be over --
    otherwise keeping a cheap bucket permanently tripped would shield the
    others from ever counting."""
    client, redis = _make_resolve_client(resolve_max_requests=2)

    for _ in range(5):
        client.get(RESOLVE, params={"location_id": VENUE_A})

    ip_key = next(k for k in redis.keys if "portal_resolve:ip" in k)
    assert redis._store[ip_key] == 5


def test_resolve_fails_open_when_redis_is_unavailable() -> None:
    """Unauthenticated, and the guest's first request. A limiter that
    500s when Redis blinks turns a hiccup into "the WiFi is broken" for
    every guest at every venue at once."""
    client, redis = _make_resolve_client(resolve_max_requests=1)
    redis.fail = True

    for _ in range(5):
        assert client.get(RESOLVE, params={"location_id": VENUE_A}).status_code == 200


def test_other_paths_fail_open_too_and_keep_their_ip_keying() -> None:
    client, redis = _make_client(max_requests=2)

    client.get("/api/v1/auth/login")
    assert any(key.startswith("rate_limit:") for key in redis.keys)

    redis.fail = True
    for _ in range(5):
        assert client.get("/api/v1/auth/login").status_code == 200
