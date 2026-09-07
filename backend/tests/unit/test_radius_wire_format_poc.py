"""Proof-of-concept regression test: does POST /api/v1/radius/authorize's
actual wire response match FreeRADIUS ``rlm_rest``'s real attribute-name
JSON-decoding convention?

Context (see ``app.domains.guest.router.radius_authorize``'s own
docstring): this endpoint used to return a plain
``{"authorized": true, "session_timeout_seconds": ..., ...}`` shape.
``rlm_rest``'s JSON response decoder treats every top-level key as a
literal RADIUS attribute name -- a key it doesn't recognize (``"authorized"``
is not a RADIUS attribute) is silently discarded
("Invalid vendor name in attribute name 'authorized', skipping...").
With nothing ever setting ``control:Auth-Type``, FreeRADIUS fell through to
its own hardcoded default ("No Auth-Type found: rejecting the user") and
rejected *every* login, regardless of this endpoint's own correct
accept/reject decision -- invisible behind an HTTP 200. That was fixed by
switching the reply to rlm_rest's literal attribute-name convention
(``control:Auth-Type``, ``Session-Timeout``, ``Mikrotik-Rate-Limit``,
``Acct-Interim-Interval``).

**The gap this test closes:** every existing RADIUS test in
``test_guest.py`` (``TestRadius``, ``TestRadiusAuthorizeMacWhitelistBypass``)
calls ``RadiusService.authorize()`` directly and asserts on the returned
``AuthorizeResult`` dataclass -- none of them go through the actual ASGI
route and inspect what ``radius_authorize()`` in ``router.py`` puts on the
wire. A regression that reintroduced the old ``{"authorized": ...}`` shape
at the router layer (while leaving ``RadiusService.authorize`` itself
untouched) would pass every one of those tests and still silently break
every real guest login -- exactly the failure mode that took a live
physical router, a live phone, and a packet capture to diagnose in
production. This test exercises the real route through the real ASGI
stack (``httpx.ASGITransport``, no mocking of the endpoint function itself)
so that class of bug is caught by ``pytest`` in milliseconds, no NAS
required.

Run standalone: ``pytest tests/unit/test_radius_wire_format_poc.py -v``
"""

from __future__ import annotations

import uuid

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response

from app.common.exceptions import register_exception_handlers
from app.domains.guest.constants import (
    DEFAULT_IDLE_TIMEOUT_MINUTES,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    RADIUS_NAS_IDENTIFIER_HEADER,
    RADIUS_SHARED_SECRET_HEADER,
    GuestAuthMethod,
)
from app.domains.guest.dependencies import get_radius_service
from app.domains.guest.router import radius_router
from app.domains.guest.service import RadiusService

from .test_guest import make_fixture

_NAS_IDENTIFIER = "nas-1"
_NAS_SECRET = "supersecret123"


def _build_app(radius_service: RadiusService) -> FastAPI:
    """A minimal ASGI app carrying only the real ``radius_router`` --
    exactly the surface a FreeRADIUS ``rlm_rest`` REST call would hit in
    the real deployment (``POST /api/v1/radius/authorize``). No mocking of
    the route function itself; only its DB-backed service dependency is
    swapped for the same in-memory fake ``test_guest.py``'s own suite
    already uses (there is no live Postgres in this environment)."""
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(radius_router, prefix="/api/v1")
    app.dependency_overrides[get_radius_service] = lambda: radius_service
    return app


async def _authorize(app: FastAPI, *, username: str) -> Response:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(
            "/api/v1/radius/authorize",
            json={"username": username},
            headers={
                RADIUS_NAS_IDENTIFIER_HEADER: _NAS_IDENTIFIER,
                RADIUS_SHARED_SECRET_HEADER: _NAS_SECRET,
            },
        )


class TestRadiusAuthorizeWireFormat:
    async def test_accept_reply_uses_rlm_rest_attribute_name_convention(self) -> None:
        fx = make_fixture()
        await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=fx.router.id,
            nas_identifier=_NAS_IDENTIFIER,
            shared_secret=_NAS_SECRET,
        )
        await fx.guest_service.login_via_otp(
            identifier="+15550001111",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )

        app = _build_app(fx.radius_service)
        resp = await _authorize(app, username="+15550001111")

        assert resp.status_code == 200
        body = resp.json()

        # rlm_rest's real attribute names MUST be present.
        assert body.get("control:Auth-Type") == "Accept"
        # Not an exact equality. Since the Access-Accept began carrying the
        # session's REMAINING allowance rather than the full one (#178 -- the
        # change that made a venue's timeout actually expire, because the NAS
        # re-authorizes periodically and the old full value reset the clock
        # every time), this number is `full - elapsed`. Asserting equality
        # made it a function of how long the test took to run: CI observed
        # 14398 against an expected 14400 and failed a PR that had touched
        # nothing near RADIUS.
        #
        # What this test is actually for is rlm_rest's ATTRIBUTE NAMES, not
        # the arithmetic -- that belongs to
        # test_guest_last_ended_session.py::test_the_reply_carries_remaining_time_not_the_full_allowance.
        # So pin it tightly enough that a wrong attribute or a wrong unit
        # (minutes-not-seconds, or some other timeout entirely) still fails,
        # and loosely enough that the clock cannot.
        full_seconds = DEFAULT_SESSION_TIMEOUT_MINUTES * 60
        session_timeout = body.get("Session-Timeout")
        assert isinstance(session_timeout, int)
        assert full_seconds - 60 <= session_timeout <= full_seconds
        assert body.get("Acct-Interim-Interval") == 300

        # The OLD, silently-discarded-by-rlm_rest generic envelope must be
        # entirely gone -- this is the actual regression check.
        assert "authorized" not in body
        assert "session_timeout_seconds" not in body

    async def test_the_accept_reply_carries_an_idle_timeout(self) -> None:
        """The venue's idle timeout has to reach the device, and the only
        channel it has is this reply.

        Before this attribute existed here, nothing this platform sent
        said anything about idleness at all, so what actually governed a
        guest was RouterOS's ``default`` hotspot user profile -- 30
        minutes on a router Master console set up, RouterOS's factory
        ``none`` on one provisioned before that. The dashboard's Idle
        Timeout field reached the device by no path whatsoever, which is
        why it carried a "not enforced" note on its face.

        Asserted in SECONDS, because RFC 2865 s5.28 is a seconds-valued
        attribute and the dashboard's field is in minutes -- a unit slip
        here is a silent factor-of-60 that would read on the device as
        either "half a minute" or "a day"."""
        fx = make_fixture()
        await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=fx.router.id,
            nas_identifier=_NAS_IDENTIFIER,
            shared_secret=_NAS_SECRET,
        )
        await fx.guest_service.login_via_otp(
            identifier="+15550001111",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )

        app = _build_app(fx.radius_service)
        resp = await _authorize(app, username="+15550001111")

        assert resp.status_code == 200
        body = resp.json()
        assert body.get("Idle-Timeout") == DEFAULT_IDLE_TIMEOUT_MINUTES * 60

    async def test_the_idle_timeout_is_the_full_value_on_every_reauthorization(
        self,
    ) -> None:
        """An idle timeout is a rolling window the NAS resets on every
        packet, so the full configured value is the right thing to send
        every time.

        Its neighbour ``Session-Timeout`` is the exact opposite: that one
        must send what REMAINS, because sending the full allowance on each
        re-authorization is what made a venue's session timeout
        unreachable by construction. The two live one line apart in the
        reply builder and it would be easy to "fix" this one the same way
        -- which would shrink a guest's idle allowance every time anything
        spoke to RADIUS, and eventually disconnect an actively-browsing
        guest for being idle."""
        fx = make_fixture()
        await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=fx.router.id,
            nas_identifier=_NAS_IDENTIFIER,
            shared_secret=_NAS_SECRET,
        )
        await fx.guest_service.login_via_otp(
            identifier="+15550001111",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )

        app = _build_app(fx.radius_service)
        first = (await _authorize(app, username="+15550001111")).json()
        second = (await _authorize(app, username="+15550001111")).json()

        assert first["Idle-Timeout"] == DEFAULT_IDLE_TIMEOUT_MINUTES * 60
        assert second["Idle-Timeout"] == first["Idle-Timeout"]

    async def test_reject_reply_uses_rlm_rest_attribute_name_convention(self) -> None:
        fx = make_fixture()
        await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=fx.router.id,
            nas_identifier=_NAS_IDENTIFIER,
            shared_secret=_NAS_SECRET,
        )
        # No login -> no ACTIVE session for this username -> Access-Reject.

        app = _build_app(fx.radius_service)
        resp = await _authorize(app, username="+15559998888")

        assert resp.status_code == 200
        body = resp.json()
        assert body.get("control:Auth-Type") == "Reject"
        assert "Session-Timeout" not in body
        assert "Acct-Interim-Interval" not in body
        assert "authorized" not in body

    async def test_wrong_nas_secret_is_rejected_before_reaching_authorize(
        self,
    ) -> None:
        """A NAS presenting the wrong shared secret must never reach
        ``RadiusService.authorize`` at all -- this is the exact posture
        that lets a compromised/misconfigured router never spoof another
        tenant's NAS identity."""
        fx = make_fixture()
        await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=fx.router.id,
            nas_identifier=_NAS_IDENTIFIER,
            shared_secret=_NAS_SECRET,
        )
        app = _build_app(fx.radius_service)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/radius/authorize",
                json={"username": "+15550001111"},
                headers={
                    RADIUS_NAS_IDENTIFIER_HEADER: _NAS_IDENTIFIER,
                    RADIUS_SHARED_SECRET_HEADER: "wrong-secret",
                },
            )
        assert resp.status_code in (401, 403)
