"""Composition regression test: a guest that matches **no** access rule
must still get online, through the real DI graph.

## Why this file exists

Commit ``a0f1522`` ("I broke guest login three commits ago; the detector
said zero"). ``queue_management`` and ``mac_authorization`` are composed
into ``app.domains.guest.dependencies.get_guest_service`` as hooks.
Converting them to the strict ``CallerLocationScope`` -- which depends on
``CurrentUser`` -- put ``CurrentUser`` into the dependency graph of every
route that reaches the guest service. Fifteen routes silently began
requiring authentication, ``POST /radius/authorize`` among them. No guest
anywhere could have got online. **The full suite passed 4103 the whole
time**, and the invariant test that exists precisely to catch this
reported zero offenders, because its own signal ("is ``CurrentUser`` in
this route's graph?") was produced by the defect it was looking for.

Its lesson, in its own words: *a detector whose signal is produced by the
thing it is meant to detect returns all-clear at exactly the moment it
should scream.*

``GuestAccessService`` is composed into ``get_guest_service`` as
``access_control_hook`` in exactly the same way, and per-property
whitelist-only mode changes what that hook returns when **nothing
matches** -- today an allow, under that feature a refusal on the
properties that opted in. The hazard is identical in shape and worse in
consequence: a composition mistake there does not 401 a route, it flips
the default decision for every guest at every property that never opted
in, and the resolver's own unit tests keep passing because the resolver
was never the broken part.

``tests/unit/test_location_scope_coverage.py`` walks route dependency
graphs looking for ``CurrentUser``. That detects an **authentication**
regression. It cannot detect a **default-decision** regression: the graph
is unchanged, the route stays unauthenticated, and the guest is refused
anyway. Nothing else in this suite drives a login through the real
composed graph -- ``tests/unit/test_guest.py`` builds ``GuestService``
directly with hand-picked hooks, which is precisely the reading that
showed nothing in ``a0f1522``.

## What this test actually asserts

The default decision, end to end, in both directions:

* With whitelist-only mode **off** (its shipped default), an
  unauthenticated ``POST /api/v1/guest/login/otp`` from a guest with
  **zero** matching ``guest_access``/``device_access`` rules returns 200
  and an ``ACTIVE`` session.
* With it **on** for that property, the same request is refused -- 403,
  no session -- and a guest who *is* on the list still gets online.
* ``POST /api/v1/otp/request`` is gated the same way, so the venue never
  pays for an SMS to someone it is about to refuse.

Both directions matter and neither alone is enough. A composition
regression that wired the flag to a constant would keep one of the two
passing whichever constant it picked.

## What is real here and what is faked, and why the line is where it is

The composition under test is ``get_guest_service`` -> the *real*
``get_guest_access_service`` -> the *real* ``GuestAccessService`` ->
``AccessDecisionResolver``. Neither of those two providers is overridden,
and neither is ``get_guest_service`` itself; the route resolves them the
way a real request does, ``OptionalCallerLocationScope`` included.

Everything overridden is a **leaf**: the I/O-bound repositories and the
sibling services this composition merely passes through. There is no
Postgres or Redis in this environment, so the leaves are the same
in-memory fakes ``test_guest.py`` already uses. Faking a leaf cannot hide
the defect this test exists for -- that defect lives in the wiring
between the guest service and the access-control service, and that wiring
is the part left real.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response

from app.common.exceptions import register_exception_handlers
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.captive_portal.dependencies import get_captive_portal_service
from app.domains.guest.constants import (
    WHITELIST_ONLY_LOGIN_FAILURE_REASON,
    GuestAuthMethod,
    GuestSessionStatus,
)
from app.domains.guest.dependencies import (
    get_guest_repository,
    get_guest_service,
    get_shared_quota_resolver,
)
from app.domains.guest.router import guest_router
from app.domains.guest_access.constants import AccessRuleType
from app.domains.guest_access.dependencies import (
    get_block_enforcer,
    get_guest_access_repository,
    get_guest_access_service,
)
from app.domains.guest_access.models import DeviceAccessRule, GuestAccessRule
from app.domains.mac_authorization.dependencies import get_mac_authorization_service
from app.domains.monitoring.dependencies import get_monitoring_service
from app.domains.otp.dependencies import get_otp_service
from app.domains.otp.router import router as otp_router
from app.domains.policy.dependencies import get_policy_service
from app.domains.queue_management.dependencies import get_queue_management_service
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.router.dependencies import get_router_service
from app.domains.voucher.dependencies import get_voucher_service

from .test_guest import make_fixture

_IDENTIFIER = "+15550002222"


@dataclass
class RecordingOtpService:
    """A leaf stand-in for ``OtpService`` that records every code it would
    have *sent*.

    The point of gating ``POST /otp/request`` is that a refused guest costs
    the venue nothing, and "costs nothing" is only observable as a send
    that did not happen. ``tests/unit/test_guest.py``'s ``FakeOtpService``
    implements only ``verify_otp``, because nothing in that file ever
    requested a code.
    """

    requests: list[str] = field(default_factory=list)

    async def verify_otp(self, *, identifier: str, code: str, purpose: object):
        if code != "GOOD":
            raise AssertionError("unexpected verify in this file")
        return None

    async def request_otp(
        self,
        *,
        identifier: str,
        channel: object,
        purpose: object,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ):
        self.requests.append(identifier)

        class _Sent:
            id = uuid.uuid4()
            channel = "sms"
            purpose = "guest_login"
            expires_at = datetime.now(UTC)
            created_at = datetime.now(UTC)

        sent = _Sent()
        sent.identifier = identifier  # type: ignore[attr-defined]
        return sent


@dataclass
class RecordingAccessRepository:
    """An ``app.domains.guest_access`` repository holding **no rules at
    all** -- the exact state this test is about, and the state the vast
    majority of real venues are in.

    It records every ``check_access`` lookup so the test can assert the
    real ``GuestAccessService`` was actually reached, rather than
    inferring it from a 200 that a silently-unwired hook would also
    produce. That distinction is the whole point: ``_enforce_access_control``
    returns early and lets the guest online when no hook is wired, so
    "login succeeded" alone proves nothing about the composition.
    """

    guest_lookups: list[str] = field(default_factory=list)
    device_lookups: list[str] = field(default_factory=list)
    #: Identifiers that *do* have an allow-shaped rule at this property.
    #: Empty by default -- "no rules at all" is the state this file is
    #: about and the state nearly every real venue is in.
    listed: set[str] = field(default_factory=set)

    async def list_matching_guest_rules(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        identifier: str,
        now: datetime,
    ) -> list[GuestAccessRule]:
        self.guest_lookups.append(identifier)
        if identifier not in self.listed:
            return []
        return [
            GuestAccessRule(
                id=uuid.uuid4(),
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                deleted_at=None,
                is_deleted=False,
                created_by=None,
                updated_by=None,
                version=1,
                organization_id=organization_id,
                location_id=location_id,
                identifier=identifier,
                rule_type=AccessRuleType.WHITELIST.value,
                reason=None,
                expires_at=None,
                is_active=True,
            )
        ]

    async def list_matching_device_rules(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        mac_address: str,
        now: datetime,
    ) -> list[DeviceAccessRule]:
        self.device_lookups.append(mac_address)
        return []


def _build_app(
    fx,
    access_repository: RecordingAccessRepository,
    *,
    otp_service: object | None = None,
    mac_authorization_service: object | None = None,
) -> FastAPI:
    """The real ``guest_router`` (and ``otp_router``) with only leaf
    dependencies swapped.

    Deliberately **not** overridden, because they are the composition
    under test: ``get_guest_service`` and ``get_guest_access_service``.
    FastAPI builds both for real, so ``GuestService.access_control_hook``
    is a real ``GuestAccessService`` over ``access_repository``.
    """
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(guest_router, prefix="/api/v1")
    # `POST /otp/request` now composes `GuestService.check_portal_admission`
    # for the whitelist-only gate, and that composition is exactly as
    # capable of breaking silently as the login one. Mounted here so it is
    # driven through the same real graph.
    app.include_router(otp_router, prefix="/api/v1")

    # Nothing in this test path issues a query -- every repository below is
    # already an in-memory fake -- but FastAPI still resolves the session
    # provider for `OptionalCallerLocationScope`'s own auth sub-graph, which
    # it reaches before discovering there is no credential to check.
    async def _no_db():
        yield object()

    app.dependency_overrides[get_db_session] = _no_db
    app.dependency_overrides[get_redis_client] = lambda: fx.redis

    app.dependency_overrides[get_guest_repository] = lambda: fx.repository
    app.dependency_overrides[get_otp_service] = (
        lambda: otp_service if otp_service is not None else fx.otp_service
    )
    app.dependency_overrides[get_voucher_service] = lambda: fx.voucher_service
    app.dependency_overrides[get_captive_portal_service] = (
        lambda: fx.captive_portal_service
    )
    app.dependency_overrides[get_router_service] = lambda: fx.router_service
    app.dependency_overrides[get_rbac_repository] = lambda: fx.audit_writer

    # The optional, best-effort hooks this login path does not exercise.
    # `GuestService` accepts `None` for each by design (see its own
    # docstring); leaving them unstubbed would only add I/O this test has
    # no opinion about.
    app.dependency_overrides[get_monitoring_service] = lambda: None
    app.dependency_overrides[get_queue_management_service] = lambda: None
    app.dependency_overrides[get_policy_service] = lambda: None
    app.dependency_overrides[get_mac_authorization_service] = (
        lambda: mac_authorization_service
    )
    app.dependency_overrides[get_shared_quota_resolver] = lambda: None

    # The access-control service's own leaves. The service itself is real.
    app.dependency_overrides[get_guest_access_repository] = lambda: access_repository
    app.dependency_overrides[get_block_enforcer] = lambda: None

    # Stated as an assertion rather than trusted to the reader: the two
    # providers whose composition this file exists to test are built by
    # FastAPI for real. An override sneaking in here would turn every test
    # below into a tautology.
    assert get_guest_service not in app.dependency_overrides
    assert get_guest_access_service not in app.dependency_overrides
    return app


async def _request_otp(app: FastAPI, fx, *, identifier: str = _IDENTIFIER) -> Response:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.post(
            "/api/v1/otp/request",
            json={
                "identifier": identifier,
                "channel": "sms",
                "purpose": "guest_login",
                "location_id": str(fx.location_id),
            },
        )


async def _login(
    app: FastAPI, fx, *, device_mac: str | None, identifier: str = _IDENTIFIER
) -> Response:
    payload: dict[str, object] = {
        "identifier": identifier,
        "code": "GOOD",
        "auth_method": GuestAuthMethod.OTP_SMS.value,
        "location_id": str(fx.location_id),
        "router_id": str(fx.router.id),
    }
    if device_mac is not None:
        payload["device_mac"] = device_mac
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # No Authorization header, on purpose: this is a guest device that
        # has no platform identity at all, which is also what makes this
        # test fail loudly if a confinement dependency ever puts
        # `CurrentUser` back into this route's graph.
        return await client.post("/api/v1/guest/login/otp", json=payload)


@pytest.fixture(autouse=True)
def _no_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    """``get_guest_service`` wires ``tasks.enqueue_guest_queue_assignment``
    as the queue dispatcher, which publishes to a Celery broker there is
    none of here. It is best-effort and never raises, so a real call would
    only make this test slow and noisy; it is a leaf either way."""
    import app.domains.guest.tasks as guest_tasks

    async def _noop(**_kwargs: object) -> None:
        return None

    monkeypatch.setattr(guest_tasks, "enqueue_guest_queue_assignment", _noop)


class TestGuestLoginThroughTheRealDependencyGraph:
    async def test_guest_matching_no_access_rule_still_gets_online(self) -> None:
        """The invariant, stated once: **default-allow survives
        composition.**

        A guest with no VIP, no TEMPORARY, no BLOCKLIST and no WHITELIST
        rule -- which is nearly every guest at nearly every venue -- logs
        in through the real, composed dependency graph and gets an ACTIVE
        session. Per-property whitelist-only mode is off, which is the
        column's default and the state of every existing config.

        This is the assertion ``a0f1522`` did not have. Its detector asked
        a question whose answer the defect itself supplied; this one asks
        the only question that cannot be answered wrongly by the thing it
        is testing -- did a real guest actually get online.
        """
        fx = make_fixture()
        access_repository = RecordingAccessRepository()
        app = _build_app(fx, access_repository)

        resp = await _login(app, fx, device_mac="aa:bb:cc:dd:ee:01")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["success"] is True
        assert body["data"]["session"]["status"] == GuestSessionStatus.ACTIVE.value

        # The hook was genuinely wired and genuinely consulted. Without
        # this, an `access_control_hook=None` regression -- which lets
        # every guest online with no decision made at all -- would pass
        # the assertions above unchanged.
        assert access_repository.guest_lookups == [_IDENTIFIER]
        assert access_repository.device_lookups == ["AA:BB:CC:DD:EE:01"]

    async def test_the_route_needs_no_credential(self) -> None:
        """The other half of ``a0f1522``, kept honest at the response
        level rather than by graph inspection.

        The fifteen-route breakage was invisible to a dependency-graph
        walk because the walk's own signal had been polluted. A 200 from
        an unauthenticated client cannot be polluted that way: if any
        dependency of this route ever resolves ``CurrentUser`` again, this
        returns 401 or 403 and says so.
        """
        fx = make_fixture()
        app = _build_app(fx, RecordingAccessRepository())

        resp = await _login(app, fx, device_mac=None)

        assert resp.status_code not in (401, 403), resp.text
        assert resp.status_code == 200, resp.text

    async def test_the_access_hook_is_reached_even_with_no_device_mac(self) -> None:
        """A guest signing in on a network that reports no MAC still goes
        through the access-control service -- the identifier lookup
        happens, the device lookup correctly does not, and the guest gets
        online.

        Worth pinning because the MAC is the optional half: a composition
        that only consulted the hook when a MAC was present would look
        correct in the test above and skip the gate entirely on the paths
        that do not carry one.
        """
        fx = make_fixture()
        access_repository = RecordingAccessRepository()
        app = _build_app(fx, access_repository)

        resp = await _login(app, fx, device_mac=None)

        assert resp.status_code == 200, resp.text
        assert access_repository.guest_lookups == [_IDENTIFIER]
        assert access_repository.device_lookups == []


class TestUnwiredAccessControlHookIsLoud:
    async def test_missing_hook_logs_a_warning_rather_than_passing_silently(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``GuestService._enforce_access_control`` returns early when no
        ``access_control_hook`` was wired, letting the guest online with
        no access-control decision made at all.

        That is fail-open, and under per-property whitelist-only mode --
        where the entire enforcement is "refuse whoever does not match" --
        it is a venue that believes it is running closed while running
        wide open. It cannot be made a hard failure here without breaking
        the Celery tasks and tests that legitimately construct
        ``GuestService`` without the hook, so it is made **loud** instead.
        This test is what stops the log line from being quietly deleted.
        """
        import logging

        fx = make_fixture()  # access_control_hook defaults to None
        assert fx.guest_service.access_control_hook is None

        with caplog.at_level(logging.WARNING, logger="app.domains.guest.service"):
            result = await fx.guest_service.login_via_otp(
                identifier=_IDENTIFIER,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

        assert result.session.status == GuestSessionStatus.ACTIVE.value
        assert any(
            record.message == "guest_access_control_hook_not_wired"
            for record in caplog.records
        )

    async def test_a_wired_hook_logs_nothing(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The counterpart: the warning must fire on the unwired case
        only, or it is noise every real login emits and everybody learns
        to ignore."""
        import logging

        from .test_guest import FakeAccessControlHook

        fx = make_fixture(access_control_hook=FakeAccessControlHook())

        with caplog.at_level(logging.WARNING, logger="app.domains.guest.service"):
            await fx.guest_service.login_via_otp(
                identifier=_IDENTIFIER,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

        assert not any(
            record.message == "guest_access_control_hook_not_wired"
            for record in caplog.records
        )


# ============================================================================
# Per-property whitelist-only mode, through the same real graph
# ============================================================================


class TestWhitelistOnlyThroughTheRealDependencyGraph:
    """The half ``a0f1522`` says nothing else can catch.

    ``GuestAccessService`` is composed into ``get_guest_service`` as
    ``access_control_hook``, and this feature changes what that hook
    returns when nothing matches. A mistake in the wiring does not 401 a
    route and does not fail a resolver unit test -- the resolver was never
    the broken part. It flips the default decision, and the only assertion
    that cannot be answered wrongly by the thing under test is: did a real
    guest, driven through the real graph, get online or not.

    So both directions are pinned. Off, an unlisted guest gets in. On, the
    same guest does not, and a listed one does.
    """

    async def test_off_the_unlisted_guest_still_gets_online(self) -> None:
        fx = make_fixture(whitelist_only_enabled=False)
        access_repository = RecordingAccessRepository()
        app = _build_app(fx, access_repository)

        resp = await _login(app, fx, device_mac=None)

        assert resp.status_code == 200, resp.text
        assert resp.json()["data"]["session"]["status"] == (
            GuestSessionStatus.ACTIVE.value
        )

    async def test_on_the_unlisted_guest_is_refused(self) -> None:
        fx = make_fixture(whitelist_only_enabled=True)
        access_repository = RecordingAccessRepository()
        app = _build_app(fx, access_repository)

        resp = await _login(app, fx, device_mac=None)

        assert resp.status_code == 403, resp.text
        # Refused, not 401'd: the route still needs no credential. If the
        # flag ever reached this decision by way of an auth dependency,
        # this is where it would show.
        assert resp.status_code not in (401, 404, 500)
        # And the hook was genuinely consulted -- a 403 produced by
        # something other than the composed access-control service would
        # not have touched the repository.
        assert access_repository.guest_lookups == [_IDENTIFIER]
        # No session was created for the refused guest.
        assert fx.repository.sessions == {}

    async def test_on_a_listed_guest_still_gets_online(self) -> None:
        """The flag is not a kill switch: the list has to work, or a venue
        that switched this on has simply turned its WiFi off."""
        fx = make_fixture(whitelist_only_enabled=True)
        access_repository = RecordingAccessRepository(listed={_IDENTIFIER})
        app = _build_app(fx, access_repository)

        resp = await _login(app, fx, device_mac=None)

        assert resp.status_code == 200, resp.text
        assert resp.json()["data"]["session"]["status"] == (
            GuestSessionStatus.ACTIVE.value
        )

    async def test_the_refused_guest_is_told_the_venues_own_words(self) -> None:
        fx = make_fixture(
            whitelist_only_enabled=True,
            whitelist_only_denied_message="Ask reception to add your number.",
        )
        app = _build_app(fx, RecordingAccessRepository())

        resp = await _login(app, fx, device_mac=None)

        assert resp.status_code == 403
        assert "Ask reception" in resp.text

    async def test_a_trusted_device_survives_the_switch(self) -> None:
        """The reconciliation, through the real graph. A device on
        ``mac_authorization_entries`` -- a table the access-control service
        does not query -- must not be refused by a property switching to
        whitelist-only, and its operator must not have to enter it twice."""
        from .test_guest import FakeMacAuthorizationHook

        fx = make_fixture(whitelist_only_enabled=True)
        mac_hook = FakeMacAuthorizationHook(whitelisted={"AA:BB:CC:DD:EE:01"})
        app = _build_app(
            fx, RecordingAccessRepository(), mac_authorization_service=mac_hook
        )

        resp = await _login(app, fx, device_mac="aa:bb:cc:dd:ee:01")

        assert resp.status_code == 200, resp.text

    async def test_a_refusal_is_recorded_for_the_venue_to_read(self) -> None:
        fx = make_fixture(whitelist_only_enabled=True)
        app = _build_app(fx, RecordingAccessRepository())

        assert (await _login(app, fx, device_mac=None)).status_code == 403

        refusals = [r for r in fx.repository.login_history if not r.success]
        assert len(refusals) == 1
        assert refusals[0].identifier == _IDENTIFIER
        assert refusals[0].failure_reason == WHITELIST_ONLY_LOGIN_FAILURE_REASON


class TestOtpRequestIsGatedThroughTheRealDependencyGraph:
    """``POST /otp/request`` is where the venue's money is spent, and it is
    reached *before* any login endpoint. Gating only the login call would
    mean anyone on the street could send real SMS at the owner's expense
    and be refused afterwards."""

    async def test_off_a_code_is_sent_as_it_always_was(self) -> None:
        fx = make_fixture(whitelist_only_enabled=False)
        otp = RecordingOtpService()
        app = _build_app(fx, RecordingAccessRepository(), otp_service=otp)

        resp = await _request_otp(app, fx)

        assert resp.status_code == 201, resp.text
        assert otp.requests == [_IDENTIFIER]

    async def test_on_an_unlisted_guest_gets_no_sms_at_all(self) -> None:
        fx = make_fixture(whitelist_only_enabled=True)
        otp = RecordingOtpService()
        app = _build_app(fx, RecordingAccessRepository(), otp_service=otp)

        resp = await _request_otp(app, fx)

        assert resp.status_code == 403, resp.text
        # The assertion the money rides on.
        assert otp.requests == []

    async def test_on_a_listed_guest_still_gets_their_code(self) -> None:
        fx = make_fixture(whitelist_only_enabled=True)
        otp = RecordingOtpService()
        app = _build_app(
            fx, RecordingAccessRepository(listed={_IDENTIFIER}), otp_service=otp
        )

        resp = await _request_otp(app, fx)

        assert resp.status_code == 201, resp.text
        assert otp.requests == [_IDENTIFIER]

    async def test_the_route_still_needs_no_credential(self) -> None:
        """``/otp/request`` now reaches ``get_guest_service`` -- a much
        larger dependency graph than it had. That is precisely the shape of
        ``a0f1522``: fifteen routes silently began requiring
        authentication because a service they composed grew a dependency on
        ``CurrentUser``. An unauthenticated 201 cannot be faked by graph
        inspection."""
        fx = make_fixture(whitelist_only_enabled=False)
        app = _build_app(
            fx, RecordingAccessRepository(), otp_service=RecordingOtpService()
        )

        resp = await _request_otp(app, fx)

        assert resp.status_code not in (401, 403), resp.text
        assert resp.status_code == 201, resp.text


# ============================================================================
# Guest-facing limit errors: the 409 text the portal renders verbatim
# ============================================================================


class TestGuestFacingLimitErrorMessagesDoNotLeakTheGuestId:
    """The 409 ``message`` of the session/device/FUP limit errors is what a
    guest's captive-portal screen shows verbatim, and until de-identified it
    began with the guest's internal ``Guest.id`` UUID -- an identifier the
    unauthenticated client was never meant to see. The exception-level
    assertions in ``test_guest.py`` pin the text at the source; this pins
    the *response* a real login route returns once the app-wide handler has
    serialised ``exc.message`` into the 409 body, which is the exact bytes
    the portal renders."""

    async def test_a_409_concurrent_session_message_contains_no_guest_uuid(
        self,
    ) -> None:
        from app.domains.guest.constants import (
            DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST,
        )

        fx = make_fixture()
        app = _build_app(fx, RecordingAccessRepository())

        first = await _login(app, fx, device_mac=None)
        assert first.status_code == 200, first.text
        guest_id = first.json()["data"]["guest_id"]

        # Fill the guest's concurrent-session allowance over the real
        # dependency graph, the way a repeated-login guest actually hits it.
        for _ in range(DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST - 1):
            fill = await _login(app, fx, device_mac=None)
            assert fill.status_code == 200, fill.text

        over = await _login(app, fx, device_mac=None)

        assert over.status_code == 409, over.text
        body = over.json()
        assert body["success"] is False
        assert "active session(s)" in body["message"]
        # The regression this test exists for: the setup guest's UUID used
        # to be interpolated straight into this message.
        assert guest_id not in body["message"]
        # The structured half is unchanged -- the machine-readable limit is
        # still surfaced to the caller.
        assert body["data"] == {
            "max_concurrent_sessions": DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST
        }
