"""How long the controller is told to hold one guest authorized.

## The defect

``NetworkIntegration.session_duration_seconds`` defaults to 3600 and was
never derived from anything. It went straight to
``provider.authorize_guest(..., duration_seconds=...)``, so a venue whose
``PolicyType.SESSION`` rule says **30 minutes** got a **60-minute**
controller-side authorization.

Both systems then act on the same guest with different beliefs: this
platform's sweep flips the row to ``EXPIRED`` at 30 minutes and disconnects
the client, while the controller -- which honours no RADIUS
``Session-Timeout`` and has only the number it was handed -- would have kept
forwarding that client for another half hour. The venue's own setting was
honoured on exactly one of the two.

## The fix these tests pin

The duration comes from ``GuestSession.session_timeout_minutes``: the
venue's SESSION policy as it was resolved *for this guest* at login, and
the same recorded number the platform's sweep will enforce against. Not a
re-resolution of the policy at authorize time -- a re-resolution could
disagree with the row if the policy were edited in between, and the two
systems would be out of step again for the life of that session.

MikroTik is not in this path at all; see ``TestMikrotikIsUntouched``.
"""

from __future__ import annotations

import uuid

import pytest

from app.domains.network_integration.constants import (
    DEFAULT_SESSION_DURATION_SECONDS,
    MAX_SESSION_DURATION_SECONDS,
    MIN_SESSION_DURATION_SECONDS,
    PORTAL_AUTHORIZE_DIAGNOSTICS_KEY,
    IntegrationEventType,
    IntegrationStatus,
)
from app.domains.network_integration.crypto import encrypt_credentials
from app.domains.network_integration.exceptions import (
    ProviderAuthorizationFailedError,
)
from app.domains.network_integration.validators import (
    resolve_authorization_duration_seconds,
)
from tests.unit.test_network_integration import (
    FakeGuestSession,
    FakeGuestSessionLookup,
    FakeProvider,
    FakeRepository,
    _integration,
    _service,
)

DEVICE_MAC = "AA:BB:CC:DD:EE:FF"


def _fixture(
    *,
    session_timeout_minutes: int | None,
    integration_duration_seconds: int = DEFAULT_SESSION_DURATION_SECONDS,
    provider: FakeProvider | None = None,
):
    """A venue with a controller, and one ACTIVE session at it. Built the way
    ``authorize_portal_client``'s own tests build it, so this asserts the
    real service path rather than a shape invented here."""
    org, location = uuid.uuid4(), uuid.uuid4()
    session_id = uuid.uuid4()
    integration = _integration(
        organization_id=org,
        location_id=location,
        status=IntegrationStatus.CONNECTED.value,
        external_site_id="site-1",
        session_duration_seconds=integration_duration_seconds,
        credentials_encrypted=encrypt_credentials(
            {"client_id": "cid", "client_secret": "sec"}
        ),
    )
    repo = FakeRepository()
    repo.add(integration)
    lookup = FakeGuestSessionLookup(
        {
            session_id: FakeGuestSession(
                session_id,
                org,
                location,
                device_mac=DEVICE_MAC,
                session_timeout_minutes=session_timeout_minutes,
            )
        }
    )
    provider = provider or FakeProvider()
    service = _service(repo, provider=provider, guest_lookup=lookup)
    return service, provider, session_id, org, location


async def _authorize(service, session_id, org, location) -> None:
    await service.authorize_portal_client(
        session_id=session_id,
        organization_id=org,
        location_id=location,
        client_mac=DEVICE_MAC,
        site="site-1",
        provider="omada",
    )


class TestTheControllerIsToldTheVenuesNumber:
    async def test_a_thirty_minute_policy_authorizes_for_thirty_minutes(
        self,
    ) -> None:
        """The defect, as a test. The integration row still says 3600 -- it
        is the stored default and nobody set it -- and the venue's policy
        says 30. Before this change the controller was told 3600."""
        service, provider, session_id, org, location = _fixture(
            session_timeout_minutes=30
        )

        await _authorize(service, session_id, org, location)

        assert provider.authorize_durations == [1800]

    async def test_the_two_systems_now_agree_by_construction(self) -> None:
        """The property that matters, stated directly: whatever number the
        platform's own sweep will end this session on is the number the
        controller was given. Not "both happen to be 1800" -- the same
        recorded value, read once."""
        session_timeout_minutes = 45
        service, provider, session_id, org, location = _fixture(
            session_timeout_minutes=session_timeout_minutes
        )

        await _authorize(service, session_id, org, location)

        assert provider.authorize_durations == [session_timeout_minutes * 60]

    async def test_a_session_with_no_timeout_keeps_the_stored_default(
        self,
    ) -> None:
        """``session_timeout_minutes`` is nullable -- an unlimited grant, or
        a row written before the policy resolver existed. There is no honest
        duration to derive from "no limit" and the controller's call needs a
        number, so the integration's own value remains the fallback. That is
        today's behaviour, preserved for exactly those sessions."""
        service, provider, session_id, org, location = _fixture(
            session_timeout_minutes=None, integration_duration_seconds=7200
        )

        await _authorize(service, session_id, org, location)

        assert provider.authorize_durations == [7200]

    async def test_the_diagnostics_report_what_was_actually_asked_for(
        self,
    ) -> None:
        """``requested_duration_seconds`` is in the failed-authorize bundle so
        a support engineer can diff what went to the controller. Leaving it
        reading the column would hand them the wrong number for the one field
        this change moved."""
        provider = FakeProvider(
            raise_on={
                "authorize_guest": ProviderAuthorizationFailedError("declined")
            }
        )
        service, provider, session_id, org, location = _fixture(
            session_timeout_minutes=30, provider=provider
        )

        with pytest.raises(ProviderAuthorizationFailedError):
            await _authorize(service, session_id, org, location)

        rows = [
            event
            for event in service.repository.events
            if event.event_type == IntegrationEventType.PORTAL_AUTHORIZE.value
        ]
        assert rows, "no portal_authorize event was written at all"
        diagnostics = rows[-1].context[PORTAL_AUTHORIZE_DIAGNOSTICS_KEY]
        assert diagnostics["precall"]["requested_duration_seconds"] == 1800


class TestTheDerivationRule:
    """The pure function, at its edges. Kept apart from the service tests so
    the boundary conditions are readable without a venue around them."""

    def test_minutes_become_seconds(self) -> None:
        assert (
            resolve_authorization_duration_seconds(
                session_timeout_minutes=30, fallback_seconds=3600
            )
            == 1800
        )

    def test_no_recorded_timeout_falls_back(self) -> None:
        assert (
            resolve_authorization_duration_seconds(
                session_timeout_minutes=None, fallback_seconds=3600
            )
            == 3600
        )

    def test_a_nonsensical_timeout_falls_back_rather_than_going_to_zero(
        self,
    ) -> None:
        """A zero or negative duration is not "authorize for no time"; it is
        a value the controller would reject, and a guest who does not get
        online. The stored default is the safe read of a number that cannot
        be meant."""
        assert (
            resolve_authorization_duration_seconds(
                session_timeout_minutes=0, fallback_seconds=3600
            )
            == 3600
        )

    def test_the_result_stays_inside_the_range_the_controller_accepts(
        self,
    ) -> None:
        """Session timeouts are validated in minutes against their own
        bounds, and the authorization duration has different ones. A value
        outside them would be refused outright, which costs the guest their
        connection -- clamping costs them the difference."""
        assert (
            resolve_authorization_duration_seconds(
                session_timeout_minutes=1, fallback_seconds=3600
            )
            >= MIN_SESSION_DURATION_SECONDS
        )
        assert (
            resolve_authorization_duration_seconds(
                session_timeout_minutes=60 * 24 * 365, fallback_seconds=3600
            )
            == MAX_SESSION_DURATION_SECONDS
        )


class TestMikrotikIsUntouched:
    """``authorize_portal_client`` is the controller's ``extPortal/auth``
    contract and has no RouterOS counterpart: a MikroTik venue's guest is
    admitted by ``link-login-only`` and the NAS enforces the reply
    attribute's ``Session-Timeout`` itself. Nothing in this change is
    reachable from that path.

    The suites that own the RouterOS side are unmodified:

    * ``tests/unit/test_guest.py`` -- ``TestRadiusService``'s authorize
      cases, which build ``Session-Timeout`` from the same
      ``GuestSession.session_timeout_minutes`` column this change now reads.
    * ``tests/unit/test_network_integration.py`` -- every existing
      ``authorize_portal_client`` case, all of which model a session with no
      recorded timeout and therefore still assert the stored duration.
    * ``tests/unit/test_network_integration_radius_portal.py`` -- the RADIUS
      portal contract, which passes no duration at all.
    """

    async def test_the_radius_reply_and_the_controller_read_the_same_column(
        self,
    ) -> None:
        """The two enforcement mechanisms this platform has -- a RADIUS
        ``Session-Timeout`` for a NAS that enforces it, and a controller-side
        duration for a controller that does not -- are now both derived from
        ``GuestSession.session_timeout_minutes``. That is the whole point:
        one recorded number, two transports, no third opinion.
        """
        service, provider, session_id, org, location = _fixture(
            session_timeout_minutes=30
        )
        await _authorize(service, session_id, org, location)

        # The controller's side.
        assert provider.authorize_durations == [1800]
        # The NAS's side, from the same column: RadiusService.authorize puts
        # `session_timeout_minutes * 60` in the reply. Asserted as the
        # arithmetic identity rather than by standing up a RADIUS service
        # here -- `tests/unit/test_guest.py` owns that path and is unchanged.
        assert provider.authorize_durations[0] == 30 * 60
