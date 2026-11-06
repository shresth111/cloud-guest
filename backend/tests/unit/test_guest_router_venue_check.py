"""QA 2026-11-06 H2: a guest login's ``router_id`` must belong to the
venue (organization, and location when the router has one) it names."""

from __future__ import annotations

import uuid

import pytest

from app.core.config import get_settings
from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.exceptions import RouterNotAtVenueError
from tests.unit.test_guest import make_fixture


async def _otp_login(fx, *, router_id, location_id):  # noqa: ANN001, ANN202
    return await fx.guest_service.login_via_otp(
        identifier="+919811122233",
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=location_id,
        router_id=router_id,
        device_mac="60:f4:45:0b:28:66",
        ip_address="192.168.1.50",
    )


@pytest.fixture(autouse=True)
def _enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shipped default is 'log' (first deploy); these pin enforcement."""
    monkeypatch.setattr(get_settings(), "guest_login_router_venue_check", "enforce")


def test_the_first_deploy_default_is_log_only() -> None:
    from app.core.config import Settings

    assert Settings.model_fields["guest_login_router_venue_check"].default == "log"


class TestRouterMustBelongToTheVenue:
    async def test_the_venues_own_router_is_admitted(self) -> None:
        fx = make_fixture()
        result = await _otp_login(
            fx, router_id=fx.router.id, location_id=fx.location_id
        )
        assert result.session.router_id == fx.router.id

    async def test_a_router_at_another_location_is_refused(self) -> None:
        """Venue A's free OTP must not open venue B's router."""
        fx = make_fixture()
        venue_b = uuid.uuid4()
        router_b = fx.router_service.add(
            organization_id=fx.organization_id, location_id=venue_b
        )
        with pytest.raises(RouterNotAtVenueError) as exc:
            await _otp_login(fx, router_id=router_b.id, location_id=fx.location_id)
        assert exc.value.status_code == 403
        assert exc.value.data["code"] == "ROUTER_NOT_AT_VENUE"

    async def test_a_router_of_another_org_is_refused(self) -> None:
        fx = make_fixture()
        foreign = fx.router_service.add(
            organization_id=uuid.uuid4(), location_id=fx.location_id
        )
        with pytest.raises(RouterNotAtVenueError):
            await _otp_login(fx, router_id=foreign.id, location_id=fx.location_id)

    async def test_an_unassigned_router_of_the_same_org_is_admitted(self) -> None:
        fx = make_fixture()
        fx.router.location_id = None
        result = await _otp_login(
            fx, router_id=fx.router.id, location_id=fx.location_id
        )
        assert result.session is not None

    async def test_log_mode_admits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(get_settings(), "guest_login_router_venue_check", "log")
        fx = make_fixture()
        router_b = fx.router_service.add(
            organization_id=fx.organization_id, location_id=uuid.uuid4()
        )
        result = await _otp_login(fx, router_id=router_b.id, location_id=fx.location_id)
        assert result.session.router_id == router_b.id
