"""QA 2026-11-06 H3: a voucher only works at a venue of the org (and, for a
location-bound batch, the location) that issued it."""

from __future__ import annotations

import uuid

import pytest

from app.domains.guest.constants import GuestAuthMethod
from app.domains.voucher.constants import VoucherStatus
from app.domains.voucher.exceptions import VoucherNotFoundError
from tests.unit.test_guest import make_fixture
from tests.unit.test_voucher import _create_batch, make_service


async def _code(fx) -> str:  # noqa: ANN001
    await _create_batch(fx, quantity=1, has_manage_permission=True)
    return next(iter(fx.repository.vouchers.values())).code


class TestVoucherServiceScope:
    async def test_the_issuing_org_redeems(self) -> None:
        fx = make_service()
        code = await _code(fx)
        voucher, _ = await fx.service.redeem_voucher(
            code=code,
            identifier="+15551234567",
            source="1.2.3.4",
            organization_id=fx.organization.id,
            location_id=uuid.uuid4(),  # org-wide batch: any of its locations
        )
        assert voucher.use_count == 1

    async def test_another_org_gets_not_found_and_burns_nothing(self) -> None:
        fx = make_service()
        code = await _code(fx)
        with pytest.raises(VoucherNotFoundError):
            await fx.service.redeem_voucher(
                code=code,
                identifier="+15551234567",
                source="1.2.3.4",
                organization_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
            )
        voucher = await fx.repository.get_voucher_by_code(code)
        assert voucher.status == VoucherStatus.UNUSED.value
        assert voucher.use_count == 0

    async def test_a_location_bound_batch_refuses_other_locations(self) -> None:
        fx = make_service()
        code = await _code(fx)
        voucher = await fx.repository.get_voucher_by_code(code)
        batch = await fx.repository.get_batch(voucher.batch_id)
        batch.location_id = uuid.uuid4()
        with pytest.raises(VoucherNotFoundError):
            await fx.service.redeem_voucher(
                code=code,
                identifier="+15551234567",
                source="1.2.3.4",
                organization_id=fx.organization.id,
                location_id=uuid.uuid4(),
            )
        redeemed, _ = await fx.service.redeem_voucher(
            code=code,
            identifier="+15551234567",
            source="1.2.3.4",
            organization_id=fx.organization.id,
            location_id=batch.location_id,
        )
        assert redeemed.use_count == 1


class TestGuestVoucherLoginPassesTheVenue:
    async def test_a_foreign_orgs_voucher_is_refused_at_login(self) -> None:
        fx = make_fixture()
        fx.voucher_service.register(
            "FOREIGN1",
            data_limit_mb=None,
            validity_minutes=60,
            organization_id=uuid.uuid4(),
        )
        with pytest.raises(VoucherNotFoundError):
            await fx.guest_service.login_via_voucher(
                identifier="+919811122233",
                code="FOREIGN1",
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
                device_mac="60:f4:45:0b:28:66",
                ip_address="192.168.1.50",
            )

    async def test_the_venues_own_voucher_logs_in(self) -> None:
        fx = make_fixture()
        fx.voucher_service.register("OWN00001", data_limit_mb=None, validity_minutes=60)
        result = await fx.guest_service.login_via_voucher(
            identifier="+919811122233",
            code="OWN00001",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="60:f4:45:0b:28:66",
            ip_address="192.168.1.50",
        )
        assert result.session.auth_method == GuestAuthMethod.VOUCHER.value
        assert fx.voucher_service.redeem_calls[-1]["organization_id"] == (
            fx.organization_id
        )


class TestVoucherRateLimitKeyIsTheTrustedAddress:
    """QA 2026-11-06 M2: the body's ``ip_address`` (the device's LAN address
    as the portal reports it) must not choose the brute-force bucket."""

    async def test_rotating_the_body_ip_keeps_one_bucket(self) -> None:
        fx = make_fixture()
        for i in range(3):
            code = f"ROT0000{i}"
            fx.voucher_service.register(code, data_limit_mb=None, validity_minutes=60)
            await fx.guest_service.login_via_voucher(
                identifier=f"+91981112223{i}",
                code=code,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
                device_mac=f"60:f4:45:0b:28:6{i}",
                ip_address=f"192.168.1.{50 + i}",
                client_ip="203.0.113.7",
            )
        assert {c["source"] for c in fx.voucher_service.redeem_calls} == {
            "guest-login:203.0.113.7"
        }

    async def test_the_venue_sized_cap_applies(self) -> None:
        from app.domains.voucher.exceptions import (
            VoucherRedemptionRateLimitExceededError,
        )

        fx = make_service(redemption_max_attempts_per_window=1)
        await _create_batch(fx, quantity=3, has_manage_permission=True)
        codes = [v.code for v in fx.repository.vouchers.values()]
        for code in codes[:2]:
            await fx.service.redeem_voucher(
                code=code,
                identifier="+15551234567",
                source="guest-login:203.0.113.7",
                max_attempts_per_window=2,
            )
        with pytest.raises(VoucherRedemptionRateLimitExceededError):
            await fx.service.redeem_voucher(
                code=codes[2],
                identifier="+15551234567",
                source="guest-login:203.0.113.7",
                max_attempts_per_window=2,
            )


def test_the_public_redeem_route_is_gone() -> None:
    """QA 2026-11-06 M5: ``POST /vouchers/redeem`` burned a code with no
    venue or session behind it, and nothing called it."""
    from app.domains.voucher.router import router

    paths = {(m, r.path) for r in router.routes for m in getattr(r, "methods", ())}
    assert ("POST", "/vouchers/redeem") not in paths
    assert ("POST", "/vouchers/validate") in paths
