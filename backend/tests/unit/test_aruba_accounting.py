"""Accounting at a NAS-only venue (Aruba Instant On): what reaches the logs.

MikroTik and Omada are pinned unchanged in every case below.
"""

from __future__ import annotations

import pytest

from app.domains.guest.constants import GuestSessionStatus
from app.domains.guest.exceptions import GuestSessionNotFoundError
from tests.unit.test_aruba_access_rules import (
    _ARUBA_CSID,
    _PHONE,
    _fixture,
    _register_nas,
    _sign_in,
)


async def _with_recorded_bytes(fx, nas) -> None:  # noqa: ANN001
    await _sign_in(fx)
    await fx.radius_service.accounting_interim_update(
        nas_client=nas,
        username=_PHONE,
        bytes_uploaded_delta=0,
        bytes_downloaded_delta=0,
        bytes_uploaded_total=1000,
        bytes_downloaded_total=5000,
        calling_station_id=_ARUBA_CSID,
    )


@pytest.mark.asyncio
class TestStopNeverShrinksTheRecord:
    """The AP counters restart when a guest reconnects onto a reused session,
    and the shared listener's config sends 0 for a Stop without octets."""

    @pytest.mark.parametrize(("up", "down"), [(10, 20), (0, 0)])
    async def test_a_lower_stop_total_keeps_the_recorded_bytes(
        self, up: int, down: int
    ) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        await _with_recorded_bytes(fx, nas)

        stopped = await fx.radius_service.accounting_stop(
            nas_client=nas,
            username=_PHONE,
            bytes_uploaded_total=up,
            bytes_downloaded_total=down,
            calling_station_id=_ARUBA_CSID,
        )

        assert stopped.status == GuestSessionStatus.DISCONNECTED.value
        assert stopped.bytes_uploaded == 1000
        assert stopped.bytes_downloaded == 5000

    async def test_a_higher_stop_total_is_still_recorded(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        await _with_recorded_bytes(fx, nas)

        stopped = await fx.radius_service.accounting_stop(
            nas_client=nas,
            username=_PHONE,
            bytes_uploaded_total=2000,
            bytes_downloaded_total=9000,
            calling_station_id=_ARUBA_CSID,
        )

        assert stopped.bytes_uploaded == 2000
        assert stopped.bytes_downloaded == 9000

    @pytest.mark.parametrize("vendor", ["mikrotik", "tplink_omada"])
    async def test_other_vendors_keep_the_stop_total_as_sent(self, vendor: str) -> None:
        fx = _fixture(vendor=vendor)
        nas = await _register_nas(fx)
        await _with_recorded_bytes(fx, nas)

        stopped = await fx.radius_service.accounting_stop(
            nas_client=nas,
            username=_PHONE,
            bytes_uploaded_total=10,
            bytes_downloaded_total=20,
            calling_station_id=_ARUBA_CSID,
        )

        assert stopped.bytes_uploaded == 10
        assert stopped.bytes_downloaded == 20


@pytest.mark.asyncio
class TestBlockedGuestStaysInTheRecord:
    """Blocking a guest only sets a flag, and nothing can take them off an
    Instant On AP without cloud control. They stay online until the session
    ends, so that usage and its Stop must still reach their session row."""

    async def test_interim_and_stop_still_land_on_the_session(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        login = await _sign_in(fx)
        login.guest.is_blocked = True

        updated = await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_PHONE,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=1000,
            bytes_downloaded_total=5000,
            calling_station_id=_ARUBA_CSID,
        )
        assert updated.id == login.session.id
        assert updated.bytes_downloaded == 5000

        stopped = await fx.radius_service.accounting_stop(
            nas_client=nas,
            username=_PHONE,
            bytes_uploaded_total=2000,
            bytes_downloaded_total=9000,
            calling_station_id=_ARUBA_CSID,
        )
        assert stopped.status == GuestSessionStatus.DISCONNECTED.value
        assert stopped.bytes_downloaded == 9000

    async def test_a_blocked_guest_is_still_refused_at_authorize(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        login = await _sign_in(fx)
        login.guest.is_blocked = True

        authz = await fx.radius_service.authorize(
            nas_client=nas, username=_PHONE, calling_station_id=_ARUBA_CSID
        )

        assert authz.authorized is False

    @pytest.mark.parametrize("vendor", ["mikrotik", "tplink_omada"])
    async def test_other_vendors_still_answer_not_found(self, vendor: str) -> None:
        fx = _fixture(vendor=vendor)
        nas = await _register_nas(fx)
        login = await _sign_in(fx)
        login.guest.is_blocked = True

        with pytest.raises(GuestSessionNotFoundError):
            await fx.radius_service.accounting_stop(
                nas_client=nas,
                username=_PHONE,
                bytes_uploaded_total=1,
                bytes_downloaded_total=1,
                calling_station_id=_ARUBA_CSID,
            )


@pytest.mark.asyncio
class TestBareHexMac:
    async def test_a_bare_hex_calling_station_finds_the_device_session(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        login = await _sign_in(fx)

        for bare in ("60f4450b2866", "60F4450B2866"):
            session = await fx.radius_service.accounting_start(
                nas_client=nas, username=_PHONE, calling_station_id=bare
            )
            assert session.id == login.session.id
