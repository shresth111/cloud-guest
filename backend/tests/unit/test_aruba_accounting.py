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


# ============================================================================
# Reconnect onto a reused GuestSession: per-NAS-session baselines
# ============================================================================


async def _interim(fx, nas, up: int, down: int, sid: str | None):  # noqa: ANN001, ANN202
    kwargs = {"nas_session_id": sid} if sid is not None else {}
    return await fx.radius_service.accounting_interim_update(
        nas_client=nas,
        username=_PHONE,
        bytes_uploaded_delta=0,
        bytes_downloaded_delta=0,
        bytes_uploaded_total=up,
        bytes_downloaded_total=down,
        calling_station_id=_ARUBA_CSID,
        **kwargs,
    )


async def _start(fx, nas, sid: str):  # noqa: ANN001, ANN202
    return await fx.radius_service.accounting_start(
        nas_client=nas,
        username=_PHONE,
        calling_station_id=_ARUBA_CSID,
        nas_session_id=sid,
    )


@pytest.mark.asyncio
class TestReconnectKeepsTheNewNasSessionsBytes:
    async def test_interim_after_reconnect_counts_from_zero(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        await _sign_in(fx)
        await _start(fx, nas, "A1")
        first = await _interim(fx, nas, 1000, 5000, "A1")
        assert (first.bytes_uploaded, first.bytes_downloaded) == (1000, 5000)

        # Reconnect: new Acct-Session-Id, AP counters restart at 0.
        await _start(fx, nas, "B2")
        second = await _interim(fx, nas, 100, 400, "B2")
        assert (second.bytes_uploaded, second.bytes_downloaded) == (1100, 5400)
        third = await _interim(fx, nas, 300, 900, "B2")
        assert (third.bytes_uploaded, third.bytes_downloaded) == (1300, 5900)

    async def test_first_interim_of_an_unseen_session_without_a_start(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        await _sign_in(fx)
        await _interim(fx, nas, 1000, 5000, "A1")
        # Start for B2 was lost: the unseen id still starts from 0.
        after = await _interim(fx, nas, 50, 70, "B2")
        assert (after.bytes_uploaded, after.bytes_downloaded) == (1050, 5070)

    async def test_retransmits_add_nothing(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        await _sign_in(fx)
        await _start(fx, nas, "A1")
        await _start(fx, nas, "A1")  # retransmitted Start
        await _interim(fx, nas, 1000, 5000, "A1")
        again = await _interim(fx, nas, 1000, 5000, "A1")
        assert (again.bytes_uploaded, again.bytes_downloaded) == (1000, 5000)
        await _start(fx, nas, "B2")
        await _interim(fx, nas, 100, 400, "B2")
        # A late packet of the previous NAS session, then a B2 retransmit.
        late = await _interim(fx, nas, 1000, 5000, "A1")
        assert (late.bytes_uploaded, late.bytes_downloaded) == (1100, 5400)
        repeat = await _interim(fx, nas, 100, 400, "B2")
        assert (repeat.bytes_uploaded, repeat.bytes_downloaded) == (1100, 5400)

    async def test_stop_after_reconnect_adds_the_new_sessions_bytes(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        await _sign_in(fx)
        await _start(fx, nas, "A1")
        await _interim(fx, nas, 1000, 5000, "A1")
        await _start(fx, nas, "B2")
        await _interim(fx, nas, 100, 400, "B2")

        stopped = await fx.radius_service.accounting_stop(
            nas_client=nas,
            username=_PHONE,
            bytes_uploaded_total=250,
            bytes_downloaded_total=600,
            calling_station_id=_ARUBA_CSID,
            nas_session_id="B2",
        )
        assert stopped.status == GuestSessionStatus.DISCONNECTED.value
        assert (stopped.bytes_uploaded, stopped.bytes_downloaded) == (1250, 5600)

    async def test_stop_with_zero_octets_keeps_the_record(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        await _sign_in(fx)
        await _interim(fx, nas, 1000, 5000, "A1")
        stopped = await fx.radius_service.accounting_stop(
            nas_client=nas,
            username=_PHONE,
            bytes_uploaded_total=0,
            bytes_downloaded_total=0,
            calling_station_id=_ARUBA_CSID,
            nas_session_id="A1",
        )
        assert (stopped.bytes_uploaded, stopped.bytes_downloaded) == (1000, 5000)

    async def test_session_in_flight_across_the_deploy(self) -> None:
        """Bytes recorded before tracking existed came from this NAS session
        when its totals are at or above them: the old answer, exactly."""
        fx = _fixture()
        nas = await _register_nas(fx)
        await _with_recorded_bytes(fx, nas)  # no session id: untracked
        after = await _interim(fx, nas, 1200, 5500, "A1")
        assert (after.bytes_uploaded, after.bytes_downloaded) == (1200, 5500)

    async def test_no_session_id_keeps_the_old_behaviour(self) -> None:
        fx = _fixture()
        nas = await _register_nas(fx)
        await _with_recorded_bytes(fx, nas)
        after = await _interim(fx, nas, 100, 400, None)
        assert (after.bytes_uploaded, after.bytes_downloaded) == (1000, 5000)
        assert getattr(after, "nas_counters", None) is None

    @pytest.mark.parametrize("vendor", ["mikrotik", "tplink_omada"])
    async def test_other_vendors_ignore_the_session_id(self, vendor: str) -> None:
        fx = _fixture(vendor=vendor)
        nas = await _register_nas(fx)
        await _with_recorded_bytes(fx, nas)
        after = await _interim(fx, nas, 100, 400, "B2")
        assert (after.bytes_uploaded, after.bytes_downloaded) == (1000, 5000)
        assert getattr(after, "nas_counters", None) is None
        stopped = await fx.radius_service.accounting_stop(
            nas_client=nas,
            username=_PHONE,
            bytes_uploaded_total=10,
            bytes_downloaded_total=20,
            calling_station_id=_ARUBA_CSID,
            nas_session_id="B2",
        )
        assert (stopped.bytes_uploaded, stopped.bytes_downloaded) == (10, 20)


class TestNasSessionCountersPure:
    def test_old_sessions_are_dropped_oldest_first(self) -> None:
        from app.domains.guest.nas_session_counters import (
            MAX_TRACKED_NAS_SESSIONS,
            start_nas_session,
        )

        counters: dict = {}
        for i in range(MAX_TRACKED_NAS_SESSIONS + 3):
            counters = start_nas_session(counters, f"s{i}")
        assert len(counters) == MAX_TRACKED_NAS_SESSIONS
        assert "s0" not in counters
        assert f"s{MAX_TRACKED_NAS_SESSIONS + 2}" in counters

    def test_garbage_counters_are_ignored(self) -> None:
        from app.domains.guest.nas_session_counters import nas_session_delta

        delta = nas_session_delta(
            {"x": "bad", 5: [1, 2], "y": [-1, 2]},
            "A1",
            bytes_uploaded_total=10,
            bytes_downloaded_total=20,
            recorded_uploaded=0,
            recorded_downloaded=0,
        )
        assert (delta.bytes_uploaded_delta, delta.bytes_downloaded_delta) == (10, 20)
        assert delta.counters == {"A1": [10, 20]}

    def test_empty_id_is_none(self) -> None:
        from app.domains.guest.nas_session_counters import clean_nas_session_id

        assert clean_nas_session_id("") is None
        assert clean_nas_session_id("  ") is None
        assert clean_nas_session_id(None) is None
        assert len(clean_nas_session_id("x" * 200)) == 64


@pytest.mark.asyncio
class TestOnlyTheSharedListenerPassesTheSessionId:
    class _Service:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict]] = []

        async def _record(self, name: str, kwargs: dict):  # noqa: ANN202
            import uuid as _uuid
            from types import SimpleNamespace

            self.calls.append((name, kwargs))
            return SimpleNamespace(id=_uuid.uuid4(), status="active")

        async def accounting_start(self, **kw):  # noqa: ANN003, ANN201
            return await self._record("start", kw)

        async def accounting_interim_update(self, **kw):  # noqa: ANN003, ANN201
            return await self._record("interim", kw)

        async def accounting_stop(self, **kw):  # noqa: ANN003, ANN201
            return await self._record("stop", kw)

    @pytest.mark.parametrize("status_type", ["start", "interim-update", "stop"])
    @pytest.mark.parametrize("track", [True, False])
    async def test_session_id_reaches_the_service_only_when_tracked(
        self, status_type: str, track: bool
    ) -> None:
        from app.domains.guest.router import _radius_accounting
        from app.domains.guest.schemas import RadiusAccountingRequest

        service = self._Service()
        payload = RadiusAccountingRequest(
            status_type=status_type,
            username=_PHONE,
            session_id="AP-SESS-7",
            bytes_uploaded_total=1,
            bytes_downloaded_total=2,
        )
        await _radius_accounting(payload, object(), service, track_nas_session=track)
        ((_, kwargs),) = service.calls
        if track:
            assert kwargs["nas_session_id"] == "AP-SESS-7"
        else:
            assert "nas_session_id" not in kwargs
