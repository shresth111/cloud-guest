"""Interim-update accounting must be driven by the NAS's running totals,
not by deltas.

RADIUS has no delta attribute. ``Acct-Input-Octets``/``Acct-Output-Octets``
are cumulative counters for the NAS's session (RFC 2866 §5.3-5.4), so a
real router can only ever report totals. The ``rest`` module on the hub was
configured to map those straight onto this backend's
``bytes_uploaded_delta``/``bytes_downloaded_delta``, which would make every
interim update re-add the whole session to date -- a session that has moved
1 GB reports 1 GB on its first interim, 2 GB after two, 3 GB after three.
Data caps and FUP quotas would fire against a figure that grows with uptime
rather than with traffic.

It never actually did that in production, because ``accounting{}`` in
``sites-available/default`` never called ``rest`` at all, so no
Accounting-Request has ever reached this backend from a real router and
every ``GuestSession.bytes_uploaded``/``bytes_downloaded`` on the live
platform is still zero. Wiring ``accounting{}`` up without fixing the
mapping first would have turned a "no usage data" bug into a "wrong usage
data that enforces caps" bug, which is worse.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.domains.guest.constants import GuestAuthMethod

from .test_guest import make_fixture

_NAS_IDENTIFIER = "nas-1"
_NAS_SECRET = "supersecret123"
_GUEST = "+15554445555"

#  Byte figures a real 4G/hotel session actually produces, so the
#  assertions read as traffic rather than as arbitrary integers.
_ONE_GIB = 1024**3


async def _session(fx: Any) -> Any:
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier=_NAS_IDENTIFIER,
        shared_secret=_NAS_SECRET,
    )
    await fx.guest_service.login_via_otp(
        identifier=_GUEST,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
    )
    return await fx.radius_service.authenticate_nas(
        nas_identifier=_NAS_IDENTIFIER, shared_secret=_NAS_SECRET
    )


class TestInterimUpdateTotals:
    async def test_totals_are_not_re_added_on_every_update(self) -> None:
        """THE regression test. Three interims from a session that has moved
        exactly 3 GiB up must record 3 GiB, not 6 GiB."""
        fx = make_fixture()
        nas = await _session(fx)

        for gib in (1, 2, 3):
            session = await fx.radius_service.accounting_interim_update(
                nas_client=nas,
                username=_GUEST,
                bytes_uploaded_delta=0,
                bytes_downloaded_delta=0,
                bytes_uploaded_total=gib * _ONE_GIB,
                bytes_downloaded_total=gib * 2 * _ONE_GIB,
            )

        assert session.bytes_uploaded == 3 * _ONE_GIB
        assert session.bytes_downloaded == 6 * _ONE_GIB

    async def test_a_retransmitted_packet_is_a_no_op(self) -> None:
        """RADIUS accounting retransmits are routine -- the hub's config
        deliberately withholds the Accounting-Response while the backend is
        unreachable precisely so the NAS repeats the packet. A repeated
        total must change nothing; a delta-based protocol would
        double-count every single one."""
        fx = make_fixture()
        nas = await _session(fx)

        first = await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=500_000,
            bytes_downloaded_total=900_000,
        )
        replay = await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=500_000,
            bytes_downloaded_total=900_000,
        )
        assert first.bytes_uploaded == replay.bytes_uploaded == 500_000
        assert first.bytes_downloaded == replay.bytes_downloaded == 900_000

    async def test_a_counter_that_goes_backwards_never_refunds_usage(self) -> None:
        """A total below what is recorded means the NAS's counter restarted
        (reboot, or a new NAS-side session on the same GuestSession).
        Clamping at zero keeps usage monotonic rather than crediting a
        guest back quota they have already spent."""
        fx = make_fixture()
        nas = await _session(fx)

        await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=8_000_000,
            bytes_downloaded_total=9_000_000,
        )
        after_reboot = await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=12_000,
            bytes_downloaded_total=15_000,
        )
        assert after_reboot.bytes_uploaded == 8_000_000
        assert after_reboot.bytes_downloaded == 9_000_000

    async def test_a_64_bit_total_survives_intact(self) -> None:
        """The hub reassembles Acct-*-Gigawords into a value well past
        2**32 before sending it. Nothing on this side may truncate it."""
        fx = make_fixture()
        nas = await _session(fx)
        huge = 12 * 1024**3 + 4096  # ~12 GiB, needs the gigawords high word

        session = await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=huge,
            bytes_downloaded_total=huge,
        )
        assert session.bytes_uploaded == huge
        assert session.bytes_downloaded == huge

    async def test_deltas_still_work_when_no_totals_are_supplied(self) -> None:
        """The delta parameters stay wired up for callers that genuinely
        have a delta -- totals only win when present."""
        fx = make_fixture()
        nas = await _session(fx)

        await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=1024,
            bytes_downloaded_delta=2048,
        )
        session = await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=1024,
            bytes_downloaded_delta=2048,
        )
        assert session.bytes_uploaded == 2048
        assert session.bytes_downloaded == 4096

    async def test_one_direction_supplied_as_a_total_does_not_disturb_the_other(
        self,
    ) -> None:
        fx = make_fixture()
        nas = await _session(fx)

        session = await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=777,
            bytes_uploaded_total=4_000,
        )
        assert session.bytes_uploaded == 4_000
        assert session.bytes_downloaded == 777


class TestAccountingWireContract:
    """The exact JSON the hub's ``rest`` module sends, verified live on the
    hub's FreeRADIUS 3.2.1 against a capturing HTTP server, must be
    accepted by this backend's request schema.

    Captured bodies (see ops/freeradius/README.md):
      Start:  {"status_type": "start", "username": "...", "session_id": "...",
               "bytes_uploaded_total": 0, "bytes_downloaded_total": 0,
               "disconnect_reason": ""}
      On/Off: same shape with username and session_id both ""
    """

    def test_start_packet_body_validates(self) -> None:
        from app.domains.guest.schemas import RadiusAccountingRequest

        payload = RadiusAccountingRequest.model_validate(
            {
                "status_type": "start",
                "username": _GUEST,
                "session_id": "80000006",
                "bytes_uploaded_total": 0,
                "bytes_downloaded_total": 0,
                "disconnect_reason": "",
            }
        )
        assert payload.status_type == "start"
        assert payload.bytes_uploaded_total == 0

    def test_accounting_on_body_with_empty_username_validates(self) -> None:
        """Accounting-On/Off carry no User-Name at all, and the hub's unlang
        defaults the attribute to "" so the JSON template stays valid. An
        empty username must not trip the session-scoped-status validator."""
        from app.domains.guest.schemas import RadiusAccountingRequest

        payload = RadiusAccountingRequest.model_validate(
            {
                "status_type": "accounting-on",
                "username": "",
                "session_id": "",
                "bytes_uploaded_total": 0,
                "bytes_downloaded_total": 0,
                "disconnect_reason": "",
            }
        )
        assert payload.status_type == "accounting-on"

    def test_stop_packet_carries_the_terminate_cause(self) -> None:
        from app.domains.guest.schemas import RadiusAccountingRequest

        payload = RadiusAccountingRequest.model_validate(
            {
                "status_type": "stop",
                "username": _GUEST,
                "session_id": "80000006",
                "bytes_uploaded_total": 5000,
                "bytes_downloaded_total": 6000,
                "disconnect_reason": "User-Request",
            }
        )
        assert payload.disconnect_reason == "User-Request"

    def test_every_status_type_the_hub_can_send_is_handled(self) -> None:
        """``%{tolower:%{Acct-Status-Type}}`` on the hub produces exactly
        these five strings -- verified live. Each must match a constant this
        backend dispatches on, or the endpoint 400s on real traffic."""
        from app.domains.guest import constants

        produced_by_the_hub = {
            "start",
            "interim-update",
            "stop",
            "accounting-on",
            "accounting-off",
        }
        handled = {
            constants.RADIUS_ACCT_STATUS_START,
            constants.RADIUS_ACCT_STATUS_INTERIM_UPDATE,
            constants.RADIUS_ACCT_STATUS_STOP,
            constants.RADIUS_ACCT_STATUS_ACCOUNTING_ON,
            constants.RADIUS_ACCT_STATUS_ACCOUNTING_OFF,
        }
        assert produced_by_the_hub == handled


class TestTotalToDeltaConversionAtTheBoundary:
    """The total-to-delta conversion is asserted directly, on the value
    handed to ``GuestService.record_usage``.

    Necessary because ``record_usage`` independently clamps with
    ``max(delta, 0)``, so a negative delta produced here is invisible in the
    resulting row -- a mutation removing the clamp in
    ``accounting_interim_update`` survived the row-level tests above for
    exactly that reason. Two clamps is deliberate (this method's arithmetic
    should be correct on its own terms rather than relying on a downstream
    method's behaviour), and this is where that is actually checked.
    """

    @staticmethod
    def _spy(fx: Any) -> list[dict[str, int]]:
        seen: list[dict[str, int]] = []
        original = fx.guest_service.record_usage

        async def _recording(**kwargs: Any) -> Any:
            seen.append(
                {
                    "up": kwargs["bytes_uploaded_delta"],
                    "down": kwargs["bytes_downloaded_delta"],
                }
            )
            return await original(**kwargs)

        fx.guest_service.record_usage = _recording
        return seen

    async def test_a_total_becomes_the_difference_not_the_whole_figure(self) -> None:
        fx = make_fixture()
        nas = await _session(fx)
        seen = self._spy(fx)

        for total in (1_000, 2_500, 2_500, 9_000):
            await fx.radius_service.accounting_interim_update(
                nas_client=nas,
                username=_GUEST,
                bytes_uploaded_delta=0,
                bytes_downloaded_delta=0,
                bytes_uploaded_total=total,
                bytes_downloaded_total=total,
            )

        #  1000 new, then 1500 more, then a retransmit worth nothing, then 6500.
        assert [s["up"] for s in seen] == [1_000, 1_500, 0, 6_500]
        assert [s["down"] for s in seen] == [1_000, 1_500, 0, 6_500]

    async def test_a_reset_counter_never_produces_a_negative_delta(self) -> None:
        fx = make_fixture()
        nas = await _session(fx)
        seen = self._spy(fx)

        await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=8_000_000,
            bytes_downloaded_total=9_000_000,
        )
        await fx.radius_service.accounting_interim_update(
            nas_client=nas,
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=12_000,
            bytes_downloaded_total=15_000,
        )
        assert seen[1] == {"up": 0, "down": 0}
