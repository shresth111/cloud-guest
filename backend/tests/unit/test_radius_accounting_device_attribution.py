"""RADIUS accounting must credit the device that moved the bytes.

``User-Name`` names a *person*. ``Calling-Station-Id`` names the *device*.
One guest routinely holds two concurrent sessions on one router -- two
phones, or one phone whose per-SSID randomized MAC changed between logins --
and resolving an Accounting-Request by identifier alone hands it to whichever
of those sessions started last. That is not a tie-break; it is a coin toss
that decides whose data cap fires.

Measured on production 2026-09-18, guest ``+919315074877`` at the ``QA Omada
Controller`` venue. The RADIUS hub's accounting detail file for that day
reported exactly **one** session::

    Acct-Status-Type = Stop
    Calling-Station-Id = "26-79-94-B5-24-D9"
    Acct-Input-Octets = 45206908
    Acct-Output-Octets = 1136766855
    Acct-Terminate-Cause = User-Request

Those two figures landed, to the byte, on ``guest_sessions`` row
``6b550eac-6f3d-4a55-a8f4-3ed5ed3b70b3`` -- whose device is
``86-25-FE-F0-D7-D9``, a MAC that appears nowhere in that file. The guest's
*other* session, ``00a11b27``, held the same traffic again from the Omada
usage poll, which matches on MAC and got it right. Total recorded: 2.36 GB
against 1.18 GB actually moved, on a venue whose data cap now really ends
sessions.

The numbers below are that measurement, so an assertion failure reads as the
production incident rather than as arbitrary integers.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.domains.guest.constants import GuestAuthMethod, GuestSessionStatus
from app.domains.guest.schemas import RadiusAccountingRequest

from .test_guest import make_fixture

_NAS_IDENTIFIER = "nas-attribution"
_NAS_SECRET = "supersecret123"
_GUEST = "+919315074877"

#: The device the hub actually reported on.
_REPORTING_MAC = "26-79-94-B5-24-D9"
#: The guest's other device -- later-started session, zero bytes of its own.
_OTHER_MAC = "86-25-FE-F0-D7-D9"

_INPUT_OCTETS = 45_206_908
_OUTPUT_OCTETS = 1_136_766_855


async def _venue(fx: Any):
    return await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier=_NAS_IDENTIFIER,
        shared_secret=_NAS_SECRET,
    )


async def _login(fx: Any, mac: str):
    return await fx.guest_service.login_via_otp(
        identifier=_GUEST,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
    )


async def _nas(fx: Any):
    return await fx.radius_service.authenticate_nas(
        nas_identifier=_NAS_IDENTIFIER, shared_secret=_NAS_SECRET
    )


async def _two_devices(fx: Any) -> tuple[Any, Any]:
    """The production shape: the reporting device logs in first, the other
    device logs in second, so the identifier-only lookup resolves to the
    *wrong* one. Returns ``(reporting_session, other_session)``."""
    await _venue(fx)
    reporting = await _login(fx, _REPORTING_MAC)
    other = await _login(fx, _OTHER_MAC)
    return reporting.session, other.session


class TestUsageLandsOnTheReportingDevice:
    async def test_interim_credits_the_named_device_not_the_latest_session(
        self,
    ) -> None:
        """THE regression test. Both sessions belong to one guest on one
        router; the NAS names ``26-79-94-B5-24-D9``; the octets must land
        there and nowhere else."""
        fx = make_fixture()
        reporting, other = await _two_devices(fx)
        assert reporting.id != other.id

        updated = await fx.radius_service.accounting_interim_update(
            nas_client=await _nas(fx),
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=_INPUT_OCTETS,
            bytes_downloaded_total=_OUTPUT_OCTETS,
            calling_station_id=_REPORTING_MAC,
        )

        assert updated.id == reporting.id
        assert updated.bytes_uploaded == _INPUT_OCTETS
        assert updated.bytes_downloaded == _OUTPUT_OCTETS

        untouched = await fx.repository.get_session_by_id(other.id)
        assert untouched.bytes_uploaded == 0
        assert untouched.bytes_downloaded == 0

    async def test_the_venue_total_is_what_the_hub_reported_not_double(
        self,
    ) -> None:
        """The consequence QA measured: 2.36 GB recorded against 1.18 GB
        moved. Summed across the guest's sessions, the platform must hold
        exactly the octets the hub reported."""
        fx = make_fixture()
        reporting, other = await _two_devices(fx)

        await fx.radius_service.accounting_stop(
            nas_client=await _nas(fx),
            username=_GUEST,
            bytes_uploaded_total=_INPUT_OCTETS,
            bytes_downloaded_total=_OUTPUT_OCTETS,
            disconnect_reason="User-Request",
            calling_station_id=_REPORTING_MAC,
        )

        rows = [
            await fx.repository.get_session_by_id(reporting.id),
            await fx.repository.get_session_by_id(other.id),
        ]
        total = sum(r.bytes_uploaded + r.bytes_downloaded for r in rows)
        assert total == _INPUT_OCTETS + _OUTPUT_OCTETS == 1_181_973_763

    async def test_a_stop_ends_the_reporting_session_not_the_other_one(
        self,
    ) -> None:
        """Accounting-Stop is a session end, not only a byte write. Ending
        the wrong row takes a guest offline in this platform's records while
        the one that is actually over keeps reading ACTIVE."""
        fx = make_fixture()
        reporting, other = await _two_devices(fx)

        await fx.radius_service.accounting_stop(
            nas_client=await _nas(fx),
            username=_GUEST,
            bytes_uploaded_total=_INPUT_OCTETS,
            bytes_downloaded_total=_OUTPUT_OCTETS,
            disconnect_reason="User-Request",
            calling_station_id=_REPORTING_MAC,
        )

        ended = await fx.repository.get_session_by_id(reporting.id)
        survivor = await fx.repository.get_session_by_id(other.id)
        assert ended.status != GuestSessionStatus.ACTIVE.value
        assert survivor.status == GuestSessionStatus.ACTIVE.value

    async def test_separator_and_case_spelling_do_not_decide_the_match(
        self,
    ) -> None:
        """The two sides genuinely disagree on spelling: ``GuestDevice
        .mac_address`` keeps whatever the captive-portal login submitted, and
        a NAS writes ``Calling-Station-Id`` however its firmware likes. The
        same physical device must match through either."""
        fx = make_fixture()
        reporting, other = await _two_devices(fx)

        updated = await fx.radius_service.accounting_interim_update(
            nas_client=await _nas(fx),
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=_INPUT_OCTETS,
            bytes_downloaded_total=_OUTPUT_OCTETS,
            calling_station_id="26:79:94:b5:24:d9",
        )
        assert updated.id == reporting.id


class TestNothingElseChanges:
    """MikroTik venues -- every venue, in fact -- must behave exactly as
    before wherever the device cannot be named. The device match only ever
    *narrows* the existing identifier lookup."""

    async def test_a_nas_that_sends_no_mac_still_resolves_the_latest_session(
        self,
    ) -> None:
        """The pre-fix behaviour, preserved verbatim: no
        ``Calling-Station-Id`` on the packet means the guest's latest session
        on this router, in any status, exactly as before. A hub running the
        previous ``rest.conf`` keeps working."""
        fx = make_fixture()
        reporting, other = await _two_devices(fx)

        updated = await fx.radius_service.accounting_interim_update(
            nas_client=await _nas(fx),
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=_INPUT_OCTETS,
            bytes_downloaded_total=_OUTPUT_OCTETS,
        )
        assert updated.id == other.id

    async def test_a_single_device_guest_is_untouched(self) -> None:
        """The overwhelming majority of real sessions. One device means one
        candidate, so the match and the fallback are the same row -- with or
        without a MAC on the packet."""
        fx = make_fixture()
        await _venue(fx)
        login = await _login(fx, _REPORTING_MAC)

        with_mac = await fx.radius_service.accounting_interim_update(
            nas_client=await _nas(fx),
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=_INPUT_OCTETS,
            bytes_downloaded_total=_OUTPUT_OCTETS,
            calling_station_id=_REPORTING_MAC,
        )
        assert with_mac.id == login.session.id
        assert with_mac.bytes_uploaded == _INPUT_OCTETS

    async def test_an_unparseable_mac_falls_back_rather_than_losing_the_packet(
        self,
    ) -> None:
        """A MAC this platform cannot parse must never be treated as "no
        session": dropping accounting would lose usage silently, which is how
        a cap stops enforcing. Fall back to the identifier lookup."""
        fx = make_fixture()
        reporting, other = await _two_devices(fx)

        updated = await fx.radius_service.accounting_interim_update(
            nas_client=await _nas(fx),
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=_INPUT_OCTETS,
            bytes_downloaded_total=_OUTPUT_OCTETS,
            calling_station_id="not-a-mac",
        )
        assert updated.id == other.id

    async def test_a_mac_belonging_to_no_session_of_this_guests_falls_back(
        self,
    ) -> None:
        """A NAS naming a device this platform has never seen for this guest
        (a MAC-whitelist bypass, a device row written by another venue) is a
        "cannot say", not a reason to discard the octets."""
        fx = make_fixture()
        reporting, other = await _two_devices(fx)

        updated = await fx.radius_service.accounting_interim_update(
            nas_client=await _nas(fx),
            username=_GUEST,
            bytes_uploaded_delta=0,
            bytes_downloaded_delta=0,
            bytes_uploaded_total=_INPUT_OCTETS,
            bytes_downloaded_total=_OUTPUT_OCTETS,
            calling_station_id="AA-BB-CC-DD-EE-FF",
        )
        assert updated.id == other.id


class TestTheWirePayloadShape:
    """The hub sends JSON built by ``ops/freeradius/rest.conf``. Asserting
    the numbers inside a payload while never asserting the payload's *shape*
    is how a wrong request shipped this morning -- so this parses the
    accounting ``data`` template out of the file this repo actually ships,
    substitutes what a real Accounting-Stop carries, and feeds the result to
    the model the endpoint validates against."""

    @staticmethod
    def _rest_conf_accounting_payload() -> dict[str, object]:
        import json
        import re
        from pathlib import Path

        rest = (
            Path(__file__).resolve().parents[2] / "ops" / "freeradius" / "rest.conf"
        ).read_text()
        accounting = rest.split("accounting {", 1)[1]
        template = re.search(r'data\s*=\s*"(.*)"', accounting).group(1)
        #  Undo rest.conf's own escaping, then substitute the FreeRADIUS
        #  expansions with what the hub's detail file recorded on 2026-09-18.
        body = template.replace('\\"', '"')
        for expansion, value in (
            ("%{control:Tmp-String-0}", "stop"),
            ("%{User-Name}", _GUEST),
            ("%{Calling-Station-Id}", _REPORTING_MAC),
            ("%{Acct-Session-Id}", "01125f5cb1ed46e3ad6e3acc2f219482"),
            ("%{control:Tmp-Integer64-0}", str(_INPUT_OCTETS)),
            ("%{control:Tmp-Integer64-1}", str(_OUTPUT_OCTETS)),
            ("%{control:Tmp-String-1}", "User-Request"),
        ):
            body = body.replace(expansion, value)
        return json.loads(body)

    def test_the_hub_payload_carries_the_device_and_the_model_accepts_it(
        self,
    ) -> None:
        payload = self._rest_conf_accounting_payload()
        #  The shape first: the field the backend reads must be in the
        #  request the hub actually builds, under that exact name.
        assert "calling_station_id" in payload

        request = RadiusAccountingRequest(**payload)
        assert request.calling_station_id == _REPORTING_MAC
        assert request.username == _GUEST
        assert request.bytes_uploaded_total == _INPUT_OCTETS
        assert request.bytes_downloaded_total == _OUTPUT_OCTETS

    def test_a_payload_without_the_device_still_validates(self) -> None:
        """A hub that has not had the new ``rest.conf`` applied yet keeps
        working -- the field is optional and the absence means "cannot say",
        not "no device"."""
        payload = self._rest_conf_accounting_payload()
        payload.pop("calling_station_id")
        assert RadiusAccountingRequest(**payload).calling_station_id is None
