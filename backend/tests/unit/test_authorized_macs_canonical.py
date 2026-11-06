"""``GET /agent/authorized-macs`` hands the router one spelling of each MAC,
and nothing that is not a MAC.

The consumer is a RouterOS script (``cloudguest-authmac-sched``), which
keeps a ``type=bypassed`` hotspot binding for every address listed and is
meant to remove the binding once an address is no longer listed. It cannot
tolerate either of the two things this file pins out of the response:

* a value RouterOS cannot parse as a MAC -- a script error that stops the
  sync for every guest at the venue;
* a second spelling of an address the router holds -- read as "not
  listed", so the binding is removed and re-added on every tick.

No router is involved: these assert what leaves the platform, not what the
script does with it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from app.domains.guest.constants import GuestAuthMethod
from app.domains.router_agent.dependencies import AgentIdentity
from app.domains.router_agent.router import agent_authorized_macs
from app.domains.router_agent.validators import routeros_mac_address

from .test_guest import FakeAccessControlHook, Fixture, make_fixture


class TestRouterosMacAddress:
    @pytest.mark.parametrize(
        "value",
        [
            "AA:BB:CC:DD:EE:01",
            "aa:bb:cc:dd:ee:01",
            "AA-BB-CC-DD-EE-01",
            "  aa-bb-CC:dd:EE:01 ",
        ],
    )
    def test_every_spelling_of_one_address_becomes_the_routers(
        self, value: str
    ) -> None:
        assert routeros_mac_address(value) == "AA:BB:CC:DD:EE:01"

    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            "UNKNOWN",
            "AABBCCDDEE01",  # not a form `mac-address=` is known to accept
            "AA:BB:CC:DD:EE",
            "AA:BB:CC:DD:EE:01:02",
            "GG:BB:CC:DD:EE:01",
            "10.5.50.254",
            12,
        ],
    )
    def test_anything_else_is_not_a_mac(self, value: object) -> None:
        assert routeros_mac_address(value) is None


@dataclass
class _Trusted:
    macs: list[str] = field(default_factory=list)

    async def list_active_entries_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[object]:
        return [SimpleNamespace(mac_address=mac) for mac in self.macs]


async def _login(fx: Fixture, identifier: str, mac: str) -> None:
    await fx.guest_service.login_via_otp(
        identifier=identifier,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
    )


async def _authorized_macs(fx: Fixture, trusted: _Trusted) -> list[str]:
    identity = AgentIdentity(router=fx.router, credential=None)  # type: ignore[arg-type]
    response = await agent_authorized_macs(
        identity=identity,
        guest_repository=fx.repository,
        mac_authorization_service=trusted,  # type: ignore[arg-type]
        access_decision_service=FakeAccessControlHook(),  # type: ignore[arg-type]
        captive_portal_service=fx.captive_portal_service,  # type: ignore[arg-type]
    )
    return response.mac_addresses


class TestAuthorizedMacsResponse:
    async def test_a_dash_separated_sign_in_is_listed_the_routers_way(self) -> None:
        fx = make_fixture(access_control_hook=FakeAccessControlHook())
        await _login(fx, "+15553330001", "aa-bb-cc-dd-ee-01")

        assert await _authorized_macs(fx, _Trusted()) == ["AA:BB:CC:DD:EE:01"]

    async def test_two_spellings_of_one_device_are_listed_once(self) -> None:
        fx = make_fixture(access_control_hook=FakeAccessControlHook())
        await _login(fx, "+15553330001", "AA:BB:CC:DD:EE:01")

        macs = await _authorized_macs(fx, _Trusted(macs=["aa-bb-cc-dd-ee-01"]))

        assert macs == ["AA:BB:CC:DD:EE:01"]

    async def test_a_value_that_is_not_a_mac_is_left_out_and_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """One malformed entry must not cost every other guest their
        access: it is dropped, the rest are served, and the drop is
        counted where an operator can find it."""
        fx = make_fixture(access_control_hook=FakeAccessControlHook())
        await _login(fx, "+15553330001", "AA:BB:CC:DD:EE:01")
        await _login(fx, "+15553330002", "not-a-mac")

        with caplog.at_level("WARNING"):
            macs = await _authorized_macs(fx, _Trusted())

        assert macs == ["AA:BB:CC:DD:EE:01"]
        dropped = [
            r
            for r in caplog.records
            if r.msg == "agent_authorized_macs_dropped_malformed"
        ]
        assert len(dropped) == 1
        assert dropped[0].dropped == 1

    async def test_a_clean_list_logs_nothing(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        fx = make_fixture(access_control_hook=FakeAccessControlHook())
        await _login(fx, "+15553330001", "AA:BB:CC:DD:EE:01")

        with caplog.at_level("WARNING"):
            await _authorized_macs(fx, _Trusted(macs=["AA:BB:CC:DD:EE:02"]))

        assert "agent_authorized_macs_dropped_malformed" not in caplog.text
