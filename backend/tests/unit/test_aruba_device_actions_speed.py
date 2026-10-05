"""Aruba Instant On: the guest drawer's device block/unblock and the venue's
guest-network speed (one cap for every device), both through Instant On's
cloud and both gated on cloud control.

Every Instant On request goes to the in-memory ``FakeSite`` of
``test_instant_on_cloud_control`` (an ``httpx.MockTransport``): nothing here
can reach Instant On. No real token, secret or customer MAC appears.
"""

from __future__ import annotations

import json
import uuid

import pytest

from app.domains.network_integration import instant_on_control as control
from app.domains.network_integration.exceptions import (
    ClientActionUnavailableError,
    LocationHasNoControllerError,
)
from app.domains.network_integration.service import (
    NAS_ONLY_DEVICE_BLOCK_NEEDS_CLOUD_REASON,
    nas_only_client_capabilities,
)
from tests.unit.test_instant_on_cloud_control import (  # noqa: F401 -- fixture
    MAC,
    NET,
    _settings,
    wired,
)

_ARUBA = "aruba_instant_on"


# ---------------------------------------------------------------------------
# Venue guest speed
# ---------------------------------------------------------------------------


class TestVenueGuestSpeedRead:
    async def test_closed_gate_sends_nothing(self, wired) -> None:  # noqa: ANN001, F811
        site, _, _, target = wired
        result = await control.read_venue_guest_speed(
            None,
            organization_id=None,
            location_id=target.location_id,
            settings=_settings(),
        )
        assert result.status == "unavailable"
        assert result.reason == "cloud_control_not_enabled"
        assert site.requests == []

    async def test_lists_guest_networks_without_any_secret(self, wired) -> None:  # noqa: ANN001, F811
        site, _, _, target = wired
        result = await control.read_venue_guest_speed(
            None,
            organization_id=target.organization_id,
            location_id=target.location_id,
            settings=_settings(),
        )
        assert result.status == "ok"
        (network,) = result.networks
        assert network.network_id == NET
        assert network.network_name == "WYFY_ARUBA"
        assert network.enabled is False
        assert "do-not-lose-me" not in repr(result)
        assert [r.method for r in site.requests] == ["GET"]


class TestVenueGuestSpeedWrite:
    async def test_applies_a_preset_both_ways_and_reads_it_back(self, wired) -> None:  # noqa: ANN001, F811
        site, _, _, target = wired
        result = await control.set_venue_guest_speed(
            None,
            organization_id=target.organization_id,
            location_id=target.location_id,
            network_id=NET,
            download_mbps=20,
            upload_mbps=10,
            settings=_settings(),
        )
        assert result.status == "applied"
        assert result.applied is not None
        assert (result.applied.download_mbps, result.applied.upload_mbps) == (20, 10)
        (put,) = site.writes()
        assert put.method == "PUT" and put.url.path.endswith(f"networksSummary/{NET}")
        body = json.loads(put.content)
        # The whole network goes back, its secret unchanged; only qos moves.
        assert body["preSharedKey"] == "do-not-lose-me"
        assert body["qos"]["perClientDownloadBandwidthLimitInMbps"] == 20
        assert body["qos"]["perClientUploadBandwidthLimitInMbps"] == 10
        assert body["qos"]["isBandwidthLimitEnabled"] is True
        assert "do-not-lose-me" not in repr(result)

    async def test_no_limit_clears_the_cap(self, wired) -> None:  # noqa: ANN001, F811
        site, _, _, target = wired
        await control.set_venue_guest_speed(
            None,
            organization_id=target.organization_id,
            location_id=target.location_id,
            network_id=NET,
            download_mbps=50,
            upload_mbps=50,
            settings=_settings(),
        )
        result = await control.set_venue_guest_speed(
            None,
            organization_id=target.organization_id,
            location_id=target.location_id,
            network_id=NET,
            download_mbps=None,
            upload_mbps=None,
            settings=_settings(),
        )
        assert result.status == "applied"
        assert result.applied is not None and result.applied.enabled is False
        assert site.network["qos"]["isBandwidthLimitEnabled"] is False

    async def test_a_write_instant_on_did_not_keep_is_failed(self, wired) -> None:  # noqa: ANN001, F811
        site, _, _, target = wired
        site.ignore_writes = True
        result = await control.set_venue_guest_speed(
            None,
            organization_id=target.organization_id,
            location_id=target.location_id,
            network_id=NET,
            download_mbps=30,
            upload_mbps=30,
            settings=_settings(),
        )
        assert result.status == "failed"
        assert result.reason == "write_not_confirmed"

    @pytest.mark.parametrize("value", [5, 15, 101, 1000, 0, True])
    async def test_only_presets_are_accepted(self, wired, value) -> None:  # noqa: ANN001, F811
        site, _, _, target = wired
        with pytest.raises(ValueError):
            await control.set_venue_guest_speed(
                None,
                organization_id=target.organization_id,
                location_id=target.location_id,
                network_id=NET,
                download_mbps=value,
                upload_mbps=None,
                settings=_settings(),
            )
        assert site.requests == []

    async def test_a_network_not_on_the_site_or_not_guest_is_never_written(
        self,
        wired,  # noqa: ANN001, F811
    ) -> None:
        site, _, _, target = wired
        result = await control.set_venue_guest_speed(
            None,
            organization_id=target.organization_id,
            location_id=target.location_id,
            network_id="someone-elses-net",
            download_mbps=10,
            upload_mbps=10,
            settings=_settings(),
        )
        assert result.status == "failed" and result.reason == "network_not_found"
        site.network["isGuestPortalEnabled"] = False  # a staff network
        result = await control.set_venue_guest_speed(
            None,
            organization_id=target.organization_id,
            location_id=target.location_id,
            network_id=NET,
            download_mbps=10,
            upload_mbps=10,
            settings=_settings(),
        )
        assert result.status == "failed" and result.reason == "network_not_found"
        assert site.writes() == []

    async def test_closed_gate_writes_nothing(self, wired) -> None:  # noqa: ANN001, F811
        site, _, _, target = wired
        result = await control.set_venue_guest_speed(
            None,
            organization_id=None,
            location_id=target.location_id,
            network_id=NET,
            download_mbps=10,
            upload_mbps=10,
            settings=_settings(),
        )
        assert result.status == "unavailable"
        assert site.requests == []

    def test_presets_are_ten_to_one_hundred(self) -> None:
        assert tuple(range(10, 101, 10)) == control.GUEST_SPEED_PRESETS_MBPS


# ---------------------------------------------------------------------------
# Drawer: Block device / Allow device at an Aruba venue
# ---------------------------------------------------------------------------


class _RepoWithSession:
    """The FakeRepository plus a ``session`` attribute (the real repository
    has one); the Instant On calls are monkeypatched, so it is never used."""

    def __new__(cls):  # noqa: ANN204
        from tests.unit.test_network_integration import FakeRepository

        repo = FakeRepository()
        repo.session = object()  # type: ignore[attr-defined]
        return repo


def _service(repo):  # noqa: ANN001, ANN202
    from tests.unit.test_omada_client_management import _service as make

    return make(repo)


@pytest.fixture
def instant_on_calls(monkeypatch):  # noqa: ANN001, ANN201
    calls: list[tuple[str, str]] = []
    state = {"status": "enforced", "present": True}

    def fake(action: str):  # noqa: ANN202
        async def call(session, **kwargs):  # noqa: ANN001, ANN003, ANN202
            calls.append((action, kwargs["client_mac"]))
            return control.DeviceWriteOutcome(
                status=state["status"],
                error_code="write_not_confirmed"
                if state["status"] == "failed"
                else None,
            )

        return call

    async def present(session, **kwargs):  # noqa: ANN001, ANN003, ANN202
        return state["present"]

    monkeypatch.setattr(control, "instant_on_block_device", fake("block"))
    monkeypatch.setattr(control, "instant_on_release_device", fake("unblock"))
    monkeypatch.setattr(control, "instant_on_control_present", present)
    return calls, state


class TestDrawerDeviceBlockAtAruba:
    async def test_block_goes_to_instant_on_and_reports_the_read_back(
        self,
        instant_on_calls,  # noqa: ANN001
    ) -> None:
        calls, _ = instant_on_calls
        repo = _RepoWithSession()
        org, loc = uuid.uuid4(), uuid.uuid4()
        repo.nas_only_rows[(loc, org)] = _ARUBA
        result = await _service(repo).block_client(
            location_id=loc, organization_id=org, client_mac=MAC, actor_user_id=None
        )
        assert result.performed is True and result.action == "block"
        assert calls == [("block", MAC)]
        result = await _service(repo).unblock_client(
            location_id=loc, organization_id=org, client_mac=MAC, actor_user_id=None
        )
        assert result.performed is True and calls[-1] == ("unblock", MAC)

    async def test_an_unconfirmed_block_is_not_performed(
        self, instant_on_calls
    ) -> None:  # noqa: ANN001
        _, state = instant_on_calls
        state["status"] = "failed"
        repo = _RepoWithSession()
        org, loc = uuid.uuid4(), uuid.uuid4()
        repo.nas_only_rows[(loc, org)] = _ARUBA
        result = await _service(repo).block_client(
            location_id=loc, organization_id=org, client_mac=MAC, actor_user_id=None
        )
        assert result.performed is False

    async def test_cloud_control_off_says_what_is_needed(
        self, instant_on_calls
    ) -> None:  # noqa: ANN001
        _, state = instant_on_calls
        state["status"] = "unavailable"
        repo = _RepoWithSession()
        org, loc = uuid.uuid4(), uuid.uuid4()
        repo.nas_only_rows[(loc, org)] = _ARUBA
        with pytest.raises(ClientActionUnavailableError) as raised:
            await _service(repo).block_client(
                location_id=loc, organization_id=org, client_mac=MAC, actor_user_id=None
            )
        assert NAS_ONLY_DEVICE_BLOCK_NEEDS_CLOUD_REASON in str(
            raised.value.message
        ) or (NAS_ONLY_DEVICE_BLOCK_NEEDS_CLOUD_REASON in str(raised.value))

    async def test_another_tenant_or_a_plain_location_is_not_found(
        self,
        instant_on_calls,  # noqa: ANN001
    ) -> None:
        calls, _ = instant_on_calls
        repo = _RepoWithSession()
        org, loc = uuid.uuid4(), uuid.uuid4()
        repo.nas_only_rows[(loc, org)] = _ARUBA
        with pytest.raises(LocationHasNoControllerError):
            await _service(repo).block_client(
                location_id=loc,
                organization_id=uuid.uuid4(),
                client_mac=MAC,
                actor_user_id=None,
            )
        with pytest.raises(LocationHasNoControllerError):
            await _service(repo).unblock_client(
                location_id=uuid.uuid4(),
                organization_id=org,
                client_mac=MAC,
                actor_user_id=None,
            )
        assert calls == []

    async def test_capabilities_follow_cloud_control(self, instant_on_calls) -> None:  # noqa: ANN001
        _, state = instant_on_calls
        repo = _RepoWithSession()
        org, loc = uuid.uuid4(), uuid.uuid4()
        repo.nas_only_rows[(loc, org)] = _ARUBA
        report = await _service(repo).get_client_capabilities(
            location_id=loc, organization_id=org
        )
        assert report.capabilities["block"]["supported"] is True
        assert report.capabilities["unblock"]["supported"] is True
        assert report.capabilities["set_rate_limit"]["supported"] is False
        state["present"] = False
        report = await _service(repo).get_client_capabilities(
            location_id=loc, organization_id=org
        )
        assert report.capabilities["block"] == {
            "supported": False,
            "reason": NAS_ONLY_DEVICE_BLOCK_NEEDS_CLOUD_REASON,
        }

    def test_the_block_reason_never_says_cant_disconnect(self) -> None:
        caps = nas_only_client_capabilities().capabilities
        assert "disconnect" not in (caps["block"]["reason"] or "").lower()
        assert "Blocked Guests" in (caps["block"]["reason"] or "")


# ---------------------------------------------------------------------------
# Routes: scopes pinned, no new permission key
# ---------------------------------------------------------------------------


def _gates(router):  # noqa: ANN001, ANN202
    found = {}
    for route in router.routes:
        for dep in route.dependencies:
            call = dep.dependency
            if "RequirePermission" not in getattr(call, "__qualname__", ""):
                continue
            cells = dict(
                zip(
                    call.__code__.co_freevars,
                    (c.cell_contents for c in call.__closure__),
                    strict=True,
                )
            )
            for method in route.methods:
                found[(method, route.path)] = (cells["permission_key"], cells["scope"])
    return found


def test_guest_speed_routes_are_org_scoped_existing_permissions() -> None:
    from app.domains.network_integration.instant_on_router import (
        instant_on_customer_router,
    )
    from app.domains.rbac.enums import ScopeType

    gates = _gates(instant_on_customer_router)
    path = "/network-integrations/locations/{location_id}/instant-on/guest-speed"
    assert gates[("GET", path)] == ("locations.read", ScopeType.ORGANIZATION)
    assert gates[("PUT", path)] == ("bandwidth.update", ScopeType.ORGANIZATION)


def test_speed_control_view_carries_the_cloud_flag() -> None:
    from app.domains.queue_management.speed_gateway_router import SpeedControlView

    assert SpeedControlView(per_guest_speed=False).model_dump() == {
        "per_guest_speed": False,
        "instant_on_cloud_control": False,
    }


# ---------------------------------------------------------------------------
# Guests & devices tab: a BLOCKLIST device rule at an Aruba venue
# ---------------------------------------------------------------------------


class _FakeInstantOn:
    def __init__(self, status: str = "enforced") -> None:
        self.status = status
        self.calls: list[tuple[str, str]] = []

    async def block(self, *, router, mac_address):  # noqa: ANN001, ANN201
        self.calls.append(("block", mac_address))
        return self.status, (None if self.status == "enforced" else "nope")

    async def release(self, *, router, mac_address):  # noqa: ANN001, ANN201
        self.calls.append(("release", mac_address))
        return self.status, (None if self.status == "enforced" else "nope")


def _device_rule_harness(instant_on: _FakeInstantOn):  # noqa: ANN202
    from app.domains.guest_access.device_blocking import RouterDeviceBlocker
    from app.domains.guest_access.service import GuestAccessService
    from tests.unit.test_guest_access import FakeAuditLogWriter, FakeLocationLookup
    from tests.unit.test_guest_access_device_block import H, _Repo, _Routers

    org, location = uuid.uuid4(), uuid.uuid4()
    repo, routers = _Repo(), _Routers()
    lookup = FakeLocationLookup()
    lookup.add(location, org)
    service = GuestAccessService(
        repo,
        block_enforcer=None,
        location_lookup=lookup,
        audit_writer=FakeAuditLogWriter(),
        device_blocker=RouterDeviceBlocker(router_lookup=routers, nas_only=instant_on),
    )
    return H(service, repo, routers, org, location)


class TestDeviceRuleAtAruba:
    async def test_cloud_control_on_blocks_on_instant_on_and_releases(self) -> None:
        from tests.unit.test_guest_access_device_block import _block, _router

        instant_on = _FakeInstantOn()
        h = _device_rule_harness(instant_on)
        h.routers.add(_router(h.org, h.location, vendor=_ARUBA))
        rule = await _block(h)
        assert [b.status for b in rule.router_blocks] == ["enforced"]
        assert [c[0] for c in instant_on.calls] == ["block"]
        await h.service.deactivate_device_rule(
            rule_id=rule.id, requesting_organization_id=h.org, actor_user_id=None
        )
        assert instant_on.calls[-1][0] == "release"
        assert rule.router_blocks[0].cleared_at is not None

    async def test_cloud_control_off_records_not_applicable_with_the_reason(
        self,
    ) -> None:
        from app.domains.guest_access.device_blocking import (
            NAS_ONLY_DEVICE_BLOCK_UNAVAILABLE,
        )
        from tests.unit.test_guest_access_device_block import _block, _router

        instant_on = _FakeInstantOn(status="unavailable")
        h = _device_rule_harness(instant_on)
        h.routers.add(_router(h.org, h.location, vendor=_ARUBA))
        rule = await _block(h)
        (block,) = rule.router_blocks
        assert block.status == "not_applicable"
        assert block.error_message == NAS_ONLY_DEVICE_BLOCK_UNAVAILABLE
        assert rule.is_active  # the sign-in refusal still stands
        await h.service.deactivate_device_rule(
            rule_id=rule.id, requesting_organization_id=h.org, actor_user_id=None
        )
        assert [c[0] for c in instant_on.calls] == ["block"]  # nothing to release

    async def test_an_unconfirmed_instant_on_block_is_failed(self) -> None:
        from tests.unit.test_guest_access_device_block import _block, _router

        h = _device_rule_harness(_FakeInstantOn(status="failed"))
        h.routers.add(_router(h.org, h.location, vendor=_ARUBA))
        rule = await _block(h)
        assert [b.status for b in rule.router_blocks] == ["failed"]
        assert rule.router_blocks[0].blocked_at is None
