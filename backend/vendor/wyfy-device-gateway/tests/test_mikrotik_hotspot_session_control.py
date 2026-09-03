"""Ending a live captive-portal session, and reading -- never assuming --
whether the router would accept a RADIUS Disconnect instead.

Every test here asserts a *behaviour change on the fake device's tables*,
not that a method was called: the bug being fixed was a code path that
returned success while touching nothing, so a test that only checks a call
happened would pass against the bug.
"""

from __future__ import annotations

import pytest
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError

from tests.fake_write_transport import FakeRouterOSApi

_HOTSPOT = ("ip", "hotspot")
_ACTIVE = ("ip", "hotspot", "active")
_RADIUS_INCOMING = ("radius", "incoming")


def _api(active_rows, *, coa_accept=True, coa_port="3799", hotspot=True):
    menus = {
        _HOTSPOT: [{".id": "*1", "name": "hotspot1"}] if hotspot else [],
        _ACTIVE: list(active_rows),
        _RADIUS_INCOMING: [{".id": "*0", "accept": coa_accept, "port": coa_port}],
    }
    return FakeRouterOSApi(menus=menus)


def _row(row_id, *, user, mac, address="10.5.50.20"):
    return {".id": row_id, "user": user, "mac-address": mac, "address": address}


# ============================================================================
# The session really ends
# ============================================================================


@pytest.mark.asyncio
async def test_matching_session_is_removed_from_the_active_table(
    patch_connect, mikrotik_creds
):
    """The whole point. Before this method existed, blocking a guest
    changed nothing on the router; the row below survived and RouterOS
    kept forwarding for them."""
    api = _api(
        [
            _row("*A", user="+919876543210", mac="AA:BB:CC:DD:EE:01"),
            _row("*B", user="+911111111111", mac="AA:BB:CC:DD:EE:02"),
        ]
    )
    patch_connect(api)

    result = await MikroTikAdapter().end_hotspot_sessions(
        mikrotik_creds, mac_address="AA:BB:CC:DD:EE:01", username="+919876543210"
    )

    remaining = [row[".id"] for row in api._menus[_ACTIVE]]
    assert remaining == ["*B"], "the blocked guest's row must be gone"
    assert result.removed_ids == ("*A",)
    assert result.still_active == ()
    # Removal is per-row by .id, never a broad ``remove [find]``.
    assert api.remove_calls == [(_ACTIVE, ("*A",))]


@pytest.mark.asyncio
async def test_a_guest_is_matched_by_username_alone_when_no_mac_is_known(
    patch_connect, mikrotik_creds
):
    """``GuestSession.device_id`` is nullable, so a real session can reach
    this with no MAC at all. Matching on the portal ``user`` is what keeps
    that guest blockable rather than silently skipped."""
    api = _api([_row("*A", user="guest@example.com", mac="AA:BB:CC:DD:EE:01")])
    patch_connect(api)

    result = await MikroTikAdapter().end_hotspot_sessions(
        mikrotik_creds, mac_address=None, username="guest@example.com"
    )

    assert api._menus[_ACTIVE] == []
    assert result.removed_ids == ("*A",)


@pytest.mark.asyncio
async def test_a_guest_is_matched_by_mac_alone_when_the_device_user_differs(
    patch_connect, mikrotik_creds
):
    """The 2026-08-18 RADIUS incident turned up live sessions whose ``user``
    on the device did not match what this platform had stored. Passing the
    MAC as well is what keeps those endable."""
    api = _api([_row("*A", user="something-else", mac="aa:bb:cc:dd:ee:01")])
    patch_connect(api)

    result = await MikroTikAdapter().end_hotspot_sessions(
        mikrotik_creds, mac_address="AA:BB:CC:DD:EE:01", username="+919876543210"
    )

    assert api._menus[_ACTIVE] == []
    assert result.removed_ids == ("*A",)


@pytest.mark.asyncio
async def test_a_still_present_row_is_reported_rather_than_claimed_gone(
    patch_connect, mikrotik_creds
):
    """A router that accepts the remove and keeps the session must not
    produce a success. This is the read-back that turns "the call did not
    raise" into "the row is gone"."""

    class _RefusingApi(FakeRouterOSApi):
        def path(self, *segments: str):
            path = super().path(*segments)
            if segments == _ACTIVE:
                path.remove = lambda *ids: None  # accepted, ignored
            return path

    api = _RefusingApi(
        menus={
            _HOTSPOT: [{".id": "*1", "name": "hotspot1"}],
            _ACTIVE: [_row("*A", user="u", mac="AA:BB:CC:DD:EE:01")],
            _RADIUS_INCOMING: [{".id": "*0", "accept": False, "port": "3799"}],
        }
    )
    patch_connect(api)

    result = await MikroTikAdapter().end_hotspot_sessions(
        mikrotik_creds, mac_address="AA:BB:CC:DD:EE:01", username="u"
    )

    assert result.removed_ids == ("*A",)
    assert [row.routeros_id for row in result.still_active] == ["*A"]


# ============================================================================
# Idempotence and blast radius
# ============================================================================


@pytest.mark.asyncio
async def test_no_matching_session_removes_nothing_and_raises_nothing(
    patch_connect, mikrotik_creds
):
    """Blocking a guest who is already offline, or blocking one twice, is
    a no-op -- not an error, and not a removal of somebody else."""
    api = _api([_row("*B", user="other", mac="AA:BB:CC:DD:EE:02")])
    patch_connect(api)

    result = await MikroTikAdapter().end_hotspot_sessions(
        mikrotik_creds, mac_address="AA:BB:CC:DD:EE:01", username="+919876543210"
    )

    assert api.remove_calls == []
    assert result.matched == ()
    assert [row[".id"] for row in api._menus[_ACTIVE]] == ["*B"]


@pytest.mark.asyncio
async def test_both_identifiers_none_ends_zero_sessions(patch_connect, mikrotik_creds):
    """A block whose subject could not be identified must end nothing.
    A predicate that matched everything here would log every guest on the
    router off."""
    api = _api(
        [
            _row("*A", user="a", mac="AA:BB:CC:DD:EE:01"),
            _row("*B", user="b", mac="AA:BB:CC:DD:EE:02"),
        ]
    )
    patch_connect(api)

    result = await MikroTikAdapter().end_hotspot_sessions(
        mikrotik_creds, mac_address=None, username=None
    )

    assert api.remove_calls == []
    assert result.matched == ()
    assert len(api._menus[_ACTIVE]) == 2


# ============================================================================
# CoA availability is read from the device, never assumed
# ============================================================================


@pytest.mark.asyncio
async def test_coa_accept_false_is_reported_as_unavailable(
    patch_connect, mikrotik_creds
):
    """The lab router's own state: ``/radius incoming accept=FALSE
    port=3799``. Port 3799 is not RouterOS's default (1700) -- it is what
    this codebase writes, in the same statement that sets ``accept=yes``.
    Inferring availability from "we configured it" is wrong about this
    router."""
    api = _api([], coa_accept=False, coa_port="3799")
    patch_connect(api)

    control = await MikroTikAdapter().read_hotspot_session_control(mikrotik_creds)

    assert control.coa_accept is False
    assert control.coa_port == 3799
    assert control.hotspot_servers == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [True, "yes", "true"])
async def test_a_truthy_accept_is_read_as_available_in_every_shape(
    patch_connect, mikrotik_creds, raw
):
    """RouterOS answers a read with a real ``bool`` but accepts
    ``"yes"``/``"true"`` on write, and a fake or older firmware may hand
    back either. String-comparing is how a live ``True`` gets read as
    disabled."""
    patch_connect(_api([], coa_accept=raw))

    control = await MikroTikAdapter().read_hotspot_session_control(mikrotik_creds)

    assert control.coa_accept is True


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [False, "no", "false"])
async def test_a_falsy_accept_is_read_as_unavailable_in_every_shape(
    patch_connect, mikrotik_creds, raw
):
    patch_connect(_api([], coa_accept=raw))

    control = await MikroTikAdapter().read_hotspot_session_control(mikrotik_creds)

    assert control.coa_accept is False


@pytest.mark.asyncio
async def test_ending_a_session_never_writes_to_radius_incoming(
    patch_connect, mikrotik_creds
):
    """Reading ``accept=no`` is not a licence to repair it. Changing a live
    router's RADIUS configuration as a side effect of a customer clicking
    "Block" is the kind of change that took the guest network down; the
    honest move is to report it so an operator repairs it deliberately
    through ``set_radius_client_config``, which owns that setting."""
    api = _api(
        [_row("*A", user="u", mac="AA:BB:CC:DD:EE:01")],
        coa_accept=False,
    )
    patch_connect(api)

    await MikroTikAdapter().end_hotspot_sessions(
        mikrotik_creds, mac_address="AA:BB:CC:DD:EE:01", username="u"
    )

    touched = [segments for segments, _ in api.update_calls + api.add_calls]
    assert _RADIUS_INCOMING not in touched
    assert api._menus[_RADIUS_INCOMING][0]["accept"] is False


@pytest.mark.asyncio
async def test_an_unreadable_radius_incoming_menu_reports_no_coa_rather_than_failing(
    patch_connect, mikrotik_creds
):
    """A router with no ``/radius incoming`` menu cannot accept a
    Disconnect either. The session-ending path does not depend on it, so
    this degrades to "no CoA" instead of aborting a block."""
    api = FakeRouterOSApi(
        menus={
            _HOTSPOT: [{".id": "*1", "name": "hotspot1"}],
            _ACTIVE: [],
        },
        missing_menus={_RADIUS_INCOMING},
    )
    patch_connect(api)

    control = await MikroTikAdapter().read_hotspot_session_control(mikrotik_creds)

    assert control.coa_accept is False
    assert control.coa_port is None


# ============================================================================
# Failures are raised, never swallowed
# ============================================================================


@pytest.mark.asyncio
async def test_an_unreadable_active_table_raises(patch_connect, mikrotik_creds):
    """Unlike ``disconnect_device``'s optional wireless menu, this one is
    fatal: without ``/ip hotspot active`` there is no way to tell whether
    the guest is still online, and reporting success would be a guess."""
    api = FakeRouterOSApi(
        menus={
            _HOTSPOT: [{".id": "*1", "name": "hotspot1"}],
            _RADIUS_INCOMING: [{".id": "*0", "accept": True, "port": "3799"}],
        },
        missing_menus={_ACTIVE},
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().end_hotspot_sessions(
            mikrotik_creds, mac_address="AA:BB:CC:DD:EE:01", username="u"
        )


@pytest.mark.asyncio
async def test_a_router_with_no_hotspot_reports_zero_servers(
    patch_connect, mikrotik_creds
):
    """``hotspot_servers == 0`` is what lets the caller tell "removed
    nothing because they were not online" from "removed nothing because
    this router has no captive portal at all"."""
    patch_connect(_api([], hotspot=False))

    result = await MikroTikAdapter().end_hotspot_sessions(
        mikrotik_creds, mac_address="AA:BB:CC:DD:EE:01", username="u"
    )

    assert result.control.hotspot_servers == 0
