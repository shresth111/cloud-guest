"""``/ip dhcp-server option`` -- the menu this platform could not write.

Every fixture in this module is the state read off the live venue router
over the API (serial HJP0ATMRJ6X, enrolled as "Office Guest"), not a shape
invented for a test:

    /ip/dhcp-server/option
      name cloudguest-captive-portal  code 114  force True
      value 'https://master.wyfyguest.com/api/v1/captive-portal/rfc8908?...'
    /ip/dhcp-server/option/sets
      name cloudguest-opts  options cloudguest-captive-portal
    /ip/dhcp-server/network
      address 10.5.50.0/24  dhcp-option-set 'cloudguest-opts'

The three things worth asserting, all of which cost real time on hardware
to establish:

1. removal happens in the order detach -> set -> option, because RouterOS
   refuses every other order;
2. detaching clears ``dhcp-option-set`` with ``set dhcp-option-set=none``,
   the only one of three shapes that works on 7.23.3. ``set field=""``
   fails with "ambiguous value of dhcp-option-set, more than one possible
   value matches input"; bare ``unset`` fails with "input does not match
   any value of value-name"; and the *documented* ``!`` prefix is accepted
   and silently changes nothing -- which is why every clear is proved by
   re-reading the row rather than by a clean return;
3. the option is matched by **name**, never by ``code=114``.

The last block of this file runs against a fake configured with those two
rejections, i.e. against the router as it really answers. Everything above
that block runs against a permissive fake, which is precisely how a removal
path that could not work on hardware passed a green suite.
"""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import DhcpOptionConfig
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError

_OPTION_NAME = "cloudguest-captive-portal"
_SET_NAME = "cloudguest-opts"
_VALUE = (
    "https://master.wyfyguest.com/api/v1/captive-portal/rfc8908"
    "?portal_url=http://wifi.wyfyguest.com/"
)

_OPTION_PATH = ("ip", "dhcp-server", "option")
_SET_PATH = ("ip", "dhcp-server", "option", "sets")
_NETWORK_PATH = ("ip", "dhcp-server", "network")


def _spec(**overrides) -> DhcpOptionConfig:
    fields = {
        "name": _OPTION_NAME,
        "code": 114,
        "value": _VALUE,
        "force": True,
        "option_set_name": _SET_NAME,
        "network_addresses": ("10.5.50.0/24",),
    }
    fields.update(overrides)
    return DhcpOptionConfig(**fields)


def _venue_router() -> FakeRouterOSApi:
    """The live router's actual state, as read over 8728."""
    return FakeRouterOSApi(
        menus={
            _OPTION_PATH: [
                {
                    ".id": "*1",
                    "name": _OPTION_NAME,
                    "code": "114",
                    "value": _VALUE,
                    "force": True,
                }
            ],
            _SET_PATH: [{".id": "*1", "name": _SET_NAME, "options": _OPTION_NAME}],
            _NETWORK_PATH: [
                {
                    ".id": "*1",
                    "address": "10.5.50.0/24",
                    "gateway": "10.5.50.1",
                    "dhcp-option-set": _SET_NAME,
                }
            ],
        }
    )


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_reports_the_option_its_set_and_where_it_is_bound(
    patch_connect, mikrotik_creds
):
    patch_connect(_venue_router())

    snapshot = await MikroTikAdapter().read_dhcp_options(mikrotik_creds)

    assert snapshot.supported is True
    found = snapshot.option(_OPTION_NAME)
    assert found is not None
    assert (found.code, found.value, found.force) == (114, _VALUE, True)
    assert [s.name for s in snapshot.option_sets] == [_SET_NAME]
    assert [(b.menu, b.identity, b.option_set_name) for b in snapshot.bindings] == [
        ("ip/dhcp-server/network", "10.5.50.0/24", _SET_NAME)
    ]


@pytest.mark.asyncio
async def test_a_router_with_no_option_menu_is_unsupported_not_empty(
    patch_connect, mikrotik_creds
):
    """"We could not ask" and "it answered none" are different facts.

    A fleet audit that flattened them would report every router whose
    RouterOS lacks the menu as clean -- certifying exactly the devices
    nobody has actually checked.
    """
    patch_connect(FakeRouterOSApi(missing_menus={_OPTION_PATH}))

    snapshot = await MikroTikAdapter().read_dhcp_options(mikrotik_creds)

    assert snapshot.supported is False
    assert snapshot.options == ()


@pytest.mark.asyncio
async def test_read_writes_nothing(patch_connect, mikrotik_creds):
    api = _venue_router()
    patch_connect(api)

    await MikroTikAdapter().read_dhcp_options(mikrotik_creds)

    assert api.ops == []


# ---------------------------------------------------------------------------
# removal -- the fix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_removal_clears_the_option_the_set_and_the_binding(
    patch_connect, mikrotik_creds
):
    api = _venue_router()
    patch_connect(api)

    removal = await MikroTikAdapter().delete_dhcp_option(
        mikrotik_creds, option=_spec()
    )

    assert list(api.path(*_OPTION_PATH)) == []
    assert list(api.path(*_SET_PATH)) == []
    assert "dhcp-option-set" not in list(api.path(*_NETWORK_PATH))[0]
    assert removal.option_removed is True
    assert removal.option_sets_removed == (_SET_NAME,)
    assert removal.bindings_detached == ("ip/dhcp-server/network:10.5.50.0/24",)
    assert removal.changed is True


@pytest.mark.asyncio
async def test_the_network_row_itself_survives(patch_connect, mikrotik_creds):
    """Only the option binding comes off. The row hands out the subnet's
    gateway; removing it would take a working venue offline."""
    api = _venue_router()
    patch_connect(api)

    await MikroTikAdapter().delete_dhcp_option(mikrotik_creds, option=_spec())

    rows = list(api.path(*_NETWORK_PATH))
    assert len(rows) == 1
    assert rows[0]["gateway"] == "10.5.50.1"


@pytest.mark.asyncio
async def test_the_binding_is_cleared_with_the_bang_prefix_never_set_to_empty(
    patch_connect, mikrotik_creds
):
    """The single most expensive fact in this file.

    ``set dhcp-option-set=""`` does not clear the field on real hardware:
    ``dhcp-option-set`` is a name-reference property, RouterOS resolves
    name-typed values by prefix, and "" prefixes every candidate -- so it
    fails with "ambiguous value of dhcp-option-set, more than one possible
    value matches input".

    The documented clear is the ``!`` prefix on ``set`` ("The parameter can
    be unset by specifying '!' before the parameter"), which on the wire is
    the attribute word ``=!dhcp-option-set=``. If someone "simplifies" this
    back into a plain update, this test is what says no.
    """
    api = _venue_router()
    patch_connect(api)

    await MikroTikAdapter().delete_dhcp_option(mikrotik_creds, option=_spec())

    assert (_NETWORK_PATH, {".id": "*1", "!dhcp-option-set": ""}) in api.update_calls
    assert not any(
        fields.get("dhcp-option-set") == "" for _, fields in api.update_calls
    )


@pytest.mark.asyncio
async def test_removal_order_is_detach_then_set_then_option(
    patch_connect, mikrotik_creds
):
    """RouterOS refuses to remove an option a set still lists, and a set a
    network row still names. Any other order fails partway and leaves the
    option still being handed out."""
    api = _venue_router()
    patch_connect(api)

    await MikroTikAdapter().delete_dhcp_option(mikrotik_creds, option=_spec())

    kinds = [(op, segments) for op, segments, _ in api.ops]
    # The clear may take more than one sentence -- the ladder tries shapes
    # until the device says the field is empty -- so what is asserted is the
    # *order of the three phases*, not a fixed sentence count.
    assert kinds[-2:] == [("remove", _SET_PATH), ("remove", _OPTION_PATH)]
    assert kinds[:-2], "the binding must be detached before anything is removed"
    assert all(
        (op, segments) == ("update", _NETWORK_PATH) for op, segments in kinds[:-2]
    )


@pytest.mark.asyncio
async def test_removing_twice_is_a_no_op(patch_connect, mikrotik_creds):
    api = _venue_router()
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.delete_dhcp_option(mikrotik_creds, option=_spec())
    api.ops.clear()
    second = await adapter.delete_dhcp_option(mikrotik_creds, option=_spec())

    assert api.ops == []
    assert second.changed is False


@pytest.mark.asyncio
async def test_removing_from_a_router_that_never_had_it_is_a_no_op(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={_NETWORK_PATH: [{".id": "*1", "address": "10.5.50.0/24"}]}
    )
    patch_connect(api)

    removal = await MikroTikAdapter().delete_dhcp_option(
        mikrotik_creds, option=_spec()
    )

    assert removal.changed is False
    assert api.ops == []


@pytest.mark.asyncio
async def test_an_option_on_the_same_code_with_another_name_is_left_alone(
    patch_connect, mikrotik_creds
):
    """A venue running its own option on code 114 is a real configuration,
    not a mistake, and deleting it would be a worse outage than the one
    being fixed. Identity is the name; ``code`` is never a match key."""
    api = FakeRouterOSApi(
        menus={
            _OPTION_PATH: [
                {".id": "*1", "name": "venue-pxe", "code": "114", "value": "tftp://x"}
            ],
            _SET_PATH: [{".id": "*1", "name": "venue-opts", "options": "venue-pxe"}],
            _NETWORK_PATH: [
                {
                    ".id": "*1",
                    "address": "10.5.50.0/24",
                    "dhcp-option-set": "venue-opts",
                }
            ],
        }
    )
    patch_connect(api)

    removal = await MikroTikAdapter().delete_dhcp_option(
        mikrotik_creds, option=_spec()
    )

    assert removal.changed is False
    assert [r["name"] for r in api.path(*_OPTION_PATH)] == ["venue-pxe"]
    assert [r["name"] for r in api.path(*_SET_PATH)] == ["venue-opts"]
    assert list(api.path(*_NETWORK_PATH))[0]["dhcp-option-set"] == "venue-opts"


@pytest.mark.asyncio
async def test_a_shared_option_set_is_shrunk_not_deleted(
    patch_connect, mikrotik_creds
):
    """A set that also carries somebody else's option loses our entry and
    keeps theirs -- and stays attached to the network row, because the
    other option still has to reach clients."""
    api = FakeRouterOSApi(
        menus={
            _OPTION_PATH: [
                {".id": "*1", "name": _OPTION_NAME, "code": "114", "value": _VALUE},
                {".id": "*2", "name": "venue-pxe", "code": "66", "value": "tftp://x"},
            ],
            _SET_PATH: [
                {
                    ".id": "*1",
                    "name": _SET_NAME,
                    "options": f"{_OPTION_NAME},venue-pxe",
                }
            ],
            _NETWORK_PATH: [
                {".id": "*1", "address": "10.5.50.0/24", "dhcp-option-set": _SET_NAME}
            ],
        }
    )
    patch_connect(api)

    removal = await MikroTikAdapter().delete_dhcp_option(
        mikrotik_creds, option=_spec()
    )

    assert removal.option_sets_removed == ()
    assert removal.option_sets_rewritten == (_SET_NAME,)
    assert list(api.path(*_SET_PATH))[0]["options"] == "venue-pxe"
    # Still bound: venue-pxe is in that set and must keep reaching clients.
    assert list(api.path(*_NETWORK_PATH))[0]["dhcp-option-set"] == _SET_NAME
    assert api.unset_calls == []
    assert [r["name"] for r in api.path(*_OPTION_PATH)] == ["venue-pxe"]


@pytest.mark.asyncio
async def test_a_direct_dhcp_option_list_is_edited_not_unset(
    patch_connect, mikrotik_creds
):
    """``dhcp-option`` is a *list* field. Unsetting the whole thing to
    remove one entry would drop another feature's option on the way past;
    only an empty remainder gets unset."""
    api = FakeRouterOSApi(
        menus={
            _OPTION_PATH: [
                {".id": "*1", "name": _OPTION_NAME, "code": "114", "value": _VALUE}
            ],
            _NETWORK_PATH: [
                {
                    ".id": "*1",
                    "address": "10.5.50.0/24",
                    "dhcp-option": f"{_OPTION_NAME},venue-pxe",
                },
                {
                    ".id": "*2",
                    "address": "10.6.0.0/24",
                    "dhcp-option": _OPTION_NAME,
                },
            ],
        }
    )
    patch_connect(api)

    await MikroTikAdapter().delete_dhcp_option(mikrotik_creds, option=_spec())

    rows = {r["address"]: r for r in api.path(*_NETWORK_PATH)}
    assert rows["10.5.50.0/24"]["dhcp-option"] == "venue-pxe"
    assert "dhcp-option" not in rows["10.6.0.0/24"]
    # The row that still has another option is *rewritten*; only the row
    # whose remainder is empty is cleared outright.
    assert (_NETWORK_PATH, {".id": "*1", "dhcp-option": "venue-pxe"}) in (
        api.update_calls
    )
    assert (_NETWORK_PATH, {".id": "*2", "!dhcp-option": ""}) in api.update_calls


@pytest.mark.asyncio
async def test_a_lease_row_binding_is_detached_too(patch_connect, mikrotik_creds):
    """``/ip dhcp-server lease`` carries the same two fields, and a
    per-lease binding survives a network-only sweep."""
    api = FakeRouterOSApi(
        menus={
            _OPTION_PATH: [{".id": "*1", "name": _OPTION_NAME, "code": "114"}],
            _SET_PATH: [{".id": "*1", "name": _SET_NAME, "options": _OPTION_NAME}],
            ("ip", "dhcp-server", "lease"): [
                {".id": "*9", "address": "10.5.50.44", "dhcp-option-set": _SET_NAME}
            ],
        }
    )
    patch_connect(api)

    removal = await MikroTikAdapter().delete_dhcp_option(
        mikrotik_creds, option=_spec()
    )

    assert removal.bindings_detached == ("ip/dhcp-server/lease:10.5.50.44",)
    assert "dhcp-option-set" not in list(api.path("ip", "dhcp-server", "lease"))[0]


# ---------------------------------------------------------------------------
# the write direction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_configure_writes_option_set_and_binding(patch_connect, mikrotik_creds):
    api = FakeRouterOSApi(
        menus={_NETWORK_PATH: [{".id": "*1", "address": "10.5.50.0/24"}]}
    )
    patch_connect(api)

    await MikroTikAdapter().configure_dhcp_option(mikrotik_creds, option=_spec())

    assert api.add_calls == [
        (
            _OPTION_PATH,
            {"name": _OPTION_NAME, "code": "114", "value": _VALUE, "force": "yes"},
        ),
        (_SET_PATH, {"name": _SET_NAME, "options": _OPTION_NAME}),
    ]
    assert list(api.path(*_NETWORK_PATH))[0]["dhcp-option-set"] == _SET_NAME


@pytest.mark.asyncio
async def test_re_configuring_an_unchanged_option_writes_nothing(
    patch_connect, mikrotik_creds
):
    """``force`` comes back from RouterOS as a real bool. Compared as a
    string it would differ on every push and write forever -- the identical
    trap ``_ensure_dhcp_server`` documents for ``disabled``."""
    api = _venue_router()
    patch_connect(api)

    await MikroTikAdapter().configure_dhcp_option(mikrotik_creds, option=_spec())

    assert api.ops == []


@pytest.mark.asyncio
async def test_a_drifted_value_is_updated_not_skipped(patch_connect, mikrotik_creds):
    """An option carrying a stale URL is worse than an absent one: it reads
    as configured and points every client at the wrong place."""
    api = _venue_router()
    patch_connect(api)

    await MikroTikAdapter().configure_dhcp_option(
        mikrotik_creds, option=_spec(value="https://new.example/api")
    )

    assert api.update_calls == [
        (_OPTION_PATH, {".id": "*1", "value": "https://new.example/api"})
    ]


@pytest.mark.asyncio
async def test_configure_appends_to_a_shared_set_rather_than_replacing_it(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={_SET_PATH: [{".id": "*1", "name": _SET_NAME, "options": "venue-pxe"}]}
    )
    patch_connect(api)

    await MikroTikAdapter().configure_dhcp_option(
        mikrotik_creds, option=_spec(network_addresses=())
    )

    assert list(api.path(*_SET_PATH))[0]["options"] == f"venue-pxe,{_OPTION_NAME}"


@pytest.mark.asyncio
async def test_configure_never_creates_a_missing_network_row(
    patch_connect, mikrotik_creds
):
    """Fabricating a network row here would invent a gateway and DNS for a
    subnet nobody asked this code about."""
    api = FakeRouterOSApi()
    patch_connect(api)

    await MikroTikAdapter().configure_dhcp_option(mikrotik_creds, option=_spec())

    assert list(api.path(*_NETWORK_PATH)) == []


@pytest.mark.asyncio
async def test_configure_refuses_without_a_code_and_value(
    patch_connect, mikrotik_creds
):
    """A removal is identified by name alone, but an option cannot be
    *created* without the fields that give it meaning -- and inventing
    either would put a fabricated URI in front of every guest device."""
    patch_connect(FakeRouterOSApi())

    with pytest.raises(MikroTikDeviceError):
        await MikroTikAdapter().configure_dhcp_option(
            mikrotik_creds, option=DhcpOptionConfig(name=_OPTION_NAME)
        )


@pytest.mark.asyncio
async def test_configure_then_remove_returns_the_device_to_where_it_started(
    patch_connect, mikrotik_creds
):
    api = FakeRouterOSApi(
        menus={_NETWORK_PATH: [{".id": "*1", "address": "10.5.50.0/24"}]}
    )
    patch_connect(api)
    adapter = MikroTikAdapter()

    await adapter.configure_dhcp_option(mikrotik_creds, option=_spec())
    await adapter.delete_dhcp_option(mikrotik_creds, option=_spec())

    assert list(api.path(*_OPTION_PATH)) == []
    assert list(api.path(*_SET_PATH)) == []
    assert list(api.path(*_NETWORK_PATH)) == [{".id": "*1", "address": "10.5.50.0/24"}]


# ---------------------------------------------------------------------------
# RouterOS 7.23.3, as it actually behaves
# ---------------------------------------------------------------------------
#
# Everything above this line runs against a fake that accepts whatever the
# adapter sends. The venue router does not. These fixtures switch on the two
# rejections observed on HJP0ATMRJ6X (RouterOS 7.23.3, hEX lite) and are the
# reason the shipped removal path converged in the suite and failed on
# hardware.

_ROS_723 = {_NETWORK_PATH: {"dhcp-option-set"}}


def _venue_router_as_it_really_is() -> FakeRouterOSApi:
    """The venue router *including* the two dynamic lease rows it really
    has, and the name-reference semantics of 7.23.3.

    The lease rows matter independently: ``_DHCP_OPTION_BINDING_PATHS``
    walks the lease menu too, real lease rows carry ``dhcp-option`` but no
    ``dhcp-option-set``, and no fixture above this line has any lease rows
    at all -- so the whole lease half of the walk was untested against a
    router that has leases.
    """
    api = FakeRouterOSApi(
        menus={
            _OPTION_PATH: [
                {
                    ".id": "*1",
                    "name": _OPTION_NAME,
                    "code": "114",
                    "value": _VALUE,
                    "force": True,
                }
            ],
            _SET_PATH: [{".id": "*1", "name": _SET_NAME, "options": _OPTION_NAME}],
            _NETWORK_PATH: [
                {
                    ".id": "*1",
                    "address": "10.5.50.0/24",
                    "gateway": "10.5.50.1",
                    "dns-server": "10.5.50.1",
                    "dhcp-option": "",
                    "dhcp-option-set": _SET_NAME,
                    "dynamic": False,
                }
            ],
            ("ip", "dhcp-server", "lease"): [
                {
                    ".id": "*1",
                    "address": "10.5.50.101",
                    "mac-address": "AA:BB:CC:DD:EE:01",
                    "dhcp-option": "",
                    "dynamic": True,
                },
                {
                    ".id": "*2",
                    "address": "10.5.50.102",
                    "mac-address": "AA:BB:CC:DD:EE:02",
                    "dhcp-option": "",
                    "dynamic": True,
                },
            ],
        },
        name_reference_fields=_ROS_723,
    )
    return api


@pytest.mark.asyncio
async def test_removal_converges_on_a_real_routeros_7_23_router(
    patch_connect, mikrotik_creds
):
    """THE REGRESSION TEST.

    Against the real device this failed with::

        Router rejected remove_dhcp_option: delete_dhcp_option:
        input does not match any value of value-name

    ...because the removal issued ``unset value-name=dhcp-option-set`` and
    7.23.3 does not list that field in that menu's ``unset`` enum. The
    option stayed on the router and kept being handed to every client.
    """
    api = _venue_router_as_it_really_is()
    patch_connect(api)

    removal = await MikroTikAdapter().delete_dhcp_option(
        mikrotik_creds, option=_spec()
    )

    assert removal.option_removed is True
    assert removal.option_sets_removed == (_SET_NAME,)
    assert removal.bindings_detached == ("ip/dhcp-server/network:10.5.50.0/24",)
    # The device, read back: nothing left that hands out code 114.
    assert list(api.path(*_OPTION_PATH)) == []
    assert list(api.path(*_SET_PATH)) == []
    network = list(api.path(*_NETWORK_PATH))[0]
    assert network.get("dhcp-option-set", "") == ""
    # ...and the row that serves guests is otherwise untouched.
    assert network["address"] == "10.5.50.0/24"
    assert network["gateway"] == "10.5.50.1"
    assert network["dns-server"] == "10.5.50.1"


@pytest.mark.asyncio
async def test_the_shape_that_works_on_this_firmware_is_tried_first(
    patch_connect, mikrotik_creds
):
    """Rung order is load-bearing, and it is ordered by what the hardware
    does, not by what the documentation says.

    ``set dhcp-option-set=none`` is the shape observed to clear the field
    on 7.23.3. It must be the first thing on the wire, so the fleet's
    common case costs one sentence and no rejected ones.
    """
    api = _venue_router_as_it_really_is()
    patch_connect(api)

    await MikroTikAdapter().delete_dhcp_option(mikrotik_creds, option=_spec())

    writes = [op for op in api.ops if op[0] in ("update", "unset", "remove")]
    assert writes[0] == (
        "update",
        _NETWORK_PATH,
        {".id": "*1", "dhcp-option-set": "none"},
    )
    # It worked, so the fallbacks were never issued at all.
    assert api.unset_calls == []
    assert not any(
        field.startswith("!") for _, fields in api.update_calls for field in fields
    )


@pytest.mark.asyncio
async def test_the_documented_bang_shape_is_a_silent_no_op_and_is_not_believed(
    patch_connect, mikrotik_creds
):
    """The observation that justifies this whole method.

    Run against the venue router on 2026-09-07, ``set !dhcp-option-set``
    -- the shape MikroTik *documents* for clearing a parameter -- was
    accepted with no trap and no error, and the field was still set
    afterwards::

        [rung] A: set !dhcp-option-set
               issued without error
               read-back: dhcp-option-set='cloudguest-opts' -> still set

    A clean return is not evidence of a change. If the ladder is ever
    reordered to lead with the documented shape, or if the read-back is
    ever dropped for being an "extra round trip", this test fails: the
    removal would report success while option 114 stayed on the router.
    """
    api = _venue_router_as_it_really_is()
    patch_connect(api)

    await MikroTikAdapter().delete_dhcp_option(mikrotik_creds, option=_spec())

    # The bang shape is modelled as the no-op the device really performs,
    # so a removal can only converge here by not trusting it.
    assert list(api.path(*_OPTION_PATH)) == []
    assert list(api.path(*_NETWORK_PATH))[0].get("dhcp-option-set", "") == ""


@pytest.mark.asyncio
async def test_lease_rows_are_walked_without_being_written_to(
    patch_connect, mikrotik_creds
):
    """Real lease rows have ``dhcp-option`` (empty) and no
    ``dhcp-option-set`` at all. Nothing about them matches, so nothing must
    be written to them -- an ``unset`` aimed at the lease menu would be
    rejected exactly the way the network one was, and a lease is not ours
    to edit."""
    api = _venue_router_as_it_really_is()
    patch_connect(api)

    await MikroTikAdapter().delete_dhcp_option(mikrotik_creds, option=_spec())

    lease_path = ("ip", "dhcp-server", "lease")
    assert not any(path == lease_path for path, _ in api.update_calls)
    assert not any(path == lease_path for path, _, _ in api.unset_calls)
    assert not any(path == lease_path for path, _ in api.remove_calls)
    assert len(list(api.path(*lease_path))) == 2


@pytest.mark.asyncio
async def test_a_router_that_refuses_every_clear_shape_changes_nothing(
    patch_connect, mikrotik_creds
):
    """Fail closed, and say so.

    If no supported shape clears the binding, the option is still attached
    and removing the set and option underneath it would be wrong. The
    device must be left exactly as found, and the caller must hear about
    it -- which is what makes the sweep report ``changed: False`` honestly
    rather than claiming a removal that did not happen.
    """
    api = _venue_router_as_it_really_is()
    # A router where even the documented shape does nothing: `set` returns
    # cleanly and the field stays put. This is the silent-no-op failure
    # mode, which no exception would ever reveal.
    api.silently_ignore_updates.add(_NETWORK_PATH)
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await MikroTikAdapter().delete_dhcp_option(mikrotik_creds, option=_spec())

    assert "could not clear dhcp-option-set" in str(excinfo.value)
    # Nothing was removed on the way past.
    assert [r["name"] for r in api.path(*_OPTION_PATH)] == [_OPTION_NAME]
    assert [r["name"] for r in api.path(*_SET_PATH)] == [_SET_NAME]
    assert list(api.path(*_NETWORK_PATH))[0]["dhcp-option-set"] == _SET_NAME


@pytest.mark.asyncio
async def test_removal_is_still_idempotent_on_a_7_23_router(
    patch_connect, mikrotik_creds
):
    """The strong idempotency guarantee survives the ladder: a second run
    against an already-clean router writes nothing at all."""
    api = _venue_router_as_it_really_is()
    patch_connect(api)

    await MikroTikAdapter().delete_dhcp_option(mikrotik_creds, option=_spec())
    api.ops.clear()
    api.update_calls.clear()
    api.unset_calls.clear()
    api.remove_calls.clear()

    second = await MikroTikAdapter().delete_dhcp_option(
        mikrotik_creds, option=_spec()
    )

    assert second.option_removed is False
    assert second.bindings_detached == ()
    assert api.ops == []
