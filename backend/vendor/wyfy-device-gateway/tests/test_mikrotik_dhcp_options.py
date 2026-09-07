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
2. detaching uses RouterOS's ``unset``, never ``set field=""`` -- which
   fails with "ambiguous value of dhcp-option-set, more than one possible
   value matches input";
3. the option is matched by **name**, never by ``code=114``.
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
async def test_the_binding_is_cleared_with_unset_never_set_to_empty(
    patch_connect, mikrotik_creds
):
    """The single most expensive fact in this file.

    ``set dhcp-option-set=""`` does not clear the field on real hardware:
    RouterOS treats the empty string as a value to match against existing
    option-set names and fails with "ambiguous value of dhcp-option-set,
    more than one possible value matches input". The removal must issue
    ``unset`` with ``value-name``. If someone "simplifies" this back into
    an update, this test is what says no.
    """
    api = _venue_router()
    patch_connect(api)

    await MikroTikAdapter().delete_dhcp_option(mikrotik_creds, option=_spec())

    assert api.unset_calls == [(_NETWORK_PATH, "*1", "dhcp-option-set")]
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
    assert kinds == [
        ("unset", _NETWORK_PATH),
        ("remove", _SET_PATH),
        ("remove", _OPTION_PATH),
    ]


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
    assert api.unset_calls == [(_NETWORK_PATH, "*2", "dhcp-option")]


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
