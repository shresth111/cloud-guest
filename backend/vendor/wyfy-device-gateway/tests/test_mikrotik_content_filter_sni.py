"""A blocked domain is also dropped by its HTTPS name (``tls-host``).

The DNS sinkhole only binds a guest who asks this router for the name. These
tests pin the second half of a domain rule: two ``/ip firewall filter``
drops on tcp/443, ``tls-host=<domain>`` and ``tls-host=*.<domain>``, written
under the rule's own content-filter marker, placed where a ClientHello can
still be seen, read back after writing, and removed exactly on unblock.

The forward chain below is the one read off the lab hEX lite (RouterOS
7.23.3) -- see docs/security/PRD.md section 37.1 -- plus the firewall
sentinel band, which sits directly above the established accept.
"""

from __future__ import annotations

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import ContentFilterRuleConfig
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter, MikroTikDeviceError

_RULE_ID = "3f2a1c64-0000-4000-8000-0000000000aa"
_OTHER_ID = "3f2a1c64-0000-4000-8000-0000000000bb"
_FILTER = ("ip", "firewall", "filter")
_STATIC = ("ip", "dns", "static")
_EXACT = f"WyfyGuest content filter {_RULE_ID} (https): "
_SUBS = f"WyfyGuest content filter {_RULE_ID} (https subdomains): "


class _Api(FakeRouterOSApi):
    """RouterOS never reuses an ``.id``; the default fake does once a row is
    removed, which would let a re-add collide with a stale id."""

    def __init__(self, **kwargs) -> None:  # noqa: ANN003
        super().__init__(**kwargs)
        self._next = 100

    def mint_id(self, row_count: int) -> str:
        self._next += 1
        return f"*{self._next:X}"


def _rule(
    value: str = "facebook.com",
    label: str = "Block Facebook",
    rule_id: str = _RULE_ID,
    value_type: str = "domain",
) -> ContentFilterRuleConfig:
    return ContentFilterRuleConfig(
        rule_id=rule_id, value_type=value_type, value=value, label=label
    )


def _lab_forward_chain() -> list[dict]:
    return [
        {".id": "*1", "chain": "forward", "action": "jump",
         "jump-target": "hs-unauth", "dynamic": "true"},
        {".id": "*2", "chain": "forward", "action": "jump",
         "jump-target": "hs-unauth-to", "dynamic": "true"},
        {".id": "*3", "chain": "forward", "action": "drop",
         "comment": "cloudguest-block-dot-udp"},
        {".id": "*4", "chain": "forward", "action": "drop",
         "comment": "cloudguest-block-doh"},
        {".id": "*5", "chain": "forward", "action": "passthrough",
         "comment": "cloudguest-fw-band-begin"},
        {".id": "*6", "chain": "forward", "action": "accept",
         "comment": "cloudguest-fw:11111111-1111-4111-8111-111111111111"},
        {".id": "*7", "chain": "forward", "action": "passthrough",
         "comment": "cloudguest-fw-band-end"},
        {".id": "*8", "chain": "forward", "action": "accept",
         "comment": "cloudguest-fw-fwd-established",
         "connection-state": "established,related"},
        {".id": "*9", "chain": "forward", "action": "drop",
         "comment": "cloudguest-fw-fwd-drop-invalid",
         "connection-state": "invalid"},
        {".id": "*A", "chain": "input", "action": "accept",
         "comment": "cloudguest-fw-allow-wg-mgmt"},
    ]


def _forward(api) -> list[dict]:  # noqa: ANN001
    return [r for r in api.path(*_FILTER) if r.get("chain") == "forward"]


def _labels(api) -> list[str]:  # noqa: ANN001
    out = []
    for row in _forward(api):
        comment = str(row.get("comment") or f"<{row.get('action')}>")
        if comment.startswith(_SUBS):
            out.append("SNI*")
        elif comment.startswith(_EXACT):
            out.append("SNI")
        else:
            out.append(comment)
    return out


def _ours(api) -> list[dict]:  # noqa: ANN001
    return [
        r for r in api.path(*_FILTER)
        if str(r.get("comment", "")).startswith(("WyfyGuest content filter",))
    ]


@pytest.mark.asyncio
async def test_a_blocked_domain_becomes_two_tls_host_drops(
    patch_connect, mikrotik_creds
):
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(mikrotik_creds, rule=_rule())

    rows = {r["tls-host"]: r for r in _ours(api)}
    assert set(rows) == {"facebook.com", "*.facebook.com"}
    for row in rows.values():
        assert row["chain"] == "forward"
        assert row["protocol"] == "tcp"
        assert row["dst-port"] == "443"
        assert row["action"] == "drop"
        assert row["disabled"] == "no"
        # Never matched on the hotspot's auth state: a staff LAN on the same
        # router uses the same sinkhole, and gets the same HTTPS block.
        assert "hotspot" not in row
    assert rows["facebook.com"]["comment"] == f"{_EXACT}Block Facebook"
    assert rows["*.facebook.com"]["comment"] == f"{_SUBS}Block Facebook"


@pytest.mark.asyncio
async def test_the_drops_sit_where_a_client_hello_is_still_visible(
    patch_connect, mikrotik_creds
):
    """A ClientHello rides an *established* connection, so a drop below
    cloudguest-fw-fwd-established never sees one. They go where the
    bypass hardening's doh_hostnames tls-host rows go: directly above
    cloudguest-block-dot-udp -- under the hotspot jumps, above the band (a
    customer allow rule cannot re-open them) and above the accept."""
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(mikrotik_creds, rule=_rule())

    assert _labels(api)[:5] == [
        "<jump>", "<jump>", "SNI", "SNI*", "cloudguest-block-dot-udp",
    ]
    filter_adds = [f for s, f in api.add_calls if s == _FILTER]
    assert [f["place-before"] for f in filter_adds] == ["*3", "*3"]
    # The input chain -- the router's own management path -- is untouched.
    assert [r for r in api.path(*_FILTER) if r.get("chain") == "input"] == [
        _lab_forward_chain()[-1]
    ]


@pytest.mark.asyncio
async def test_without_the_dot_anchor_the_drops_go_above_the_first_accept(
    patch_connect, mikrotik_creds
):
    chain = [
        r for r in _lab_forward_chain()
        if r.get("comment") not in ("cloudguest-block-dot-udp",)
    ]
    api = _Api(menus={_FILTER: chain})
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(mikrotik_creds, rule=_rule())

    labels = _labels(api)
    first_accept = next(
        i for i, r in enumerate(_forward(api)) if r.get("action") == "accept"
    )
    assert labels.index("SNI") < first_accept
    assert labels.index("SNI*") < first_accept


@pytest.mark.asyncio
async def test_with_no_accept_at_all_the_drops_are_appended(
    patch_connect, mikrotik_creds
):
    chain = [{".id": "*1", "chain": "forward", "action": "drop", "comment": "x"}]
    api = _Api(menus={_FILTER: chain})
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(mikrotik_creds, rule=_rule())

    assert _labels(api) == ["x", "SNI", "SNI*"]
    assert all("place-before" not in f for s, f in api.add_calls if s == _FILTER)


@pytest.mark.asyncio
async def test_re_pushing_is_a_clean_no_op(patch_connect, mikrotik_creds):
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())
    writes = len(api.ops)

    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())

    assert api.ops[writes:] == []
    assert len(_ours(api)) == 2


@pytest.mark.asyncio
async def test_a_read_back_boolean_disabled_is_not_a_difference(
    patch_connect, mikrotik_creds
):
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())
    for row in _ours(api):
        row["disabled"] = False

    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())

    assert [c for c in api.update_calls if c[0] == _FILTER] == []


@pytest.mark.asyncio
async def test_editing_the_domain_updates_the_drops_in_place(
    patch_connect, mikrotik_creds
):
    """Keyed on the marker, not on tls-host -- otherwise the edit adds a
    second pair and the old pair keeps blocking a site nobody asked for."""
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())

    await adapter.configure_content_filter_rule(
        mikrotik_creds, rule=_rule(value="instagram.com", label="IG")
    )

    hosts = sorted(r["tls-host"] for r in _ours(api))
    assert hosts == ["*.instagram.com", "instagram.com"]
    assert "facebook" not in str(list(api.path(*_FILTER)))
    assert all(op != "remove" for op, s, _ in api.ops if s == _FILTER)


@pytest.mark.asyncio
async def test_a_drop_found_below_the_accept_is_moved_up_failing_closed(
    patch_connect, mikrotik_creds
):
    """A row that sits below the established accept blocks nothing. It is
    re-added above, and the stale one removed only after -- the chain is
    never left without the drop."""
    chain = _lab_forward_chain()
    chain.insert(9, {
        ".id": "*50", "chain": "forward", "protocol": "tcp", "dst-port": "443",
        "tls-host": "facebook.com", "action": "drop", "comment": f"{_EXACT}old",
    })
    api = _Api(menus={_FILTER: chain})
    patch_connect(api)

    await MikroTikAdapter().configure_content_filter_rule(mikrotik_creds, rule=_rule())

    labels = _labels(api)
    assert labels.count("SNI") == 1
    assert labels.index("SNI") < labels.index("cloudguest-fw-fwd-established")
    ops = [(op, payload) for op, s, payload in api.ops if s == _FILTER]
    exact_add = next(
        i for i, (op, p) in enumerate(ops)
        if op == "add" and p.get("tls-host") == "facebook.com"
    )
    stale_remove = next(
        i for i, (op, p) in enumerate(ops) if op == "remove" and p == ("*50",)
    )
    assert exact_add < stale_remove


@pytest.mark.asyncio
async def test_a_duplicate_of_our_own_row_is_removed(patch_connect, mikrotik_creds):
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())
    rows = api.path(*_FILTER)
    original = [r for r in _ours(api) if r["tls-host"] == "facebook.com"][0]
    rows.add(**{k: v for k, v in original.items() if k != ".id"}, **{"place-before": "*3"})

    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())

    assert sorted(r["tls-host"] for r in _ours(api)) == ["*.facebook.com", "facebook.com"]


@pytest.mark.asyncio
async def test_a_write_the_router_silently_ignored_fails_the_push(
    patch_connect, mikrotik_creds
):
    """Read back after writing: an update that returned cleanly and changed
    nothing is a known RouterOS shape, and must not report a block that is
    not on the device."""
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())
    api.silently_ignore_updates.add(_FILTER)

    with pytest.raises(MikroTikDeviceError, match="read-back"):
        await adapter.configure_content_filter_rule(
            mikrotik_creds, rule=_rule(value="instagram.com")
        )


@pytest.mark.asyncio
async def test_a_dropped_dns_write_is_caught_by_the_read_back_too(
    patch_connect, mikrotik_creds
):
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())
    api.silently_ignore_updates.add(_STATIC)

    with pytest.raises(MikroTikDeviceError, match="DNS entry has wrong name"):
        await adapter.configure_content_filter_rule(
            mikrotik_creds, rule=_rule(value="instagram.com")
        )


@pytest.mark.asyncio
async def test_unblock_removes_exactly_this_rules_drops(patch_connect, mikrotik_creds):
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())
    await adapter.configure_content_filter_rule(
        mikrotik_creds, rule=_rule(value="tiktok.com", label="TT", rule_id=_OTHER_ID)
    )

    await adapter.delete_content_filter_rule(mikrotik_creds, rule=_rule())

    assert sorted(r["tls-host"] for r in _ours(api)) == ["*.tiktok.com", "tiktok.com"]
    assert [r["comment"] for r in api.path(*_FILTER) if "cloudguest" in r.get("comment", "")] == [
        r["comment"] for r in _lab_forward_chain() if "cloudguest" in r.get("comment", "")
    ]
    assert not any(_RULE_ID in str(r.get("comment")) for r in api.path(*_STATIC))


@pytest.mark.asyncio
async def test_unblock_twice_is_a_no_op(patch_connect, mikrotik_creds):
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())
    await adapter.delete_content_filter_rule(mikrotik_creds, rule=_rule())

    await adapter.delete_content_filter_rule(mikrotik_creds, rule=_rule())

    assert _ours(api) == []


@pytest.mark.asyncio
async def test_unblock_that_leaves_a_row_behind_fails(patch_connect, mikrotik_creds):
    """The read-back on unblock: anything of this rule's still on the router
    is a site still blocked with no row in the dashboard to show for it."""

    class _StickyApi(_Api):
        def path(self, *segments: str):
            path = super().path(*segments)
            if segments == _FILTER:
                path.remove = lambda *ids: None  # accepted, does nothing
            return path

    api = _StickyApi(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())

    with pytest.raises(MikroTikDeviceError, match="still found"):
        await adapter.delete_content_filter_rule(mikrotik_creds, rule=_rule())


@pytest.mark.asyncio
async def test_retyping_to_an_address_removes_the_drops(patch_connect, mikrotik_creds):
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(mikrotik_creds, rule=_rule())

    await adapter.configure_content_filter_rule(
        mikrotik_creds, rule=_rule(value="203.0.113.0/24", value_type="ip_cidr")
    )

    assert not any("tls-host" in r for r in api.path(*_FILTER))


@pytest.mark.asyncio
async def test_a_rule_whose_id_starts_the_same_is_not_claimed(
    patch_connect, mikrotik_creds
):
    """Markers end in ``": "`` or continue with ``" ("``; a longer id is a
    different rule and survives this one's unblock."""
    longer = _RULE_ID + "f"
    api = _Api(menus={_FILTER: _lab_forward_chain()})
    patch_connect(api)
    adapter = MikroTikAdapter()
    await adapter.configure_content_filter_rule(
        mikrotik_creds, rule=_rule(value="tiktok.com", rule_id=longer)
    )

    await adapter.delete_content_filter_rule(mikrotik_creds, rule=_rule())

    assert len(_ours(api)) == 2
