"""The per-guest connection-flood limit, against a fake RouterOS API.

What these pin, and why each matters on a real router:

* **Forward chain, inside the band, at its top.** One drop row per guest
  network, above every customer rule and below band-begin. Nothing is ever
  written to ``input`` -- that is where the management path lives.
* **Scoped to guest sources.** ``src-address`` is a guest network read off
  the router; with none, the write is refused rather than widened to all
  traffic.
* **Idempotent, and fail closed on change.** An identical re-apply writes
  nothing; a changed limit adds the new rows before removing the old ones.
* **Removable cleanly.** Off removes exactly our rows and nothing else.
* **Invisible to the customer-rule push.** ``sync_rules`` neither counts,
  moves nor removes these rows, and they do not upset its verification.

Nothing in this file has been run against hardware; see
``~/wyfy-ops/cftest/floodtest.py`` for the device check.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import FirewallFilterRuleConfig
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikFirewallPushFailedError,
    MikroTikFirewallRefusedError,
)
from wyfy_device_gateway.mikrotik_firewall import (
    FLOOD_LIMIT_COMMENT,
    FLOOD_LIMIT_INVALID,
    FLOOD_NO_GUEST_NETWORK,
    FLOOD_OUTSIDE_BAND,
)

_FILTER = ("ip", "firewall", "filter")


class _Api(FakeRouterOSApi):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._next = 100

    def mint_id(self, row_count: int) -> str:
        self._next += 1
        return f"*N{self._next}"


def _forward(extra_in_band: list[dict] | None = None, *, band: bool = True) -> list[dict]:
    rows: list[dict[str, Any]] = [
        {".id": "*D1", "chain": "forward", "action": "jump", "jump-target": "hs-unauth",
         "hotspot": "from-client,!auth", "dynamic": True},
        {".id": "*V1", "chain": "forward", "action": "drop", "src-address": "192.168.88.50",
         "comment": "venue's own rule"},
    ]
    if band:
        rows.append({".id": "*BB", "chain": "forward", "action": "passthrough",
                     "comment": "cloudguest-fw-band-begin"})
        rows.extend(extra_in_band or [])
        rows.append({".id": "*BE", "chain": "forward", "action": "passthrough",
                     "comment": "cloudguest-fw-band-end"})
    rows.append({".id": "*E", "chain": "forward", "action": "accept",
                 "connection-state": "established,related",
                 "comment": "cloudguest-fw-fwd-established"})
    return rows


def _input() -> list[dict]:
    return [
        {".id": "*W", "chain": "input", "action": "accept", "protocol": "udp",
         "in-interface": "wg-cloudguard", "comment": "cloudguest-fw-allow-wg-mgmt"},
        {".id": "*X", "chain": "input", "action": "drop", "in-interface-list": "WAN",
         "comment": "cloudguest-fw-drop-wan-input"},
    ]


def _api(*, extra_in_band=None, band=True, guest=True, two_guest_nets=False) -> _Api:
    addresses = [{".id": "*A1", "address": "203.0.113.2/30", "interface": "ether1"}]
    hotspot: list[dict] = []
    if guest:
        addresses.append({".id": "*A2", "address": "10.5.50.1/24", "interface": "bridge-guest"})
        hotspot.append({".id": "*H1", "name": "hs1", "interface": "bridge-guest"})
    if two_guest_nets:
        addresses.append({".id": "*A3", "address": "10.6.0.1/24", "interface": "vlan-guest2"})
        hotspot.append({".id": "*H2", "name": "hs2", "interface": "vlan-guest2"})
    return _Api(
        menus={
            _FILTER: _input() + _forward(extra_in_band, band=band),
            ("ip", "address"): addresses,
            ("ip", "hotspot"): hotspot,
        }
    )


def _rows(api: FakeRouterOSApi) -> list[dict]:
    return list(api.path(*_FILTER))


def _band(api: FakeRouterOSApi) -> list[dict]:
    forward = [r for r in _rows(api) if r.get("chain") == "forward"]
    comments = [r.get("comment") for r in forward]
    return forward[comments.index("cloudguest-fw-band-begin") + 1 : comments.index(
        "cloudguest-fw-band-end"
    )]


def _flood(api: FakeRouterOSApi) -> list[dict]:
    return [r for r in _rows(api) if r.get("comment") == FLOOD_LIMIT_COMMENT]


def _customer(rule_id: str) -> dict:
    return {".id": f"*C{rule_id[:4]}", "chain": "forward", "action": "drop",
            "src-address": "10.5.50.0/24", "dst-address": "10.20.0.0/24",
            "comment": f"cloudguest-fw:{rule_id}"}


async def _apply(patch_connect, creds, api, limit):
    patch_connect(api)
    return await MikroTikAdapter().apply_flood_limit(creds, limit=limit)


class TestApply:
    async def test_one_drop_row_per_guest_network_at_the_top_of_the_band(
        self, patch_connect, mikrotik_creds
    ) -> None:
        rid = str(uuid.uuid4())
        api = _api(extra_in_band=[_customer(rid)], two_guest_nets=True)
        result = await _apply(patch_connect, mikrotik_creds, api, 150)

        assert result.added == 2 and result.removed == 0
        band = _band(api)
        # Ours first, then the customer's rule: a customer accept can never
        # exempt a guest from the cap.
        assert [r.get("comment") for r in band] == [
            FLOOD_LIMIT_COMMENT, FLOOD_LIMIT_COMMENT, f"cloudguest-fw:{rid}"
        ]
        for row, net in zip(band[:2], ["10.5.50.0/24", "10.6.0.0/24"], strict=True):
            assert row["chain"] == "forward"
            assert row["action"] == "drop"
            assert row["protocol"] == "tcp"
            assert row["connection-state"] == "new"
            assert row["connection-limit"] == "150,32"
            assert row["src-address"] == net
        # Every add was positioned, and positioned inside the band.
        assert all(f.get("place-before") == "*C" + rid[:4] for _, f in api.add_calls)

    async def test_nothing_is_written_to_the_input_chain_or_outside_the_band(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        before = [dict(r) for r in _rows(api)]
        await _apply(patch_connect, mikrotik_creds, api, 80)
        after = _rows(api)
        assert [r for r in after if r.get("chain") == "input"] == [
            r for r in before if r.get("chain") == "input"
        ]
        assert all(r["chain"] == "forward" for _, r in api.add_calls)
        assert api.remove_calls == []
        # Only band rows changed.
        outside = [r for r in after if r.get("comment") != FLOOD_LIMIT_COMMENT]
        assert outside == before

    async def test_re_applying_the_same_limit_writes_nothing(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        await _apply(patch_connect, mikrotik_creds, api, 150)
        writes = len(api.ops)
        result = await _apply(patch_connect, mikrotik_creds, api, 150)
        assert result.added == 0 and result.removed == 0
        assert len(api.ops) == writes

    async def test_changing_the_limit_adds_before_it_removes(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        await _apply(patch_connect, mikrotik_creds, api, 300)
        start = len(api.ops)
        result = await _apply(patch_connect, mikrotik_creds, api, 80)
        ops = [op for op, *_ in api.ops[start:]]
        assert ops == ["add", "remove"]
        assert result.added == 1 and result.removed == 1
        assert [r["connection-limit"] for r in _flood(api)] == ["80,32"]

    async def test_no_guest_network_is_refused_not_widened(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(guest=False)
        with pytest.raises(MikroTikFirewallRefusedError) as info:
            await _apply(patch_connect, mikrotik_creds, api, 150)
        assert info.value.code == FLOOD_NO_GUEST_NETWORK
        assert api.ops == []

    async def test_no_band_is_refused(self, patch_connect, mikrotik_creds) -> None:
        api = _api(band=False)
        with pytest.raises(MikroTikFirewallRefusedError) as info:
            await _apply(patch_connect, mikrotik_creds, api, 150)
        assert info.value.code == "ACCESS_RULES_BAND_MISSING"
        assert api.ops == []

    @pytest.mark.parametrize("limit", [0, 5, 19, 5001, True])
    async def test_an_out_of_range_limit_is_refused(
        self, patch_connect, mikrotik_creds, limit
    ) -> None:
        api = _api()
        with pytest.raises(MikroTikFirewallRefusedError) as info:
            await _apply(patch_connect, mikrotik_creds, api, limit)
        assert info.value.code == FLOOD_LIMIT_INVALID
        assert api.ops == []

    async def test_our_row_moved_outside_the_band_refuses(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        _rows(api)  # materialise
        api._menus[_FILTER].insert(
            2,
            {".id": "*Z", "chain": "forward", "action": "drop", "protocol": "tcp",
             "connection-state": "new", "src-address": "10.5.50.0/24",
             "connection-limit": "150,32", "comment": FLOOD_LIMIT_COMMENT},
        )
        with pytest.raises(MikroTikFirewallRefusedError) as info:
            await _apply(patch_connect, mikrotik_creds, api, 150)
        assert info.value.code == FLOOD_OUTSIDE_BAND
        assert api.ops == []

    async def test_a_row_that_did_not_land_is_taken_off_again(
        self, patch_connect, mikrotik_creds
    ) -> None:
        class _Lost(_Api):
            """``add`` returns an id but the row never appears."""

            def path(self, *segments: str):
                menu = super().path(*segments)
                if segments == _FILTER:
                    def add(**fields: Any) -> str:
                        self.ops.append(("add", segments, fields))
                        return "*GHOST"
                    menu.add = add  # type: ignore[method-assign]
                return menu

        base = _api()
        api = _Lost(menus={k: list(v) for k, v in base._menus.items()})
        with pytest.raises(MikroTikFirewallPushFailedError) as info:
            await _apply(patch_connect, mikrotik_creds, api, 150)
        assert info.value.restored is True
        assert _flood(api) == []


class TestRemoveAndRead:
    async def test_off_removes_exactly_our_rows(self, patch_connect, mikrotik_creds) -> None:
        rid = str(uuid.uuid4())
        api = _api(extra_in_band=[_customer(rid)], two_guest_nets=True)
        before = [dict(r) for r in _rows(api)]
        await _apply(patch_connect, mikrotik_creds, api, 150)
        patch_connect(api)
        result = await MikroTikAdapter().remove_flood_limit(mikrotik_creds)
        assert result.removed == 2
        assert _flood(api) == []
        assert _rows(api) == before

    async def test_off_when_already_off_is_a_clean_no_op(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        patch_connect(api)
        result = await MikroTikAdapter().remove_flood_limit(mikrotik_creds)
        assert result.removed == 0
        assert api.ops == []

    async def test_read_reports_on_off_and_limit(self, patch_connect, mikrotik_creds) -> None:
        api = _api()
        patch_connect(api)
        status = await MikroTikAdapter().read_flood_limit(mikrotik_creds)
        assert (status.enabled, status.limit, status.band_state) == (False, None, "ready")
        await _apply(patch_connect, mikrotik_creds, api, 300)
        status = await MikroTikAdapter().read_flood_limit(mikrotik_creds)
        assert status.enabled and status.limit == 300 and status.consistent
        assert status.guest_networks == ("10.5.50.0/24",)
        assert api.ops[-1][0] == "add"  # the reads wrote nothing


class TestCoexistsWithCustomerPush:
    async def test_customer_push_leaves_flood_rows_alone_and_verifies(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        await _apply(patch_connect, mikrotik_creds, api, 150)
        rule = FirewallFilterRuleConfig(
            rule_id=str(uuid.uuid4()), chain="forward", action="drop", priority=10,
            src_address="10.5.50.0/24", dst_address="10.20.0.0/24",
        )
        patch_connect(api)
        await MikroTikAdapter().sync_firewall_rules(
            mikrotik_creds, rules=[rule], known_rule_ids=[rule.rule_id]
        )
        comments = [r.get("comment") for r in _band(api)]
        assert comments == [FLOOD_LIMIT_COMMENT, f"cloudguest-fw:{rule.rule_id}"]
        # And an empty customer push removes the customer rule only.
        patch_connect(api)
        await MikroTikAdapter().sync_firewall_rules(
            mikrotik_creds, rules=[], known_rule_ids=[rule.rule_id]
        )
        assert [r.get("comment") for r in _band(api)] == [FLOOD_LIMIT_COMMENT]
