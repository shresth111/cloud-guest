"""Firewall rules inside the sentinel band, against a fake RouterOS API.

What these tests pin, and why each matters on a real router:

* **Band lookup, and refusal without it.** Every rule is written
  ``place-before=<band-end .id>``; a router without both sentinels is refused
  with ``ACCESS_RULES_BAND_MISSING`` and not one write is issued. A push that
  created the band at a guessed position is how a guest network goes down.
* **Ordering.** Band order is ascending priority, whatever order the rules
  arrive in and whatever the device held before.
* **Idempotency.** An unchanged re-push issues no writes at all.
* **Marker isolation.** Rows without our ``cloudguest-fw:<uuid>`` marker --
  inside the band or out, in any chain -- are never updated or removed; a
  malformed, out-of-band or orphaned marker refuses the whole push.
* **Fail closed.** Adds come before removes, and a failure after writing
  began restores the pre-push snapshot of our own rows.

The fake's ``add`` honours ``place-before`` by ``.id`` (device test T1,
recorded in ``fake_write_transport.py``), so an append-instead-of-insert bug
changes the resulting order and fails here. Nothing in this file has been run
against hardware.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from librouteros.exceptions import LibRouterosError

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import FirewallFilterRuleConfig
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikFirewallPushFailedError,
    MikroTikFirewallRefusedError,
)

_FILTER = ("ip", "firewall", "filter")


class _Api(FakeRouterOSApi):
    """RouterOS never reuses an ``.id``; the base fake does after a remove."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._next = 100

    def mint_id(self, row_count: int) -> str:
        self._next += 1
        return f"*N{self._next}"


class _FailingAddApi(_Api):
    """Raises a RouterOS error on the Nth ``add`` (1-based), and optionally on
    every add after it too -- a connection that died mid-push."""

    def __init__(self, *args: Any, fail_on: int, fail_after: bool = False, **kw: Any):
        super().__init__(*args, **kw)
        self._fail_on = fail_on
        self._fail_after = fail_after
        self._adds = 0

    def path(self, *segments: str):
        menu = super().path(*segments)
        original = menu.add

        def add(**fields: Any) -> str:
            self._adds += 1
            if self._adds == self._fail_on or (
                self._fail_after and self._adds > self._fail_on
            ):
                raise LibRouterosError("failure: simulated")
            return original(**fields)

        menu.add = add  # type: ignore[method-assign]
        return menu


def _lab_forward(*, band: bool = True, extra_in_band: list[dict] | None = None) -> list[dict]:
    """The lab router's forward chain (PRD §37.1), with the band placed where
    ``install_band`` puts it: directly above the established accept."""
    rows: list[dict[str, Any]] = [
        {".id": "*D1", "chain": "forward", "action": "jump", "jump-target": "hs-unauth",
         "hotspot": "from-client,!auth", "dynamic": True},
        {".id": "*D2", "chain": "forward", "action": "jump", "jump-target": "hs-unauth-to",
         "hotspot": "to-client,!auth", "dynamic": True},
        {".id": "*3", "chain": "forward", "action": "drop", "protocol": "udp",
         "dst-port": "853", "comment": "cloudguest-block-dot-udp"},
        {".id": "*4", "chain": "forward", "action": "drop", "protocol": "tcp",
         "dst-port": "443", "comment": "cloudguest-block-doh"},
        {".id": "*V1", "chain": "forward", "action": "drop", "src-address": "192.168.88.50",
         "comment": "venue's own rule, outside the band"},
    ]
    if band:
        rows.append({".id": "*BB", "chain": "forward", "action": "passthrough",
                     "comment": "cloudguest-fw-band-begin"})
        rows.extend(extra_in_band or [])
        rows.append({".id": "*BE", "chain": "forward", "action": "passthrough",
                     "comment": "cloudguest-fw-band-end"})
    rows += [
        {".id": "*E", "chain": "forward", "action": "accept",
         "connection-state": "established,related", "comment": "cloudguest-fw-fwd-established"},
        {".id": "*I", "chain": "forward", "action": "drop", "connection-state": "invalid",
         "comment": "cloudguest-fw-fwd-drop-invalid"},
    ]
    return rows


def _input_chain() -> list[dict]:
    return [
        {".id": "*W", "chain": "input", "action": "accept", "protocol": "udp",
         "in-interface": "wg-cloudguard", "comment": "cloudguest-fw-allow-wg-mgmt"},
        {".id": "*X", "chain": "input", "action": "drop", "in-interface-list": "WAN",
         "comment": "cloudguest-fw-drop-wan-input"},
    ]


def _api(*, api_cls=_Api, band: bool = True, extra_in_band=None, **kwargs) -> _Api:
    return api_cls(
        menus={_FILTER: _input_chain() + _lab_forward(band=band, extra_in_band=extra_in_band)},
        **kwargs,
    )


def _rows(api: FakeRouterOSApi) -> list[dict]:
    return list(api.path(*_FILTER))


def _band(api: FakeRouterOSApi) -> list[dict]:
    forward = [r for r in _rows(api) if r.get("chain") == "forward"]
    comments = [r.get("comment") for r in forward]
    begin = comments.index("cloudguest-fw-band-begin")
    end = comments.index("cloudguest-fw-band-end")
    return forward[begin + 1 : end]


def _band_ids(api: FakeRouterOSApi) -> list[str]:
    return [str(r.get("comment", "")).removeprefix("cloudguest-fw:") for r in _band(api)]


def _rule(priority: int, *, rule_id: str | None = None, **overrides: Any) -> FirewallFilterRuleConfig:
    fields: dict[str, Any] = {
        "rule_id": rule_id or str(uuid.uuid4()),
        "chain": "forward",
        "action": "drop",
        "priority": priority,
        "src_address": "10.10.0.0/24",
        "dst_address": "10.20.0.0/24",
    }
    fields.update(overrides)
    return FirewallFilterRuleConfig(**fields)


async def _sync(patch_connect, creds, api, rules, known=()):
    patch_connect(api)
    return await MikroTikAdapter().sync_firewall_rules(
        creds, rules=rules, known_rule_ids=list(known) + [r.rule_id for r in rules]
    )


def _snapshot_outside_band(api: FakeRouterOSApi) -> list[dict]:
    band_ids = {r[".id"] for r in _band(api)}
    return [dict(r) for r in _rows(api) if r[".id"] not in band_ids]


# ---------------------------------------------------------------------------
# Band lookup and refusal
# ---------------------------------------------------------------------------


class TestBand:
    async def test_rules_are_written_inside_the_band_before_band_end(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        a, b = _rule(10), _rule(20)
        await _sync(patch_connect, mikrotik_creds, api, [a, b])

        assert _band_ids(api) == [a.rule_id, b.rule_id]
        # Written last-to-first, each placed before the one after it; the
        # first write is anchored on band-end itself.
        anchors = [fields["place-before"] for _, fields in api.add_calls]
        assert anchors[0] == "*BE"
        assert all("place-before" in fields for _, fields in api.add_calls)
        # The established accept is still directly below band-end, so every
        # platform rule sits above it and sees established flows too.
        forward = [r["comment"] for r in _rows(api) if r["chain"] == "forward" and "comment" in r]
        assert forward.index("cloudguest-fw-band-end") + 1 == forward.index(
            "cloudguest-fw-fwd-established"
        )

    async def test_the_rule_carries_the_marker_and_the_match(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        rule = _rule(
            5, action="reject", protocol="tcp", dst_port=445,
            src_address="10.10.0.7/32", in_interface="vlan-guest",
        )
        await _sync(patch_connect, mikrotik_creds, api, [rule])

        (row,) = _band(api)
        assert row["comment"] == f"cloudguest-fw:{rule.rule_id}"
        assert row["chain"] == "forward"
        assert row["action"] == "reject"
        assert row["protocol"] == "tcp"
        assert row["dst-port"] == "445"
        assert row["src-address"] == "10.10.0.7"
        assert row["dst-address"] == "10.20.0.0/24"
        assert row["in-interface"] == "vlan-guest"
        assert row["disabled"] == "no"

    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda rows: [r for r in rows if r.get("comment") != "cloudguest-fw-band-end"], id="no-end"),
            pytest.param(lambda rows: [r for r in rows if r.get("comment") != "cloudguest-fw-band-begin"], id="no-begin"),
            pytest.param(
                lambda rows: [
                    r for r in rows if not str(r.get("comment")).startswith("cloudguest-fw-band-")
                ],
                id="no-band",
            ),
            pytest.param(
                lambda rows: rows + [{".id": "*BB2", "chain": "forward", "action": "passthrough",
                                      "comment": "cloudguest-fw-band-begin"}],
                id="duplicate-begin",
            ),
            pytest.param(
                lambda rows: [
                    {**r, "action": "drop"} if r.get("comment") == "cloudguest-fw-band-end" else r
                    for r in rows
                ],
                id="sentinel-not-passthrough",
            ),
            pytest.param(
                lambda rows: [
                    {**r, "comment": "cloudguest-fw-band-end"} if r.get("comment") == "cloudguest-fw-band-begin"
                    else {**r, "comment": "cloudguest-fw-band-begin"} if r.get("comment") == "cloudguest-fw-band-end"
                    else r
                    for r in rows
                ],
                id="inverted",
            ),
        ],
    )
    async def test_a_push_without_a_sound_band_refuses_and_writes_nothing(
        self, patch_connect, mikrotik_creds, mutate
    ) -> None:
        api = _Api(menus={_FILTER: mutate(_input_chain() + _lab_forward())})
        before = _rows(api)

        with pytest.raises(MikroTikFirewallRefusedError) as caught:
            await _sync(patch_connect, mikrotik_creds, api, [_rule(10)])

        assert caught.value.code == "ACCESS_RULES_BAND_MISSING"
        assert api.ops == []
        assert _rows(api) == before

    async def test_the_band_is_never_created_by_a_push(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(band=False)
        with pytest.raises(MikroTikFirewallRefusedError):
            await _sync(patch_connect, mikrotik_creds, api, [_rule(10)])
        assert not any(
            str(r.get("comment")).startswith("cloudguest-fw-band-") for r in _rows(api)
        )


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


class TestOrdering:
    async def test_band_order_is_ascending_priority_not_arrival_order(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        low, mid, high = _rule(10), _rule(20), _rule(30)
        await _sync(patch_connect, mikrotik_creds, api, [high, low, mid])
        assert _band_ids(api) == [low.rule_id, mid.rule_id, high.rule_id]

    async def test_equal_priorities_order_by_id_so_the_order_is_stable(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        rules = [_rule(10) for _ in range(4)]
        await _sync(patch_connect, mikrotik_creds, api, rules)
        assert _band_ids(api) == sorted(r.rule_id for r in rules)

    async def test_reprioritising_moves_the_rule_and_adds_before_it_removes(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        a, b, c = _rule(10), _rule(20), _rule(30)
        await _sync(patch_connect, mikrotik_creds, api, [a, b, c])
        api.ops.clear()

        c_first = _rule(5, rule_id=c.rule_id)
        await _sync(patch_connect, mikrotik_creds, api, [a, b, c_first])

        assert _band_ids(api) == [c.rule_id, a.rule_id, b.rule_id]
        kinds = [op[0] for op in api.ops]
        assert kinds == ["add", "remove"], kinds
        assert kinds.index("add") < kinds.index("remove")

    async def test_a_misordered_device_band_is_put_right(
        self, patch_connect, mikrotik_creds
    ) -> None:
        a, b = _rule(10), _rule(20)
        # The device holds b above a -- e.g. an older build, or a hand edit.
        pre = [
            {".id": "*P2", "chain": "forward", "action": "drop", "src-address": "10.10.0.0/24",
             "dst-address": "10.20.0.0/24", "comment": f"cloudguest-fw:{b.rule_id}", "disabled": "no"},
            {".id": "*P1", "chain": "forward", "action": "drop", "src-address": "10.10.0.0/24",
             "dst-address": "10.20.0.0/24", "comment": f"cloudguest-fw:{a.rule_id}", "disabled": "no"},
        ]
        api = _api(extra_in_band=pre)
        await _sync(patch_connect, mikrotik_creds, api, [a, b])
        assert _band_ids(api) == [a.rule_id, b.rule_id]


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    async def test_an_unchanged_re_push_issues_no_writes(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        rules = [_rule(10), _rule(20, protocol="tcp", dst_port=22 + 1000)]
        await _sync(patch_connect, mikrotik_creds, api, rules)
        api.ops.clear()

        result = await _sync(patch_connect, mikrotik_creds, api, rules)

        assert api.ops == []
        assert (result.added, result.removed, result.unchanged) == (0, 0, 2)
        assert list(result.ordered_rule_ids) == [r.rule_id for r in rules]

    async def test_a_host_written_with_slash_32_compares_equal_to_the_device_read_back(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        rule = _rule(10, src_address="10.10.0.7/32")
        await _sync(patch_connect, mikrotik_creds, api, [rule])
        api.ops.clear()
        await _sync(patch_connect, mikrotik_creds, api, [rule])
        assert api.ops == []

    async def test_changing_a_field_replaces_only_that_rule(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        a, b = _rule(10), _rule(20)
        await _sync(patch_connect, mikrotik_creds, api, [a, b])
        untouched_id = next(r[".id"] for r in _band(api) if r["comment"].endswith(a.rule_id))
        api.ops.clear()

        b2 = _rule(20, rule_id=b.rule_id, dst_address="10.30.0.0/24")
        result = await _sync(patch_connect, mikrotik_creds, api, [a, b2])

        assert (result.added, result.removed) == (1, 1)
        assert [op[0] for op in api.ops] == ["add", "remove"]
        assert untouched_id in {r[".id"] for r in _band(api)}
        assert next(r for r in _band(api) if r["comment"].endswith(b.rule_id))[
            "dst-address"
        ] == "10.30.0.0/24"

    async def test_a_hand_disabled_platform_rule_is_re_enabled(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        rule = _rule(10)
        await _sync(patch_connect, mikrotik_creds, api, [rule])
        for row in _band(api):
            row["disabled"] = True
        await _sync(patch_connect, mikrotik_creds, api, [rule])
        (row,) = _band(api)
        assert row["disabled"] == "no"


# ---------------------------------------------------------------------------
# Marker isolation
# ---------------------------------------------------------------------------


class TestMarkerIsolation:
    async def test_rows_without_our_marker_are_never_touched(
        self, patch_connect, mikrotik_creds
    ) -> None:
        foreign_in_band = {".id": "*F", "chain": "forward", "action": "accept",
                           "src-address": "10.99.0.0/24", "comment": "someone else's"}
        api = _api(extra_in_band=[foreign_in_band])
        outside_before = _snapshot_outside_band(api)

        rule = _rule(10)
        await _sync(patch_connect, mikrotik_creds, api, [rule])
        await _sync(  # remove ours again
            patch_connect, mikrotik_creds, api, [], known=[rule.rule_id]
        )

        assert _snapshot_outside_band(api) == outside_before
        assert [r[".id"] for r in _band(api)] == ["*F"]
        removed = [row_id for _, ids in api.remove_calls for row_id in ids]
        assert "*F" not in removed
        assert "*V1" not in removed
        # Changes are add-then-remove; nothing is ever updated in place.
        assert api.update_calls == []

    async def test_the_input_chain_is_never_written(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        await _sync(patch_connect, mikrotik_creds, api, [_rule(10), _rule(20)])
        assert all(fields["chain"] == "forward" for _, fields in api.add_calls)
        assert [r for r in _rows(api) if r["chain"] == "input"] == _input_chain()

    async def test_a_rule_no_longer_desired_is_removed_by_id(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        keep, drop_me = _rule(10), _rule(20)
        await _sync(patch_connect, mikrotik_creds, api, [keep, drop_me])
        gone_id = next(r[".id"] for r in _band(api) if r["comment"].endswith(drop_me.rule_id))
        api.ops.clear()

        result = await _sync(
            patch_connect, mikrotik_creds, api, [keep], known=[drop_me.rule_id]
        )

        assert _band_ids(api) == [keep.rule_id]
        assert api.remove_calls == [(_FILTER, (gone_id,))]
        assert result.removed == 1

    @pytest.mark.parametrize(
        ("row", "code"),
        [
            pytest.param(
                {".id": "*M", "chain": "forward", "action": "drop", "comment": "cloudguest-fw:not-a-uuid"},
                "ACCESS_RULES_MARKER_MALFORMED",
                id="malformed",
            ),
            pytest.param(
                {".id": "*M", "chain": "forward", "action": "drop",
                 "comment": f"cloudguest-fw:{uuid.uuid4()}"},
                "ACCESS_RULES_ORPHAN_MARKER",
                id="orphan-in-band",
            ),
        ],
    )
    async def test_an_unexplained_marker_in_the_band_refuses_everything(
        self, patch_connect, mikrotik_creds, row, code
    ) -> None:
        api = _api(extra_in_band=[row])
        with pytest.raises(MikroTikFirewallRefusedError) as caught:
            await _sync(patch_connect, mikrotik_creds, api, [_rule(10)])
        assert caught.value.code == code
        assert api.ops == []

    async def test_our_marker_outside_the_band_refuses_rather_than_moving_it(
        self, patch_connect, mikrotik_creds
    ) -> None:
        stray_id = str(uuid.uuid4())
        api = _api()
        api.path(*_FILTER).add(
            chain="input", action="drop", comment=f"cloudguest-fw:{stray_id}"
        )
        api.ops.clear()
        with pytest.raises(MikroTikFirewallRefusedError) as caught:
            await _sync(patch_connect, mikrotik_creds, api, [], known=[stray_id])
        assert caught.value.code == "ACCESS_RULES_MARKER_OUTSIDE_BAND"
        assert api.ops == []


# ---------------------------------------------------------------------------
# Rules the writer refuses to put on a router
# ---------------------------------------------------------------------------


class TestRefusedRules:
    @pytest.mark.parametrize(
        ("overrides", "code"),
        [
            pytest.param({"chain": "input"}, "ACCESS_RULES_CHAIN_UNSUPPORTED", id="input-chain"),
            pytest.param({"chain": "output"}, "ACCESS_RULES_CHAIN_UNSUPPORTED", id="output-chain"),
            pytest.param({"in_interface": "wg-cloudguard"}, "ACCESS_RULES_WOULD_ORPHAN_MANAGEMENT", id="tunnel"),
            pytest.param({"protocol": "tcp", "dst_port": 8728}, "ACCESS_RULES_WOULD_ORPHAN_MANAGEMENT", id="api-port"),
            pytest.param({"protocol": "udp", "dst_port": 1812}, "ACCESS_RULES_WOULD_ORPHAN_MANAGEMENT", id="radius"),
            pytest.param({"src_address": None, "dst_address": None}, "ACCESS_RULES_WOULD_BREAK_GUEST_PATH", id="drop-everything"),
            pytest.param({"src_address": "0.0.0.0/0", "dst_address": None}, "ACCESS_RULES_WOULD_BREAK_GUEST_PATH", id="slash-zero"),
            pytest.param({"dst_port": 80}, "ACCESS_RULES_RULE_INVALID", id="port-without-protocol"),
            pytest.param({"src_address": "not-an-ip"}, "ACCESS_RULES_RULE_INVALID", id="bad-address"),
        ],
    )
    async def test_refused_before_any_write(
        self, patch_connect, mikrotik_creds, overrides, code
    ) -> None:
        api = _api()
        with pytest.raises(MikroTikFirewallRefusedError) as caught:
            await _sync(patch_connect, mikrotik_creds, api, [_rule(10), _rule(20, **overrides)])
        assert caught.value.code == code
        assert api.ops == []

    async def test_an_accept_needs_no_narrowing(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        rule = _rule(10, action="accept", src_address=None, dst_address=None)
        await _sync(patch_connect, mikrotik_creds, api, [rule])
        assert _band_ids(api) == [rule.rule_id]


# ---------------------------------------------------------------------------
# Snapshot and restore
# ---------------------------------------------------------------------------


class TestRestore:
    async def test_a_failure_mid_push_restores_the_previous_rules(
        self, patch_connect, mikrotik_creds
    ) -> None:
        a, b = _rule(10), _rule(20)
        api = _api(api_cls=_FailingAddApi, fail_on=4)
        await _sync(patch_connect, mikrotik_creds, api, [a, b])  # adds 1 and 2
        before = [(r["comment"], r.get("dst-address")) for r in _band(api)]

        c = _rule(5)
        b2 = _rule(20, rule_id=b.rule_id, dst_address="10.40.0.0/24")
        with pytest.raises(MikroTikFirewallPushFailedError) as caught:
            # add 3 = b2, add 4 = c -> fails.
            await _sync(patch_connect, mikrotik_creds, api, [a, b2, c])

        assert caught.value.restored is True
        assert [(r["comment"], r.get("dst-address")) for r in _band(api)] == before
        assert "restored" in str(caught.value)

    async def test_a_failed_restore_says_so(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(api_cls=_FailingAddApi, fail_on=2, fail_after=True)
        a = _rule(10)
        await _sync(patch_connect, mikrotik_creds, api, [a])  # add 1

        with pytest.raises(MikroTikFirewallPushFailedError) as caught:
            await _sync(patch_connect, mikrotik_creds, api, [a, _rule(5)])

        assert caught.value.restored is False
        assert "could NOT be restored" in str(caught.value)

    async def test_a_refusal_never_needs_a_restore(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(band=False)
        with pytest.raises(MikroTikFirewallRefusedError):
            await _sync(patch_connect, mikrotik_creds, api, [_rule(10)])
        assert api.ops == []


# ---------------------------------------------------------------------------
# Placing the band
# ---------------------------------------------------------------------------


class TestInstallBand:
    async def test_the_band_lands_directly_above_the_established_accept(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(band=False)
        patch_connect(api)
        result = await MikroTikAdapter().install_firewall_band(mikrotik_creds)

        assert result.created is True
        assert result.anchor_id == "*E"
        forward = [r.get("comment") for r in _rows(api) if r["chain"] == "forward"]
        i = forward.index("cloudguest-fw-band-begin")
        assert forward[i : i + 3] == [
            "cloudguest-fw-band-begin",
            "cloudguest-fw-band-end",
            "cloudguest-fw-fwd-established",
        ]
        assert all(fields["action"] == "passthrough" for _, fields in api.add_calls)
        assert all(fields["place-before"] == "*E" for _, fields in api.add_calls)
        assert [r for r in _rows(api) if r["chain"] == "input"] == _input_chain()

    async def test_an_existing_band_is_left_exactly_where_it_is(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api()
        patch_connect(api)
        result = await MikroTikAdapter().install_firewall_band(mikrotik_creds)
        assert result.created is False
        assert (result.begin_id, result.end_id) == ("*BB", "*BE")
        assert api.ops == []

    async def test_half_a_band_is_not_repaired(
        self, patch_connect, mikrotik_creds
    ) -> None:
        rows = [r for r in _input_chain() + _lab_forward() if r.get("comment") != "cloudguest-fw-band-end"]
        api = _Api(menus={_FILTER: rows})
        patch_connect(api)
        with pytest.raises(MikroTikFirewallRefusedError) as caught:
            await MikroTikAdapter().install_firewall_band(mikrotik_creds)
        assert caught.value.code == "ACCESS_RULES_BAND_PARTIAL"
        assert api.ops == []

    @pytest.mark.parametrize("copies", [0, 2])
    async def test_no_single_anchor_means_no_band(
        self, patch_connect, mikrotik_creds, copies
    ) -> None:
        rows = [r for r in _input_chain() + _lab_forward(band=False)
                if r.get("comment") != "cloudguest-fw-fwd-established"]
        rows += [
            {".id": f"*E{n}", "chain": "forward", "action": "accept",
             "comment": "cloudguest-fw-fwd-established"}
            for n in range(copies)
        ]
        api = _Api(menus={_FILTER: rows})
        patch_connect(api)
        with pytest.raises(MikroTikFirewallRefusedError) as caught:
            await MikroTikAdapter().install_firewall_band(mikrotik_creds)
        assert caught.value.code == "ACCESS_RULES_BAND_ANCHOR_MISSING"
        assert api.ops == []

    async def test_a_push_after_install_lands_above_the_established_accept(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _api(band=False)
        patch_connect(api)
        await MikroTikAdapter().install_firewall_band(mikrotik_creds)
        rule = _rule(10)
        await _sync(patch_connect, mikrotik_creds, api, [rule])
        forward = [r.get("comment") for r in _rows(api) if r["chain"] == "forward"]
        assert forward.index(f"cloudguest-fw:{rule.rule_id}") < forward.index(
            "cloudguest-fw-fwd-established"
        )
