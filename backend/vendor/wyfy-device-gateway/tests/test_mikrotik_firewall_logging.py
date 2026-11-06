"""Rate-limited ``WYFY-FW`` log companions in front of Wyfy's own forward
drops, against the write-capable fake RouterOS API.

What these pin, and why each matters on a real router:

* **Only Wyfy drops, only forward, only inside the band.** The venue's own
  rules, the hotspot's dynamic rows, accept rules and anything in
  ``input`` never get a companion.
* **Same matchers, a limit, a marker, directly above the target.** That
  is what makes "this line means the packet was dropped" true and the
  volume bounded.
* **Idempotent, removable, and invisible to the other band writers.** A
  re-sync writes nothing; off removes exactly our rows; the Access Rules
  push, the flood limit and guest isolation still verify with companions
  in the band.
* **Fails towards silence.** A companion that came back without its
  ``limit`` (unbounded) is removed, never left.

Nothing in this file has been run against hardware.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import (
    DeviceCredentials,
    DeviceVendor,
    FirewallFilterRuleConfig,
)
from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError
from wyfy_device_gateway.mikrotik_firewall import (
    FLOOD_LIMIT_COMMENT,
    apply_flood_limit,
    sync_rules,
)
from wyfy_device_gateway.mikrotik_firewall_logging import (
    COMPANION_COMMENT_PREFIX,
    LOG_LIMIT,
    LOG_PREFIX,
    MAX_COMPANIONS,
    MikroTikFirewallLogging,
    companion_fields,
    read_firewall_logging,
    sync_firewall_logging,
)
from wyfy_device_gateway.mikrotik_guest_isolation import GUARD_COMMENT

_FILTER = ("ip", "firewall", "filter")
_RULE_A = "11111111-1111-4111-8111-111111111111"
_RULE_B = "22222222-2222-4222-8222-222222222222"


class _Api(FakeRouterOSApi):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._next = 100

    def mint_id(self, row_count: int) -> str:
        self._next += 1
        return f"*N{self._next}"


def _access(rule_id: str, *, action: str = "drop", **extra: str) -> dict:
    return {
        ".id": f"*C{rule_id[:4]}",
        "chain": "forward",
        "action": action,
        "protocol": "tcp",
        "src-address": "10.5.50.0/24",
        "dst-address": "1.1.1.1",
        "dst-port": "443",
        "comment": f"cloudguest-fw:{rule_id}",
        **extra,
    }


def _guard() -> dict:
    return {
        ".id": "*G1",
        "chain": "forward",
        "action": "drop",
        "src-address": "10.5.50.0/24",
        "dst-address": "10.5.50.0/24",
        "comment": GUARD_COMMENT,
    }


def _flood() -> dict:
    return {
        ".id": "*F1",
        "chain": "forward",
        "action": "drop",
        "protocol": "tcp",
        "connection-state": "new",
        "src-address": "10.5.50.0/24",
        "connection-limit": "200,32",
        "comment": FLOOD_LIMIT_COMMENT,
    }


def _api(in_band: list[dict] | None = None, *, band: bool = True) -> _Api:
    forward: list[dict[str, Any]] = [
        {".id": "*D1", "chain": "forward", "action": "drop",
         "hotspot": "from-client,!auth", "dynamic": True},
        {".id": "*V1", "chain": "forward", "action": "drop",
         "src-address": "192.168.88.50", "comment": "venue's own rule"},
    ]
    if band:
        forward.append({".id": "*BB", "chain": "forward", "action": "passthrough",
                        "comment": "cloudguest-fw-band-begin"})
        forward.extend(in_band or [])
        forward.append({".id": "*BE", "chain": "forward", "action": "passthrough",
                        "comment": "cloudguest-fw-band-end"})
    else:
        forward.extend(in_band or [])
    forward.append({".id": "*E", "chain": "forward", "action": "accept",
                    "connection-state": "established,related",
                    "comment": "cloudguest-fw-fwd-established"})
    inputs = [
        {".id": "*W", "chain": "input", "action": "accept", "protocol": "udp",
         "in-interface": "wg-cloudguard", "comment": "cloudguest-fw-allow-wg-mgmt"},
        {".id": "*X", "chain": "input", "action": "drop",
         "in-interface-list": "WAN", "comment": "cloudguest-fw-drop-wan-input"},
    ]
    return _Api(
        menus={
            _FILTER: inputs + forward,
            ("ip", "address"): [
                {".id": "*A1", "address": "203.0.113.2/30", "interface": "ether1"},
                {".id": "*A2", "address": "10.5.50.1/24", "interface": "bridge-guest"},
            ],
            ("ip", "hotspot"): [
                {".id": "*H1", "name": "hs1", "interface": "bridge-guest"}
            ],
        }
    )


def _rows(api: FakeRouterOSApi) -> list[dict]:
    return list(api.path(*_FILTER))


def _companions(api: FakeRouterOSApi) -> list[dict]:
    return [
        r for r in _rows(api)
        if str(r.get("comment", "")).startswith(COMPANION_COMMENT_PREFIX)
    ]


def _above(api: FakeRouterOSApi, target_id: str) -> dict:
    rows = _rows(api)
    index = next(i for i, r in enumerate(rows) if r[".id"] == target_id)
    return rows[index - 1]


# -- rule generation ---------------------------------------------------------


def test_companion_copies_matchers_and_adds_limit_prefix_and_marker() -> None:
    fields = companion_fields(_access(_RULE_A))
    assert fields == {
        "chain": "forward",
        "action": "log",
        "protocol": "tcp",
        "src-address": "10.5.50.0/24",
        "dst-address": "1.1.1.1",
        "dst-port": "443",
        "limit": LOG_LIMIT,
        "log-prefix": LOG_PREFIX,
        "comment": f"{COMPANION_COMMENT_PREFIX}cloudguest-fw:{_RULE_A}",
    }
    flood = companion_fields(_flood())
    assert flood is not None
    assert flood["connection-limit"] == "200,32"
    assert flood["connection-state"] == "new"


def test_a_target_with_an_unknown_matcher_is_skipped_not_broadened() -> None:
    target = _access(_RULE_A, **{"tls-host": "*.example.com"})
    assert companion_fields(target) is None

    api = _api([target])
    result = sync_firewall_logging(api, enabled=True)
    assert result.ok
    assert _companions(api) == []
    assert result.skipped == ((f"cloudguest-fw:{_RULE_A}", "UNSUPPORTED_MATCHER"),)


def test_sync_places_one_companion_directly_above_each_wyfy_drop() -> None:
    api = _api([_guard(), _flood(), _access(_RULE_A),
                _access(_RULE_B, action="accept")])
    result = sync_firewall_logging(api, enabled=True)

    assert result.ok, result.detail
    assert (result.targets, result.companions, result.added) == (3, 3, 3)
    for target_id, target in (("*G1", _guard()), ("*F1", _flood()),
                              (f"*C{_RULE_A[:4]}", _access(_RULE_A))):
        above = _above(api, target_id)
        assert above["action"] == "log"
        assert above["comment"] == COMPANION_COMMENT_PREFIX + target["comment"]
        assert above["limit"] == LOG_LIMIT
        assert above["log-prefix"] == LOG_PREFIX
        assert "log" not in target  # the drop itself is never log=yes
    # Every add is positioned by .id, never appended.
    assert all("place-before" in fields for _, fields in api.add_calls)


def test_never_the_venues_own_rules_dynamic_rows_or_input_chain() -> None:
    api = _api([_access(_RULE_A)])
    sync_firewall_logging(api, enabled=True)
    commented = {r["comment"] for r in _companions(api)}
    assert commented == {f"{COMPANION_COMMENT_PREFIX}cloudguest-fw:{_RULE_A}"}
    assert all(r["chain"] == "forward" for r in _companions(api))


def test_disabled_target_gets_no_companion() -> None:
    api = _api([_access(_RULE_A, disabled="true")])
    result = sync_firewall_logging(api, enabled=True)
    assert result.ok and result.targets == 0 and _companions(api) == []


def test_no_band_means_nothing_to_log_and_nothing_written() -> None:
    api = _api([_access(_RULE_A)], band=False)
    result = sync_firewall_logging(api, enabled=True)
    assert result.ok
    assert result.band_state == "missing"
    assert api.add_calls == []


def test_companion_count_is_capped_platform_rows_first() -> None:
    rules = [str(uuid.UUID(int=i + 1, version=4)) for i in range(MAX_COMPANIONS + 2)]
    in_band = [_guard()] + [
        {**_access(r), ".id": f"*R{i}"} for i, r in enumerate(rules)
    ]
    api = _api(in_band)
    result = sync_firewall_logging(api, enabled=True)
    assert result.ok
    assert result.companions == MAX_COMPANIONS
    assert _above(api, "*G1")["comment"] == COMPANION_COMMENT_PREFIX + GUARD_COMMENT
    assert [reason for _, reason in result.skipped] == ["OVER_CAP"] * 3


# -- idempotency and removal -------------------------------------------------


def test_second_sync_writes_nothing() -> None:
    api = _api([_guard(), _access(_RULE_A)])
    sync_firewall_logging(api, enabled=True)
    writes = len(api.ops)
    again = sync_firewall_logging(api, enabled=True)
    assert again.ok and (again.added, again.removed) == (0, 0)
    assert len(api.ops) == writes


def test_routeros_printing_the_default_interval_still_counts_as_kept() -> None:
    api = _api([_access(_RULE_A)])
    sync_firewall_logging(api, enabled=True)
    _companions(api)[0]["limit"] = "2,5:packet"
    again = sync_firewall_logging(api, enabled=True)
    assert again.ok and again.added == 0


def test_off_removes_every_companion_and_nothing_else() -> None:
    api = _api([_guard(), _access(_RULE_A)])
    before = [r[".id"] for r in _rows(api)]
    sync_firewall_logging(api, enabled=True)
    # A stray companion in another chain is ours too, and goes.
    api.path(*_FILTER).add(chain="input", action="log",
                           comment=f"{COMPANION_COMMENT_PREFIX}stray")
    result = sync_firewall_logging(api, enabled=False)
    assert result.ok and result.removed == 3
    assert [r[".id"] for r in _rows(api)] == before


def test_moved_target_gets_a_fresh_companion_and_the_old_one_goes() -> None:
    api = _api([_access(_RULE_A), _access(_RULE_B)])
    sync_firewall_logging(api, enabled=True)
    # The Access Rules push re-adds a changed rule A at a new position
    # (no `move` in librouteros): new row, old row removed.
    rows = api._menus[_FILTER]
    old_a = next(r for r in rows if r.get(".id") == f"*C{_RULE_A[:4]}")
    rows.remove(old_a)
    end = next(i for i, r in enumerate(rows) if r.get("comment") ==
               "cloudguest-fw-band-end")
    rows.insert(end, {**old_a, ".id": "*NEWA", "dst-port": "80"})

    result = sync_firewall_logging(api, enabled=True)
    assert result.ok, result.detail
    assert result.companions == 2
    assert _above(api, "*NEWA")["dst-port"] == "80"
    assert _above(api, f"*C{_RULE_B[:4]}")["comment"].endswith(_RULE_B)
    # Adds happened before removes.
    kinds = [op for op, path, _ in api.ops if path == _FILTER][-3:]
    assert kinds.index("add") < kinds.index("remove")


def test_read_reports_state_without_writing() -> None:
    api = _api([_access(_RULE_A)])
    assert read_firewall_logging(api).enabled is False
    sync_firewall_logging(api, enabled=True)
    writes = len(api.ops)
    state = read_firewall_logging(api)
    assert state.enabled and state.ok and state.companions == 1
    assert len(api.ops) == writes


# -- read-back ---------------------------------------------------------------


class _DropsLimit(_Api):
    """A router that accepts the add and silently does not hold ``limit``
    -- the case that would make a companion unbounded."""

    def path(self, *segments: str):  # noqa: ANN201
        menu = super().path(*segments)
        if segments != _FILTER:
            return menu
        original = menu.add

        def add(**fields: Any) -> str:
            fields.pop("limit", None)
            return original(**fields)

        menu.add = add  # type: ignore[method-assign]
        return menu


def test_a_companion_that_lost_its_limit_is_removed_and_reported() -> None:
    base = _api([_access(_RULE_A)])
    api = _DropsLimit(menus={k: list(v) for k, v in base._menus.items()})
    result = sync_firewall_logging(api, enabled=True)
    assert result.ok is False
    assert "read-back failed" in result.detail
    assert _companions(api) == []


# -- other band writers stay happy ------------------------------------------


def _config(rule_id: str, dst_port: int) -> FirewallFilterRuleConfig:
    return FirewallFilterRuleConfig(
        rule_id=rule_id, chain="forward", action="drop", priority=10,
        protocol="tcp", src_address="10.5.50.0/24", dst_address="1.1.1.1",
        dst_port=dst_port,
    )


def test_access_rules_push_and_flood_limit_still_verify_with_companions() -> None:
    api = _api([_access(_RULE_A)])
    sync_firewall_logging(api, enabled=True)

    pushed = sync_rules(api, [_config(_RULE_A, 8443)], known_rule_ids=[_RULE_A])
    assert pushed.ordered_rule_ids == (_RULE_A,)
    flood = apply_flood_limit(api, limit=200)
    assert flood.added == 1

    result = sync_firewall_logging(api, enabled=True)
    assert result.ok, result.detail
    assert result.targets == 2  # the re-added access rule and the flood row
    for row in _rows(api):
        if row.get("comment") in (f"cloudguest-fw:{_RULE_A}", FLOOD_LIMIT_COMMENT):
            assert _above(api, row[".id"])["action"] == "log"


# -- async entry point -------------------------------------------------------


def test_entry_point_refuses_other_vendors_and_closes_the_connection() -> None:
    api = _api([_access(_RULE_A)])
    client = MikroTikFirewallLogging(connect=lambda creds: api)
    creds = DeviceCredentials(vendor=DeviceVendor.MIKROTIK, host="10.0.0.2",
                              username="u", secret="s")
    result = asyncio.run(client.sync(creds, enabled=True))
    assert result.ok and api.closed

    omada = DeviceCredentials(vendor=DeviceVendor.TPLINK_OMADA, host="10.0.0.3",
                              username="u", secret="s")
    with pytest.raises(MikroTikDeviceError):
        asyncio.run(client.read(omada))
