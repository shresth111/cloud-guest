"""Remote logging writer: converge, idempotency, and read-back that catches a
write the device accepted but did not hold."""

from __future__ import annotations

import itertools

import pytest

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError
from wyfy_device_gateway.mikrotik_remote_logging import (
    MikroTikRemoteLogging,
    apply_remote_logging,
    read_remote_logging,
    remove_remote_logging,
)

ACTION = ("system", "logging", "action")
RULES = ("system", "logging")

DESIRED_ACTION = {
    "name": "wyfysyslog",
    "target": "remote",
    "remote": "10.20.0.1",
    "remote-port": "514",
    "src-address": "10.20.0.31",
    "bsd-syslog": "yes",
    "syslog-facility": "local5",
    "syslog-severity": "auto",
}
DESIRED_RULES = [
    {"action": "wyfysyslog", "topics": t, "prefix": "wyfy-8a199617"}
    for t in ("critical", "error", "warning", "info")
]
DEFAULTS = [
    {".id": "*0", "name": "memory", "target": "memory"},
    {".id": "*1", "name": "remote", "target": "remote", "remote": "0.0.0.0"},
]
DEFAULT_RULES = [
    {".id": "*a", "topics": "info", "action": "memory", "disabled": False},
    {".id": "*b", "topics": "error", "action": "memory", "disabled": False},
]


def _api(menus: dict | None = None) -> FakeRouterOSApi:
    api = FakeRouterOSApi(
        menus={
            ACTION: [dict(r) for r in DEFAULTS],
            RULES: [dict(r) for r in DEFAULT_RULES],
            **(menus or {}),
        }
    )
    counter = itertools.count(100)
    api.mint_id = lambda _n: f"*{next(counter)}"  # RouterOS never reuses .id
    return api


def _apply(api):
    return apply_remote_logging(
        api, desired_action=DESIRED_ACTION, desired_rules=DESIRED_RULES
    )


def test_apply_on_a_clean_router_writes_one_action_and_four_rules_and_verifies():
    api = _api()
    result = _apply(api)
    assert result.ok, result.detail
    ours = [r for r in api.path(*ACTION) if r.get("name") == "wyfysyslog"]
    assert len(ours) == 1
    rules = [r for r in api.path(*RULES) if r.get("action") == "wyfysyslog"]
    assert sorted(r["topics"] for r in rules) == ["critical", "error", "info", "warning"]


def test_second_apply_writes_nothing():
    api = _api()
    _apply(api)
    before = len(api.ops)
    result = _apply(api)
    assert result.ok
    assert len(api.ops) == before


def test_default_actions_and_rules_are_never_touched():
    api = _api()
    _apply(api)
    remove_remote_logging(api, action_name="wyfysyslog")
    assert [r["name"] for r in api.path(*ACTION)] == ["memory", "remote"]
    assert [r[".id"] for r in api.path(*RULES)] == ["*a", "*b"]


def test_drift_is_converged_duplicate_disabled_and_stale_rules():
    api = _api(
        {
            ACTION: [
                *[dict(r) for r in DEFAULTS],
                {**DESIRED_ACTION, ".id": "*9", "remote": "10.20.0.99"},
            ],
            RULES: [
                *[dict(r) for r in DEFAULT_RULES],
                {".id": "*c", "action": "wyfysyslog", "topics": "info", "prefix": "wyfy-8a199617"},
                {".id": "*d", "action": "wyfysyslog", "topics": "info", "prefix": "wyfy-8a199617"},
                {".id": "*e", "action": "wyfysyslog", "topics": "error", "prefix": "wyfy-8a199617", "disabled": True},
                {".id": "*f", "action": "wyfysyslog", "topics": "debug", "prefix": "old"},
            ],
        }
    )
    result = _apply(api)
    assert result.ok, result.detail
    action = next(r for r in api.path(*ACTION) if r.get("name") == "wyfysyslog")
    assert action["remote"] == "10.20.0.1"
    rules = [r for r in api.path(*RULES) if r.get("action") == "wyfysyslog"]
    assert len(rules) == 4
    assert "*c" in {r[".id"] for r in rules}  # a matching row is kept, not churned


def test_read_back_reports_a_field_the_device_did_not_hold():
    api = _api(
        {ACTION: [*[dict(r) for r in DEFAULTS], {**DESIRED_ACTION, ".id": "*9", "remote": "10.20.0.99"}]}
    )
    api.silently_ignore_updates.add(ACTION)
    result = _apply(api)
    assert not result.ok
    assert "remote" in result.action_mismatches
    assert "10.20.0.99" in result.detail


def test_read_back_normalizes_routeros_types():
    """The API reads back booleans and ints, not the strings written."""
    api = _api(
        {
            ACTION: [
                {**DESIRED_ACTION, ".id": "*9", "bsd-syslog": True, "remote-port": 514},
            ],
            RULES: [dict(r, **{".id": f"*r{i}"}) for i, r in enumerate(DESIRED_RULES)],
        }
    )
    result = read_remote_logging(
        api,
        desired_action=DESIRED_ACTION,
        desired_rules=DESIRED_RULES,
        action_name="wyfysyslog",
    )
    assert result.ok, result.detail


def test_remove_removes_rules_before_the_action_and_verifies_gone():
    api = _api()
    _apply(api)
    result = remove_remote_logging(api, action_name="wyfysyslog")
    assert result.ok and result.detail == "removed"
    removes = [op for op in api.ops if op[0] == "remove"]
    assert removes[0][1] == RULES and removes[-1][1] == ACTION


def test_remove_on_a_router_that_never_had_it_is_a_verified_no_op():
    api = _api()
    result = remove_remote_logging(api, action_name="wyfysyslog")
    assert result.ok
    assert not [op for op in api.ops if op[0] == "remove"]


@pytest.mark.asyncio
async def test_async_entry_point_closes_and_maps_errors():
    from librouteros.exceptions import LibRouterosError

    api = _api()
    client = MikroTikRemoteLogging(connect=lambda _c: api)
    creds = DeviceCredentials(
        vendor=DeviceVendor.MIKROTIK, host="10.20.0.31", username="u", secret="s"
    )
    result = await client.apply(
        creds, desired_action=DESIRED_ACTION, desired_rules=DESIRED_RULES
    )
    assert result.ok and api.closed

    class Boom(FakeRouterOSApi):
        def path(self, *segments):
            raise LibRouterosError("failure: no such command")

    broken = Boom()
    client = MikroTikRemoteLogging(connect=lambda _c: broken)
    with pytest.raises(MikroTikDeviceError):
        await client.remove(creds, action_name="wyfysyslog")
    assert broken.closed


# -- RouterOS dialects: bsd-syslog=yes vs remote-log-format=bsd-syslog --------

MODERN_DEFAULTS = [
    {".id": "*0", "name": "memory", "target": "memory"},
    {
        ".id": "*1",
        "name": "remote",
        "target": "remote",
        "remote": "0.0.0.0",
        "remote-log-format": "default",
    },
]


def test_modern_router_gets_remote_log_format_not_bsd_syslog():
    """Prod 2026-10-07: "unknown parameter bsd-syslog" on a newer RouterOS 7."""
    api = _api({ACTION: [dict(r) for r in MODERN_DEFAULTS]})
    readback = _apply(api)
    ours = [r for r in api._menus[ACTION] if r.get("name") == "wyfysyslog"]
    assert len(ours) == 1
    assert "bsd-syslog" not in ours[0]
    assert ours[0]["remote-log-format"] == "bsd-syslog"
    assert readback.ok, readback.detail


def test_modern_router_second_apply_writes_nothing():
    api = _api({ACTION: [dict(r) for r in MODERN_DEFAULTS]})
    _apply(api)
    before = [dict(r) for r in api._menus[ACTION]]
    readback = _apply(api)
    assert [dict(r) for r in api._menus[ACTION]] == before
    assert readback.ok, readback.detail


def test_legacy_router_keeps_bsd_syslog():
    legacy = [dict(r) for r in DEFAULTS]
    legacy[1]["bsd-syslog"] = False
    api = _api({ACTION: legacy})
    readback = _apply(api)
    ours = [r for r in api._menus[ACTION] if r.get("name") == "wyfysyslog"][0]
    assert _truthy(ours["bsd-syslog"]) and "remote-log-format" not in ours
    assert readback.ok, readback.detail


def _truthy(v):
    return v is True or str(v).lower() in {"yes", "true"}
