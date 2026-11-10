"""``wyfy_device_gateway.mikrotik_snmp`` against an in-memory RouterOS API.

The fake models the two menus the module touches -- ``/snmp`` (one settings
object) and ``/snmp community`` (rows, with the factory ``public`` row
flagged ``default=true``) -- closely enough that the read-back is a real
read of what the writes left behind, not an echo of what was sent.
"""

from __future__ import annotations

from typing import Any

import pytest
from wyfy_device_gateway.mikrotik_snmp import (
    COMMUNITY_COMMENT,
    DEFAULT_COMMUNITY_FENCE,
    SnmpDeviceConfig,
    apply_snmp_config,
    desired_community_row,
    read_snmp_state,
    remove_snmp_config,
)


class _Menu:
    def __init__(self, api: _FakeApi, key: tuple[str, ...]) -> None:
        self.api = api
        self.key = key

    def _rows(self) -> list[dict[str, Any]]:
        return self.api.menus.setdefault(self.key, [])

    def __iter__(self):
        return iter([dict(r) for r in self._rows()])

    def add(self, **fields: str) -> str:
        if self.api.ignore_writes:
            return "*0"
        self.api.counter += 1
        row = {".id": f"*{self.api.counter:X}", "default": False, "disabled": False}
        row.update(fields)
        self._rows().append(row)
        self.api.writes.append(("add", self.key, dict(fields)))
        return row[".id"]

    def update(self, **fields: str) -> None:
        self.api.writes.append(("update", self.key, dict(fields)))
        if self.api.ignore_writes:
            return
        rid = fields.pop(".id", None)
        for row in self._rows():
            if rid is None or row.get(".id") == rid:
                row.update(fields)
                if rid is not None:
                    return

    def remove(self, *ids: str) -> None:
        self.api.writes.append(("remove", self.key, {"ids": ids}))
        if self.api.ignore_writes:
            return
        self.api.menus[self.key] = [r for r in self._rows() if r.get(".id") not in ids]


class _FakeApi:
    def __init__(
        self,
        *,
        enabled: bool = False,
        communities: list[dict[str, Any]] | None = None,
        echo_passwords: bool = False,
        ignore_writes: bool = False,
    ) -> None:
        self.counter = 0x20
        self.echo_passwords = echo_passwords
        self.ignore_writes = ignore_writes
        self.writes: list[tuple[str, tuple[str, ...], dict[str, Any]]] = []
        self.menus: dict[tuple[str, ...], list[dict[str, Any]]] = {
            ("snmp",): [{"enabled": enabled}],
            ("snmp", "community"): communities
            if communities is not None
            else [
                {
                    ".id": "*0",
                    "name": "public",
                    "addresses": "::/0",
                    "default": True,
                    "read-access": True,
                    "write-access": False,
                    "security": "none",
                    "disabled": False,
                }
            ],
        }

    def path(self, *segments: str) -> _Menu:
        menu = _Menu(self, segments)
        if segments == ("snmp", "community") and not self.echo_passwords:
            return _NoPasswordEcho(self, segments)
        return menu


class _NoPasswordEcho(_Menu):
    """RouterOS may not echo USM passphrases on print."""

    def __iter__(self):
        for row in self._rows():
            yield {
                k: v
                for k, v in row.items()
                if k not in ("authentication-password", "encryption-password")
            }


SOURCES = ("172.31.38.118/32",)


def _v2(name: str = "s3cret-comm") -> SnmpDeviceConfig:
    return SnmpDeviceConfig(name=name, addresses=SOURCES)


def _ours(api: _FakeApi) -> list[dict[str, Any]]:
    return [
        r
        for r in api.menus[("snmp", "community")]
        if r.get("comment") == COMMUNITY_COMMENT
    ]


def _public(api: _FakeApi) -> dict[str, Any]:
    return next(r for r in api.menus[("snmp", "community")] if r.get("default"))


class TestDesiredRow:
    def test_v2c_is_read_only_and_source_restricted(self) -> None:
        row = desired_community_row(_v2())
        assert row["read-access"] == "yes"
        assert row["write-access"] == "no"
        assert row["addresses"] == "172.31.38.118/32"
        assert row["security"] == "none"
        assert "authentication-password" not in row

    def test_empty_addresses_refused_because_routeros_reads_it_as_any(self) -> None:
        with pytest.raises(ValueError):
            desired_community_row(SnmpDeviceConfig(name="x", addresses=()))

    def test_v3_private_carries_both_protocols(self) -> None:
        row = desired_community_row(
            SnmpDeviceConfig(
                name="wyfy",
                addresses=SOURCES,
                security="private",
                auth_protocol="SHA1",
                auth_password="authpass1",
                priv_protocol="AES",
                priv_password="privpass1",
            )
        )
        assert row["security"] == "private"
        assert row["authentication-protocol"] == "SHA1"
        assert row["encryption-protocol"] == "AES"

    def test_repr_never_contains_secrets(self) -> None:
        cfg = SnmpDeviceConfig(
            name="topsecret", addresses=SOURCES, auth_password="authpass1"
        )
        assert "topsecret" not in repr(cfg)
        assert "authpass1" not in repr(cfg)


class TestApply:
    def test_fresh_router_converges_and_verifies(self) -> None:
        api = _FakeApi()
        result = apply_snmp_config(api, _v2())
        assert result.verified, result.mismatches
        assert len(_ours(api)) == 1
        assert _ours(api)[0]["name"] == "s3cret-comm"
        assert api.menus[("snmp",)][0]["enabled"] == "yes"
        # Factory public fenced.
        assert _public(api)["addresses"] == DEFAULT_COMMUNITY_FENCE
        assert result.state is not None
        assert result.state.agent_enabled
        assert not result.state.default_public_open
        assert set(result.changed) >= {
            "community",
            "default-public-fenced",
            "agent-enabled",
        }

    def test_public_is_fenced_before_agent_is_enabled(self) -> None:
        api = _FakeApi()
        apply_snmp_config(api, _v2())
        order = [
            (
                "fence"
                if w[1] == ("snmp", "community") and w[0] == "update"
                else "enable"
                if w[1] == ("snmp",)
                else w[0]
            )
            for w in api.writes
        ]
        assert order.index("fence") < order.index("enable")

    def test_second_apply_is_a_no_op(self) -> None:
        api = _FakeApi()
        apply_snmp_config(api, _v2())
        api.writes.clear()
        result = apply_snmp_config(api, _v2())
        assert result.changed == []
        assert api.writes == []
        assert result.verified

    def test_rotation_updates_in_place_found_by_marker_not_name(self) -> None:
        api = _FakeApi()
        apply_snmp_config(api, _v2("old-community"))
        result = apply_snmp_config(api, _v2("new-community"))
        assert result.verified
        assert [r["name"] for r in _ours(api)] == ["new-community"]

    def test_renamed_default_community_is_left_alone(self) -> None:
        api = _FakeApi(
            communities=[
                {
                    ".id": "*0",
                    "name": "ops-monitoring",
                    "addresses": "10.0.0.0/8",
                    "default": True,
                    "disabled": False,
                }
            ]
        )
        apply_snmp_config(api, _v2())
        assert _public(api)["addresses"] == "10.0.0.0/8"

    def test_write_that_does_nothing_is_reported_not_verified(self) -> None:
        api = _FakeApi(ignore_writes=True)
        result = apply_snmp_config(api, _v2())
        assert not result.verified
        assert "community:missing" in result.mismatches
        assert "agent:enabled" in result.mismatches

    def test_v3_passwords_not_echoed_are_unverified_not_assumed(self) -> None:
        api = _FakeApi()
        cfg = SnmpDeviceConfig(
            name="wyfy",
            addresses=SOURCES,
            security="authorized",
            auth_protocol="SHA1",
            auth_password="authpass1",
        )
        result = apply_snmp_config(api, cfg)
        assert result.verified
        assert result.unverified == ["community:authentication-password"]

    def test_duplicate_marker_rows_are_collapsed(self) -> None:
        api = _FakeApi()
        apply_snmp_config(api, _v2())
        api.menus[("snmp", "community")].append(
            {
                ".id": "*99",
                "name": "dup",
                "comment": COMMUNITY_COMMENT,
                "default": False,
            }
        )
        result = apply_snmp_config(api, _v2())
        assert len(_ours(api)) == 1
        assert result.verified


class TestRemove:
    def test_remove_turns_agent_off_when_nothing_else_uses_it(self) -> None:
        api = _FakeApi()
        apply_snmp_config(api, _v2())
        result = remove_snmp_config(api)
        assert _ours(api) == []
        assert api.menus[("snmp",)][0]["enabled"] == "no"
        assert result.verified
        # The fence stays: it only made the device safer.
        assert _public(api)["addresses"] == DEFAULT_COMMUNITY_FENCE

    def test_remove_leaves_agent_on_for_an_operators_own_community(self) -> None:
        api = _FakeApi()
        apply_snmp_config(api, _v2())
        api.menus[("snmp", "community")].append(
            {".id": "*77", "name": "theirs", "default": False, "comment": ""}
        )
        remove_snmp_config(api)
        assert api.menus[("snmp",)][0]["enabled"] == "yes"


def test_read_state_reports_open_factory_public() -> None:
    api = _FakeApi(enabled=True)
    state = read_snmp_state(api)
    assert state.agent_enabled
    assert state.default_public_open
    assert not state.community_present


# -- librouteros-shaped reads (Master "NOT verified" on every real router) --
#
# librouteros 3.2.1 parses ``yes``/``no``/``true``/``false`` on the wire into
# Python ``True``/``False`` (measured on CHR 7.25.1, 2026-11-10). The fake
# above stores what was sent, so it echoed ``"yes"`` back and the text
# compare ``"True" != "yes"`` was never exercised.

_WIRE_BOOLS = {"yes": True, "true": True, "no": False, "false": False}


def _as_librouteros(row: dict[str, Any]) -> dict[str, Any]:
    return {
        k: _WIRE_BOOLS.get(v, v) if isinstance(v, str) else v for k, v in row.items()
    }


class _LibrouterosMenu(_NoPasswordEcho):
    def __iter__(self):
        return (_as_librouteros(r) for r in super().__iter__())


class _LibrouterosSettings(_Menu):
    def __iter__(self):
        return (_as_librouteros(r) for r in super().__iter__())


class _LibrouterosApi(_FakeApi):
    def path(self, *segments: str) -> _Menu:
        if segments == ("snmp", "community"):
            return _LibrouterosMenu(self, segments)
        return _LibrouterosSettings(self, segments)


class TestBooleanReadBack:
    def test_real_router_read_back_verifies(self) -> None:
        api = _LibrouterosApi()
        result = apply_snmp_config(api, _v2())
        assert result.mismatches == []
        assert result.verified
        # the read really did come back as bools
        mine = next(iter(api.path("snmp", "community")))
        assert mine["default"] is True

    def test_real_router_second_apply_is_a_no_op(self) -> None:
        api = _LibrouterosApi()
        apply_snmp_config(api, _v2())
        api.writes.clear()
        result = apply_snmp_config(api, _v2())
        assert result.changed == []
        assert api.writes == []
        assert result.verified

    def test_real_mismatch_still_fails_with_bools(self) -> None:
        # The router keeps write-access on (an operator, or a write that
        # did nothing): read back as Python True, desired "no".
        api = _LibrouterosApi()
        apply_snmp_config(api, _v2())
        _ours(api)[0]["write-access"] = "yes"
        api.ignore_writes = True
        result = apply_snmp_config(api, _v2())
        assert "community:write-access" in result.mismatches
        assert not result.verified

    def test_real_mismatch_still_fails_on_text_fields(self) -> None:
        api = _LibrouterosApi()
        apply_snmp_config(api, _v2())
        _ours(api)[0]["addresses"] = "0.0.0.0/0"
        api.ignore_writes = True
        result = apply_snmp_config(api, _v2())
        assert result.mismatches == ["community:addresses"]
        assert not result.verified


@pytest.mark.parametrize(
    ("key", "actual", "desired", "same"),
    [
        # booleans: librouteros bools and every RouterOS spelling
        ("read-access", True, "yes", True),
        ("read-access", "yes", "yes", True),
        ("read-access", "true", "yes", True),
        ("read-access", "TRUE", "yes", True),
        ("write-access", False, "no", True),
        ("write-access", "no", "no", True),
        ("write-access", "false", "no", True),
        ("disabled", False, "no", True),
        # real boolean mismatches
        ("read-access", False, "yes", False),
        ("write-access", True, "no", False),
        ("write-access", "yes", "no", False),
        ("read-access", "", "yes", False),
        ("read-access", None, "yes", False),
        ("read-access", "maybe", "yes", False),
        # text fields compare as text, exactly as before
        ("addresses", "172.31.38.118/32", "172.31.38.118/32", True),
        ("addresses", "0.0.0.0/0", "172.31.38.118/32", False),
        ("security", "none", "none", True),
        ("security", "private", "none", False),
        # a community NAME that spells a boolean is not normalised
        ("name", True, "yes", False),
        ("name", "true", "yes", False),
        ("name", "yes", "yes", True),
    ],
)
def test_field_compare(key: str, actual: Any, desired: str, same: bool) -> None:
    from wyfy_device_gateway.mikrotik_snmp import _field_matches

    assert _field_matches(key, actual, desired) is same
