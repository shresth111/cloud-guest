"""Cloudflare Gateway DoH switch, its rollback, and the bypass hardening,
against a fake RouterOS API. Nothing here has been run on hardware.

What these pin, and why each matters on a real router:

* **Snapshot before, restore on failure.** A broken DoH upstream means no
  guest resolves anything; a probe failure must leave the router exactly as
  it was, and say so.
* **Read-back.** A ``set`` that returns cleanly and changes nothing is
  treated as a failure, not a success.
* **Re-push rolls back to the ORIGINAL snapshot**, never to the router's
  current (already-Gateway) state.
* **Static DNS is never touched** -- content filtering's sinkhole lives there.
* **Version gate** for certificate trust; refusal before any write.
* **Bypass hardening** writes only ``cloudguest-dnsf-`` rows, above the
  existing DoT drop, idempotently, and removes only its own.
"""

from __future__ import annotations

from typing import Any

import pytest
from librouteros.exceptions import LibRouterosError

from tests.fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.mikrotik_dns_filtering import (
    BYPASS_FILTER_MARKERS,
    BYPASS_NAT_MARKERS,
    DnsResolverSnapshot,
    MikroTikDnsFilteringRefusedError,
    MikroTikDohProbeFailedError,
    apply_dns_bypass_hardening,
    apply_gateway_doh,
    parse_routeros_version,
    remove_dns_bypass_hardening,
    restore_dns_resolver,
)

_URL = "https://abc123.cloudflare-gateway.com/dns-query"
_PROBE = "cloudflare.com"
_DNS = ("ip", "dns")
_STATIC = ("ip", "dns", "static")
_CERT = ("certificate", "settings")
_FILTER = ("ip", "firewall", "filter")
_NAT = ("ip", "firewall", "nat")


def _no_sleep(_: float) -> None:
    return None


def _resolves(address: str = "104.16.132.229"):
    def handler(api: Any, kwargs: dict[str, Any]) -> list[dict[str, Any]]:
        return [{"ret": f"{address}\n"}]

    return handler


def _router(
    *,
    version: str = "7.23.3 (stable)",
    doh: str = "",
    verify: bool = False,
    trust: dict[str, Any] | None = None,
    servers: str = "8.8.8.8",
    dynamic: str = "192.168.1.1",
    probe: Any = None,
    raise_on_command: dict[str, Exception] | None = None,
) -> FakeRouterOSApi:
    return FakeRouterOSApi(
        menus={
            ("system", "resource"): [{"version": version}],
            _DNS: [
                {
                    "servers": servers,
                    "dynamic-servers": dynamic,
                    "use-doh-server": doh,
                    "verify-doh-cert": verify,
                    "allow-remote-requests": True,
                }
            ],
            _CERT: [trust if trust is not None else {"builtin-trust-store": "default"}],
            _STATIC: [
                {
                    ".id": "*S1",
                    "name": "facebook.com",
                    "address": "127.0.0.1",
                    "comment": "WyfyGuest content filter x: Block",
                }
            ],
        },
        command_handlers={"/execute": probe or _resolves()},
        raise_on_command=raise_on_command,
    )


def _dns(api: FakeRouterOSApi) -> dict[str, Any]:
    return next(iter(api.path(*_DNS)))


def _failing_probe(api: Any, kwargs: dict[str, Any]) -> list[dict[str, Any]]:
    raise LibRouterosError("failure: dns server failure")


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------


class TestSwitch:
    async def test_switches_verifies_and_returns_the_prior_state(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _router(doh="https://old.example/dns-query", verify=False)
        patch_connect(api)

        result = await apply_gateway_doh(
            mikrotik_creds, doh_url=_URL, probe_hostname=_PROBE, sleep=_no_sleep
        )

        assert _dns(api)["use-doh-server"] == _URL
        assert _dns(api)["verify-doh-cert"] == "yes"
        assert result.changed is True
        assert result.probe_address == "104.16.132.229"
        assert result.snapshot == DnsResolverSnapshot(
            use_doh_server="https://old.example/dns-query", verify_doh_cert=False
        )
        # The probe runs :resolve through the router, after a cache flush.
        cmds = [c for c, _ in api.command_calls]
        assert cmds.index("/ip/dns/cache/flush") < cmds.index("/execute")
        assert api.command_calls[-1][1]["script"] == ':put [:resolve "cloudflare.com"]'
        assert api.closed

    async def test_never_touches_static_dns_or_the_upstream_servers(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _router()
        patch_connect(api)

        await apply_gateway_doh(
            mikrotik_creds, doh_url=_URL, probe_hostname=_PROBE, sleep=_no_sleep
        )

        touched = {op[1] for op in api.ops if op[0] != "command"}
        assert _STATIC not in touched
        for _path, fields in api.update_calls:
            assert "servers" not in fields

    async def test_unchanged_repush_writes_nothing_and_still_probes(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _router(doh=_URL, verify=True)
        patch_connect(api)
        original = DnsResolverSnapshot(use_doh_server="", verify_doh_cert=False)

        result = await apply_gateway_doh(
            mikrotik_creds,
            doh_url=_URL,
            probe_hostname=_PROBE,
            rollback_to=original,
            sleep=_no_sleep,
        )

        assert api.update_calls == []
        assert result.changed is False
        assert result.snapshot == original
        assert any(c == "/execute" for c, _ in api.command_calls)


class TestRollback:
    async def test_probe_failure_restores_the_snapshot(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _router(doh="", verify=False, probe=_failing_probe)
        patch_connect(api)

        with pytest.raises(MikroTikDohProbeFailedError) as exc:
            await apply_gateway_doh(
                mikrotik_creds, doh_url=_URL, probe_hostname=_PROBE, sleep=_no_sleep
            )

        assert exc.value.rolled_back is True
        assert exc.value.code == "DOH_PROBE_FAILED"
        assert _dns(api)["use-doh-server"] == ""
        assert _dns(api)["verify-doh-cert"] == "no"
        # Three attempts before giving up.
        assert sum(1 for c, _ in api.command_calls if c == "/execute") == 3

    async def test_a_write_that_does_not_read_back_is_rolled_back(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _router()
        api.silently_ignore_updates.add(_DNS)
        patch_connect(api)

        with pytest.raises(MikroTikDohProbeFailedError, match="did not read back"):
            await apply_gateway_doh(
                mikrotik_creds, doh_url=_URL, probe_hostname=_PROBE, sleep=_no_sleep
            )
        # No probe was attempted against a switch that never happened.
        assert not any(c == "/execute" for c, _ in api.command_calls)

    async def test_repush_failure_restores_the_original_not_the_current_state(
        self, patch_connect, mikrotik_creds
    ) -> None:
        """The router already holds our URL. Rolling back to *that* would
        leave the venue on a broken Gateway and call it restored."""
        api = _router(doh=_URL, verify=True, probe=_failing_probe)
        patch_connect(api)
        original = DnsResolverSnapshot(
            use_doh_server="https://isp.example/dns-query", verify_doh_cert=True
        )

        with pytest.raises(MikroTikDohProbeFailedError):
            await apply_gateway_doh(
                mikrotik_creds,
                doh_url=_URL,
                probe_hostname=_PROBE,
                rollback_to=original,
                sleep=_no_sleep,
            )

        assert _dns(api)["use-doh-server"] == "https://isp.example/dns-query"

    async def test_a_failed_restore_is_reported_as_such(
        self, patch_connect, mikrotik_creds
    ) -> None:
        class _Api(FakeRouterOSApi):
            writes = 0

            def path(self, *segments: str):
                menu = super().path(*segments)
                if segments == _DNS:
                    original = menu.update

                    def update(**fields: Any) -> None:
                        type(self).writes += 1
                        if type(self).writes > 1:
                            raise LibRouterosError("failure: simulated")
                        original(**fields)

                    menu.update = update  # type: ignore[method-assign]
                return menu

        base = _router(probe=_failing_probe)
        api = _Api(
            menus={k: list(v) for k, v in base._menus.items()},
            command_handlers={"/execute": _failing_probe},
        )
        patch_connect(api)

        with pytest.raises(MikroTikDohProbeFailedError) as exc:
            await apply_gateway_doh(
                mikrotik_creds, doh_url=_URL, probe_hostname=_PROBE, sleep=_no_sleep
            )
        assert exc.value.rolled_back is False
        assert "ROLLBACK FAILED" in str(exc.value)


class TestRefusals:
    @pytest.mark.parametrize("version", ["7.18.2 (stable)", "6.49.10 (long-term)"])
    async def test_old_routeros_is_refused_before_any_write(
        self, patch_connect, mikrotik_creds, version: str
    ) -> None:
        api = _router(version=version)
        patch_connect(api)

        with pytest.raises(MikroTikDnsFilteringRefusedError) as exc:
            await apply_gateway_doh(
                mikrotik_creds, doh_url=_URL, probe_hostname=_PROBE, sleep=_no_sleep
            )
        assert exc.value.code == "ROUTEROS_TOO_OLD"
        assert api.update_calls == []

    async def test_no_upstream_to_bootstrap_the_doh_hostname_is_refused(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _router(servers="", dynamic="")
        patch_connect(api)

        with pytest.raises(MikroTikDnsFilteringRefusedError) as exc:
            await apply_gateway_doh(
                mikrotik_creds, doh_url=_URL, probe_hostname=_PROBE, sleep=_no_sleep
            )
        assert exc.value.code == "DNS_BOOTSTRAP_MISSING"
        assert api.update_calls == []


class TestTrust:
    async def test_7_21_narrowed_store_gets_dns_appended_and_restored(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _router(trust={"builtin-trust-store": "fetch,www"}, probe=_failing_probe)
        patch_connect(api)

        with pytest.raises(MikroTikDohProbeFailedError):
            await apply_gateway_doh(
                mikrotik_creds, doh_url=_URL, probe_hostname=_PROBE, sleep=_no_sleep
            )

        writes = [f for p, f in api.update_calls if p == _CERT]
        assert writes[0] == {"builtin-trust-store": "fetch,www,dns"}
        # Put back on rollback.
        assert next(iter(api.path(*_CERT)))["builtin-trust-store"] == "fetch,www"

    async def test_7_21_default_store_is_left_alone(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _router(trust={"builtin-trust-store": "default"})
        patch_connect(api)

        result = await apply_gateway_doh(
            mikrotik_creds, doh_url=_URL, probe_hostname=_PROBE, sleep=_no_sleep
        )
        assert not [f for p, f in api.update_calls if p == _CERT]
        assert result.snapshot.trust_setting is None

    async def test_7_19_uses_trust_anchors(self, patch_connect, mikrotik_creds) -> None:
        api = _router(
            version="7.19.4 (stable)", trust={"builtin-trust-anchors": "not-trusted"}
        )
        patch_connect(api)

        result = await apply_gateway_doh(
            mikrotik_creds, doh_url=_URL, probe_hostname=_PROBE, sleep=_no_sleep
        )
        assert next(iter(api.path(*_CERT)))["builtin-trust-anchors"] == "trusted"
        assert result.snapshot.trust_setting == "builtin-trust-anchors"
        assert result.snapshot.trust_setting_value == "not-trusted"


class TestRestore:
    async def test_disable_restores_the_snapshot(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _router(doh=_URL, verify=True)
        patch_connect(api)

        result = await restore_dns_resolver(
            mikrotik_creds,
            snapshot=DnsResolverSnapshot(use_doh_server="", verify_doh_cert=False),
            expected_doh_url=_URL,
            probe_hostname=_PROBE,
            sleep=_no_sleep,
        )
        assert result.changed is True
        assert result.probe_ok is True
        assert _dns(api)["use-doh-server"] == ""
        assert not [p for p, _ in api.update_calls if p == _STATIC]

    async def test_restore_is_idempotent(self, patch_connect, mikrotik_creds) -> None:
        api = _router(doh="", verify=False)
        patch_connect(api)

        result = await restore_dns_resolver(
            mikrotik_creds,
            snapshot=DnsResolverSnapshot(use_doh_server="", verify_doh_cert=False),
            expected_doh_url=_URL,
            probe_hostname=_PROBE,
            sleep=_no_sleep,
        )
        assert result.changed is False
        assert api.update_calls == []

    async def test_a_doh_url_set_by_someone_else_is_not_overwritten(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _router(doh="https://someone-else.example/dns-query", verify=True)
        patch_connect(api)

        with pytest.raises(MikroTikDnsFilteringRefusedError) as exc:
            await restore_dns_resolver(
                mikrotik_creds,
                snapshot=DnsResolverSnapshot(use_doh_server="", verify_doh_cert=False),
                expected_doh_url=_URL,
                probe_hostname=_PROBE,
                sleep=_no_sleep,
            )
        assert exc.value.code == "DNS_CHANGED_EXTERNALLY"
        assert api.update_calls == []


def test_parse_routeros_version() -> None:
    assert parse_routeros_version("7.23.3 (stable)") == (7, 23, 3)
    assert parse_routeros_version("7.19rc2") == (7, 19, 0)
    assert parse_routeros_version("garbage") is None


# ---------------------------------------------------------------------------
# bypass hardening
# ---------------------------------------------------------------------------


def _provisioned_forward() -> list[dict[str, Any]]:
    return [
        {".id": "*F1", "chain": "forward", "action": "jump", "dynamic": True},
        {".id": "*F3", "chain": "forward", "action": "drop", "protocol": "udp",
         "dst-port": "853", "hotspot": "!auth", "comment": "cloudguest-block-dot-udp"},
        {".id": "*F4", "chain": "forward", "action": "drop", "protocol": "tcp",
         "dst-port": "853", "hotspot": "!auth", "comment": "cloudguest-block-dot-tcp"},
        {".id": "*F5", "chain": "forward", "action": "drop", "protocol": "tcp",
         "dst-port": "443", "hotspot": "!auth", "dst-address-list": "cloudguest-doh-ips",
         "comment": "cloudguest-block-doh"},
        {".id": "*F6", "chain": "forward", "action": "accept", "comment": "customer-own"},
        {".id": "*F7", "chain": "forward", "action": "accept",
         "connection-state": "established,related",
         "comment": "cloudguest-fw-fwd-established"},
    ]


def _hardening_router(overrides: dict | None = None) -> FakeRouterOSApi:
    menus = {
        _FILTER: _provisioned_forward(),
        _NAT: [{".id": "*N1", "chain": "srcnat", "action": "masquerade",
                "comment": "WYFYGUEST-masq"}],
        ("ip", "firewall", "address-list"): [
            {".id": "*A1", "list": "cloudguest-doh-ips", "address": "1.1.1.1"}
        ],
    }
    menus.update(overrides or {})
    return FakeRouterOSApi(menus=menus)


def _comments(api: FakeRouterOSApi, path: tuple[str, ...]) -> list[str]:
    return [str(r.get("comment", "")) for r in api.path(*path)]


class TestBypassHardening:
    async def test_adds_marked_rows_above_the_existing_dot_drop(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _hardening_router()
        patch_connect(api)

        await apply_dns_bypass_hardening(mikrotik_creds)

        forward = _comments(api, _FILTER)
        anchor = forward.index("cloudguest-block-dot-udp")
        assert forward[anchor - 3 : anchor] == list(BYPASS_FILTER_MARKERS)
        assert forward.index(BYPASS_FILTER_MARKERS[-1]) < forward.index(
            "cloudguest-fw-fwd-established"
        )
        for row in api.path(*_FILTER):
            if row.get("comment") in BYPASS_FILTER_MARKERS:
                assert row["hotspot"] == "auth"
        assert _comments(api, _NAT)[-2:] == list(BYPASS_NAT_MARKERS)

    async def test_existing_rules_are_never_modified(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _hardening_router()
        patch_connect(api)
        before = [dict(r) for r in api.path(*_FILTER)]

        await apply_dns_bypass_hardening(mikrotik_creds)

        assert api.update_calls == []
        assert api.remove_calls == []
        after = {r[".id"]: r for r in api.path(*_FILTER)}
        for row in before:
            assert after[row[".id"]] == row

    async def test_idempotent(self, patch_connect, mikrotik_creds) -> None:
        api = _hardening_router()
        patch_connect(api)

        await apply_dns_bypass_hardening(mikrotik_creds)
        adds = len(api.add_calls)
        await apply_dns_bypass_hardening(mikrotik_creds)

        assert len(api.add_calls) == adds
        assert api.update_calls == []

    async def test_a_drifted_row_is_corrected_in_place(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _hardening_router()
        patch_connect(api)
        await apply_dns_bypass_hardening(mikrotik_creds)
        row = next(
            r for r in api.path(*_FILTER) if r.get("comment") == BYPASS_FILTER_MARKERS[0]
        )
        row["dst-port"] = "54"
        row["disabled"] = True

        await apply_dns_bypass_hardening(mikrotik_creds)

        assert api.update_calls[-1][1] == {
            ".id": row[".id"], "dst-port": "853", "disabled": "no"
        }

    @pytest.mark.parametrize("missing", ["rule", "list"])
    async def test_refuses_without_the_platform_drops(
        self, patch_connect, mikrotik_creds, missing: str
    ) -> None:
        if missing == "rule":
            api = _hardening_router({
                _FILTER: [r for r in _provisioned_forward()
                          if r.get("comment") != "cloudguest-block-dot-udp"]
            })
        else:
            api = _hardening_router({("ip", "firewall", "address-list"): []})
        patch_connect(api)

        with pytest.raises(MikroTikDnsFilteringRefusedError) as exc:
            await apply_dns_bypass_hardening(mikrotik_creds)
        assert exc.value.code == "BYPASS_ANCHOR_MISSING"
        assert api.add_calls == []

    async def test_remove_takes_off_only_our_rows(
        self, patch_connect, mikrotik_creds
    ) -> None:
        api = _hardening_router()
        patch_connect(api)
        before_filter = _comments(api, _FILTER)
        before_nat = _comments(api, _NAT)

        await apply_dns_bypass_hardening(mikrotik_creds)
        await remove_dns_bypass_hardening(mikrotik_creds)
        await remove_dns_bypass_hardening(mikrotik_creds)

        assert _comments(api, _FILTER) == before_filter
        assert _comments(api, _NAT) == before_nat
