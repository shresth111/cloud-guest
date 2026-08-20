"""Unit tests for the ISP Management domain's real device I/O adapter
layer (``app.domains.isp.device_adapters``) -- specifically
``MikroTikIspHealthAdapter.get_active_default_gateway`` (renamed
2026-08-17 from ``get_dynamic_default_gateway``), which delegates to
``wyfy_device_gateway.mikrotik_adapter.MikroTikAdapter
._get_active_default_gateway_sync`` / ``_select_default_gateway``.

## The bug this file guards against

The original implementation only ever recognized a genuinely *dynamic*
``0.0.0.0/0`` route (RouterOS's own DHCP-client-negotiated gateway).
This platform's own Setup Script generator
(``buildRouterSetupChunks``/``buildRouterSetupScriptChunks`` in
cloudguest-foundation's ``RouterDetailTabs.tsx``) deliberately sets
``add-default-route=no`` on every ``dhcp-client`` it provisions and
instead creates a *static* ``0.0.0.0/0`` route with
``check-gateway=ping``, specifically to keep RouterOS's own
dhcp-client-created dynamic route from fighting the platform's own
routing-mark/failover mangle rules. A router provisioned exactly as
intended therefore legitimately never has a dynamic default route, so
every DHCP-mode WAN link on it was permanently, incorrectly reported
unavailable -- confirmed fleet-wide in production, 2026-08-17, router
"gurugram".

These tests exercise the real fix (a fallback to any *active*,
non-disabled static default route) end-to-end through the same
delegation chain ``ping_link`` actually uses, mirroring
``test_queue_management_adapters.py``'s own "monkeypatch
``librouteros.connect`` with a hand-rolled fake transport that mirrors
the real library's own ``Path``/iteration contract, never a real
socket" convention exactly -- see that file's own module docstring for
the full rationale.

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly.
"""

from __future__ import annotations

import librouteros
import pytest

from app.domains.isp.device_adapters import IspCredentials, MikroTikIspHealthAdapter

CREDENTIALS = IspCredentials(host="10.0.0.1", username="admin", password="secret")


# ============================================================================
# Fake librouteros transport -- identical shape to
# test_queue_management_adapters.FakeRouterosApi/FakePath.
# ============================================================================


class FakePath:
    def __init__(self, store: dict[str, dict]) -> None:
        self.store = store

    def __iter__(self):
        return iter(list(self.store.values()))


class FakeRouterosApi:
    def __init__(self) -> None:
        self._paths: dict[tuple[str, ...], dict[str, dict]] = {}
        self.closed = False

    def path(self, *segments: str) -> FakePath:
        store = self._paths.setdefault(segments, {})
        return FakePath(store)

    def close(self) -> None:
        self.closed = True


def _seed_routes(api: FakeRouterosApi, rows: list[dict[str, str]]) -> None:
    store = api._paths.setdefault(("ip", "route"), {})
    for i, row in enumerate(rows):
        store[f"*{i}"] = {".id": f"*{i}", **row}


# ============================================================================
# get_active_default_gateway
# ============================================================================


class TestGetActiveDefaultGateway:
    async def test_dynamic_route_present_wins_outright(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        _seed_routes(
            api,
            [
                {
                    "dst-address": "0.0.0.0/0",
                    "gateway": "198.51.100.1",
                    "dynamic": "true",
                    "active": "true",
                }
            ],
        )
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikIspHealthAdapter()

        gateway = await adapter.get_active_default_gateway(CREDENTIALS)
        assert gateway == "198.51.100.1"

    async def test_no_dynamic_route_falls_back_to_active_static_route(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real fix: a router provisioned exactly the way this
        platform's own Setup Script generator intends -- static
        ``0.0.0.0/0`` route, ``check-gateway=ping``, no dynamic route at
        all -- must still resolve a usable gateway."""
        api = FakeRouterosApi()
        _seed_routes(
            api,
            [
                {
                    "dst-address": "0.0.0.0/0",
                    "gateway": "203.0.113.1",
                    "dynamic": "false",
                    "static": "true",
                    "active": "true",
                    "disabled": "false",
                    "check-gateway": "ping",
                    "comment": "cloudguest-plain-wan1",
                },
            ],
        )
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikIspHealthAdapter()

        gateway = await adapter.get_active_default_gateway(CREDENTIALS)
        assert gateway == "203.0.113.1"

    async def test_never_hardcoded_to_a_specific_route_comment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Future-proofing check: the fallback must key off ``active``/
        ``disabled``, never off a comment string -- a static default
        route with no comment at all (or a totally different one) must
        resolve identically."""
        api = FakeRouterosApi()
        _seed_routes(
            api,
            [
                {
                    "dst-address": "0.0.0.0/0",
                    "gateway": "203.0.113.9",
                    "dynamic": "false",
                    "static": "true",
                    "active": "true",
                    "disabled": "false",
                    "comment": "",
                },
            ],
        )
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikIspHealthAdapter()

        gateway = await adapter.get_active_default_gateway(CREDENTIALS)
        assert gateway == "203.0.113.9"

    async def test_static_route_present_but_inactive_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A real outage: the static route exists but its own
        ``check-gateway`` probe has failed, so RouterOS itself has marked
        it ``active == "false"``. The fallback must never mask this --
        callers (``IspService.ping_link``) must still see "no usable
        target" and raise, not a fabricated success."""
        api = FakeRouterosApi()
        _seed_routes(
            api,
            [
                {
                    "dst-address": "0.0.0.0/0",
                    "gateway": "203.0.113.1",
                    "dynamic": "false",
                    "static": "true",
                    "active": "false",
                    "disabled": "false",
                    "check-gateway": "ping",
                    "comment": "cloudguest-plain-wan1",
                },
            ],
        )
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikIspHealthAdapter()

        gateway = await adapter.get_active_default_gateway(CREDENTIALS)
        assert gateway is None

    async def test_disabled_static_route_never_used_even_if_marked_active(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        _seed_routes(
            api,
            [
                {
                    "dst-address": "0.0.0.0/0",
                    "gateway": "203.0.113.1",
                    "dynamic": "false",
                    "static": "true",
                    "active": "true",
                    "disabled": "true",
                },
            ],
        )
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikIspHealthAdapter()

        gateway = await adapter.get_active_default_gateway(CREDENTIALS)
        assert gateway is None

    async def test_no_default_route_at_all_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        _seed_routes(
            api,
            [
                {
                    "dst-address": "10.0.0.0/24",
                    "gateway": "0.0.0.0",
                    "dynamic": "false",
                    "active": "true",
                },
            ],
        )
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikIspHealthAdapter()

        gateway = await adapter.get_active_default_gateway(CREDENTIALS)
        assert gateway is None

    async def test_dynamic_route_preferred_over_coexisting_active_static_route(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeRouterosApi()
        _seed_routes(
            api,
            [
                {
                    "dst-address": "0.0.0.0/0",
                    "gateway": "203.0.113.1",
                    "dynamic": "false",
                    "static": "true",
                    "active": "true",
                    "disabled": "false",
                },
                {
                    "dst-address": "0.0.0.0/0",
                    "gateway": "198.51.100.1",
                    "dynamic": "true",
                    "active": "true",
                },
            ],
        )
        monkeypatch.setattr(librouteros, "connect", lambda **kw: api)
        adapter = MikroTikIspHealthAdapter()

        gateway = await adapter.get_active_default_gateway(CREDENTIALS)
        assert gateway == "198.51.100.1"
