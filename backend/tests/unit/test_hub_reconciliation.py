"""Unit tests for ``app.domains.hub_reconciliation``: the layer that owns
the pair nobody owned -- a router's WireGuard identity and the FreeRADIUS
``client{}`` stanza keyed on its tunnel address.

The failure these are written against, measured on the production hub on
2026-08-27: the platform recorded router 21e13913 on ``10.20.0.8`` and had
pushed its RADIUS client stanza to match, while the device was handshaking
on ``10.20.0.6`` with a key the platform had overwritten. FreeRADIUS drops
an Access-Request from an address it has no ``client{}`` for without
replying, so every guest login at that venue failed with nothing logged
anywhere.

The RADIUS bridge itself (``guest.radius_bridge.push_nas_client``) is
monkeypatched rather than driven over HTTP, matching this suite's
established in-memory style; what is under test here is the decision of
*whether* and *with what address* to push, which is the half that was
missing.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import pytest

from app.domains.guest.constants import NasStatus
from app.domains.guest.radius_bridge import RadiusBridgePushError
from app.domains.hub_reconciliation import service as reconciliation_module
from app.domains.hub_reconciliation.service import HubReconciliationService
from app.domains.router.crypto import encrypt_secret


@dataclass
class FakeNasClient:
    id: uuid.UUID
    router_id: uuid.UUID
    nas_identifier: str
    shared_secret_encrypted: str
    hub_client_synced_ip: str | None = None
    hub_client_synced_at: object | None = None
    ip_address: str | None = None


@dataclass
class FakeRadiusService:
    """Only the two methods ``HubReconciliationService`` actually uses --
    the same narrow-surface posture the WireGuard domain's own fakes take
    toward ``RouterService``."""

    clients: dict[uuid.UUID, FakeNasClient] = field(default_factory=dict)
    synced: list[tuple[uuid.UUID, str]] = field(default_factory=list)

    async def list_nas_clients(
        self,
        *,
        requesting_organization_id,
        router_id=None,
        status=None,
        page=1,
        page_size=25,
        location_id=None,
    ):
        assert status is NasStatus.ACTIVE
        found = [c for c in self.clients.values() if c.router_id == router_id]
        return found[:page_size], object()

    async def record_hub_client_sync(
        self, *, nas_id, tunnel_ip_address, requesting_organization_id=None
    ):
        client = self.clients[nas_id]
        client.hub_client_synced_ip = tunnel_ip_address
        client.ip_address = tunnel_ip_address
        self.synced.append((nas_id, tunnel_ip_address))
        return client


@dataclass
class FakeWireGuardService:
    fleet: object = None
    adopt_calls: list[bool] = field(default_factory=list)

    async def get_fleet_status(self, *, now=None, adopt=False):
        self.adopt_calls.append(adopt)
        return self.fleet


def _nas(radius: FakeRadiusService, router_id: uuid.UUID, **overrides):
    client = FakeNasClient(
        id=uuid.uuid4(),
        router_id=router_id,
        nas_identifier=f"cg-{str(router_id)[:8]}",
        shared_secret_encrypted=encrypt_secret("a-real-shared-secret"),
        **overrides,
    )
    radius.clients[client.id] = client
    return client


@pytest.fixture
def pushes(monkeypatch):
    """Records every ``push_nas_client`` call. Patched on the reconciliation
    module's own reference, not the source module, because it is imported
    by name there."""
    recorded: list[dict] = []

    async def _push(*, tunnel_ip: str, nas_identifier: str, secret: str) -> None:
        recorded.append(
            {
                "tunnel_ip": tunnel_ip,
                "nas_identifier": nas_identifier,
                "secret": secret,
            }
        )

    monkeypatch.setattr(reconciliation_module, "push_nas_client", _push)
    return recorded


class TestRebindNasForRouter:
    async def test_pushes_then_records_what_the_hub_confirmed(
        self, pushes
    ) -> None:
        """Order is the point. The whole class of bug this code keeps
        meeting is a database that says an external system was changed when
        it was not -- 21 live client stanzas against 0 active NAS rows, a
        peer row on .8 against a device on .6."""
        radius = FakeRadiusService()
        router_id = uuid.uuid4()
        client = _nas(radius, router_id, hub_client_synced_ip="10.20.0.8")
        service = HubReconciliationService(FakeWireGuardService(), radius)

        result = await service.rebind_nas_for_router(
            router_id=router_id, tunnel_ip_address="10.20.0.6"
        )

        assert result.pushed is True
        assert pushes == [
            {
                "tunnel_ip": "10.20.0.6",
                "nas_identifier": client.nas_identifier,
                "secret": "a-real-shared-secret",
            }
        ]
        assert client.hub_client_synced_ip == "10.20.0.6"

    async def test_a_refused_push_records_nothing(self, monkeypatch) -> None:
        """A failed push must leave `hub_client_synced_ip` untouched. That
        column is the ONLY thing that claims to describe clients.conf, and
        the mismatch it preserves is what makes the next pass retry."""
        radius = FakeRadiusService()
        router_id = uuid.uuid4()
        client = _nas(radius, router_id, hub_client_synced_ip="10.20.0.8")

        async def _boom(**kwargs: object) -> None:
            raise RadiusBridgePushError(
                "config validation failed, reverted",
                transport=False,
                status_code=500,
            )

        monkeypatch.setattr(reconciliation_module, "push_nas_client", _boom)
        service = HubReconciliationService(FakeWireGuardService(), radius)

        result = await service.rebind_nas_for_router(
            router_id=router_id, tunnel_ip_address="10.20.0.6"
        )

        assert result.pushed is False
        assert "config validation failed" in result.reason
        assert client.hub_client_synced_ip == "10.20.0.8"
        assert radius.synced == []

    async def test_a_router_with_no_nas_client_is_reported_not_crashed(
        self, pushes
    ) -> None:
        radius = FakeRadiusService()
        service = HubReconciliationService(FakeWireGuardService(), radius)

        result = await service.rebind_nas_for_router(
            router_id=uuid.uuid4(), tunnel_ip_address="10.20.0.6"
        )

        assert result.pushed is False
        assert "no active RADIUS NAS client" in result.reason
        assert pushes == []

    async def test_the_shared_secret_is_reused_never_rotated(self, pushes) -> None:
        """An address change is not a credential change. Rotating the secret
        here would break the device, which is still holding the old one."""
        radius = FakeRadiusService()
        router_id = uuid.uuid4()
        _nas(radius, router_id)
        service = HubReconciliationService(FakeWireGuardService(), radius)

        await service.rebind_nas_for_router(
            router_id=router_id, tunnel_ip_address="10.20.0.6"
        )
        await service.rebind_nas_for_router(
            router_id=router_id, tunnel_ip_address="10.20.0.7"
        )

        assert {p["secret"] for p in pushes} == {"a-real-shared-secret"}


class TestReconcilePass:
    def _fleet(self, peers, summary=None):  # noqa: ANN001, ANN202 -- helper
        from app.domains.wireguard.service import FleetStatus

        return FleetStatus(
            summary=summary or {},
            peers=peers,
            adopted_public_keys=[],
        )

    def _entry(self, **overrides):  # noqa: ANN001, ANN202 -- helper
        from app.domains.wireguard.constants import FleetPeerStatus
        from app.domains.wireguard.service import FleetPeerEntry

        fields = {
            "status": FleetPeerStatus.TRACKED_CONNECTED,
            "public_key": "KEY",
            "router_id": uuid.uuid4(),
            "router_name": "lobby router",
            "tunnel_ip_address": "10.20.0.6",
            "hub_tunnel_ip_address": "10.20.0.6",
            "last_handshake_at": None,
        }
        fields.update(overrides)
        return FleetPeerEntry(**fields)

    async def test_a_stale_binding_is_repushed_even_with_nothing_to_adopt(
        self, pushes
    ) -> None:
        """The property that makes this converge rather than depend on the
        moment of change: a push that failed last time is simply retried,
        because the condition identifying it is still true."""
        radius = FakeRadiusService()
        router_id = uuid.uuid4()
        _nas(radius, router_id, hub_client_synced_ip="10.20.0.8")
        entry = self._entry(router_id=router_id)
        wireguard = FakeWireGuardService(fleet=self._fleet([entry]))
        service = HubReconciliationService(wireguard, radius)

        report = await service.reconcile()

        assert [p["tunnel_ip"] for p in pushes] == ["10.20.0.6"]
        assert report.nas_rebinds[0].pushed is True

    async def test_an_agreeing_binding_is_left_alone(self, pushes) -> None:
        """Every push restarts FreeRADIUS for the WHOLE fleet
        (``_validate_and_restart``). A pass that pushed unconditionally
        would bounce authentication for every venue on every run -- turning
        a repair into an outage generator."""
        radius = FakeRadiusService()
        router_id = uuid.uuid4()
        _nas(radius, router_id, hub_client_synced_ip="10.20.0.6")
        wireguard = FakeWireGuardService(
            fleet=self._fleet([self._entry(router_id=router_id)])
        )
        service = HubReconciliationService(wireguard, radius)

        await service.reconcile()

        assert pushes == []

    async def test_running_twice_changes_nothing_the_second_time(
        self, pushes
    ) -> None:
        radius = FakeRadiusService()
        router_id = uuid.uuid4()
        _nas(radius, router_id, hub_client_synced_ip="10.20.0.8")
        wireguard = FakeWireGuardService(
            fleet=self._fleet([self._entry(router_id=router_id)])
        )
        service = HubReconciliationService(wireguard, radius)

        await service.reconcile()
        await service.reconcile()

        assert len(pushes) == 1

    async def test_ambiguous_and_unattributable_peers_are_reported_never_pushed(
        self, pushes
    ) -> None:
        """Each of these is either ambiguous or unattributable, and the
        correct response is an operator with context, not a background job
        with a heuristic."""
        from app.domains.wireguard.constants import FleetPeerStatus

        radius = FakeRadiusService()
        router_id = uuid.uuid4()
        _nas(radius, router_id, hub_client_synced_ip="10.20.0.8")
        entries = [
            self._entry(
                status=FleetPeerStatus.ADOPTABLE_MISMATCH,
                public_key="AMBIGUOUS",
                router_id=router_id,
            ),
            self._entry(
                status=FleetPeerStatus.UNTRACKED_CONNECTED,
                public_key="UNATTRIBUTABLE",
                router_id=None,
                tunnel_ip_address=None,
            ),
            self._entry(
                status=FleetPeerStatus.TRACKED_KEY_MISMATCH,
                public_key="ADDRESS-SPLIT",
                router_id=router_id,
            ),
        ]
        wireguard = FakeWireGuardService(fleet=self._fleet(entries))
        service = HubReconciliationService(wireguard, radius)

        report = await service.reconcile()

        assert pushes == []
        assert set(report.drift_public_keys) == {
            "AMBIGUOUS",
            "UNATTRIBUTABLE",
            "ADDRESS-SPLIT",
        }

    async def test_adopt_false_is_a_dry_run_of_the_wireguard_half(
        self, pushes
    ) -> None:
        radius = FakeRadiusService()
        wireguard = FakeWireGuardService(fleet=self._fleet([]))
        service = HubReconciliationService(wireguard, radius)

        await service.reconcile(adopt=False)

        assert wireguard.adopt_calls == [False]
