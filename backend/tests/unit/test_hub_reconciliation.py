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


# ============================================================================
# The Beat-scheduled sweep.
# ============================================================================


class TestNoCollaboratorSentinel:
    """``_NoCollaborator`` is what makes the narrowed dependency safe rather
    than merely convenient: it turns "this is never used" from a comment
    into something enforced at runtime."""

    def test_any_attribute_access_raises_naming_the_cause(self) -> None:
        from app.domains.hub_reconciliation.tasks import _NoCollaborator

        sentinel = _NoCollaborator("guest_service")

        with pytest.raises(RuntimeError) as excinfo:
            sentinel.get_guest_by_id  # noqa: B018 -- the access IS the test

        message = str(excinfo.value)
        # The message has to name the attribute, the collaborator, and the
        # decision -- a bare AttributeError several frames from the cause is
        # exactly what this exists to avoid.
        assert "guest_service.get_guest_by_id" in message
        assert "NasBindingStore" in message
        assert "do not pass None" in message


class TestTheNarrowContractHolds:
    """The load-bearing claim behind ``_NoCollaborator``: the two methods
    the sweep calls read only ``repository``.

    This test is the reason the narrowing is safe to ship. It drives a REAL
    ``RadiusService`` -- not a fake -- built exactly the way the Celery task
    builds it, sentinels and all, and asserts both methods complete. If a
    future change makes either path reach a collaborator, this fails here
    with a clear message instead of at 3am in a venue.
    """

    def _real_radius_service(self, repository):  # noqa: ANN001, ANN202
        from app.domains.guest.service import RadiusService
        from app.domains.hub_reconciliation.tasks import _NoCollaborator

        return RadiusService(
            repository,
            _NoCollaborator("guest_service"),
            _NoCollaborator("router_lookup"),
            _NoCollaborator("location_lookup"),
            _NoCollaborator("nas_code_counter_repository"),
        )

    async def test_list_nas_clients_touches_no_collaborator(self) -> None:
        from app.domains.guest.constants import NasStatus

        router_id = uuid.uuid4()

        class _Repo:
            async def list_nas_clients(self, *, page, page_size, filters=None):
                assert filters["router_id"] == router_id
                return [], object()

        service = self._real_radius_service(_Repo())

        clients, _meta = await service.list_nas_clients(
            requesting_organization_id=None,
            router_id=router_id,
            status=NasStatus.ACTIVE,
            page=1,
            page_size=1,
        )
        assert clients == []

    async def test_record_hub_client_sync_touches_no_collaborator(self) -> None:
        nas_id = uuid.uuid4()
        stored = FakeNasClient(
            id=nas_id,
            router_id=uuid.uuid4(),
            nas_identifier="cg-narrow",
            shared_secret_encrypted=encrypt_secret("s"),
        )
        stored.organization_id = uuid.uuid4()

        class _Repo:
            async def get_nas_client_by_id(self, _id):
                return stored

            async def update_nas_client(self, client, data):
                for key, value in data.items():
                    setattr(client, key, value)
                return client

        service = self._real_radius_service(_Repo())

        updated = await service.record_hub_client_sync(
            nas_id=nas_id, tunnel_ip_address="10.20.0.10"
        )

        assert updated.hub_client_synced_ip == "10.20.0.10"
        assert updated.ip_address == "10.20.0.10"


class TestSweepFailureIsolationAndCap:
    def _entry(self, router_id, **overrides):  # noqa: ANN001, ANN202
        from app.domains.wireguard.constants import FleetPeerStatus
        from app.domains.wireguard.service import FleetPeerEntry

        fields = {
            "status": FleetPeerStatus.TRACKED_CONNECTED,
            "public_key": f"KEY-{router_id}",
            "router_id": router_id,
            "router_name": "venue",
            "tunnel_ip_address": "10.20.0.6",
            "hub_tunnel_ip_address": "10.20.0.6",
            "last_handshake_at": None,
        }
        fields.update(overrides)
        return FleetPeerEntry(**fields)

    def _fleet(self, peers):  # noqa: ANN001, ANN202
        from app.domains.wireguard.service import FleetStatus

        return FleetStatus(summary={}, peers=peers, adopted_public_keys=[])

    async def test_one_router_raising_does_not_abort_the_others(
        self, monkeypatch, pushes
    ) -> None:
        """A single corrupt row must not stop reconciliation for the entire
        fleet -- and the symptom of that would be silence."""
        radius = FakeRadiusService()
        good_id, bad_id = uuid.uuid4(), uuid.uuid4()
        _nas(radius, good_id, hub_client_synced_ip="10.20.0.8")
        bad = _nas(radius, bad_id, hub_client_synced_ip="10.20.0.8")

        real_reveal = reconciliation_module.decrypt_secret

        def _explode(value):
            if value == bad.shared_secret_encrypted:
                raise ValueError("this NAS row's secret will not decrypt")
            return real_reveal(value)

        monkeypatch.setattr(reconciliation_module, "decrypt_secret", _explode)
        wireguard = FakeWireGuardService(
            fleet=self._fleet([self._entry(bad_id), self._entry(good_id)])
        )
        service = HubReconciliationService(wireguard, radius)

        report = await service.reconcile()

        # The healthy router was still repaired.
        assert [p["tunnel_ip"] for p in pushes] == ["10.20.0.6"]
        # And the broken one is reported, not swallowed.
        failed = [r for r in report.nas_rebinds if not r.pushed]
        assert len(failed) == 1
        assert "will not decrypt" in failed[0].reason

    async def test_the_per_pass_cap_defers_rather_than_drops(
        self, pushes
    ) -> None:
        """Every push restarts freeradius for the whole fleet, so an
        uncapped backlog is an outage generator, not a repair. Deferred work
        is still identified as stale on the next pass five minutes later."""
        radius = FakeRadiusService()
        entries = []
        for _ in range(5):
            router_id = uuid.uuid4()
            _nas(radius, router_id, hub_client_synced_ip="10.20.0.99")
            entries.append(self._entry(router_id))
        wireguard = FakeWireGuardService(fleet=self._fleet(entries))
        service = HubReconciliationService(wireguard, radius, max_rebinds_per_pass=2)

        report = await service.reconcile()

        assert len(pushes) == 2
        assert report.rebinds_deferred == 3


class TestSweepTask:
    async def test_the_lock_stops_a_pass_overlapping_itself(
        self, monkeypatch
    ) -> None:
        """Two passes at once would issue overlapping `systemctl restart
        freeradius` calls through the RADIUS agent -- the exact race
        `radius_agent.py`'s own _WRITE_LOCK docstring documents, where
        systemd cancels one and a valid request fails for no visible
        reason."""
        from app.domains.hub_reconciliation import tasks as tasks_module

        class _HeldRedis:
            async def set(self, *args, **kwargs):
                return None  # NX failed: another pass holds it

            async def delete(self, *args):  # pragma: no cover - not reached
                raise AssertionError("must not release a lock it never took")

            async def aclose(self):
                return None

        monkeypatch.setattr(tasks_module, "create_redis_client", lambda: _HeldRedis())

        result = await tasks_module._run_hub_reconciliation_sweep_async(adopt=True)

        assert result == {"skipped_locked": True}

    def test_an_unreachable_hub_is_reported_not_raised(self, monkeypatch) -> None:
        """A hub that cannot be read is a real, expected operational state
        for an unattended task. Letting it propagate would bury a one-line
        cause under a Celery traceback and a retry storm."""
        from app.domains.hub_reconciliation import tasks as tasks_module
        from app.domains.wireguard.exceptions import (
            HubPeerListerNotConfiguredError,
        )

        def _boom(_coro):
            _coro.close()
            raise HubPeerListerNotConfiguredError()

        monkeypatch.setattr(tasks_module, "run_celery_task", _boom)

        result = tasks_module.run_hub_reconciliation_sweep()

        assert result["hub_unreachable"] is True
        assert "not configured" in result["error"]

    def test_an_unreachable_BRIDGE_is_also_reported_not_raised(
        self, monkeypatch
    ) -> None:
        """The sibling of the test above, and the one that was missing.

        ``HubBridgeUnavailableError`` lives in ``wireguard/dependencies.py``
        and subclasses ``CloudGuestError``, NOT ``WireGuardError`` -- so the
        ``except WireGuardError`` this task has always had never caught it,
        even though the comment sitting on that ``except`` named this exact
        class. And it is the LIKELIER of the two by far: "no lister was
        injected" is a misconfiguration, while "the bridge did not answer" is
        the ordinary state of a plain-HTTP agent on a private address, raised
        by ``make_hub_peer_lister`` on every unreachable poll and deliberately
        propagated by ``get_fleet_status`` rather than guessed around.

        Until 2026-09-01 that escaped as an unhandled Celery exception --
        traceback, retry storm, and the one-line cause buried under both,
        which is the precise burial this handler exists to prevent.
        """
        from app.domains.hub_reconciliation import tasks as tasks_module
        from app.domains.wireguard.dependencies import HubBridgeUnavailableError
        from app.domains.wireguard.exceptions import WireGuardError

        # The trap itself, asserted rather than described: if someone later
        # makes this a WireGuardError subclass, this test should stop being
        # about anything and say so loudly rather than passing vacuously.
        assert not issubclass(HubBridgeUnavailableError, WireGuardError)

        def _boom(_coro):
            _coro.close()
            raise HubBridgeUnavailableError(
                "Could not reach the WireGuard hub bridge to list live peers"
            )

        monkeypatch.setattr(tasks_module, "run_celery_task", _boom)

        result = tasks_module.run_hub_reconciliation_sweep()

        assert result["hub_unreachable"] is True
        assert "hub bridge" in result["error"]

    def test_the_summary_is_json_serialisable_and_diagnostic(
        self, monkeypatch
    ) -> None:
        """The log line has to say what the pass DID. A bare "completed" is
        indistinguishable from a pass that silently found nothing because it
        was broken."""
        import json

        from app.domains.hub_reconciliation import tasks as tasks_module

        payload = {
            "skipped_locked": False,
            "hub_unreachable": False,
            "peers_seen": 9,
            "adopted": 1,
            "rebound": 1,
            "rebind_failed": 0,
            "rebinds_deferred": 0,
            "needs_operator": 6,
            "orphaned": 6,
            "unchanged": 7,
        }
        monkeypatch.setattr(tasks_module, "run_celery_task", lambda c: (
            c.close(), payload)[1])

        result = tasks_module.run_hub_reconciliation_sweep()

        assert result == payload
        json.dumps(result)  # must survive Celery's JSON-only serialization
