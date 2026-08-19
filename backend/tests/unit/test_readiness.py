"""Unit tests for the Router Readiness Checklist domain: the five
auto-detected items' pass/fail/not_checked branching, manual confirm/
override persistence, and a structural RBAC check that every route carries
a permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_content_filtering.py``); ``asyncio_mode = "auto"`` runs
async tests directly. ``ReadinessService`` is exercised against small,
hand-rolled in-memory fakes for its own repository and its four composed
lookup protocols (router/isp/wireguard/router_agent) -- no live device I/O
in this domain at all (see ``service.py``'s own module docstring).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.readiness.constants import (
    CHECKLIST_ITEMS,
    ChecklistItemKey,
    ChecklistItemStatus,
    DetectionMode,
)
from app.domains.readiness.exceptions import UnknownChecklistItemError
from app.domains.readiness.models import RouterChecklistItem
from app.domains.readiness.router import router as readiness_router
from app.domains.readiness.service import ReadinessService
from app.domains.router.models import Router
from app.domains.wireguard.exceptions import WireGuardPeerNotFoundError

# ============================================================================
# Shared helpers
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


def _make_router(*, status: str = "online", health_status: str | None = None) -> Router:
    return Router(
        **_base_fields(
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor="mikrotik",
            routeros_version=None,
            management_ip_address="10.0.0.1",
            public_ip_address=None,
            status=status,
            last_seen_at=_now(),
            last_health_check_at=None,
            health_status=health_status,
            api_username="admin",
            api_credentials_encrypted="encrypted-placeholder",
            settings={},
        )
    )


@dataclass
class FakeIspLink:
    is_enabled: bool
    health_status: str | None


@dataclass
class FakeWireGuardPeer:
    status: str
    last_handshake_at: datetime | None


@dataclass
class FakeCredential:
    revoked_at: datetime | None
    expires_at: datetime

    def is_active(self, *, now: datetime) -> bool:
        return self.revoked_at is None and now <= self.expires_at


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeReadinessRepository:
    rows: dict[tuple[uuid.UUID, str], RouterChecklistItem] = field(default_factory=dict)

    async def get_all_for_router(
        self, router_id: uuid.UUID
    ) -> list[RouterChecklistItem]:
        return [row for (rid, _key), row in self.rows.items() if rid == router_id]

    async def get_item(
        self, router_id: uuid.UUID, item_key: str
    ) -> RouterChecklistItem | None:
        return self.rows.get((router_id, item_key))

    async def upsert_item(
        self, router_id: uuid.UUID, item_key: str, data: dict[str, object]
    ) -> RouterChecklistItem:
        existing = self.rows.get((router_id, item_key))
        if existing is None:
            row = RouterChecklistItem(
                **_base_fields(router_id=router_id, item_key=item_key, **data)
            )
        else:
            row = existing
            for k, v in data.items():
                setattr(row, k, v)
        self.rows[(router_id, item_key)] = row
        return row


@dataclass
class FakeRouterLookup:
    routers: dict[uuid.UUID, Router] = field(default_factory=dict)

    def add(self, router: Router) -> Router:
        self.routers[router.id] = router
        return router

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Router:
        return self.routers[router_id]


@dataclass
class FakeIspLookup:
    links_by_router: dict[uuid.UUID, list[FakeIspLink]] = field(default_factory=dict)

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[FakeIspLink], object]:
        links = self.links_by_router.get(router_id, [])
        return links, None


@dataclass
class FakeWireGuardLookup:
    peers_by_router: dict[uuid.UUID, FakeWireGuardPeer] = field(default_factory=dict)
    health_by_peer_status: dict[str, str] = field(default_factory=dict)

    async def get_peer(
        self, *, router_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> FakeWireGuardPeer:
        peer = self.peers_by_router.get(router_id)
        if peer is None:
            raise WireGuardPeerNotFoundError(router_id)
        return peer

    def compute_health_status(
        self, peer: FakeWireGuardPeer, *, now: datetime | None = None
    ) -> str:
        return self.health_by_peer_status.get(peer.status, "unknown")


@dataclass
class FakeRouterAgentLookup:
    credentials_by_router: dict[uuid.UUID, FakeCredential] = field(default_factory=dict)

    async def get_credential_for_router(
        self, router_id: uuid.UUID
    ) -> FakeCredential | None:
        return self.credentials_by_router.get(router_id)


def _build_service() -> tuple[
    ReadinessService,
    FakeReadinessRepository,
    FakeRouterLookup,
    FakeIspLookup,
    FakeWireGuardLookup,
    FakeRouterAgentLookup,
]:
    repo = FakeReadinessRepository()
    router_lookup = FakeRouterLookup()
    isp_lookup = FakeIspLookup()
    wg_lookup = FakeWireGuardLookup()
    agent_lookup = FakeRouterAgentLookup()
    service = ReadinessService(repo, router_lookup, isp_lookup, wg_lookup, agent_lookup)
    return service, repo, router_lookup, isp_lookup, wg_lookup, agent_lookup


# ============================================================================
# Registry sanity
# ============================================================================


class TestChecklistItemRegistry:
    def test_fourteen_items_registered(self) -> None:
        assert len(CHECKLIST_ITEMS) == 14

    def test_five_items_are_auto_detected(self) -> None:
        auto = [i for i in CHECKLIST_ITEMS if i.detection_mode == DetectionMode.AUTO]
        assert {i.key for i in auto} == {
            ChecklistItemKey.HEARTBEAT,
            ChecklistItemKey.SAAS_PROVISIONING,
            ChecklistItemKey.WAN_CONNECTIVITY,
            ChecklistItemKey.WIREGUARD,
            ChecklistItemKey.API_REACHABILITY,
        }


# ============================================================================
# Auto-detection
# ============================================================================


class TestHeartbeat:
    async def test_online_router_passes(self) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router(status="online"))
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "heartbeat")
        assert row.status == ChecklistItemStatus.PASS.value
        assert row.detection_mode == DetectionMode.AUTO.value

    async def test_offline_router_fails(self) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router(status="offline"))
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "heartbeat")
        assert row.status == ChecklistItemStatus.FAIL.value


class TestSaasProvisioning:
    async def test_no_credential_fails(self) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router(status="online"))
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "saas_provisioning")
        assert row.status == ChecklistItemStatus.FAIL.value

    async def test_active_credential_and_online_passes(self) -> None:
        service, _repo, router_lookup, _isp, _wg, agent_lookup = _build_service()
        router = router_lookup.add(_make_router(status="online"))
        agent_lookup.credentials_by_router[router.id] = FakeCredential(
            revoked_at=None, expires_at=_now() + timedelta(days=30)
        )
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "saas_provisioning")
        assert row.status == ChecklistItemStatus.PASS.value

    async def test_revoked_credential_fails(self) -> None:
        service, _repo, router_lookup, _isp, _wg, agent_lookup = _build_service()
        router = router_lookup.add(_make_router(status="online"))
        agent_lookup.credentials_by_router[router.id] = FakeCredential(
            revoked_at=_now(), expires_at=_now() + timedelta(days=30)
        )
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "saas_provisioning")
        assert row.status == ChecklistItemStatus.FAIL.value


class TestWanConnectivity:
    async def test_no_enabled_links_is_not_checked(self) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router())
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "wan_connectivity")
        assert row.status == ChecklistItemStatus.NOT_CHECKED.value

    async def test_one_healthy_enabled_link_passes(self) -> None:
        service, _repo, router_lookup, isp_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router())
        isp_lookup.links_by_router[router.id] = [
            FakeIspLink(is_enabled=True, health_status="unhealthy"),
            FakeIspLink(is_enabled=True, health_status="healthy"),
        ]
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "wan_connectivity")
        assert row.status == ChecklistItemStatus.PASS.value

    async def test_all_enabled_links_unhealthy_fails(self) -> None:
        service, _repo, router_lookup, isp_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router())
        isp_lookup.links_by_router[router.id] = [
            FakeIspLink(is_enabled=True, health_status="unhealthy"),
        ]
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "wan_connectivity")
        assert row.status == ChecklistItemStatus.FAIL.value


class TestWireGuard:
    async def test_not_configured_is_not_checked(self) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router())
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "wireguard")
        assert row.status == ChecklistItemStatus.NOT_CHECKED.value

    async def test_healthy_handshake_passes(self) -> None:
        service, _repo, router_lookup, _isp, wg_lookup, _agent = _build_service()
        router = router_lookup.add(_make_router())
        wg_lookup.peers_by_router[router.id] = FakeWireGuardPeer(
            status="active", last_handshake_at=_now()
        )
        wg_lookup.health_by_peer_status["active"] = "healthy"
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "wireguard")
        assert row.status == ChecklistItemStatus.PASS.value

    async def test_stale_handshake_fails(self) -> None:
        service, _repo, router_lookup, _isp, wg_lookup, _agent = _build_service()
        router = router_lookup.add(_make_router())
        wg_lookup.peers_by_router[router.id] = FakeWireGuardPeer(
            status="active", last_handshake_at=_now() - timedelta(days=30)
        )
        wg_lookup.health_by_peer_status["active"] = "stale"
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "wireguard")
        assert row.status == ChecklistItemStatus.FAIL.value


class TestApiReachability:
    async def test_unknown_is_not_checked(self) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router(health_status=None))
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "api_reachability")
        assert row.status == ChecklistItemStatus.NOT_CHECKED.value

    async def test_healthy_passes(self) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router(health_status="healthy"))
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "api_reachability")
        assert row.status == ChecklistItemStatus.PASS.value

    async def test_unhealthy_fails(self) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router(health_status="unhealthy"))
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "api_reachability")
        assert row.status == ChecklistItemStatus.FAIL.value


# ============================================================================
# Manual items + confirm_item
# ============================================================================


class TestManualItems:
    async def test_untouched_manual_item_defaults_to_not_checked(self) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router())
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "guest_sign_in")
        assert row.status == ChecklistItemStatus.NOT_CHECKED.value
        assert row.detection_mode == DetectionMode.MANUAL.value

    async def test_confirm_item_persists_and_is_returned_on_next_read(self) -> None:
        service, *_ = _build_service()
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router())
        actor = uuid.uuid4()
        await service.confirm_item(
            router.id,
            "guest_sign_in",
            status=ChecklistItemStatus.MANUALLY_CONFIRMED,
            detail="Tested on-site with a phone.",
            actor_user_id=actor,
            requesting_organization_id=None,
        )
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "guest_sign_in")
        assert row.status == ChecklistItemStatus.MANUALLY_CONFIRMED.value
        assert row.checked_by_user_id == actor
        assert row.detail == "Tested on-site with a phone."

    async def test_confirm_item_overrides_an_auto_item_until_next_auto_recheck(
        self,
    ) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router(status="offline"))
        await service.confirm_item(
            router.id,
            "heartbeat",
            status=ChecklistItemStatus.MANUALLY_CONFIRMED,
            detail="Known offline for maintenance, expected.",
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
        )
        row = await _repo_get(service, router.id, "heartbeat")
        assert row.status == ChecklistItemStatus.MANUALLY_CONFIRMED.value
        # The next get_checklist call re-runs auto-detection and overwrites
        # this back to a fresh, live result -- confirm_item is a one-shot
        # override, not a permanent pin.
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        row = next(r for r in rows if r.item_key == "heartbeat")
        assert row.status == ChecklistItemStatus.FAIL.value
        assert row.detection_mode == DetectionMode.AUTO.value

    async def test_confirm_item_rejects_unknown_key(self) -> None:
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router())
        with pytest.raises(UnknownChecklistItemError):
            await service.confirm_item(
                router.id,
                "not_a_real_item",
                status=ChecklistItemStatus.MANUALLY_CONFIRMED,
                detail=None,
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=None,
            )


async def _repo_get(
    service: ReadinessService, router_id: uuid.UUID, item_key: str
) -> RouterChecklistItem:
    return await service.repository.get_item(router_id, item_key)


# ============================================================================
# Summary
# ============================================================================


class TestSummarize:
    async def test_counts_pass_fail_not_checked(self) -> None:
        service, _repo, router_lookup, _isp, wg_lookup, agent_lookup = _build_service()
        router = router_lookup.add(
            _make_router(status="online", health_status="healthy")
        )
        agent_lookup.credentials_by_router[router.id] = FakeCredential(
            revoked_at=None, expires_at=_now() + timedelta(days=30)
        )
        rows = await service.get_checklist(router.id, requesting_organization_id=None)
        summary = service.summarize(rows)
        assert summary["total"] == 14
        # heartbeat, saas_provisioning, api_reachability pass; wan_connectivity
        # and wireguard are not_checked (nothing configured); the remaining
        # nine manual items are not_checked.
        assert summary["passing"] == 3
        assert summary["failing"] == 0
        assert summary["not_checked"] == 11


# ============================================================================
# Structural RBAC check
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_readiness_route_has_a_permission_dependency(self) -> None:
        assert len(readiness_router.routes) == 2
        for route in readiness_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
