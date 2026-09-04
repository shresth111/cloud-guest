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
    FAILING_STATUSES,
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
    def test_sixteen_items_registered(self) -> None:
        assert len(CHECKLIST_ITEMS) == 16

    def test_seven_items_are_auto_detected(self) -> None:
        auto = [i for i in CHECKLIST_ITEMS if i.detection_mode == DetectionMode.AUTO]
        assert {i.key for i in auto} == {
            ChecklistItemKey.HEARTBEAT,
            ChecklistItemKey.SAAS_PROVISIONING,
            ChecklistItemKey.WAN_CONNECTIVITY,
            # Asks whether a data path was ever ASSERTED, which is a
            # different question from WAN_CONNECTIVITY's "is the link
            # healthy" -- and the one nothing was asking on 2026-08-27.
            ChecklistItemKey.GUEST_DATA_PATH,
            ChecklistItemKey.WIREGUARD,
            ChecklistItemKey.API_REACHABILITY,
            # Reads only the row ``app.domains.dhcp.tasks``'s scheduled
            # detector persisted -- still zero new device I/O on this
            # domain's read path, which is what lets a real device fact
            # be an AUTO item here at all.
            ChecklistItemKey.ROGUE_DHCP_GUARD,
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
        assert summary["total"] == 16
        # heartbeat, saas_provisioning, api_reachability pass; wan_connectivity
        # and wireguard are not_checked (nothing configured); the remaining
        # nine manual items are not_checked.
        assert summary["passing"] == 3
        # ONE FAILURE, AND ITS ARRIVAL IS THE POINT OF THIS CHANGE.
        #
        # This assertion read `failing == 0` until 2026-08-28: a router
        # with no WAN link, no config version and no data path whatsoever
        # summarised as nothing being wrong, because every check that could
        # have noticed returned NOT_CHECKED and NOT_CHECKED is not in
        # FAILING_STATUSES. That is the shape of the "huda city center"
        # fault exactly -- a venue that passed every check it was given and
        # could not put one guest on the internet.
        #
        # GUEST_DATA_PATH now fails it, and a fixture describing a router
        # nobody has configured SHOULD produce a failure.
        assert summary["failing"] == 1
        # Twelve, not eleven: ROGUE_DHCP_GUARD joins them. This harness
        # builds the service without a rogue-DHCP lookup, and an item with
        # no evidence behind it reports NOT_CHECKED -- never a pass, and
        # never a failure for a router nobody has looked at yet.
        assert summary["not_checked"] == 12


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


# ============================================================================
# GUEST_DATA_PATH -- the item that would have caught the 2026-08-27 fault.
# ============================================================================


@dataclass
class FakeConfigVersion:
    status: str


@dataclass
class FakeConfigVersionLookup:
    versions_by_router: dict[uuid.UUID, list[FakeConfigVersion]] = field(
        default_factory=dict
    )

    async def list_versions(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[FakeConfigVersion], object]:
        return self.versions_by_router.get(router_id, []), None


def _build_service_with_config_versions():  # noqa: ANN202 -- test helper
    repo = FakeReadinessRepository()
    router_lookup = FakeRouterLookup()
    isp_lookup = FakeIspLookup()
    wg_lookup = FakeWireGuardLookup()
    agent_lookup = FakeRouterAgentLookup()
    version_lookup = FakeConfigVersionLookup()
    service = ReadinessService(
        repo, router_lookup, isp_lookup, wg_lookup, agent_lookup, version_lookup
    )
    return service, router_lookup, isp_lookup, version_lookup


def _item(rows, key):  # noqa: ANN001, ANN202 -- test helper
    return next(r for r in rows if r.item_key == key.value)


class TestGuestDataPathCheck:
    """The distinction this item exists for: every other check asks whether
    something the platform configured is working. This asks whether it was
    ever configured at all.

    Router 21e13913 on 2026-08-27 passed heartbeat, SaaS provisioning,
    WireGuard and API reachability; its guests authenticated cleanly and had
    no internet, because no NAT rule had ever been asserted and nothing
    anywhere said so.
    """

    async def test_a_router_with_no_data_path_at_all_fails(self) -> None:
        service, router_lookup, _isp, _versions = (
            _build_service_with_config_versions()
        )
        router = router_lookup.add(
            _make_router(status="online", health_status="healthy")
        )

        rows = await service.get_checklist(
            router.id, requesting_organization_id=None
        )

        row = _item(rows, ChecklistItemKey.GUEST_DATA_PATH)
        assert row.status == ChecklistItemStatus.FAIL.value
        # FAIL, never NOT_CHECKED. NOT_CHECKED is absent from
        # FAILING_STATUSES, so it summarises as nothing-wrong -- which is
        # precisely how a venue that could not serve one guest reported
        # clean.
        assert ChecklistItemStatus(row.status) in FAILING_STATUSES
        assert "no enabled WAN link and no applied config version" in row.detail

    async def test_an_enabled_wan_link_is_sufficient_evidence(self) -> None:
        """An enabled ISP link is what makes wan.assembler emit anything at
        all -- it short-circuits on `if not ctx.links` -- and with it the
        discovered-uplink masquerade."""
        service, router_lookup, isp_lookup, _versions = (
            _build_service_with_config_versions()
        )
        router = router_lookup.add(_make_router(status="online"))
        isp_lookup.links_by_router[router.id] = [
            FakeIspLink(is_enabled=True, health_status="down")
        ]

        rows = await service.get_checklist(
            router.id, requesting_organization_id=None
        )

        # PASSES even though the link is DOWN: this item is about whether a
        # path was ever asserted, not whether it is up right now. That
        # second question is WAN_CONNECTIVITY's, and conflating them would
        # give one row two meanings and no clear remedy.
        assert (
            _item(rows, ChecklistItemKey.GUEST_DATA_PATH).status
            == ChecklistItemStatus.PASS.value
        )
        assert (
            _item(rows, ChecklistItemKey.WAN_CONNECTIVITY).status
            == ChecklistItemStatus.FAIL.value
        )

    async def test_an_applied_config_version_is_sufficient_evidence(self) -> None:
        service, router_lookup, _isp, versions = (
            _build_service_with_config_versions()
        )
        router = router_lookup.add(_make_router(status="online"))
        versions.versions_by_router[router.id] = [FakeConfigVersion(status="applied")]

        rows = await service.get_checklist(
            router.id, requesting_organization_id=None
        )

        assert (
            _item(rows, ChecklistItemKey.GUEST_DATA_PATH).status
            == ChecklistItemStatus.PASS.value
        )

    async def test_a_draft_config_version_is_not_evidence(self) -> None:
        """Exactly the state router 21e13913 was in: one config_versions row,
        status `draft`, never applied, zero provisioning jobs. A rendered
        config that never reached the device asserts nothing."""
        service, router_lookup, _isp, versions = (
            _build_service_with_config_versions()
        )
        router = router_lookup.add(_make_router(status="online"))
        versions.versions_by_router[router.id] = [FakeConfigVersion(status="draft")]

        rows = await service.get_checklist(
            router.id, requesting_organization_id=None
        )

        row = _item(rows, ChecklistItemKey.GUEST_DATA_PATH)
        assert row.status == ChecklistItemStatus.FAIL.value
        assert row.evidence["applied_config_version_count"] == 0

    async def test_without_a_version_lookup_it_still_reports_honestly(self) -> None:
        """The lookup is optional so existing constructions keep working.
        Absent, it must fall back to ISP-link evidence and SAY so in the
        evidence -- never pass by default because it could not look."""
        service, _repo, router_lookup, _isp, _wg, _agent = _build_service()
        router = router_lookup.add(_make_router(status="online"))

        rows = await service.get_checklist(
            router.id, requesting_organization_id=None
        )

        row = _item(rows, ChecklistItemKey.GUEST_DATA_PATH)
        assert row.status == ChecklistItemStatus.FAIL.value
        assert row.evidence["config_version_lookup_available"] is False


# ============================================================================
# ROGUE_DHCP_GUARD -- the surface over the rogue-DHCP detector.
#
# Detector writes, surface reads. The device read happens on a six-hour
# schedule in ``app.domains.dhcp.tasks``; this item reads only the row it
# left behind, which is what keeps this domain's documented zero-new-device-
# I/O rule intact on a path that re-runs on every GET.
#
# THE INVARIANT UNDER TEST: ``unknown`` and ``unguarded`` are different
# answers end to end. ``unknown`` maps to NOT_CHECKED and must never read as
# a failure anywhere -- not in the row's status, and not in the summary
# counts an operator actually looks at.
# ============================================================================


@dataclass
class FakeRogueDhcpStatusRow:
    """Shaped like ``app.domains.dhcp.models.RouterRogueDhcpStatus``.

    ``alert_present``/``enabled`` are carried even though this item's own
    logic reads only ``alert_state``, because they are what makes an
    ``unguarded`` row legible to a human: "no row at all" and "row present,
    switched off" are both unguarded, and only these two say which.
    """

    interface: str
    alert_state: str
    alert_present: bool = False
    enabled: bool = False
    serves_dhcp: bool = True
    checked_at: datetime | None = None
    detail: str | None = None


@dataclass
class FakeRogueDhcpLookup:
    """Taught the method before any assertion was written against it.

    ``ReadinessService`` treats this lookup as optional, so a fake missing
    ``get_rogue_dhcp_statuses`` would not raise -- the service would simply
    never call it and the item would report NOT_CHECKED, which is a
    plausible-looking result and a completely untested one. That is the
    cloud-guest#131 failure mode in a different costume.
    """

    rows_by_router: dict[uuid.UUID, list[FakeRogueDhcpStatusRow]] = field(
        default_factory=dict
    )
    calls: int = 0

    async def get_rogue_dhcp_statuses(
        self, router_id: uuid.UUID
    ) -> list[FakeRogueDhcpStatusRow]:
        self.calls += 1
        return self.rows_by_router.get(router_id, [])


def _build_service_with_rogue_dhcp():  # noqa: ANN202 -- test helper
    repo = FakeReadinessRepository()
    router_lookup = FakeRouterLookup()
    rogue_lookup = FakeRogueDhcpLookup()
    service = ReadinessService(
        repo,
        router_lookup,
        FakeIspLookup(),
        FakeWireGuardLookup(),
        FakeRouterAgentLookup(),
        None,
        rogue_lookup,
    )
    return service, router_lookup, rogue_lookup


async def _rogue_item(service, router_lookup, rogue_lookup, rows):  # noqa: ANN001, ANN202
    router = router_lookup.add(_make_router())
    rogue_lookup.rows_by_router[router.id] = rows
    checklist = await service.get_checklist(
        router.id, requesting_organization_id=None
    )
    return _item(checklist, ChecklistItemKey.ROGUE_DHCP_GUARD)


class TestRogueDhcpGuardItem:
    async def test_a_watched_router_passes(self) -> None:
        service, router_lookup, rogue_lookup = _build_service_with_rogue_dhcp()
        row = await _rogue_item(
            service,
            router_lookup,
            rogue_lookup,
            [
                FakeRogueDhcpStatusRow(
                    interface="ether2",
                    alert_state="guarded",
                    alert_present=True,
                    enabled=True,
                    checked_at=_now(),
                )
            ],
        )
        assert row.status == ChecklistItemStatus.PASS.value
        assert row.detection_mode == DetectionMode.AUTO.value
        assert row.evidence["guarded_count"] == 1

    async def test_an_interface_with_no_alert_row_fails(self) -> None:
        service, router_lookup, rogue_lookup = _build_service_with_rogue_dhcp()
        row = await _rogue_item(
            service,
            router_lookup,
            rogue_lookup,
            [
                FakeRogueDhcpStatusRow(
                    interface="ether2",
                    alert_state="unguarded",
                    alert_present=False,
                    enabled=False,
                    checked_at=_now(),
                )
            ],
        )
        assert row.status == ChecklistItemStatus.FAIL.value
        assert ChecklistItemStatus(row.status) in FAILING_STATUSES
        assert "ether2" in (row.detail or "")

    async def test_a_row_present_but_disabled_fails(self) -> None:
        """The state RouterOS's own default creates. It reads as configured
        and watches nothing, so the item must fail on it exactly as it does
        on a missing row -- while ``alert_present``/``enabled`` keep the
        difference visible to whoever goes to fix it."""
        service, router_lookup, rogue_lookup = _build_service_with_rogue_dhcp()
        row = await _rogue_item(
            service,
            router_lookup,
            rogue_lookup,
            [
                FakeRogueDhcpStatusRow(
                    interface="ether2",
                    alert_state="unguarded",
                    alert_present=True,
                    enabled=False,
                    checked_at=_now(),
                )
            ],
        )
        assert row.status == ChecklistItemStatus.FAIL.value

    async def test_an_unreachable_router_is_not_checked_and_never_fails(self) -> None:
        """THE ASSERTION THIS ITEM'S DESIGN TURNS ON.

        A router the detector could not reach is an unanswered question,
        not a finding. NOT_CHECKED is absent from ``FAILING_STATUSES``, so
        this never counts against a venue -- and it must not, because
        "unguarded" on every offline router would be a failure nobody could
        act on and nothing true about rogue DHCP.
        """
        service, router_lookup, rogue_lookup = _build_service_with_rogue_dhcp()
        router = router_lookup.add(_make_router())
        rogue_lookup.rows_by_router[router.id] = [
            FakeRogueDhcpStatusRow(
                interface="ether2",
                alert_state="unknown",
                checked_at=_now(),
                detail="connection refused",
            )
        ]
        checklist = await service.get_checklist(
            router.id, requesting_organization_id=None
        )
        row = _item(checklist, ChecklistItemKey.ROGUE_DHCP_GUARD)

        assert row.status == ChecklistItemStatus.NOT_CHECKED.value
        assert row.status != ChecklistItemStatus.FAIL.value
        # Not a failure in the row...
        assert ChecklistItemStatus(row.status) not in FAILING_STATUSES
        # ...and not a failure in the number an operator actually reads.
        # Asserted as "this item is not among the failures" rather than as a
        # count: the count moves whenever an unrelated item's fixture
        # changes, and would then stop testing anything about this one.
        failing_keys = {
            r.item_key
            for r in checklist
            if ChecklistItemStatus(r.status) in FAILING_STATUSES
        }
        assert ChecklistItemKey.ROGUE_DHCP_GUARD.value not in failing_keys
        assert row.evidence["unknown_count"] == 1
        assert row.evidence["unguarded_count"] == 0

    async def test_a_known_unguarded_interface_outranks_an_unknown_one(self) -> None:
        """One interface answered "nothing watching" and another timed out.

        The failure is real -- a device answered it -- and the unknown
        beside it does not soften it.
        """
        service, router_lookup, rogue_lookup = _build_service_with_rogue_dhcp()
        row = await _rogue_item(
            service,
            router_lookup,
            rogue_lookup,
            [
                FakeRogueDhcpStatusRow(
                    interface="ether2", alert_state="unguarded", checked_at=_now()
                ),
                FakeRogueDhcpStatusRow(
                    interface="ether3", alert_state="unknown", checked_at=_now()
                ),
            ],
        )
        assert row.status == ChecklistItemStatus.FAIL.value
        assert row.evidence["unguarded_interfaces"] == ["ether2"]

    async def test_a_router_never_checked_is_not_checked(self) -> None:
        service, router_lookup, rogue_lookup = _build_service_with_rogue_dhcp()
        row = await _rogue_item(service, router_lookup, rogue_lookup, [])
        assert row.status == ChecklistItemStatus.NOT_CHECKED.value
        assert row.evidence["interface_count"] == 0

    async def test_the_item_reads_the_persisted_row_and_nothing_else(self) -> None:
        """``get_checklist`` re-runs every AUTO item on every GET. The only
        thing this item is allowed to touch is the lookup -- a device read
        here would put a RouterOS timeout behind a dashboard page load."""
        service, router_lookup, rogue_lookup = _build_service_with_rogue_dhcp()
        router = router_lookup.add(_make_router())
        await service.get_checklist(router.id, requesting_organization_id=None)
        await service.get_checklist(router.id, requesting_organization_id=None)
        assert rogue_lookup.calls == 2

    async def test_without_a_lookup_the_item_is_not_checked_never_passing(self) -> None:
        """A deployment that has not wired the detector must not report a
        router as watched. Absence of evidence is NOT_CHECKED."""
        service, _repo, router_lookup, *_ = _build_service()
        router = router_lookup.add(_make_router())
        checklist = await service.get_checklist(
            router.id, requesting_organization_id=None
        )
        row = _item(checklist, ChecklistItemKey.ROGUE_DHCP_GUARD)
        assert row.status == ChecklistItemStatus.NOT_CHECKED.value
        assert row.evidence["lookup_available"] is False


class TestRogueDhcpCopyIsDetectionOnly:
    """RouterOS's ``/ip dhcp-server alert`` writes a log entry and does
    nothing else -- it does not drop the offer, block the port, or
    rate-limit anything.

    Copy claiming otherwise would describe a capability the feature does not
    have, and an operator who believed it would stop looking for the rogue
    server. That is the actual harm, so it is asserted rather than left to
    review.
    """

    def test_the_label_and_description_never_claim_prevention(self) -> None:
        item = next(
            i for i in CHECKLIST_ITEMS if i.key == ChecklistItemKey.ROGUE_DHCP_GUARD
        )
        copy = f"{item.label} {item.description}".lower()
        # Words that assert a capability RouterOS does not have, in any form.
        for forbidden in ("protect", "prevent", "guard", "blocks", "stops"):
            assert forbidden not in copy, f"{forbidden!r} implies prevention"
        # "block" is allowed in exactly one shape: the explicit denial. The
        # description is required to carry it, because a reader who skims
        # "Rogue DHCP detection" and assumes the platform is doing something
        # about it is the failure mode this copy exists to prevent.
        assert "does not block" in copy
        assert copy.count("block") == 1
        assert "detection" in copy
