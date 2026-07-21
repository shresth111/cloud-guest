"""Unit tests for the Hotspot Settings domain: profile CRUD (tenant
isolation), walled-garden host validation (blank/whitespace entries
rejected, too-many-hosts bound enforced), the unpaginated
``list_profiles_for_router`` read path Network Configuration Management
composes, and a structural RBAC check that every route carries a
permission dependency.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_dhcp.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``HotspotService`` is exercised against small, hand-rolled
in-memory fakes for its own repository and the composed
``RouterLookupProtocol`` -- mirrors ``test_dhcp.py``'s own identical "fake
the narrow Protocol boundary" precedent. This domain has no device I/O to
test (see ``service.py``'s own module docstring -- a pure rules/inventory
domain, no ``device_adapters.py`` in this pass).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.hotspot.constants import MAX_WALLED_GARDEN_HOSTS
from app.domains.hotspot.exceptions import (
    CrossOrganizationHotspotProfileAccessError,
    HotspotProfileNotFoundError,
    InvalidWalledGardenHostError,
    TooManyWalledGardenHostsError,
)
from app.domains.hotspot.models import HotspotProfile
from app.domains.hotspot.router import router as hotspot_router
from app.domains.hotspot.service import HotspotService
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router

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


def _make_router(
    *, organization_id: uuid.UUID | None = None, location_id: uuid.UUID | None = None
) -> Router:
    return Router(
        **_base_fields(
            organization_id=organization_id or uuid.uuid4(),
            location_id=location_id or uuid.uuid4(),
            name="Test Router",
            serial_number=f"SN-{uuid.uuid4().hex[:8]}",
            mac_address="AA:BB:CC:DD:EE:FF",
            model="RB4011",
            vendor="mikrotik",
            routeros_version=None,
            management_ip_address="10.0.0.1",
            public_ip_address=None,
            status="online",
            last_seen_at=None,
            last_health_check_at=None,
            health_status=None,
            api_username="admin",
            api_credentials_encrypted="encrypted-placeholder",
            settings={},
        )
    )


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeHotspotRepository:
    profiles: dict[uuid.UUID, HotspotProfile] = field(default_factory=dict)

    async def create_profile(self, **fields: object) -> HotspotProfile:
        profile = HotspotProfile(**_base_fields(**fields))
        self.profiles[profile.id] = profile
        return profile

    async def get_profile_by_id(
        self, profile_id: uuid.UUID, *, include_deleted: bool = False
    ) -> HotspotProfile | None:
        profile = self.profiles.get(profile_id)
        if profile is None or (profile.is_deleted and not include_deleted):
            return None
        return profile

    async def update_profile(
        self, profile: HotspotProfile, data: dict[str, object]
    ) -> HotspotProfile:
        for key, value in data.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        profile.version += 1
        return profile

    async def soft_delete_profile(self, profile: HotspotProfile) -> HotspotProfile:
        profile.is_deleted = True
        profile.deleted_at = _now()
        return profile

    async def list_profiles(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        **_kw: object,
    ):
        values = [v for v in self.profiles.values() if not v.is_deleted]
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        if router_id is not None:
            values = [v for v in values if v.router_id == router_id]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_profiles_for_router(
        self, router_id: uuid.UUID
    ) -> list[HotspotProfile]:
        return [
            v
            for v in self.profiles.values()
            if v.router_id == router_id and not v.is_deleted
        ]


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


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
        include_deleted: bool = False,
    ) -> Router:
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        if (
            requesting_organization_id is not None
            and router.organization_id != requesting_organization_id
        ):
            raise RouterNotFoundError(router_id)
        return router


# ============================================================================
# Harness
# ============================================================================


@dataclass
class Harness:
    service: HotspotService
    repository: FakeHotspotRepository
    router_lookup: FakeRouterLookup
    audit_writer: FakeAuditLogWriter


def make_harness() -> Harness:
    repository = FakeHotspotRepository()
    router_lookup = FakeRouterLookup()
    audit_writer = FakeAuditLogWriter()
    service = HotspotService(repository, router_lookup, audit_writer=audit_writer)
    return Harness(
        service=service,
        repository=repository,
        router_lookup=router_lookup,
        audit_writer=audit_writer,
    )


async def _create_profile(
    h: Harness,
    router: Router,
    *,
    name: str = "Guest Hotspot",
    session_timeout_minutes: int | None = 240,
    idle_timeout_minutes: int | None = 15,
    walled_garden_hosts: list[str] | None = None,
) -> HotspotProfile:
    return await h.service.create_profile(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        name=name,
        session_timeout_minutes=session_timeout_minutes,
        idle_timeout_minutes=idle_timeout_minutes,
        upload_limit_kbps=1024,
        download_limit_kbps=4096,
        walled_garden_hosts=walled_garden_hosts,
    )


# ============================================================================
# Profile CRUD
# ============================================================================


class TestHotspotProfileCrud:
    async def test_create_profile_succeeds(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)

        profile = await _create_profile(h, router)

        assert profile.router_id == router.id
        assert profile.organization_id == router.organization_id
        assert profile.location_id == router.location_id
        assert profile.name == "Guest Hotspot"
        assert profile.session_timeout_minutes == 240
        assert profile.idle_timeout_minutes == 15
        assert profile.upload_limit_kbps == 1024
        assert profile.download_limit_kbps == 4096
        assert profile.walled_garden_hosts == []
        assert profile.is_enabled is True
        assert len(h.audit_writer.entries) == 1

    async def test_create_profile_for_unknown_router_raises(self) -> None:
        h = make_harness()
        with pytest.raises(RouterNotFoundError):
            await _create_profile(h, _make_router())

    async def test_get_profile_returns_created_profile(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        profile = await _create_profile(h, router)

        fetched = await h.service.get_profile(
            profile.id, requesting_organization_id=router.organization_id
        )
        assert fetched.id == profile.id

    async def test_get_profile_not_found_raises(self) -> None:
        h = make_harness()
        with pytest.raises(HotspotProfileNotFoundError):
            await h.service.get_profile(uuid.uuid4())

    async def test_get_profile_cross_organization_raises(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        profile = await _create_profile(h, router)

        with pytest.raises(CrossOrganizationHotspotProfileAccessError):
            await h.service.get_profile(
                profile.id, requesting_organization_id=uuid.uuid4()
            )

    async def test_list_profiles_filters_by_router(self) -> None:
        h = make_harness()
        router_a = _make_router()
        router_b = _make_router()
        h.router_lookup.add(router_a)
        h.router_lookup.add(router_b)
        profile_a = await _create_profile(h, router_a)
        await _create_profile(h, router_b)

        profiles, meta = await h.service.list_profiles(
            requesting_organization_id=None, router_id=router_a.id
        )
        assert meta.total_items == 1
        assert profiles[0].id == profile_a.id

    async def test_update_profile_changes_fields(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        profile = await _create_profile(h, router)

        updated = await h.service.update_profile(
            profile.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
            session_timeout_minutes=480,
            is_enabled=False,
        )
        assert updated.session_timeout_minutes == 480
        assert updated.is_enabled is False
        assert len(h.audit_writer.entries) == 2

    async def test_delete_profile_soft_deletes(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        profile = await _create_profile(h, router)

        deleted = await h.service.delete_profile(
            profile.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=router.organization_id,
        )
        assert deleted.is_deleted is True
        with pytest.raises(HotspotProfileNotFoundError):
            await h.service.get_profile(profile.id)


# ============================================================================
# Walled-garden validation
# ============================================================================


class TestWalledGardenValidation:
    async def test_accepts_a_normal_host_list(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        profile = await _create_profile(
            h, router, walled_garden_hosts=["example.com", "*.cdn.example.com"]
        )
        assert profile.walled_garden_hosts == ["example.com", "*.cdn.example.com"]

    async def test_rejects_a_blank_host(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(InvalidWalledGardenHostError):
            await _create_profile(h, router, walled_garden_hosts=[""])

    async def test_rejects_a_host_with_whitespace(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        with pytest.raises(InvalidWalledGardenHostError):
            await _create_profile(h, router, walled_garden_hosts=["example .com"])

    async def test_rejects_too_many_hosts(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        hosts = [f"host{i}.example.com" for i in range(MAX_WALLED_GARDEN_HOSTS + 1)]
        with pytest.raises(TooManyWalledGardenHostsError):
            await _create_profile(h, router, walled_garden_hosts=hosts)

    async def test_update_revalidates_walled_garden_hosts(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        profile = await _create_profile(h, router)

        with pytest.raises(InvalidWalledGardenHostError):
            await h.service.update_profile(
                profile.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
                walled_garden_hosts=[" bad"],
            )


# ============================================================================
# list_profiles_for_router -- the real read source Network Configuration
# Management composes to render a router's full hotspot config
# ============================================================================


class TestListProfilesForRouter:
    async def test_returns_every_non_deleted_profile_for_the_router(self) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)
        profile_a = await _create_profile(h, router, name="Profile A")
        profile_b = await _create_profile(h, router, name="Profile B")
        await h.service.delete_profile(
            profile_b.id,
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
        )

        profiles = await h.service.list_profiles_for_router(
            router.id, requesting_organization_id=router.organization_id
        )

        assert [p.id for p in profiles] == [profile_a.id]

    async def test_raises_for_a_router_outside_the_requesting_organization(
        self,
    ) -> None:
        h = make_harness()
        router = _make_router()
        h.router_lookup.add(router)

        with pytest.raises(RouterNotFoundError):
            await h.service.list_profiles_for_router(
                router.id, requesting_organization_id=uuid.uuid4()
            )


# ============================================================================
# RBAC -- every route requires a permission dependency
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_hotspot_route_has_a_permission_dependency(self) -> None:
        assert len(hotspot_router.routes) == 5
        for route in hotspot_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
