"""Discovery service: read-only device sweep → ``RouterSnapshot`` + compatibility.

Composes ``RouterService`` for tenant-scoped router load / decrypted API
secret, ``wyfy_device_gateway.ReadOnlyDeviceReader`` for the device
sweep, ``collector.collect_snapshot_fields`` for sanitization /
persistence shaping, and ``compatibility.evaluate_compatibility`` for
the Wave 1 evaluator. Never pushes config.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import MikroTikConnectionError
from wyfy_device_gateway.read_only_reader import (
    ReadOnlyDeviceReader,
    ReadOnlyStateCapture,
)

from app.domains.router.models import Router

from .collector import collect_snapshot_fields
from .compatibility import evaluate_compatibility
from .constants import SnapshotStatus, SnapshotTrigger
from .exceptions import (
    DiscoveryDeviceConnectionError,
    DiscoveryMissingCredentialsError,
    NoRouterSnapshotError,
    RouterSnapshotNotFoundError,
)
from .managed_resource_repository import (
    ManagedRouterResourceRepositoryProtocol,
)
from .managed_resources import build_managed_resource_backfill_rows
from .models import RouterSnapshot
from .repository import RouterSnapshotRepositoryProtocol
from .schemas import (
    BridgeSnapshot,
    CompatibilityReport,
    DhcpClientSnapshot,
    DhcpServerSnapshot,
    DiscoverRouterResponse,
    HotspotStateSnapshot,
    InterfaceSnapshot,
    IpAddressSnapshot,
    PackageSnapshot,
    RouterSnapshotListResponse,
    RouterSnapshotResponse,
    RouteSnapshot,
    RuleSummary,
    ServiceSnapshot,
    VlanSnapshot,
)

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


class RouterLookupProtocol(Protocol):
    """Narrow surface of ``RouterService`` this package needs."""

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Router: ...

    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


def _rule_summary(data: dict[str, Any] | None) -> RuleSummary:
    raw = data or {}
    return RuleSummary(
        total_count=int(raw.get("total_count") or 0),
        wyfy_tagged_count=int(raw.get("wyfy_tagged_count") or 0),
        disabled_count=int(raw.get("disabled_count") or 0),
    )


def _hotspot_state(data: dict[str, Any] | None) -> HotspotStateSnapshot:
    raw = data or {}
    return HotspotStateSnapshot(
        server_count=int(raw.get("server_count") or 0),
        profile_count=int(raw.get("profile_count") or 0),
        walled_garden_count=int(raw.get("walled_garden_count") or 0),
        servers=list(raw.get("servers") or []),
    )


def snapshot_to_response(row: RouterSnapshot) -> RouterSnapshotResponse:
    """Map an ORM row to the public response schema (no secrets)."""
    return RouterSnapshotResponse(
        id=str(row.id),
        router_id=str(row.router_id),
        organization_id=str(row.organization_id),
        location_id=str(row.location_id),
        captured_at=row.captured_at,
        trigger=SnapshotTrigger(row.trigger),
        status=SnapshotStatus(row.status),
        model=row.model,
        routeros_version=row.routeros_version,
        architecture=row.architecture,
        total_memory_bytes=row.total_memory_bytes,
        free_memory_bytes=row.free_memory_bytes,
        free_storage_bytes=row.free_storage_bytes,
        interfaces=[
            InterfaceSnapshot.model_validate(i) for i in (row.interfaces or [])
        ],
        bridges=[BridgeSnapshot.model_validate(b) for b in (row.bridges or [])],
        ip_addresses=[
            IpAddressSnapshot.model_validate(a) for a in (row.ip_addresses or [])
        ],
        dhcp_clients=[
            DhcpClientSnapshot.model_validate(c) for c in (row.dhcp_clients or [])
        ],
        dhcp_servers=[
            DhcpServerSnapshot.model_validate(s) for s in (row.dhcp_servers or [])
        ],
        routes=[RouteSnapshot.model_validate(r) for r in (row.routes or [])],
        dns_config=dict(row.dns_config or {}),
        firewall_summary=_rule_summary(row.firewall_summary),
        nat_summary=_rule_summary(row.nat_summary),
        hotspot_state=_hotspot_state(row.hotspot_state),
        vlans=[VlanSnapshot.model_validate(v) for v in (row.vlans or [])],
        services=[ServiceSnapshot.model_validate(s) for s in (row.services or [])],
        packages=[PackageSnapshot.model_validate(p) for p in (row.packages or [])],
        error_detail=row.error_detail,
        created_at=row.created_at,
    )


def _build_credentials(router: Router, secret: str) -> DeviceCredentials:
    host = router.management_ip_address or router.public_ip_address
    assert host is not None  # caller already validated
    assert router.api_username is not None
    return DeviceCredentials(
        vendor=DeviceVendor.MIKROTIK,
        host=host,
        username=router.api_username,
        secret=secret,
        port=_DEFAULT_API_PORT,
        timeout_seconds=_DEFAULT_TIMEOUT_SECONDS,
    )


class DiscoveryService:
    """Orchestrates read-only discovery, snapshot persistence, and
    compatibility evaluation for one router."""

    def __init__(
        self,
        repository: RouterSnapshotRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        managed_resource_repository: (
            ManagedRouterResourceRepositoryProtocol | None
        ) = None,
        reader_factory: Any | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.managed_resource_repository = managed_resource_repository
        # Injection seam for unit tests (defaults to ReadOnlyDeviceReader).
        self._reader_factory = reader_factory or ReadOnlyDeviceReader

    async def discover_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        trigger: SnapshotTrigger = SnapshotTrigger.WIZARD_DISCOVERY,
        actor_user_id: uuid.UUID | None = None,
    ) -> DiscoverRouterResponse:
        """Load credentials, sweep the device read-only, persist, evaluate.

        On connection failure a ``failed`` snapshot is still persisted
        (empty sections + ``error_detail``) so operators have an audit
        trail, then ``DiscoveryDeviceConnectionError`` is raised.
        """
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise DiscoveryMissingCredentialsError(router.id)

        creds = _build_credentials(router, secret)
        captured_at = datetime.now(UTC)
        reader = self._reader_factory(creds)

        try:
            capture: ReadOnlyStateCapture = await reader.read_all()
        except MikroTikConnectionError as exc:
            detail = getattr(exc, "detail", str(exc))
            await self.repository.create(
                {
                    "router_id": router.id,
                    "organization_id": router.organization_id,
                    "location_id": router.location_id,
                    "captured_at": captured_at,
                    "trigger": trigger.value,
                    "status": SnapshotStatus.FAILED.value,
                    "interfaces": [],
                    "bridges": [],
                    "ip_addresses": [],
                    "dhcp_clients": [],
                    "dhcp_servers": [],
                    "routes": [],
                    "dns_config": {},
                    "firewall_summary": {},
                    "nat_summary": {},
                    "hotspot_state": {},
                    "vlans": [],
                    "services": [],
                    "packages": [],
                    "error_detail": str(detail),
                    "created_by": actor_user_id,
                }
            )
            raise DiscoveryDeviceConnectionError(host, str(detail)) from exc

        fields = collect_snapshot_fields(capture)
        row = await self.repository.create(
            {
                "router_id": router.id,
                "organization_id": router.organization_id,
                "location_id": router.location_id,
                "captured_at": captured_at,
                "trigger": trigger.value,
                "created_by": actor_user_id,
                **fields,
            }
        )
        if (
            self.managed_resource_repository is not None
            and fields.get("status") != SnapshotStatus.FAILED.value
        ):
            backfill_rows = build_managed_resource_backfill_rows(
                fields,
                capture,
                router_id=router.id,
                organization_id=router.organization_id,
                location_id=router.location_id,
                applied_at=captured_at,
            )
            await self.managed_resource_repository.replace_discovery_backfill(
                router.id, backfill_rows
            )
        response = snapshot_to_response(row)
        compatibility = evaluate_compatibility(row)
        return DiscoverRouterResponse(snapshot=response, compatibility=compatibility)

    async def list_snapshots(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        limit: int = 10,
    ) -> RouterSnapshotListResponse:
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        rows = await self.repository.list_for_router(router_id, limit=limit)
        return RouterSnapshotListResponse(
            snapshots=[snapshot_to_response(row) for row in rows],
            total=len(rows),
        )

    async def get_snapshot(
        self,
        router_id: uuid.UUID,
        snapshot_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> RouterSnapshotResponse:
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        row = await self.repository.get_for_router(router_id, snapshot_id)
        if row is None:
            raise RouterSnapshotNotFoundError(snapshot_id)
        return snapshot_to_response(row)

    async def get_compatibility(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> CompatibilityReport:
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        row = await self.repository.get_latest_for_router(router_id)
        if row is None:
            raise NoRouterSnapshotError(router_id)
        return evaluate_compatibility(row)


__all__ = [
    "RouterLookupProtocol",
    "DiscoveryService",
    "snapshot_to_response",
]
