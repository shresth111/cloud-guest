"""Data access layer for the Connected Device Management domain.

Mirrors ``app.domains.isp.repository``'s shape: a ``Protocol`` describing
every operation the service layer needs
(``ConnectedDeviceRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``ConnectedDeviceRepository``), plus one hand-written query
``GenericRepository``'s equality/IN-filter support genuinely can't
express: ``list_routers_for_sync``'s own "every non-deleted router,
platform-wide" enumeration, mirroring
``app.domains.monitoring.repository.MonitoringRepository.list_routers``'s
identical "a domain owning its own read-only cross-domain router query,
not delegating to ``app.domains.router`` itself" precedent (there is no
platform-wide "list every router" method on ``RouterRepository`` itself
to delegate to).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.monitored_hardware.models import MonitoredHardware
from app.domains.router.fleet_scope import agent_managed_only
from app.domains.router.models import Router

from .models import ConnectedDevice


class ConnectedDeviceRepositoryProtocol(Protocol):
    async def create_device(self, **fields: object) -> ConnectedDevice: ...

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ConnectedDevice | None: ...

    async def get_device_by_router_and_mac(
        self, router_id: uuid.UUID, mac_address: str
    ) -> ConnectedDevice | None: ...

    async def update_device(
        self, device: ConnectedDevice, data: dict[str, object]
    ) -> ConnectedDevice: ...

    async def soft_delete_device(self, device: ConnectedDevice) -> ConnectedDevice: ...

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        is_active: bool | None = None,
        guest_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[ConnectedDevice], PaginationMeta]: ...

    async def list_devices_for_router(
        self, router_id: uuid.UUID
    ) -> list[ConnectedDevice]: ...

    async def list_routers_for_sync(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[Router]: ...

    async def list_monitored_targets(
        self,
    ) -> list[tuple[ConnectedDevice, MonitoredHardware]]: ...

    async def list_monitored_macs_for_router(
        self, router_id: uuid.UUID
    ) -> set[str]: ...

    async def list_routers_with_monitored_hardware(
        self,
    ) -> list[Router]: ...


class ConnectedDeviceRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``ConnectedDeviceRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.devices = GenericRepository(ConnectedDevice, session)

    async def create_device(self, **fields: object) -> ConnectedDevice:
        return await self.devices.create(fields)

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> ConnectedDevice | None:
        return await self.devices.get_by_id(device_id, include_deleted=include_deleted)

    async def get_device_by_router_and_mac(
        self, router_id: uuid.UUID, mac_address: str
    ) -> ConnectedDevice | None:
        results = await self.devices.get_all(
            filters={"router_id": router_id, "mac_address": mac_address}, limit=1
        )
        return results[0] if results else None

    async def update_device(
        self, device: ConnectedDevice, data: dict[str, object]
    ) -> ConnectedDevice:
        return await self.devices.update(device, data)

    async def soft_delete_device(self, device: ConnectedDevice) -> ConnectedDevice:
        return await self.devices.soft_delete(device)

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        is_active: bool | None = None,
        guest_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[ConnectedDevice], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if router_id is not None:
            filters["router_id"] = router_id
        if location_id is not None:
            filters["location_id"] = location_id
        if is_active is not None:
            filters["is_active"] = is_active
        if guest_id is not None:
            filters["guest_id"] = guest_id
        return await self.devices.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_devices_for_router(
        self, router_id: uuid.UUID
    ) -> list[ConnectedDevice]:
        return await self.devices.get_all(filters={"router_id": router_id})

    async def list_routers_for_sync(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[Router]:
        """Every agent-managed router the DHCP-lease discovery sweep may
        talk to.

        ``agent_managed_only`` is not an optimisation. Contract 11.5: a
        controller-managed fleet row (a TP-Link Omada controller, present
        only because ``guest_sessions.router_id`` is NOT NULL) has NULL API
        credentials by construction, so every tick of the sweep dispatched
        a Celery task for it, that task raised
        ``ConnectedDeviceMissingCredentialsError``, and
        ``run_device_sync_sweep``'s per-router isolation counted it in
        ``routers_failed`` and logged a warning -- forever, for a venue
        that is working. Filtered in the WHERE clause rather than skipped
        by the caller because the row has no business being loaded: the
        very next thing the caller does with it is dispatch device work.
        """
        statement = agent_managed_only(
            select(Router).where(Router.is_deleted.is_(False))
        )
        if organization_id is not None:
            statement = statement.where(Router.organization_id == organization_id)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_monitored_targets(
        self,
    ) -> list[tuple[ConnectedDevice, MonitoredHardware]]:
        """Every registered (non-deleted) monitored device that the device
        sync has ever observed, paired with its ``ConnectedDevice`` row --
        the liveness sweep's target list. The join is deliberately on
        ``location_id + mac_address`` (the same key
        ``MonitoredHardwareService.with_status`` resolves status through),
        not on ``router_id``: ``MonitoredHardware.router_id`` is the
        *intended* uplink, which is nullable and can drift from where the
        device actually showed up, whereas the ``ConnectedDevice`` row's
        own ``router_id`` is the router that genuinely saw it -- and that
        same router is where the device's management IP lives, which is
        the address a ping must target."""
        statement = (
            select(ConnectedDevice, MonitoredHardware)
            .join(
                MonitoredHardware,
                (MonitoredHardware.location_id == ConnectedDevice.location_id)
                & (MonitoredHardware.mac_address == ConnectedDevice.mac_address),
            )
            .where(MonitoredHardware.is_deleted.is_(False))
        )
        result = await self.session.execute(statement)
        return [(device, hardware) for device, hardware in result.all()]

    async def list_monitored_macs_for_router(self, router_id: uuid.UUID) -> set[str]:
        """MACs of every non-deleted monitored device under a router's own
        location -- used by ``ConnectedDeviceService.sync_router`` to stop
        the DHCP-discovery sync from overwriting the liveness verdict
        (``is_active``/``connected_at``/``last_seen_at``) the ping sweep
        owns for those rows. See ``service.sync_router``'s own docstring
        for the full "discovery sees a lease, not a live device" reason
        the exemption exists."""
        statement = (
            select(MonitoredHardware.mac_address)
            .join(
                Router,
                Router.location_id == MonitoredHardware.location_id,
            )
            .where(Router.id == router_id, MonitoredHardware.is_deleted.is_(False))
        )
        result = await self.session.execute(statement)
        return set(result.scalars().all())

    async def list_routers_with_monitored_hardware(
        self,
    ) -> list[Router]:
        """Agent-managed routers whose own location has at least one
        non-deleted monitored device -- the liveness sweep's fan-out list
        (a router with nothing to probe is skipped entirely, mirroring how
        ``list_routers_for_sync``'s callers skip nothing because every
        router has guests).

        ``agent_managed_only`` for the same reason as
        ``list_routers_for_sync`` above, and one sharper: this sweep's
        target list is built by joining on ``location_id``, so a
        controller-managed row would be handed *another vendor's* monitored
        hardware to ping through a RouterOS session it can never open."""
        statement = agent_managed_only(
            select(Router)
            .join(
                MonitoredHardware,
                MonitoredHardware.location_id == Router.location_id,
            )
            .where(
                Router.is_deleted.is_(False),
                MonitoredHardware.is_deleted.is_(False),
            )
            .distinct()
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())


__all__ = ["ConnectedDeviceRepositoryProtocol", "ConnectedDeviceRepository"]
