"""Data access layer for the Monitored Hardware domain.

Mirrors ``app.domains.network_device.repository``'s shape: a ``Protocol``
describing every operation the service layer needs
(``MonitoredHardwareRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``MonitoredHardwareRepository``).

Also owns the one cross-domain read this whole feature is built on --
``get_connected_device_by_mac`` -- a plain, read-only lookup against
``app.domains.connected_devices.models.ConnectedDevice`` for the same
``mac_address``/``location_id``, used by the service layer to derive an
honest status (see ``__init__.py``'s own module docstring). This never
writes to that table -- ``connected_devices``' own sync sweep remains the
only writer.

Also owns one read of the ``routers`` table --
``router_vendors_for_locations`` -- which exists solely to ask the vendor
question (see ``app.domains.router.vendor_capabilities``) so the service
layer can tell a status it measured from one it never could. It is
deliberately NOT narrowed to agent-managed rows: narrowing it would make a
controller-managed venue indistinguishable from a venue with no router at
all, which is the exact distinction it was added to draw. See
``tests/unit/test_router_read_vendor_coverage.py``'s entry for it.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.connected_devices.models import ConnectedDevice
from app.domains.router.models import Router

from .models import MonitoredHardware


class MonitoredHardwareRepositoryProtocol(Protocol):
    async def create_device(self, **fields: object) -> MonitoredHardware: ...

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> MonitoredHardware | None: ...

    async def get_device_by_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> MonitoredHardware | None: ...

    async def soft_delete_device(
        self, device: MonitoredHardware
    ) -> MonitoredHardware: ...

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[MonitoredHardware], PaginationMeta]: ...

    async def get_connected_device_by_mac(
        self, location_id: uuid.UUID, mac_address: str
    ) -> ConnectedDevice | None: ...

    async def router_vendors_for_locations(
        self, location_ids: Iterable[uuid.UUID]
    ) -> dict[uuid.UUID, dict[uuid.UUID, str]]: ...


class MonitoredHardwareRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``MonitoredHardwareRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.devices = GenericRepository(MonitoredHardware, session)
        self.connected_devices = GenericRepository(ConnectedDevice, session)

    async def create_device(self, **fields: object) -> MonitoredHardware:
        return await self.devices.create(fields)

    async def get_device_by_id(
        self, device_id: uuid.UUID, *, include_deleted: bool = False
    ) -> MonitoredHardware | None:
        return await self.devices.get_by_id(device_id, include_deleted=include_deleted)

    async def get_device_by_mac(
        self, organization_id: uuid.UUID, mac_address: str
    ) -> MonitoredHardware | None:
        results = await self.devices.get_all(
            filters={"organization_id": organization_id, "mac_address": mac_address},
            limit=1,
        )
        return results[0] if results else None

    async def soft_delete_device(self, device: MonitoredHardware) -> MonitoredHardware:
        return await self.devices.soft_delete(device)

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[MonitoredHardware], PaginationMeta]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        return await self.devices.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
        )

    async def get_connected_device_by_mac(
        self, location_id: uuid.UUID, mac_address: str
    ) -> ConnectedDevice | None:
        results = await self.connected_devices.get_all(
            filters={"location_id": location_id, "mac_address": mac_address},
            limit=1,
        )
        return results[0] if results else None

    async def router_vendors_for_locations(
        self, location_ids: Iterable[uuid.UUID]
    ) -> dict[uuid.UUID, dict[uuid.UUID, str]]:
        """``{location_id: {router_id: vendor}}`` for the given locations.

        Vendor strings only -- no row is returned, judged, dialled or
        configured. The service layer asks
        ``vendor_capabilities.is_agent_managed`` of them and nothing else.

        Batched over locations rather than offered one at a time because
        ``list_devices`` renders a page of hardware that may span several of
        them, and a per-row lookup would turn one list into N queries.

        A location absent from the result has no non-deleted router at all,
        which is a third answer distinct from "has one, and it is a
        controller" -- keeping them apart is the whole point of this read.
        """
        wanted = {location_id for location_id in location_ids}
        if not wanted:
            return {}
        statement = select(Router.location_id, Router.id, Router.vendor).where(
            Router.location_id.in_(wanted),
            Router.is_deleted.is_(False),
        )
        result = await self.session.execute(statement)
        vendors: dict[uuid.UUID, dict[uuid.UUID, str]] = {}
        for location_id, router_id, vendor in result.all():
            vendors.setdefault(location_id, {})[router_id] = vendor
        return vendors


__all__ = ["MonitoredHardwareRepositoryProtocol", "MonitoredHardwareRepository"]
