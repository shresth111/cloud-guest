"""Data access layer for the Monitored Hardware domain.

Mirrors ``app.domains.network_device.repository``'s shape: a ``Protocol``
describing every operation the service layer needs
(``MonitoredHardwareRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation
(``MonitoredHardwareRepository``).

Also owns the cross-domain reads this feature is built on, all of them
read-only -- this module never writes to another domain's table:

* ``get_connected_device_by_mac`` -- a plain lookup against
  ``app.domains.connected_devices.models.ConnectedDevice`` for the same
  ``mac_address``/``location_id``, used by the service layer to derive an
  honest status (see ``__init__.py``'s own module docstring).
  ``connected_devices``' own sync sweep remains that table's only writer.
* ``get_router_ids_by_mac`` + ``get_latest_uptime_by_router`` -- the pair
  that lets a hardware row report REAL device uptime when, and only when,
  the row is a ``Router`` this platform already polls. See
  ``get_latest_uptime_by_router``'s own docstring for why the join is on
  MAC rather than on ``MonitoredHardware.router_id``.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.connected_devices.models import ConnectedDevice
from app.domains.router.models import Router
from app.domains.router_provisioning.models import RouterHealthSnapshot

from .models import MonitoredHardware


@dataclasses.dataclass(frozen=True, slots=True)
class UptimeReading:
    """One router's most recent real uptime reading, and when it was taken.

    Both fields come straight off the latest ``RouterHealthSnapshot`` row;
    neither is ever computed or extrapolated here."""

    uptime_seconds: int | None
    recorded_at: datetime


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

    async def get_router_ids_by_mac(
        self, organization_id: uuid.UUID, mac_addresses: Sequence[str]
    ) -> dict[str, uuid.UUID]: ...

    async def get_latest_uptime_by_router(
        self, router_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, UptimeReading]: ...


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

    async def get_router_ids_by_mac(
        self, organization_id: uuid.UUID, mac_addresses: Sequence[str]
    ) -> dict[str, uuid.UUID]:
        """Which of ``mac_addresses`` are MACs of routers this platform
        manages for ``organization_id`` -- keyed by the MAC, upper-cased, so
        a caller can look up straight from ``MonitoredHardware.mac_address``
        (``validate_mac_address`` already normalises those to upper-case
        colon form, which is the same shape ``Router.mac_address`` is
        stored in).

        Scoped to the organization deliberately. ``Router.mac_address`` is
        globally unique, so an unscoped lookup would happily match another
        tenant's router and hand this org that router's uptime -- the
        path-id/header-org cross-tenant shape this codebase has been bitten
        by before. The organization is taken from the hardware rows
        themselves, never from a caller-supplied header."""
        if not mac_addresses:
            return {}
        statement = select(Router.mac_address, Router.id).where(
            Router.organization_id == organization_id,
            Router.is_deleted.is_(False),
            Router.mac_address.in_([m.upper() for m in mac_addresses]),
        )
        result = await self.session.execute(statement)
        return {row[0].upper(): row[1] for row in result.all()}

    async def get_latest_uptime_by_router(
        self, router_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, UptimeReading]:
        """The most recent ``RouterHealthSnapshot`` per router, as an
        ``UptimeReading``. One ``DISTINCT ON`` query, never an N+1 loop --
        the same idiom, on the same table, that
        ``app.domains.analytics.repository
        .get_latest_router_health_snapshots`` already establishes.

        ## Why "latest row" and not "latest row with a non-NULL uptime"

        ``RouterProvisioningService.record_failed_health_check`` writes a
        snapshot with ``uptime_seconds=None`` when a poll could not reach
        the device at all. Skipping past those to find the last row that
        did carry a number would resurrect a reading from before the
        outage and present it as current -- and it would be wrong by
        exactly the amount that matters, because the likeliest reason a
        router stopped answering and started again is that it rebooted.
        The last poll's honest answer is "unknown"; that is what this
        returns.

        ## Why the join is on MAC, not on ``MonitoredHardware.router_id``

        That column exists and the service layer persists it, but nothing
        in the product has ever sent it: the register endpoint's only
        caller (the frontend's ``deviceHardware.service.ts``) posts
        location/name/mac/type/floor and no ``router_id``, so in the real
        system it is always ``NULL``. Keying off it would make this
        feature correct in tests and dead in production. The MAC is what
        an admin actually types in, and ``Router.mac_address`` is
        ``NOT NULL`` and unique, so it is the link that genuinely exists.
        ``router_id`` remains honoured wherever it IS set -- see
        ``MonitoredHardwareService._uptime_by_mac``."""
        if not router_ids:
            return {}
        statement = (
            select(
                RouterHealthSnapshot.router_id,
                RouterHealthSnapshot.uptime_seconds,
                RouterHealthSnapshot.recorded_at,
            )
            .where(
                RouterHealthSnapshot.is_deleted.is_(False),
                RouterHealthSnapshot.router_id.in_(router_ids),
            )
            .distinct(RouterHealthSnapshot.router_id)
            .order_by(
                RouterHealthSnapshot.router_id, RouterHealthSnapshot.recorded_at.desc()
            )
        )
        result = await self.session.execute(statement)
        return {
            row[0]: UptimeReading(uptime_seconds=row[1], recorded_at=row[2])
            for row in result.all()
        }


__all__ = [
    "MonitoredHardwareRepositoryProtocol",
    "MonitoredHardwareRepository",
    "UptimeReading",
]
