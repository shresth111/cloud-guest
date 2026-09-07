"""Monitored Hardware business logic: registration CRUD plus the honest,
derived status lookup this whole domain exists for -- see ``__init__.py``'s
own module docstring for the full write-up.

## Composition, not duplication

``LocationLookupProtocol``/``RouterLookupProtocol`` are the identical
narrow, duck-typed Protocol composition-over-duplication pattern
``app.domains.network_device.service`` already establishes.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import datetime
from typing import Protocol

from app.domains.location.models import Location
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.location_scope import (
    LocationScope,
    enforce_entity_location,
)
from app.domains.router.models import Router

from .constants import HardwareStatus
from .events import MonitoredHardwareDeleted, MonitoredHardwareRegistered
from .exceptions import DuplicateMonitoredHardwareError, MonitoredHardwareNotFoundError
from .models import MonitoredHardware
from .repository import MonitoredHardwareRepositoryProtocol, UptimeReading
from .validators import validate_mac_address

logger = logging.getLogger(__name__)

# A device is considered reachable ("up") only if connected_devices' own
# sync sweep marked it is_active on its most recent pass. That sweep runs
# every CONNECTED_DEVICE_SYNC_SWEEP_INTERVAL_SECONDS (900s/15min as of
# this writing) -- is_active is a live flag maintained by that sweep
# itself, not a timestamp this domain has to age out on its own, so no
# separate "recently seen" threshold is needed here at all: it's already
# correct by construction.


def _event_extra(event: object) -> dict[str, object]:
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


class LocationLookupProtocol(Protocol):
    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


@dataclasses.dataclass(frozen=True, slots=True)
class HardwareWithStatus:
    """A ``MonitoredHardware`` row plus its derived status -- see module
    docstring. ``last_seen_at`` is only ever a real
    ``ConnectedDevice.last_seen_at`` value (or ``None`` when the device
    has never been observed), never invented.

    ``uptime_seconds`` is a DIFFERENT FACT from ``last_seen_at`` and the
    two must never be presented as one. ``last_seen_at`` answers "when did
    we last hear from it"; ``uptime_seconds`` answers "how long since it
    last rebooted". A device that reboots three times in two hours
    heartbeats normally between reboots, so ``last_seen_at`` stays healthy
    across all three and hides them completely -- ``uptime_seconds`` is the
    only one of the two that makes a reboot visible at all.

    It is populated only where a real reading exists (see
    ``_uptime_by_mac``) and is ``None`` everywhere else -- never a
    fall-back to the ``last_seen_at`` age, which is the substitution this
    field exists to end."""

    device: MonitoredHardware
    status: HardwareStatus
    last_seen_at: datetime | None
    uptime_seconds: int | None = None
    uptime_recorded_at: datetime | None = None


class MonitoredHardwareService:
    """Core Monitored Hardware business logic."""

    def __init__(
        self,
        repository: MonitoredHardwareRepositoryProtocol,
        location_lookup: LocationLookupProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        caller_location_scope: LocationScope = None,
    ) -> None:
        self.repository = repository
        self.location_lookup = location_lookup
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        # Constructor-injected -- see `app.domains.rbac.location_scope`.
        self.caller_location_scope = caller_location_scope

    async def register_device(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        name: str,
        mac_address: str,
        device_type: str,
        router_id: uuid.UUID | None = None,
        floor: str | None = None,
    ) -> MonitoredHardware:
        location = await self.location_lookup.get_location(
            location_id, requesting_organization_id=requesting_organization_id
        )
        if router_id is not None:
            await self.router_lookup.get_router(
                router_id, requesting_organization_id=location.organization_id
            )
        normalized_mac = validate_mac_address(mac_address)

        existing = await self.repository.get_device_by_mac(
            location.organization_id, normalized_mac
        )
        if existing is not None and not existing.is_deleted:
            raise DuplicateMonitoredHardwareError(normalized_mac)

        device = await self.repository.create_device(
            organization_id=location.organization_id,
            location_id=location.id,
            router_id=router_id,
            name=name,
            mac_address=normalized_mac,
            device_type=device_type,
            floor=floor,
            created_by=actor_user_id,
        )
        event = MonitoredHardwareRegistered(
            id=device.id, organization_id=device.organization_id
        )
        logger.info("monitored_hardware_registered", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.MONITORED_HARDWARE_CREATED,
            entity_id=device.id,
            organization_id=device.organization_id,
            description=f"Monitored hardware '{normalized_mac}' registered",
        )
        return device

    async def get_device(
        self,
        device_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> MonitoredHardware:
        device = await self.repository.get_device_by_id(device_id)
        if device is None:
            raise MonitoredHardwareNotFoundError(device_id)
        if (
            requesting_organization_id is not None
            and device.organization_id != requesting_organization_id
        ):
            raise MonitoredHardwareNotFoundError(device_id)
        # Same reasoning as firewall, but raising this domain's own
        # NotFound rather than a 403: it already answers a foreign
        # *organization* that way so as not to confirm the row exists,
        # and a location refusal that 403s would leak exactly what the
        # organization refusal is careful not to.
        #
        # DO NOT "harmonise" this to the CrossLocation*AccessError 403 the
        # other domains raise. "No such row" and "that row is not yours"
        # are different answers, and this domain has deliberately chosen
        # the first. No test asserts that a refusal must be uninformative,
        # so that change would pass CI and quietly turn an
        # existence-hiding refusal into an existence-confirming one.
        enforce_entity_location(
            entity_location_id=getattr(device, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=MonitoredHardwareNotFoundError(device_id),
        )
        return device

    async def _uptime_by_mac(
        self, devices: list[MonitoredHardware]
    ) -> dict[str, UptimeReading]:
        """Real device uptime for whichever of ``devices`` this platform can
        actually measure it for, keyed by upper-cased MAC.

        Two batched queries for the whole page, never one pair per row --
        the per-row ``get_connected_device_by_mac`` in ``with_status`` is
        already an N+1 and this must not add a second one.

        A hardware row earns an uptime reading only by being a ``Router``
        this platform polls: either it carries an explicit ``router_id``
        (honoured, though nothing in the product sets one today), or its
        MAC is a managed router's MAC. Everything else -- every third-party
        access point, printer and camera -- gets nothing, because nothing
        in this platform can read those devices' uptime. There is no
        RouterOS API on a TP-Link EAP225 and no SNMP agent configured on
        one, and inventing a number for them is exactly what this domain
        exists not to do.

        Nothing here reaches out to a device. Both queries read tables the
        existing Celery health sweeps already fill (``run_router_health_
        poll_sweep`` every 600s over the RouterOS API on port 8728,
        ``run_router_snmp_metrics_poll_sweep`` every 300s), so this stays a
        pure database read no matter how many rows the page holds."""
        if not devices:
            return {}
        organization_id = devices[0].organization_id
        # ``list_devices`` filters by organization, so a page is single-org in
        # practice. The ``== organization_id`` guards below do not assume it:
        # a row from any other organization is dropped from both lookups and
        # simply gets no uptime. Silently reading another tenant's routers is
        # the one outcome that must be impossible here, and skipping a row is
        # a safe way to be wrong.
        by_mac: dict[str, uuid.UUID] = await self.repository.get_router_ids_by_mac(
            organization_id,
            [d.mac_address for d in devices if d.organization_id == organization_id],
        )
        # ``router_id`` bypasses the MAC lookup's own organization filter, so
        # it is trusted only because ``register_device`` already validated
        # that the router belongs to the location's organization before
        # persisting it -- it cannot point across a tenant boundary.
        explicit = {
            d.mac_address.upper(): d.router_id
            for d in devices
            if d.router_id is not None and d.organization_id == organization_id
        }
        # An explicit router_id wins over the MAC match: it is the stronger
        # statement, and the two can only disagree if an admin typed a MAC
        # that belongs to a different router than the one they linked.
        by_mac = {**by_mac, **explicit}
        if not by_mac:
            return {}
        readings = await self.repository.get_latest_uptime_by_router(
            list(dict.fromkeys(by_mac.values()))
        )
        return {
            mac: readings[router_id]
            for mac, router_id in by_mac.items()
            if router_id in readings
        }

    async def with_status(
        self,
        device: MonitoredHardware,
        *,
        uptime: UptimeReading | None = None,
    ) -> HardwareWithStatus:
        """``uptime`` is passed in rather than looked up here so that a list
        render costs two queries for the whole page instead of two per row
        (see ``_uptime_by_mac``). Omitting it means "no reading", which is
        also the correct answer for every caller that has none -- it is
        never silently substituted with anything derived from
        ``last_seen_at``."""
        connected = await self.repository.get_connected_device_by_mac(
            device.location_id, device.mac_address
        )
        uptime_seconds = uptime.uptime_seconds if uptime is not None else None
        # recorded_at is only meaningful alongside a real reading -- a
        # timestamp with no number attached would say "we measured nothing,
        # at this precise moment".
        uptime_recorded_at = (
            uptime.recorded_at
            if uptime is not None and uptime.uptime_seconds is not None
            else None
        )
        if connected is None:
            return HardwareWithStatus(
                device=device,
                status=HardwareStatus.UNKNOWN,
                last_seen_at=None,
                uptime_seconds=uptime_seconds,
                uptime_recorded_at=uptime_recorded_at,
            )
        status = HardwareStatus.UP if connected.is_active else HardwareStatus.DOWN
        return HardwareWithStatus(
            device=device,
            status=status,
            last_seen_at=connected.last_seen_at,
            uptime_seconds=uptime_seconds,
            uptime_recorded_at=uptime_recorded_at,
        )

    async def list_devices(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[HardwareWithStatus], object]:
        devices, meta = await self.repository.list_devices(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            page=page,
            page_size=page_size,
        )
        uptimes = await self._uptime_by_mac(devices)
        return [
            await self.with_status(d, uptime=uptimes.get(d.mac_address.upper()))
            for d in devices
        ], meta

    async def list_all_devices_with_status(
        self, *, organization_id: uuid.UUID
    ) -> list[HardwareWithStatus]:
        """Real, unpaginated "every device in this org, with its live
        derived status" composition for ``app.domains.monitoring``'s
        ``AlertService`` (its ``ALERT_TARGET_MONITORED_HARDWARE`` rule
        evaluation, see that module's own docstring) -- the same
        "read another domain's data for alert-rule evaluation" precedent
        ``MonitoringRepository.list_routers``/``list_isp_links`` already
        establish, done through this service (not a raw repository read)
        because deriving status here genuinely requires this domain's own
        ``with_status`` join logic, unlike ``Router``/``IspLink``'s already-
        persisted ``health_status`` column. A large page size stands in for
        real "no pagination" the same pragmatic way ``list_routers``/
        ``list_isp_links`` skip pagination entirely -- an organization's
        real hardware count is small enough that a single page comfortably
        covers it; revisit if that assumption ever stops holding."""
        devices, _ = await self.list_devices(
            requesting_organization_id=organization_id, page=1, page_size=500
        )
        return devices

    async def delete_device(
        self,
        device_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> MonitoredHardware:
        device = await self.get_device(
            device_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_device(device)
        event = MonitoredHardwareDeleted(
            id=deleted.id, organization_id=deleted.organization_id
        )
        logger.info("monitored_hardware_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.MONITORED_HARDWARE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"Monitored hardware '{deleted.mac_address}' deleted",
        )
        return deleted

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="monitored_hardware",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = [
    "LocationLookupProtocol",
    "RouterLookupProtocol",
    "AuditLogWriter",
    "HardwareWithStatus",
    "MonitoredHardwareService",
]
