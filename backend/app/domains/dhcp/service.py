"""DHCP Pool Management business logic: per-router DHCP pool CRUD with
real IP-range validation and conflict detection.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## No live device push in this pass

Unlike ``app.domains.isp``, this domain has no ``device_adapters.py`` and
no Celery task -- it is a pure rules/inventory domain, mirroring
``app.domains.vlan``/``app.domains.isp_routing``'s own "config resource,
realized onto a device later" precedent. Real RouterOS DHCP server/pool
provisioning belongs to the not-yet-built Network Configuration
Management domain's own provisioning-integration layer, not this one.

## Validation and conflict detection

``address_range_start``/``address_range_end`` must both be real, parseable
IP addresses of the same family with start <= end
(``validators.validate_address_range``). ``gateway_ip_address``/
``dns_primary``/``dns_secondary``, when supplied, must be real, parseable
IP addresses too. A new/updated pool's range is also checked against
every other non-deleted pool on the *same router and interface* (two
different interfaces are different L2 domains and may legitimately reuse
the same private range) -- see ``models.DhcpPool``'s own module docstring
for why this is a service-layer check, not a database constraint.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import DEFAULT_LEASE_TIME_SECONDS
from .events import DhcpPoolCreated, DhcpPoolDeleted, DhcpPoolUpdated
from .exceptions import (
    CrossOrganizationDhcpPoolAccessError,
    DhcpPoolNotFoundError,
    DhcpPoolRangeConflictError,
)
from .models import DhcpPool
from .repository import DhcpRepositoryProtocol
from .validators import ranges_overlap, validate_address_range, validate_ip_address

logger = logging.getLogger(__name__)


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick every other domain's own ``_event_extra`` uses."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


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


class DhcpService:
    """Core DHCP Pool Management business logic."""

    def __init__(
        self,
        repository: DhcpRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer

    async def create_pool(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        name: str,
        address_range_start: str,
        address_range_end: str,
        interface: str | None = None,
        gateway_ip_address: str | None = None,
        dns_primary: str | None = None,
        dns_secondary: str | None = None,
        lease_time_seconds: int = DEFAULT_LEASE_TIME_SECONDS,
        is_enabled: bool = True,
    ) -> DhcpPool:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_address_range(address_range_start, address_range_end)
        validate_ip_address("gateway_ip_address", gateway_ip_address)
        validate_ip_address("dns_primary", dns_primary)
        validate_ip_address("dns_secondary", dns_secondary)
        await self._check_range_conflict(
            router.id, interface, address_range_start, address_range_end
        )

        pool = await self.repository.create_pool(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            name=name,
            interface=interface,
            address_range_start=address_range_start,
            address_range_end=address_range_end,
            gateway_ip_address=gateway_ip_address,
            dns_primary=dns_primary,
            dns_secondary=dns_secondary,
            lease_time_seconds=lease_time_seconds,
            is_enabled=is_enabled,
            created_by=actor_user_id,
        )
        event = DhcpPoolCreated(id=pool.id, router_id=router.id)
        logger.info("dhcp_pool_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DHCP_POOL_CREATED,
            entity_id=pool.id,
            organization_id=pool.organization_id,
            description=f"DHCP pool '{name}' created for router {router.id}",
        )
        return pool

    async def get_pool(
        self,
        pool_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> DhcpPool:
        pool = await self.repository.get_pool_by_id(pool_id)
        if pool is None:
            raise DhcpPoolNotFoundError(pool_id)
        if (
            requesting_organization_id is not None
            and pool.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationDhcpPoolAccessError()
        return pool

    async def list_pools(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DhcpPool], object]:
        return await self.repository.list_pools(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=page,
            page_size=page_size,
        )

    async def update_pool(
        self,
        pool_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> DhcpPool:
        pool = await self.get_pool(
            pool_id, requesting_organization_id=requesting_organization_id
        )
        new_start = fields.get("address_range_start", pool.address_range_start)
        new_end = fields.get("address_range_end", pool.address_range_end)
        new_interface = fields.get("interface", pool.interface)
        range_or_interface_changed = (
            new_start != pool.address_range_start
            or new_end != pool.address_range_end
            or new_interface != pool.interface
        )
        if range_or_interface_changed:
            validate_address_range(new_start, new_end)
            await self._check_range_conflict(
                pool.router_id,
                new_interface,
                new_start,
                new_end,
                exclude_pool_id=pool.id,
            )
        if "gateway_ip_address" in fields:
            validate_ip_address("gateway_ip_address", fields["gateway_ip_address"])
        if "dns_primary" in fields:
            validate_ip_address("dns_primary", fields["dns_primary"])
        if "dns_secondary" in fields:
            validate_ip_address("dns_secondary", fields["dns_secondary"])

        updated = await self.repository.update_pool(
            pool, {**fields, "updated_by": actor_user_id}
        )
        event = DhcpPoolUpdated(id=updated.id)
        logger.info("dhcp_pool_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DHCP_POOL_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"DHCP pool '{updated.name}' updated",
        )
        return updated

    async def delete_pool(
        self,
        pool_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> DhcpPool:
        pool = await self.get_pool(
            pool_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_pool(pool)
        event = DhcpPoolDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("dhcp_pool_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DHCP_POOL_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"DHCP pool '{deleted.name}' deleted",
        )
        return deleted

    async def _check_range_conflict(
        self,
        router_id: uuid.UUID,
        interface: str | None,
        start: str,
        end: str,
        *,
        exclude_pool_id: uuid.UUID | None = None,
    ) -> None:
        existing = await self.repository.list_pools_for_router(router_id)
        for other in existing:
            if other.is_deleted:
                continue
            if exclude_pool_id is not None and other.id == exclude_pool_id:
                continue
            if other.interface != interface:
                continue
            if ranges_overlap(
                start, end, other.address_range_start, other.address_range_end
            ):
                raise DhcpPoolRangeConflictError(router_id, other.id)

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
            entity_type="dhcp_pool",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = ["RouterLookupProtocol", "AuditLogWriter", "DhcpService"]
