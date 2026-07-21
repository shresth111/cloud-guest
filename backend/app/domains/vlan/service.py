"""VLAN Management business logic: per-router VLAN inventory CRUD.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## No live device push in this pass

Unlike ``app.domains.isp``, this domain has no ``device_adapters.py`` and
no Celery task -- it is a pure rules/inventory domain, mirroring
``app.domains.isp_routing``/``app.domains.policy``'s own "priority/config +
enable/disable, realized onto a device later" precedent. Real RouterOS
VLAN interface + IP address provisioning belongs to the not-yet-built
Network Configuration Management domain's own provisioning-integration
layer, not this one. See ``docs/vlan/FLOW.md``.

## Validation

``vlan_id`` must fall within IEEE 802.1Q's real 1-4094 usable range
(``validators.validate_vlan_id``) and must be unique per router among
non-deleted rows (``VlanIdAlreadyExistsError``). ``cidr``/
``gateway_ip_address``, when supplied, must be real, parseable values
(Python's own ``ipaddress`` module) -- a malformed value is rejected at
create/update time, never silently stored.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .events import VlanCreated, VlanDeleted, VlanUpdated
from .exceptions import (
    CrossOrganizationVlanAccessError,
    VlanIdAlreadyExistsError,
    VlanNotFoundError,
)
from .models import Vlan
from .repository import VlanRepositoryProtocol
from .validators import validate_cidr, validate_gateway_ip_address, validate_vlan_id

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


class VlanService:
    """Core VLAN Management business logic."""

    def __init__(
        self,
        repository: VlanRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer

    async def create_vlan(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        vlan_id: int,
        name: str,
        gateway_ip_address: str | None = None,
        cidr: str | None = None,
        interface: str | None = None,
        description: str | None = None,
        is_enabled: bool = True,
    ) -> Vlan:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_vlan_id(vlan_id)
        validate_cidr(cidr)
        validate_gateway_ip_address(gateway_ip_address)
        existing = await self.repository.get_vlan_by_router_and_tag(router.id, vlan_id)
        if existing is not None:
            raise VlanIdAlreadyExistsError(router.id, vlan_id)

        vlan = await self.repository.create_vlan(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            vlan_id=vlan_id,
            name=name,
            gateway_ip_address=gateway_ip_address,
            cidr=cidr,
            interface=interface,
            description=description,
            is_enabled=is_enabled,
            created_by=actor_user_id,
        )
        event = VlanCreated(id=vlan.id, router_id=router.id, tag=vlan_id)
        logger.info("vlan_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_CREATED,
            entity_id=vlan.id,
            organization_id=vlan.organization_id,
            description=f"VLAN '{name}' (tag {vlan_id}) created for router {router.id}",
        )
        return vlan

    async def get_vlan(
        self,
        vlan_pk: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Vlan:
        vlan = await self.repository.get_vlan_by_id(vlan_pk)
        if vlan is None:
            raise VlanNotFoundError(vlan_pk)
        if (
            requesting_organization_id is not None
            and vlan.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationVlanAccessError()
        return vlan

    async def list_vlans(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Vlan], object]:
        return await self.repository.list_vlans(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            location_id=location_id,
            page=page,
            page_size=page_size,
        )

    async def list_vlans_for_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[Vlan]:
        """Every non-deleted VLAN for this router, unpaginated -- the real
        read source ``app.domains.network_config`` composes to render a
        router's full VLAN config, mirroring
        ``app.domains.dhcp.DhcpService.list_pools_for_router``'s identical
        shape."""
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_vlans_for_router(router_id)

    async def update_vlan(
        self,
        vlan_pk: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> Vlan:
        vlan = await self.get_vlan(
            vlan_pk, requesting_organization_id=requesting_organization_id
        )
        new_vlan_id = fields.get("vlan_id", vlan.vlan_id)
        if new_vlan_id != vlan.vlan_id:
            validate_vlan_id(new_vlan_id)
            existing = await self.repository.get_vlan_by_router_and_tag(
                vlan.router_id, new_vlan_id
            )
            if existing is not None and existing.id != vlan.id:
                raise VlanIdAlreadyExistsError(vlan.router_id, new_vlan_id)
        if "cidr" in fields:
            validate_cidr(fields["cidr"])
        if "gateway_ip_address" in fields:
            validate_gateway_ip_address(fields["gateway_ip_address"])

        updated = await self.repository.update_vlan(
            vlan, {**fields, "updated_by": actor_user_id}
        )
        event = VlanUpdated(id=updated.id)
        logger.info("vlan_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"VLAN '{updated.name}' updated",
        )
        return updated

    async def delete_vlan(
        self,
        vlan_pk: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> Vlan:
        vlan = await self.get_vlan(
            vlan_pk, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_vlan(vlan)
        event = VlanDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("vlan_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.VLAN_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"VLAN '{deleted.name}' deleted",
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
            entity_type="vlan",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = ["RouterLookupProtocol", "AuditLogWriter", "VlanService"]
