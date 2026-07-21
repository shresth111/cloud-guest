"""Hotspot Settings business logic: per-router hotspot user-profile CRUD
with real walled-garden-list validation.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## No live device push in this pass

Unlike ``app.domains.isp``, this domain has no ``device_adapters.py`` and
no Celery task -- it is a pure rules/inventory domain, mirroring
``app.domains.dhcp``/``app.domains.vlan``/``app.domains
.port_forwarding``'s own "config resource, realized onto a device later"
precedent. Real RouterOS ``/ip hotspot`` provisioning is composed via
``app.domains.network_config``, not this domain.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .events import HotspotProfileCreated, HotspotProfileDeleted, HotspotProfileUpdated
from .exceptions import (
    CrossOrganizationHotspotProfileAccessError,
    HotspotProfileNotFoundError,
)
from .models import HotspotProfile
from .repository import HotspotRepositoryProtocol
from .validators import validate_walled_garden_hosts

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


class HotspotService:
    """Core Hotspot Settings business logic."""

    def __init__(
        self,
        repository: HotspotRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer

    async def create_profile(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        name: str,
        session_timeout_minutes: int | None = None,
        idle_timeout_minutes: int | None = None,
        upload_limit_kbps: int | None = None,
        download_limit_kbps: int | None = None,
        walled_garden_hosts: list[str] | None = None,
        is_enabled: bool = True,
    ) -> HotspotProfile:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        hosts = walled_garden_hosts or []
        validate_walled_garden_hosts(hosts)

        profile = await self.repository.create_profile(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            name=name,
            session_timeout_minutes=session_timeout_minutes,
            idle_timeout_minutes=idle_timeout_minutes,
            upload_limit_kbps=upload_limit_kbps,
            download_limit_kbps=download_limit_kbps,
            walled_garden_hosts=hosts,
            is_enabled=is_enabled,
            created_by=actor_user_id,
        )
        event = HotspotProfileCreated(id=profile.id, router_id=router.id)
        logger.info("hotspot_profile_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.HOTSPOT_PROFILE_CREATED,
            entity_id=profile.id,
            organization_id=profile.organization_id,
            description=f"Hotspot profile '{name}' created for router {router.id}",
        )
        return profile

    async def get_profile(
        self,
        profile_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> HotspotProfile:
        profile = await self.repository.get_profile_by_id(profile_id)
        if profile is None:
            raise HotspotProfileNotFoundError(profile_id)
        if (
            requesting_organization_id is not None
            and profile.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationHotspotProfileAccessError()
        return profile

    async def list_profiles(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[HotspotProfile], object]:
        return await self.repository.list_profiles(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=page,
            page_size=page_size,
        )

    async def list_profiles_for_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[HotspotProfile]:
        """Every non-deleted profile for this router, unpaginated -- the
        real read source ``app.domains.network_config`` composes to
        render a router's full hotspot config, mirroring
        ``app.domains.dhcp.DhcpService.list_pools_for_router``'s
        identical shape."""
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_profiles_for_router(router_id)

    async def update_profile(
        self,
        profile_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> HotspotProfile:
        profile = await self.get_profile(
            profile_id, requesting_organization_id=requesting_organization_id
        )
        if "walled_garden_hosts" in fields:
            validate_walled_garden_hosts(fields["walled_garden_hosts"])

        updated = await self.repository.update_profile(
            profile, {**fields, "updated_by": actor_user_id}
        )
        event = HotspotProfileUpdated(id=updated.id)
        logger.info("hotspot_profile_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.HOTSPOT_PROFILE_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"Hotspot profile '{updated.name}' updated",
        )
        return updated

    async def delete_profile(
        self,
        profile_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> HotspotProfile:
        profile = await self.get_profile(
            profile_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_profile(profile)
        event = HotspotProfileDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("hotspot_profile_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.HOTSPOT_PROFILE_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"Hotspot profile '{deleted.name}' deleted",
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
            entity_type="hotspot_profile",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = ["HotspotService"]
