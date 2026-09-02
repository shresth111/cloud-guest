"""DHCP Pool Management business logic: per-router DHCP pool CRUD with
real IP-range validation and conflict detection.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## Live device push

``push_pool_to_device`` realizes a pool on its router over the RouterOS
API, through ``device_adapters``. This paragraph previously said the
opposite -- "no live device push in this pass ... no ``device_adapters.py``
and no Celery task" -- and deferred real provisioning to a "not-yet-built
Network Configuration Management domain". That deferral is what made
creating a DHCP pool a database-only operation: the dashboard reported a
pool, the router had none, and guests on the network received no address
at all.

The gateway writer already existed
(``wyfy_device_gateway.mikrotik_adapter.configure_dhcp_pool``, three real
RouterOS operations over librouteros on 8728) with no callers. Creation
still writes only a row, deliberately: renaming a pool must not be able to
fail with a connection error, and an operator must be able to retry a push
without re-submitting the form.

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
from datetime import UTC, datetime
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import DEFAULT_LEASE_TIME_SECONDS, DhcpDevicePushStatus
from .device_adapters import DhcpCredentials, get_dhcp_adapter
from .events import (
    DhcpPoolCreated,
    DhcpPoolDeleted,
    DhcpPoolPushed,
    DhcpPoolUpdated,
)
from .exceptions import (
    CrossOrganizationDhcpPoolAccessError,
    DhcpMissingCredentialsError,
    DhcpPoolMissingGatewayError,
    DhcpPoolMissingInterfaceError,
    DhcpPoolNotEnabledError,
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

    # Declared because the device-push path really calls it. It was
    # previously left out, so this Protocol under-described what the
    # service requires: a collaborator could satisfy the annotation and
    # still blow up at runtime, and no type checker could see it coming.
    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


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
            # Written explicitly rather than left to the column default,
            # which only applies at INSERT: a freshly constructed row would
            # otherwise carry None until it round-trips through the
            # database, and "has this reached a device" must never read as
            # unknown.
            device_push_status=DhcpDevicePushStatus.PENDING.value,
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

    async def list_pools_for_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[DhcpPool]:
        """Every non-deleted pool for this router, unpaginated -- the real
        read source ``app.domains.network_config`` composes to render a
        router's full DHCP config, mirroring ``get_pool``'s own tenant
        validation via ``router_lookup`` rather than a per-row organization
        comparison (there is no single row here to compare against)."""
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_pools_for_router(router_id)

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

    async def push_pool_to_device(
        self,
        pool_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> DhcpPool:
        """Realizes one DHCP pool on its own router, over the RouterOS API.

        Until this existed, ``create_pool`` wrote a row, returned 201, and
        the device was never contacted -- this module's own docstring said
        so and called it deliberate. The visible consequence was not a
        missing pool but a broken network: a guest joining a VLAN the
        dashboard reported as created received no address at all, because
        no ``/ip dhcp-server`` had ever been created to answer them.

        **Separate from create/update, deliberately.** Renaming a pool must
        not be able to fail with a connection error, and an operator must be
        able to retry a push without re-submitting the form.

        **Every precondition is checked before a socket is opened**, so a
        misconfigured row fails as a 4xx naming the problem rather than as a
        device timeout.

        **A failure is committed, then re-raised.**
        ``GenericRepository.update`` only ``flush()``es and
        ``get_db_session`` rolls back on any exception, so a failure record
        written just before a re-raise is otherwise discarded and the row
        still reads ``pending`` with ``device_push_error`` NULL. Committing
        explicitly is what makes the record survive to be read.

        The exception then propagates as a real non-2xx. It must not become
        a ``200 {"success": false}``: the frontend interceptor unwraps
        ``data`` and never reads ``success``, so such a response is
        indistinguishable from success to every caller in the app.
        """
        pool = await self.get_pool(
            pool_id, requesting_organization_id=requesting_organization_id
        )

        if not pool.is_enabled:
            raise DhcpPoolNotEnabledError(pool.id)
        if not pool.interface:
            # render_dhcp_pool handles this by emitting a comment and
            # skipping -- fine for a script, but on a direct push the same
            # silence would report success for a device that received
            # nothing. The adapter also derives both RouterOS identifiers
            # from this field.
            raise DhcpPoolMissingInterfaceError(pool.id)
        if not pool.gateway_ip_address:
            # Handing out addresses with no gateway gives guests an IP and
            # no route off the subnet. Defaulting to ``.1`` would be a
            # fabricated network fact.
            raise DhcpPoolMissingGatewayError(pool.id)

        router = await self.router_lookup.get_router(
            pool.router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_device_credentials(router)
        adapter = get_dhcp_adapter(router.vendor)

        try:
            await adapter.configure_dhcp_pool(
                credentials,
                interface=pool.interface,
                range_start=pool.address_range_start,
                range_end=pool.address_range_end,
                gateway=pool.gateway_ip_address,
                dns_servers=self._dns_servers(pool),
                lease_time_seconds=pool.lease_time_seconds,
            )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            await self.repository.update_pool(
                pool,
                {
                    "device_push_status": DhcpDevicePushStatus.FAILED.value,
                    "device_push_error": str(exc),
                },
            )
            await self.repository.commit()
            raise

        updated = await self.repository.update_pool(
            pool,
            {
                "device_push_status": DhcpDevicePushStatus.ACTIVE.value,
                "device_push_error": None,
                "device_pushed_at": datetime.now(UTC),
                "updated_by": actor_user_id,
            },
        )
        event = DhcpPoolPushed(
            id=updated.id,
            router_id=updated.router_id,
            interface=updated.interface or "",
        )
        logger.info("dhcp_pool_pushed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DHCP_POOL_PUSHED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=(
                f"DHCP pool {updated.id} pushed to router {updated.router_id}"
            ),
        )
        return updated

    @staticmethod
    def _dns_servers(pool: DhcpPool) -> list[str]:
        """The DNS servers to advertise, in the operator's own order.

        Only the ones actually set: an empty list means the adapter omits
        ``dns-server=`` entirely rather than sending a blank value, which
        RouterOS would take as "no DNS" in a way that looks configured.
        """
        return [
            server
            for server in (pool.dns_primary, pool.dns_secondary)
            if server
        ]

    def _resolve_device_credentials(self, router: Router) -> DhcpCredentials:
        """Raise rather than guess -- mirrors ``vlan``/``qos``."""
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise DhcpMissingCredentialsError(router.id)
        return DhcpCredentials(
            host=host, username=router.api_username, password=secret
        )

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
