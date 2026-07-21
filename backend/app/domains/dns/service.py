"""DNS Management business logic: per-router static DNS record CRUD with
real name/address validation.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes.

## No live device push in this pass

Mirrors ``app.domains.dhcp``/``app.domains.vlan``'s own "config resource,
realized onto a device later" precedent -- real RouterOS ``/ip dns
static`` provisioning belongs to ``app.domains.network_config``'s
existing provisioning-integration layer, not this one.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import DEFAULT_TTL_SECONDS, DnsRecordType
from .events import DnsRecordCreated, DnsRecordDeleted, DnsRecordUpdated
from .exceptions import CrossOrganizationDnsRecordAccessError, DnsRecordNotFoundError
from .models import DnsRecord
from .repository import DnsRepositoryProtocol
from .validators import validate_address, validate_name

logger = logging.getLogger(__name__)


def _event_extra(event: object) -> dict[str, object]:
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


class DnsService:
    """Core DNS Management business logic."""

    def __init__(
        self,
        repository: DnsRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer

    async def create_record(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID,
        name: str,
        address: str,
        record_type: DnsRecordType = DnsRecordType.A,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        comment: str | None = None,
        is_enabled: bool = True,
    ) -> DnsRecord:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_name(name)
        validate_address(record_type, address)

        record = await self.repository.create_record(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            name=name,
            record_type=record_type.value,
            address=address,
            ttl_seconds=ttl_seconds,
            comment=comment,
            is_enabled=is_enabled,
            created_by=actor_user_id,
        )
        event = DnsRecordCreated(id=record.id, router_id=router.id)
        logger.info("dns_record_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DNS_RECORD_CREATED,
            entity_id=record.id,
            organization_id=record.organization_id,
            description=f"DNS record '{name}' created for router {router.id}",
        )
        return record

    async def get_record(
        self,
        record_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> DnsRecord:
        record = await self.repository.get_record_by_id(record_id)
        if record is None:
            raise DnsRecordNotFoundError(record_id)
        if (
            requesting_organization_id is not None
            and record.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationDnsRecordAccessError()
        return record

    async def list_records(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DnsRecord], object]:
        return await self.repository.list_records(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=page,
            page_size=page_size,
        )

    async def list_records_for_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[DnsRecord]:
        """Every non-deleted record for this router, unpaginated -- the
        real read source ``app.domains.network_config`` composes to
        render a router's full DNS config."""
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_records_for_router(router_id)

    async def update_record(
        self,
        record_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> DnsRecord:
        record = await self.get_record(
            record_id, requesting_organization_id=requesting_organization_id
        )
        new_type = DnsRecordType(fields.get("record_type", record.record_type))
        if "name" in fields:
            validate_name(fields["name"])
        if "address" in fields or "record_type" in fields:
            validate_address(new_type, fields.get("address", record.address))

        updated = await self.repository.update_record(
            record, {**fields, "updated_by": actor_user_id}
        )
        event = DnsRecordUpdated(id=updated.id)
        logger.info("dns_record_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DNS_RECORD_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"DNS record '{updated.name}' updated",
        )
        return updated

    async def delete_record(
        self,
        record_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> DnsRecord:
        record = await self.get_record(
            record_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_record(record)
        event = DnsRecordDeleted(id=deleted.id, router_id=deleted.router_id)
        logger.info("dns_record_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.DNS_RECORD_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"DNS record '{deleted.name}' deleted",
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
            entity_type="dns_record",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = ["RouterLookupProtocol", "AuditLogWriter", "DnsService"]
