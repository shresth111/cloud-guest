"""MAC Authorization business logic: organization-scoped MAC whitelist
CRUD, bulk import/export, and the ``is_mac_authorized`` read-model query.

## No device/router composition

Unlike most domains built in this batch, this one composes nothing --
it is purely organization/location scoped, trusting
``requesting_organization_id`` directly the same way
``app.domains.policy`` does (RBAC's own dependency layer already
validates real organization membership before a request reaches this
service; there is no router/device concept to resolve here at all).

## Honest scope: not yet wired into guest login

``is_mac_authorized`` is the real seam a future pass integrating this
domain with ``app.domains.guest.service.GuestService``'s own login flow
would call (to actually implement "Authentication Bypass" -- skipping
OTP/voucher verification for a trusted device). This build deliberately
does not wire that integration -- see ``docs/mac_authorization/FLOW.md``
for the full reasoning (this domain was built standalone, independent of
``app.domains.guest_access.models.DeviceAccessRule``'s own login-time
access-gating concern, per an explicit scoping decision).

## Bulk import: partial success, mirrors ``app.domains.voucher``

``import_entries`` mirrors
``app.domains.voucher.service.VoucherService.import_vouchers``'s own
"accepted rows are inserted, rejected rows are reported with a reason,
never an all-or-nothing failure" contract -- one malformed row in a
1000-row batch must not discard the other 999.
"""

from __future__ import annotations

import csv
import dataclasses
import io
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from app.domains.rbac.enums import AuditAction

from .constants import MacAuthorizationType
from .events import (
    MacAuthorizationEntryCreated,
    MacAuthorizationEntryDeleted,
    MacAuthorizationEntryUpdated,
)
from .exceptions import (
    CrossOrganizationMacAuthorizationAccessError,
    MacAuthorizationAlreadyExistsError,
    MacAuthorizationEntryNotFoundError,
    MacAuthorizationError,
    OrganizationRequiredError,
)
from .models import MacAuthorizationEntry
from .repository import MacAuthorizationRepositoryProtocol
from .validators import is_currently_valid, normalize_mac_address, validate_expiry

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


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


@dataclass(frozen=True, slots=True)
class RejectedImportRow:
    mac_address: str
    reason: str


@dataclass(frozen=True, slots=True)
class MacImportResult:
    imported_count: int
    imported_ids: list[uuid.UUID] = field(default_factory=list)
    rejected: list[RejectedImportRow] = field(default_factory=list)


class MacAuthorizationService:
    """Core MAC Authorization business logic."""

    def __init__(
        self,
        repository: MacAuthorizationRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer

    async def create_entry(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        mac_address: str,
        authorization_type: MacAuthorizationType = MacAuthorizationType.PERMANENT,
        location_id: uuid.UUID | None = None,
        expires_at: datetime | None = None,
        comment: str | None = None,
        is_enabled: bool = True,
    ) -> MacAuthorizationEntry:
        if requesting_organization_id is None:
            raise OrganizationRequiredError()
        normalized_mac = normalize_mac_address(mac_address)
        validate_expiry(authorization_type, expires_at, now=datetime.now(UTC))
        existing = await self.repository.get_entry_by_org_and_mac(
            requesting_organization_id, normalized_mac
        )
        if existing is not None:
            raise MacAuthorizationAlreadyExistsError(
                requesting_organization_id, normalized_mac
            )

        entry = await self.repository.create_entry(
            organization_id=requesting_organization_id,
            location_id=location_id,
            mac_address=normalized_mac,
            authorization_type=authorization_type.value,
            expires_at=expires_at,
            comment=comment,
            is_enabled=is_enabled,
            created_by=actor_user_id,
        )
        event = MacAuthorizationEntryCreated(
            id=entry.id,
            organization_id=requesting_organization_id,
            mac_address=normalized_mac,
        )
        logger.info("mac_authorization_entry_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.MAC_AUTHORIZATION_ENTRY_CREATED,
            entity_id=entry.id,
            organization_id=requesting_organization_id,
            description=f"MAC authorization entry '{normalized_mac}' created",
        )
        return entry

    async def get_entry(
        self,
        entry_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> MacAuthorizationEntry:
        entry = await self.repository.get_entry_by_id(entry_id)
        if entry is None:
            raise MacAuthorizationEntryNotFoundError(entry_id)
        if (
            requesting_organization_id is not None
            and entry.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationMacAuthorizationAccessError()
        return entry

    async def list_entries(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[MacAuthorizationEntry], object]:
        return await self.repository.list_entries(
            requesting_organization_id=requesting_organization_id,
            location_id=location_id,
            page=page,
            page_size=page_size,
        )

    async def update_entry(
        self,
        entry_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        **fields: object,
    ) -> MacAuthorizationEntry:
        entry = await self.get_entry(
            entry_id, requesting_organization_id=requesting_organization_id
        )
        if "mac_address" in fields:
            normalized_mac = normalize_mac_address(fields["mac_address"])
            if normalized_mac != entry.mac_address:
                existing = await self.repository.get_entry_by_org_and_mac(
                    entry.organization_id, normalized_mac
                )
                if existing is not None and existing.id != entry.id:
                    raise MacAuthorizationAlreadyExistsError(
                        entry.organization_id, normalized_mac
                    )
            fields["mac_address"] = normalized_mac

        new_authorization_type = fields.get(
            "authorization_type", entry.authorization_type
        )
        new_expires_at = fields.get("expires_at", entry.expires_at)
        if "authorization_type" in fields or "expires_at" in fields:
            validate_expiry(
                MacAuthorizationType(new_authorization_type),
                new_expires_at,
                now=datetime.now(UTC),
            )

        updated = await self.repository.update_entry(
            entry, {**fields, "updated_by": actor_user_id}
        )
        event = MacAuthorizationEntryUpdated(id=updated.id)
        logger.info("mac_authorization_entry_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.MAC_AUTHORIZATION_ENTRY_UPDATED,
            entity_id=updated.id,
            organization_id=updated.organization_id,
            description=f"MAC authorization entry '{updated.mac_address}' updated",
        )
        return updated

    async def delete_entry(
        self,
        entry_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> MacAuthorizationEntry:
        entry = await self.get_entry(
            entry_id, requesting_organization_id=requesting_organization_id
        )
        deleted = await self.repository.soft_delete_entry(entry)
        event = MacAuthorizationEntryDeleted(
            id=deleted.id, organization_id=deleted.organization_id
        )
        logger.info("mac_authorization_entry_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.MAC_AUTHORIZATION_ENTRY_DELETED,
            entity_id=deleted.id,
            organization_id=deleted.organization_id,
            description=f"MAC authorization entry '{deleted.mac_address}' deleted",
        )
        return deleted

    async def import_entries(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        entries: list[dict[str, object]],
    ) -> MacImportResult:
        if requesting_organization_id is None:
            raise OrganizationRequiredError()
        imported_ids: list[uuid.UUID] = []
        rejected: list[RejectedImportRow] = []
        for raw in entries:
            mac_address = str(raw.get("mac_address", ""))
            try:
                authorization_type = MacAuthorizationType(
                    raw.get("authorization_type", MacAuthorizationType.PERMANENT.value)
                )
                created = await self.create_entry(
                    actor_user_id=actor_user_id,
                    requesting_organization_id=requesting_organization_id,
                    mac_address=mac_address,
                    authorization_type=authorization_type,
                    location_id=raw.get("location_id"),
                    expires_at=raw.get("expires_at"),
                    comment=raw.get("comment"),
                    is_enabled=bool(raw.get("is_enabled", True)),
                )
                imported_ids.append(created.id)
            except (MacAuthorizationError, ValueError) as exc:
                rejected.append(
                    RejectedImportRow(mac_address=mac_address, reason=str(exc))
                )
        return MacImportResult(
            imported_count=len(imported_ids),
            imported_ids=imported_ids,
            rejected=rejected,
        )

    async def export_entries_csv(
        self, *, requesting_organization_id: uuid.UUID | None
    ) -> str:
        if requesting_organization_id is None:
            raise OrganizationRequiredError()
        entries = await self.repository.list_all_for_organization(
            requesting_organization_id
        )
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "mac_address",
                "authorization_type",
                "location_id",
                "expires_at",
                "comment",
                "is_enabled",
                "created_at",
            ]
        )
        for entry in entries:
            writer.writerow(
                [
                    entry.mac_address,
                    entry.authorization_type,
                    str(entry.location_id) if entry.location_id else "",
                    entry.expires_at.isoformat() if entry.expires_at else "",
                    entry.comment or "",
                    entry.is_enabled,
                    entry.created_at.isoformat(),
                ]
            )
        return buffer.getvalue()

    async def is_mac_authorized(
        self, mac_address: str, *, organization_id: uuid.UUID
    ) -> bool:
        """Whether ``mac_address`` currently has a valid (enabled,
        non-expired) authorization entry for ``organization_id`` -- see
        module docstring for this method's own "not yet wired into guest
        login" scope note. A malformed ``mac_address`` is never
        authorized (returns ``False``, never raises)."""
        try:
            normalized_mac = normalize_mac_address(mac_address)
        except MacAuthorizationError:
            return False
        entry = await self.repository.get_entry_by_org_and_mac(
            organization_id, normalized_mac
        )
        if entry is None:
            return False
        return is_currently_valid(
            is_enabled=entry.is_enabled,
            expires_at=entry.expires_at,
            now=datetime.now(UTC),
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
            entity_type="mac_authorization_entry",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


__all__ = [
    "AuditLogWriter",
    "RejectedImportRow",
    "MacImportResult",
    "MacAuthorizationService",
]
