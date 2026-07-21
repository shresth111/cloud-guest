"""Audit domain business logic: query/filter/export over RBAC's existing
``audit_log_entries`` table (``app.domains.rbac.models.AuditLogEntry``).

Per the ADD (§6.3): "No new table -- ``audit_log_entries`` already exists
under ``rbac``. This module adds a dedicated ``service.py``/``router.py``
for query/filter/export/retention over that table." This domain owns no
table/model/repository of its own -- it composes
``app.domains.rbac.repository.RBACRepositoryProtocol.search_audit_log_entries``
(an additive extension to that repository, not a new one), the same
"no-own-table domain" shape ``app.domains.network_config`` already
establishes.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime
from typing import Protocol

from app.domains.rbac.models import AuditLogEntry

from .constants import AUDIT_EXPORT_MAX_ROWS, AUDIT_EXPORT_PAGE_SIZE, CSV_EXPORT_HEADERS


class AuditRepositoryProtocol(Protocol):
    """The single method this domain needs from RBAC's repository --
    satisfied structurally by the real
    ``app.domains.rbac.repository.RBACRepository`` (no import of that
    concrete class here)."""

    async def search_audit_log_entries(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
        action: str | None = None,
        entity_type: str | None = None,
        location_id: uuid.UUID | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        page: int,
        page_size: int,
    ): ...


class AuditService:
    """Query/export over ``audit_log_entries``."""

    def __init__(self, repository: AuditRepositoryProtocol) -> None:
        self.repository = repository

    async def search(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None = None,
        action: str | None = None,
        entity_type: str | None = None,
        location_id: uuid.UUID | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        page: int = 1,
        page_size: int = 25,
    ):
        return await self.repository.search_audit_log_entries(
            organization_id=requesting_organization_id,
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            location_id=location_id,
            start=start,
            end=end,
            page=page,
            page_size=page_size,
        )

    async def export_csv(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None = None,
        action: str | None = None,
        entity_type: str | None = None,
        location_id: uuid.UUID | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> tuple[str, bool]:
        """Streams matching rows into real CSV text, paginating internally
        up to ``AUDIT_EXPORT_MAX_ROWS``. Returns ``(csv_text, truncated)``
        -- ``truncated`` is ``True`` if more rows matched than the export
        cap allows, so the caller can surface that honestly rather than
        the export silently reading as complete."""
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(CSV_EXPORT_HEADERS)

        exported = 0
        page = 1
        truncated = False
        while exported < AUDIT_EXPORT_MAX_ROWS:
            rows, meta = await self.repository.search_audit_log_entries(
                organization_id=requesting_organization_id,
                actor_user_id=actor_user_id,
                action=action,
                entity_type=entity_type,
                location_id=location_id,
                start=start,
                end=end,
                page=page,
                page_size=AUDIT_EXPORT_PAGE_SIZE,
            )
            for row in rows:
                if exported >= AUDIT_EXPORT_MAX_ROWS:
                    truncated = True
                    break
                writer.writerow(_csv_row(row))
                exported += 1
            if not meta.has_next or not rows:
                break
            page += 1

        return buffer.getvalue(), truncated


def _csv_row(entry: AuditLogEntry) -> tuple[str, ...]:
    return (
        entry.created_at.isoformat(),
        str(entry.actor_user_id) if entry.actor_user_id else "",
        entry.action,
        entry.entity_type,
        str(entry.entity_id) if entry.entity_id else "",
        str(entry.organization_id) if entry.organization_id else "",
        str(entry.location_id) if entry.location_id else "",
        entry.description or "",
    )


__all__ = ["AuditService", "AuditRepositoryProtocol"]
