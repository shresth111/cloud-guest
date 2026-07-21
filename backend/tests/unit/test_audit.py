"""Unit tests for the audit domain: query/filter over RBAC's existing
``audit_log_entries`` table, and CSV export (including the truncation
signal when more rows match than the export cap allows).

Follows this project's plain-``assert``/native-``async def`` style and its
"fake the narrow Protocol boundary" precedent (see
``tests/unit/test_isp_routing.py``).
"""

from __future__ import annotations

import csv
import io
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.audit.constants import AUDIT_EXPORT_PAGE_SIZE
from app.domains.audit.service import AuditService
from app.domains.rbac.models import AuditLogEntry


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


def _make_entry(**overrides: object) -> AuditLogEntry:
    fields: dict[str, object] = {
        "actor_user_id": uuid.uuid4(),
        "action": "role.assigned",
        "entity_type": "user_role",
        "entity_id": uuid.uuid4(),
        "description": "Role assigned",
        "event_metadata": {},
        "organization_id": uuid.uuid4(),
        "location_id": None,
    }
    fields.update(overrides)
    return AuditLogEntry(**_base_fields(**fields))


@dataclass
class FakeAuditRepository:
    entries: list[AuditLogEntry] = field(default_factory=list)

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
    ) -> tuple[list[AuditLogEntry], PaginationMeta]:
        values = list(self.entries)
        if organization_id is not None:
            values = [v for v in values if v.organization_id == organization_id]
        if actor_user_id is not None:
            values = [v for v in values if v.actor_user_id == actor_user_id]
        if action is not None:
            values = [v for v in values if v.action == action]
        if entity_type is not None:
            values = [v for v in values if v.entity_type == entity_type]
        if location_id is not None:
            values = [v for v in values if v.location_id == location_id]
        if start is not None:
            values = [v for v in values if v.created_at >= start]
        if end is not None:
            values = [v for v in values if v.created_at <= end]
        values.sort(key=lambda v: v.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))


def make_service() -> tuple[AuditService, FakeAuditRepository]:
    repository = FakeAuditRepository()
    return AuditService(repository), repository


# ============================================================================
# search
# ============================================================================


async def test_search_scopes_to_organization() -> None:
    service, repository = make_service()
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()
    repository.entries.append(_make_entry(organization_id=org_a))
    repository.entries.append(_make_entry(organization_id=org_b))

    entries, meta = await service.search(requesting_organization_id=org_a)

    assert meta.total_items == 1
    assert entries[0].organization_id == org_a


async def test_search_filters_by_location_id() -> None:
    service, repository = make_service()
    location_a = uuid.uuid4()
    location_b = uuid.uuid4()
    repository.entries.append(_make_entry(location_id=location_a))
    repository.entries.append(_make_entry(location_id=location_b))

    entries, meta = await service.search(
        requesting_organization_id=None, location_id=location_a
    )

    assert meta.total_items == 1
    assert entries[0].location_id == location_a


async def test_search_filters_by_action_and_entity_type() -> None:
    service, repository = make_service()
    repository.entries.append(
        _make_entry(action="role.assigned", entity_type="user_role")
    )
    repository.entries.append(
        _make_entry(action="role.revoked", entity_type="user_role")
    )

    entries, meta = await service.search(
        requesting_organization_id=None, action="role.assigned"
    )

    assert meta.total_items == 1
    assert entries[0].action == "role.assigned"


async def test_search_filters_by_date_range() -> None:
    service, repository = make_service()
    old_entry = _make_entry(created_at=_now() - timedelta(days=30))
    recent_entry = _make_entry(created_at=_now())
    repository.entries.extend([old_entry, recent_entry])

    entries, meta = await service.search(
        requesting_organization_id=None, start=_now() - timedelta(days=1)
    )

    assert meta.total_items == 1
    assert entries[0].id == recent_entry.id


# ============================================================================
# export_csv
# ============================================================================


async def test_export_csv_includes_header_and_rows() -> None:
    service, repository = make_service()
    repository.entries.append(_make_entry(action="role.assigned"))
    repository.entries.append(_make_entry(action="role.revoked"))

    csv_text, truncated = await service.export_csv(requesting_organization_id=None)

    rows = list(csv.reader(io.StringIO(csv_text)))
    assert rows[0] == [
        "created_at",
        "actor_user_id",
        "action",
        "entity_type",
        "entity_id",
        "organization_id",
        "location_id",
        "description",
    ]
    assert len(rows) == 3  # header + 2 data rows
    assert truncated is False


async def test_export_csv_paginates_across_multiple_pages() -> None:
    service, repository = make_service()
    for _ in range(AUDIT_EXPORT_PAGE_SIZE + 5):
        repository.entries.append(_make_entry())

    csv_text, truncated = await service.export_csv(requesting_organization_id=None)

    rows = list(csv.reader(io.StringIO(csv_text)))
    assert len(rows) - 1 == AUDIT_EXPORT_PAGE_SIZE + 5
    assert truncated is False


async def test_export_csv_signals_truncation_past_the_cap(monkeypatch) -> None:
    import app.domains.audit.service as audit_service_module

    monkeypatch.setattr(audit_service_module, "AUDIT_EXPORT_MAX_ROWS", 3)
    service, repository = make_service()
    for _ in range(5):
        repository.entries.append(_make_entry())

    csv_text, truncated = await service.export_csv(requesting_organization_id=None)

    rows = list(csv.reader(io.StringIO(csv_text)))
    assert len(rows) - 1 == 3
    assert truncated is True
