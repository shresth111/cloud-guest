"""Data access layer for the Guest Access Control domain.

Mirrors ``app.domains.voucher.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``GuestAccessRepositoryProtocol``), and a concrete,
``GenericRepository``-backed implementation (``GuestAccessRepository``)
wrapping two ``GenericRepository`` instances (one per table), plus two
hand-written ``select`` statements for the one query
``GenericRepository``'s equality/IN-filter support genuinely can't
express: "every active, non-expired rule that could apply to this
identifier/MAC at this org/location scope" -- an OR across
``location_id IS NULL`` (org-wide) vs. a specific ``location_id``, plus an
``expires_at IS NULL OR expires_at > now`` bound, neither of which is a
plain equality filter.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta

from .models import DeviceAccessRule, GuestAccessRule


class GuestAccessRepositoryProtocol(Protocol):
    # -- guest (identifier-keyed) rules --------------------------------------
    async def create_guest_rule(self, **fields: object) -> GuestAccessRule: ...

    async def get_guest_rule_by_id(
        self, rule_id: uuid.UUID
    ) -> GuestAccessRule | None: ...

    async def update_guest_rule(
        self, rule: GuestAccessRule, data: dict[str, object]
    ) -> GuestAccessRule: ...

    async def delete_guest_rule(self, rule: GuestAccessRule) -> None: ...

    async def list_guest_rules(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[GuestAccessRule], PaginationMeta]: ...

    async def list_matching_guest_rules(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        identifier: str,
        now: datetime,
    ) -> list[GuestAccessRule]: ...

    # -- device (MAC-keyed) rules --------------------------------------------
    async def create_device_rule(self, **fields: object) -> DeviceAccessRule: ...

    async def get_device_rule_by_id(
        self, rule_id: uuid.UUID
    ) -> DeviceAccessRule | None: ...

    async def update_device_rule(
        self, rule: DeviceAccessRule, data: dict[str, object]
    ) -> DeviceAccessRule: ...

    async def delete_device_rule(self, rule: DeviceAccessRule) -> None: ...

    async def list_device_rules(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[DeviceAccessRule], PaginationMeta]: ...

    async def list_matching_device_rules(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        mac_address: str,
        now: datetime,
    ) -> list[DeviceAccessRule]: ...


class GuestAccessRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``GuestAccessRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.guest_rules = GenericRepository(GuestAccessRule, session)
        self.device_rules = GenericRepository(DeviceAccessRule, session)

    # -- guest rules -----------------------------------------------------------

    async def create_guest_rule(self, **fields: object) -> GuestAccessRule:
        return await self.guest_rules.create(fields)

    async def get_guest_rule_by_id(
        self, rule_id: uuid.UUID
    ) -> GuestAccessRule | None:
        return await self.guest_rules.get_by_id(rule_id)

    async def update_guest_rule(
        self, rule: GuestAccessRule, data: dict[str, object]
    ) -> GuestAccessRule:
        return await self.guest_rules.update(rule, data)

    async def delete_guest_rule(self, rule: GuestAccessRule) -> None:
        await self.guest_rules.soft_delete(rule)

    async def list_guest_rules(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[GuestAccessRule], PaginationMeta]:
        return await self.guest_rules.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_matching_guest_rules(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        identifier: str,
        now: datetime,
    ) -> list[GuestAccessRule]:
        """Every active, non-expired rule for ``identifier`` that could
        apply at ``location_id`` (or was written org-wide) -- backs
        ``AccessDecisionResolver.resolve``. Deliberately not expressible
        via ``GenericRepository``'s equality-filter support: this needs an
        OR across ``location_id IS NULL`` vs. a specific ``location_id``,
        plus an ``expires_at IS NULL OR expires_at > now`` bound."""
        scope_clause = GuestAccessRule.location_id.is_(None)
        if location_id is not None:
            scope_clause = or_(
                scope_clause, GuestAccessRule.location_id == location_id
            )
        statement = select(GuestAccessRule).where(
            GuestAccessRule.organization_id == organization_id,
            GuestAccessRule.identifier == identifier,
            GuestAccessRule.is_active.is_(True),
            GuestAccessRule.is_deleted.is_(False),
            scope_clause,
            or_(
                GuestAccessRule.expires_at.is_(None),
                GuestAccessRule.expires_at > now,
            ),
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- device rules ------------------------------------------------------

    async def create_device_rule(self, **fields: object) -> DeviceAccessRule:
        return await self.device_rules.create(fields)

    async def get_device_rule_by_id(
        self, rule_id: uuid.UUID
    ) -> DeviceAccessRule | None:
        return await self.device_rules.get_by_id(rule_id)

    async def update_device_rule(
        self, rule: DeviceAccessRule, data: dict[str, object]
    ) -> DeviceAccessRule:
        return await self.device_rules.update(rule, data)

    async def delete_device_rule(self, rule: DeviceAccessRule) -> None:
        await self.device_rules.soft_delete(rule)

    async def list_device_rules(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[DeviceAccessRule], PaginationMeta]:
        return await self.device_rules.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_matching_device_rules(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        mac_address: str,
        now: datetime,
    ) -> list[DeviceAccessRule]:
        """Device-rule mirror of ``list_matching_guest_rules`` -- identical
        scope/expiry reasoning, keyed by ``mac_address`` instead of
        ``identifier``."""
        scope_clause = DeviceAccessRule.location_id.is_(None)
        if location_id is not None:
            scope_clause = or_(
                scope_clause, DeviceAccessRule.location_id == location_id
            )
        statement = select(DeviceAccessRule).where(
            DeviceAccessRule.organization_id == organization_id,
            DeviceAccessRule.mac_address == mac_address,
            DeviceAccessRule.is_active.is_(True),
            DeviceAccessRule.is_deleted.is_(False),
            scope_clause,
            or_(
                DeviceAccessRule.expires_at.is_(None),
                DeviceAccessRule.expires_at > now,
            ),
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())


__all__ = ["GuestAccessRepositoryProtocol", "GuestAccessRepository"]
