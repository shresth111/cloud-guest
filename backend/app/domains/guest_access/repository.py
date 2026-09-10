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
from .validators import identifier_match_terms


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

    async def find_guest_rule_for_import(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        identifier: str,
        rule_type: str,
    ) -> GuestAccessRule | None:
        """The existing row a bulk-import row would duplicate, if any.
        ``identifier`` must already be canonical.

        The match key is the whole of what makes two rules "the same rule"
        for a venue: organization, location scope, identifier, rule type.
        Deliberately ignores ``is_active`` and ``expires_at`` -- a guest who
        checked out on Tuesday and checks in again on Friday is the same
        person, and Friday's upload has to revive their row rather than
        report it as a duplicate and leave them offline. See
        ``GuestAccessService.import_guest_rules``.

        It also matches the **pre-E.164 spellings** of the same number --
        see the implementation for the bound and why the match is narrower
        here than at read time.

        Soft-deleted rows are excluded: a deleted rule is gone, and the
        import writes a fresh one.
        """
        ...

    async def list_all_guest_rules_for_organization(
        self, organization_id: uuid.UUID
    ) -> list[GuestAccessRule]:
        """Every live guest rule for one organization, unpaginated --
        backs the CSV export. Mirrors
        ``app.domains.mac_authorization.repository`` \
        ``.list_all_for_organization``'s identical "a file someone
        downloads is not paginated" shape."""
        ...

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

    # -- transaction -----------------------------------------------------------
    async def commit(self) -> None:
        """Commits the current transaction.

        Needed by ``GuestAccessService``'s block-enforcement path and
        nothing else. ``GenericRepository.create``/``update`` only
        ``flush()``, and ``get_db_session`` rolls the session back on any
        exception -- so both a block written just before a device failure
        and the failure record written just before the re-raise would be
        discarded, leaving no rule and no explanation. Committing
        explicitly is what makes each survive. Same fix, same reason, as
        ``app.domains.vlan.repository.VlanRepositoryProtocol.commit``.
        """
        ...


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

    async def get_guest_rule_by_id(self, rule_id: uuid.UUID) -> GuestAccessRule | None:
        return await self.guest_rules.get_by_id(rule_id)

    async def update_guest_rule(
        self, rule: GuestAccessRule, data: dict[str, object]
    ) -> GuestAccessRule:
        return await self.guest_rules.update(rule, data)

    async def commit(self) -> None:
        await self.session.commit()

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
        plus an ``expires_at IS NULL OR expires_at > now`` bound.

        ``identifier`` is matched against every spelling of the same phone
        number this table may hold, not by ``==``. Exact equality is what
        made every rule the customer dashboard ever wrote unmatchable in
        2026-09 -- those rows hold bare national digits ("9876543210")
        and guests sign in as E.164 ("+919876543210") -- and no migration
        can reconcile them without inventing a country code nobody
        recorded. ``validators.identifier_match_terms`` documents the
        equivalence, its bounds, and the false-match risk it accepts;
        ``validators.identifiers_match`` is the Python mirror of the
        clause built here.
        """
        scope_clause = GuestAccessRule.location_id.is_(None)
        if location_id is not None:
            scope_clause = or_(scope_clause, GuestAccessRule.location_id == location_id)
        terms = identifier_match_terms(identifier)
        identifier_clause = GuestAccessRule.identifier.in_(terms.exact)
        if terms.prefix_patterns:
            # The stored-value-is-longer direction (a rule written in
            # E.164, a guest signing in without the country code). No IN
            # list can enumerate it, so it is a bounded LIKE: "+" or
            # nothing, then 1-3 single-character wildcards, then the
            # digits themselves. No leading "%" -- the organization_id
            # equality above already confines the scan to one tenant's
            # rules, which is a handful of rows per venue.
            identifier_clause = or_(
                identifier_clause,
                *(
                    GuestAccessRule.identifier.like(pattern)
                    for pattern in terms.prefix_patterns
                ),
            )
        statement = select(GuestAccessRule).where(
            GuestAccessRule.organization_id == organization_id,
            identifier_clause,
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

    async def find_guest_rule_for_import(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        identifier: str,
        rule_type: str,
    ) -> GuestAccessRule | None:
        """See ``GuestAccessRepositoryProtocol.find_guest_rule_for_import``.

        ``location_id`` is compared with ``IS NULL`` when it is ``None``
        rather than ``= NULL`` (which is never true), so an organization-wide
        rule is correctly recognised as the duplicate of another
        organization-wide rule -- the case a hotel with one property hits on
        every single upload.

        ## Why this matches more than the exact identifier

        Every ``guest_access_rules`` row written before the 2026-09 fix is a
        bare national number ("9876543210") that matches no living guest;
        ``identifier_match_terms`` carries them at read time rather than
        migrating them, because filling in a country code needs a country
        nobody recorded. A bulk import is the one moment a human *does*
        supply it. If this lookup were exact, the first upload after that
        fix would file a second, canonical row beside every dead one --
        leaving the venue with two rows per guest, only one of which any
        future edit or deletion touches.

        So a stored bare spelling of the number being imported counts as
        the same rule, and the service rewrites it to E.164 (see
        ``GuestAccessService.import_guest_rules``). The nightly upload is
        the migration.

        ## Why it matches *less* than ``list_matching_guest_rules``

        Only spellings **without** a leading "+" are candidates. The read
        path also treats "+919876543210" and "+19876543210" as possibly the
        same person, and accepts that looseness because the alternative is
        every pre-fix rule dead. That trade does not carry over to a write:
        here a false match does not merely admit the wrong guest for one
        session, it *overwrites another real person's rule identifier* --
        a US "+19876543210" silently relabelled as an Indian number, with
        no record of what it used to be. A stored value that already has a
        "+" is already canonical and belongs to whoever it says it does, so
        it is never rewritten. Bare rows are the only ones that match
        nobody today and therefore the only ones there is nothing to lose
        by repairing.
        """
        scope_clause = (
            GuestAccessRule.location_id.is_(None)
            if location_id is None
            else GuestAccessRule.location_id == location_id
        )
        # ``.exact`` is the bounded set of spellings of this number (the
        # canonical one, plus it with 1-3 leading country-code digits
        # dropped, floored at MIN_NATIONAL_DIGITS). Reused rather than
        # re-derived so the importer cannot drift from the read path's
        # notion of "the same number"; filtered to the "+"-less half for
        # the reason in the docstring. For an email it is just the address.
        candidates = [
            spelling
            for spelling in identifier_match_terms(identifier).exact
            if not spelling.startswith("+")
        ]
        if identifier not in candidates:
            candidates.append(identifier)
        statement = (
            select(GuestAccessRule)
            .where(
                GuestAccessRule.organization_id == organization_id,
                GuestAccessRule.identifier.in_(candidates),
                GuestAccessRule.rule_type == rule_type,
                GuestAccessRule.is_deleted.is_(False),
                scope_clause,
            )
            # Canonical first, so a venue that somehow holds both spellings
            # updates the row that already works rather than resurrecting
            # the dead one and leaving the live one behind.
            .order_by(
                (GuestAccessRule.identifier == identifier).desc(),
                GuestAccessRule.created_at.asc(),
            )
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def list_all_guest_rules_for_organization(
        self, organization_id: uuid.UUID
    ) -> list[GuestAccessRule]:
        """See ``GuestAccessRepositoryProtocol
        .list_all_guest_rules_for_organization``."""
        statement = (
            select(GuestAccessRule)
            .where(
                GuestAccessRule.organization_id == organization_id,
                GuestAccessRule.is_deleted.is_(False),
            )
            .order_by(GuestAccessRule.created_at.asc())
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
