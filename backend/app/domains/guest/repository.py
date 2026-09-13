"""Data access layer for the Guest domain.

Mirrors ``app.domains.voucher.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``GuestRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``GuestRepository``) wrapping six ``GenericRepository``
instances (one per table), plus hand-written ``select``/aggregate
statements for the queries ``GenericRepository``'s equality/IN-filter
support genuinely can't express: explicit ``IS NULL``-adjacent lookups
(most-recent-session-by-guest), the per-row-varying timeout comparison, and
every ``GuestAnalyticsService`` aggregate (``func.count``/``func.sum``/
``func.avg``, ``GROUP BY``) -- the exact kind of query that needs to scale
and must never be a Python-side loop over fetched rows.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.models import Location
from app.domains.organization.models import Organization

from .constants import GuestSessionStatus
from .models import (
    Guest,
    GuestConsent,
    GuestDevice,
    GuestLoginHistory,
    GuestQuotaUsage,
    GuestSession,
    RadiusNasClient,
    RadiusNasCodeCounter,
)

# ============================================================================
# Analytics read-models (repository-layer return shapes -- service.py wraps
# these into its own public dataclasses)
# ============================================================================


@dataclass(frozen=True, slots=True)
class VoucherRedemptionRow:
    """One voucher's observed redemption -- its most recent
    ``GuestSession`` plus how many sessions that voucher has in total.
    See ``GuestRepository.list_voucher_redemptions`` for why "most
    recent, plus a count" rather than the whole list."""

    voucher_id: uuid.UUID
    session_count: int
    session_id: uuid.UUID
    guest_id: uuid.UUID
    device_mac: str | None
    ip_address: str | None
    started_at: datetime


@dataclass(frozen=True, slots=True)
class SessionAggregate:
    visitors: int
    unique_guests: int
    avg_duration_seconds: float | None
    total_bandwidth_bytes: int


@dataclass(frozen=True, slots=True)
class LocationSessionCount:
    location_id: uuid.UUID
    location_name: str
    session_count: int


@dataclass(frozen=True, slots=True)
class DeviceSessionCount:
    device_id: uuid.UUID
    mac_address: str
    session_count: int
    unique_guest_count: int


@dataclass(frozen=True, slots=True)
class AuthMethodOutcomeCounts:
    total_attempts: int
    successful_attempts: int


@dataclass(frozen=True, slots=True)
class ActiveGuestOrgPair:
    """One distinct ``(guest_id, organization_id, location_id)`` triple
    drawn from currently ``ACTIVE`` ``GuestSession`` rows -- see
    ``GuestRepository.list_active_guest_org_pairs``'s own docstring.

    ``location_id`` is the third member and the newest. Without it
    ``run_fup_time_accrual`` had no location to resolve with and passed
    ``location_id=None``, which meant a LOCATION-scoped FUP
    ``PolicyAssignment`` was never a resolution candidate for the sweep --
    see that function's own docstring for what that silently cost. The
    class keeps its name because "pair" is what every caller and test
    already says, and renaming it would churn more than it clarifies.
    """

    guest_id: uuid.UUID
    organization_id: uuid.UUID
    # Non-nullable on GuestSession, so always a real location -- but
    # defaulted here so the fakes and call sites that predate it keep
    # constructing, and so a caller that genuinely has no location (there
    # are none today) degrades to organization-scope resolution rather
    # than failing.
    location_id: uuid.UUID | None = None


@dataclass(frozen=True, slots=True)
class QuotaUsageWithOrgTimezone:
    """A ``GuestQuotaUsage`` row paired with its own organization's
    ``timezone`` -- see ``GuestRepository
    .list_all_quota_usages_with_org_timezone``'s own docstring."""

    usage: GuestQuotaUsage
    organization_timezone: str


class GuestRepositoryProtocol(Protocol):
    # -- guests ----------------------------------------------------------------
    async def create_guest(self, **fields: object) -> Guest: ...

    async def get_guest_by_id(
        self, guest_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Guest | None: ...

    async def get_guest_for_update(self, guest_id: uuid.UUID) -> Guest | None: ...

    async def get_guest_by_identifier(
        self, organization_id: uuid.UUID, identifier: str
    ) -> Guest | None: ...

    async def update_guest(self, guest: Guest, data: dict[str, object]) -> Guest: ...

    async def list_guests(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        search: str | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[Guest], PaginationMeta]: ...

    async def list_guests_by_ids(
        self,
        *,
        guest_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[Guest]: ...

    # -- devices -----------------------------------------------------------------
    async def create_device(self, **fields: object) -> GuestDevice: ...

    async def get_device_by_id(self, device_id: uuid.UUID) -> GuestDevice | None: ...

    async def get_device_by_mac(self, mac_address: str) -> GuestDevice | None: ...

    async def update_device(
        self, device: GuestDevice, data: dict[str, object]
    ) -> GuestDevice: ...

    async def count_devices_for_guest(self, guest_id: uuid.UUID) -> int: ...

    async def list_devices_by_ids(
        self,
        *,
        device_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[GuestDevice]: ...

    async def list_devices_for_guest_ids(
        self,
        *,
        guest_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[GuestDevice]: ...

    async def list_devices_for_session_ids(
        self,
        *,
        device_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[GuestDevice]: ...

    async def list_voucher_redemptions(
        self,
        *,
        voucher_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[VoucherRedemptionRow]: ...

    # -- sessions ------------------------------------------------------------------
    async def create_session(self, **fields: object) -> GuestSession: ...

    async def get_session_by_id(
        self, session_id: uuid.UUID, *, include_deleted: bool = False
    ) -> GuestSession | None: ...

    async def update_session(
        self, session: GuestSession, data: dict[str, object]
    ) -> GuestSession: ...

    async def list_sessions(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[GuestSession], PaginationMeta]: ...

    async def list_sessions_in_range(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        page: int,
        page_size: int,
    ) -> tuple[list[GuestSession], PaginationMeta]: ...

    async def list_sessions_for_guest(
        self, guest_id: uuid.UUID, *, limit: int | None = None
    ) -> list[GuestSession]: ...

    async def get_latest_session_for_guest(
        self, guest_id: uuid.UUID
    ) -> GuestSession | None: ...

    async def get_latest_terminated_session_for_guest(
        self, guest_id: uuid.UUID
    ) -> GuestSession | None: ...

    async def count_active_sessions_for_guest(self, guest_id: uuid.UUID) -> int: ...

    async def count_active_devices_for_guest(
        self, *, guest_id: uuid.UUID, exclude_device_id: uuid.UUID | None = None
    ) -> int: ...

    async def get_latest_ended_session_for_device(
        self,
        *,
        router_id: uuid.UUID,
        device_id: uuid.UUID,
        statuses: Sequence[str],
        ended_after: datetime,
    ) -> GuestSession | None: ...

    async def list_timed_out_sessions(self, *, now: datetime) -> list[GuestSession]: ...

    async def list_active_sessions_for_guest(
        self, guest_id: uuid.UUID
    ) -> list[GuestSession]: ...

    async def list_active_sessions_for_router(
        self, router_id: uuid.UUID
    ) -> list[GuestSession]: ...

    async def list_active_guest_org_pairs(self) -> list[ActiveGuestOrgPair]: ...

    # -- FUP quota usage ---------------------------------------------------------
    async def get_quota_usage(
        self, guest_id: uuid.UUID, period_type: str
    ) -> GuestQuotaUsage | None: ...

    async def get_quota_usages(
        self, guest_id: uuid.UUID, period_types: list[str]
    ) -> list[GuestQuotaUsage]: ...

    async def create_quota_usage(self, **fields: object) -> GuestQuotaUsage: ...

    async def update_quota_usage(
        self, usage: GuestQuotaUsage, data: dict[str, object]
    ) -> GuestQuotaUsage: ...

    async def list_all_quota_usages_with_org_timezone(
        self,
    ) -> list[QuotaUsageWithOrgTimezone]: ...

    async def get_organization_timezone(self, organization_id: uuid.UUID) -> str: ...

    # -- login history ---------------------------------------------------------
    async def create_login_history(self, **fields: object) -> GuestLoginHistory: ...

    # -- consents ----------------------------------------------------------------
    async def create_consent(self, **fields: object) -> GuestConsent: ...

    # -- RADIUS NAS clients --------------------------------------------------------
    async def create_nas_client(self, **fields: object) -> RadiusNasClient: ...

    async def get_nas_client_by_identifier(
        self, nas_identifier: str
    ) -> RadiusNasClient | None: ...

    async def get_nas_client_by_router(
        self, router_id: uuid.UUID
    ) -> RadiusNasClient | None: ...

    async def commit(self) -> None: ...

    async def get_nas_client_by_id(
        self, nas_id: uuid.UUID, *, include_deleted: bool = False
    ) -> RadiusNasClient | None: ...

    async def update_nas_client(
        self, nas_client: RadiusNasClient, data: dict[str, object]
    ) -> RadiusNasClient: ...

    async def soft_delete_nas_client(
        self, nas_client: RadiusNasClient
    ) -> RadiusNasClient: ...

    async def list_nas_clients(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[RadiusNasClient], PaginationMeta]: ...

    # -- analytics -----------------------------------------------------------------
    async def get_session_aggregate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> SessionAggregate: ...

    async def get_returning_guest_count(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int: ...

    async def get_top_locations(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[LocationSessionCount]: ...

    async def get_top_devices(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[DeviceSessionCount]: ...

    async def get_login_history_outcome_counts(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        auth_methods: Sequence[str],
    ) -> AuthMethodOutcomeCounts: ...

    async def get_session_auth_method_aggregate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        auth_method: str,
    ) -> SessionAggregate: ...

    async def list_login_history(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[GuestLoginHistory], PaginationMeta]: ...

    async def list_login_history_in_range(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        page: int,
        page_size: int,
    ) -> tuple[list[GuestLoginHistory], PaginationMeta]: ...


class GuestRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``GuestRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.guests = GenericRepository(Guest, session)
        self.devices = GenericRepository(GuestDevice, session)
        self.sessions = GenericRepository(GuestSession, session)
        self.login_history = GenericRepository(GuestLoginHistory, session)
        self.consents = GenericRepository(GuestConsent, session)
        self.nas_clients = GenericRepository(RadiusNasClient, session)
        self.quota_usages = GenericRepository(GuestQuotaUsage, session)

    async def commit(self) -> None:
        """Commits the current transaction.

        Needed by the RADIUS NAS device-push path and nothing else.
        ``GenericRepository.update`` only ``flush()``es and
        ``get_db_session`` rolls the session back on any exception, so a
        ``failed`` record written just before the re-raise would be
        discarded -- leaving a row that still reads as though the push had
        reached the router. Mirrors
        ``app.domains.guest_access.repository``'s own identical method and
        the reasoning on it.
        """
        await self.session.commit()

    # -- guests ----------------------------------------------------------------

    async def create_guest(self, **fields: object) -> Guest:
        return await self.guests.create(fields)

    async def get_guest_by_id(
        self, guest_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Guest | None:
        return await self.guests.get_by_id(guest_id, include_deleted=include_deleted)

    async def get_guest_for_update(self, guest_id: uuid.UUID) -> Guest | None:
        """Real row-level lock (``SELECT ... FOR UPDATE``) on this single
        ``Guest`` row -- used by ``GuestService._reuse_or_create_session``
        immediately before its read-then-insert of an ``ACTIVE``
        ``GuestSession`` for this guest. Two concurrent logins for the
        same guest can otherwise both observe "no reusable ACTIVE session"
        and both insert a duplicate ``ACTIVE`` row (the production
        double-submit incident documented at ``_find_reusable_active_session``);
        ``with_for_update()`` makes the second transaction to reach this
        guest block until the first commits, then run its reuse check
        against the first transaction's *committed* session -- real
        serialization of the find-then-insert, not a fixed sleep/retry
        guess. Mirrors ``IspRepository.get_link_for_update``'s identical
        pattern and reasoning. ``populate_existing=True`` guards the
        (same-session) case where this guest was already loaded earlier in
        the same request, so this always reflects the row's current
        committed values rather than a stale identity-mapped object."""
        statement = (
            select(Guest)
            .where(Guest.id == guest_id, Guest.is_deleted.is_(False))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def get_guest_by_identifier(
        self, organization_id: uuid.UUID, identifier: str
    ) -> Guest | None:
        results = await self.guests.get_all(
            filters={"organization_id": organization_id, "identifier": identifier},
            limit=1,
        )
        return results[0] if results else None

    async def update_guest(self, guest: Guest, data: dict[str, object]) -> Guest:
        return await self.guests.update(guest, data)

    async def list_guests(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        search: str | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[Guest], PaginationMeta]:
        if search:
            # GenericRepository.search has no pagination-meta return shape,
            # so a search query is a best-effort, capped list rather than a
            # paginated one -- acceptable for an admin free-text lookup.
            items = await self.guests.search(
                query=search,
                fields=["identifier", "display_name"],
                filters=filters,
                sort_by=sort_by,
                sort_order=sort_order,
                limit=page_size,
            )
            return items, PaginationMeta.from_total(
                PageParams(page=page, page_size=page_size), len(items)
            )
        return await self.guests.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_guests_by_ids(
        self,
        *,
        guest_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[Guest]:
        """Bulk-resolve ``guest_ids`` (e.g. a page of ``GuestSession
        .guest_id`` values) to their :class:`~.models.Guest` rows in one
        query -- the identity sibling of ``list_devices_by_ids`` below, and
        the whole anti-N+1 story for ``GuestSessionResponse
        .guest_identifier``: one extra query per page, never one per row.

        Unlike a device, a ``Guest`` carries its own ``organization_id``
        column, so tenant scoping for an organization-scoped caller is a
        plain ``WHERE`` clause with no join. A platform-level caller
        (``organization_id is None``, the same convention every other method
        in this repository uses) deliberately skips the tenant filter."""
        if not guest_ids:
            return []
        conditions = [
            Guest.id.in_(guest_ids),
            Guest.is_deleted.is_(False),
        ]
        if organization_id is not None:
            conditions.append(Guest.organization_id == organization_id)
        result = await self.session.execute(select(Guest).where(*conditions))
        return list(result.scalars().all())

    # -- devices -----------------------------------------------------------------

    async def create_device(self, **fields: object) -> GuestDevice:
        return await self.devices.create(fields)

    async def get_device_by_id(self, device_id: uuid.UUID) -> GuestDevice | None:
        return await self.devices.get_by_id(device_id)

    async def get_device_by_mac(self, mac_address: str) -> GuestDevice | None:
        results = await self.devices.get_all(
            filters={"mac_address": mac_address}, limit=1
        )
        return results[0] if results else None

    async def update_device(
        self, device: GuestDevice, data: dict[str, object]
    ) -> GuestDevice:
        return await self.devices.update(device, data)

    async def count_devices_for_guest(self, guest_id: uuid.UUID) -> int:
        """Guest Session Engine (Phase 1): how many distinct
        :class:`~.models.GuestDevice` rows currently belong to
        ``guest_id`` -- backs ``GuestService._enforce_device_limit``. A
        plain equality-filtered count, mirroring
        ``count_active_sessions_for_guest``'s identical shape."""
        return await self.devices.count(filters={"guest_id": guest_id})

    async def list_devices_by_ids(
        self,
        *,
        device_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[GuestDevice]:
        """Bulk-resolve ``device_ids`` (e.g. a page of ``GuestSession
        .device_id`` values) to their :class:`~.models.GuestDevice` rows in
        one query -- see ``constants.MAX_BULK_DEVICE_LOOKUP_IDS``'s own
        docstring for why this exists. ``GuestDevice`` carries no
        ``organization_id`` of its own (see ``models.GuestDevice``'s
        docstring: a device is owned by a ``Guest``, reassignable across
        guests), so tenant scoping for an organization-scoped caller
        requires an explicit join through ``Guest`` -- exactly the same
        "``GenericRepository`` can't express this" precedent
        ``list_sessions_in_range`` above already established for its own
        domain. A platform-level caller (``organization_id is None``, the
        same convention every other method in this repository uses)
        deliberately skips the join and the tenant filter."""
        if not device_ids:
            return []
        conditions = [
            GuestDevice.id.in_(device_ids),
            GuestDevice.is_deleted.is_(False),
        ]
        if organization_id is not None:
            statement = (
                select(GuestDevice)
                .join(Guest, Guest.id == GuestDevice.guest_id)
                .where(*conditions, Guest.organization_id == organization_id)
            )
        else:
            statement = select(GuestDevice).where(*conditions)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_devices_for_guest_ids(
        self,
        *,
        guest_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[GuestDevice]:
        """Bulk-resolve every :class:`~.models.GuestDevice` belonging to
        ``guest_ids`` (e.g. one page of ``GET /guests``) in a single query,
        newest-seen device first.

        The sibling of ``list_devices_by_ids`` above, keyed the other way
        round. ``GET /guests`` needs this one because ``Guest`` carries no
        ``device_id`` to key a by-id lookup off at all -- a guest *has*
        devices, it is not *on* one -- so the existing bulk-by-device-id
        endpoint cannot serve the Users screen no matter how it is called.

        Ordered ``last_seen_at DESC`` in SQL, not in Python, so the caller
        can take "the guest's current device" off the front of each group
        without re-sorting; ``id`` breaks the tie so the order is total and
        stable across pages rather than arbitrary between two devices
        sharing a timestamp.

        Tenant scoping joins through ``Guest`` for exactly the reason
        ``list_devices_by_ids`` documents: ``GuestDevice`` has no
        ``organization_id`` column of its own. A platform-level caller
        (``organization_id is None``) skips the join, the same convention
        every other method here uses."""
        if not guest_ids:
            return []
        conditions = [
            GuestDevice.guest_id.in_(guest_ids),
            GuestDevice.is_deleted.is_(False),
        ]
        if organization_id is not None:
            statement = (
                select(GuestDevice)
                .join(Guest, Guest.id == GuestDevice.guest_id)
                .where(*conditions, Guest.organization_id == organization_id)
            )
        else:
            statement = select(GuestDevice).where(*conditions)
        statement = statement.order_by(
            GuestDevice.last_seen_at.desc(), GuestDevice.id.desc()
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_devices_for_session_ids(
        self,
        *,
        device_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[GuestDevice]:
        """Resolve device ids taken from sessions the caller can already
        see -- backs ``GuestSessionResponse.device_mac``.

        ## Why this is not ``list_devices_by_ids``

        That method scopes by the device's **current owner**
        (``Guest.organization_id``), which is the right question for ``GET
        /guest-devices``, where the caller names devices directly. It is
        the wrong question here, because a ``GuestDevice`` is reassignable:
        ``mac_address`` is globally unique and ``get_or_create_device``
        re-points ``guest_id`` with no organization check, by design (see
        ``models.py``'s "MAC address uniqueness" write-up). So one physical
        phone carried between two venues on different organizations ends up
        with its single device row owned by whichever guest authenticated
        most recently.

        Scoping by current owner then makes org A's *own* session lose its
        MAC the moment that guest visits org B -- the field goes blank on
        exactly the screens this exists to fix, reproducing the "empty cell
        that reads as missing data" symptom that was reported in the first
        place.

        This asks the question that actually authorises the value: was this
        device used by a session **in the caller's organization**? If yes,
        that organization observed the device on its own network and is
        entitled to the address, regardless of who the device row currently
        points at. The caller reached these ids through an
        already-tenant-filtered session list, so this re-derives the same
        authorisation from the session table rather than trusting the ids
        blindly -- a bug upstream still cannot leak another org's MAC.

        ``DISTINCT`` because a device has many sessions and the join would
        otherwise return one row per session. ``GET /guest-devices``'s own
        behaviour is deliberately left unchanged; retiring or re-scoping a
        published endpoint is a separate decision."""
        if not device_ids:
            return []
        conditions = [
            GuestDevice.id.in_(device_ids),
            GuestDevice.is_deleted.is_(False),
        ]
        if organization_id is not None:
            statement = (
                select(GuestDevice)
                .join(GuestSession, GuestSession.device_id == GuestDevice.id)
                .where(
                    *conditions,
                    GuestSession.is_deleted.is_(False),
                    GuestSession.organization_id == organization_id,
                )
                .distinct()
            )
        else:
            statement = select(GuestDevice).where(*conditions)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_voucher_redemptions(
        self,
        *,
        voucher_ids: Sequence[uuid.UUID],
        organization_id: uuid.UUID | None,
    ) -> list[VoucherRedemptionRow]:
        """Resolve ``voucher_ids`` to the device and address each was
        actually redeemed on, in one query -- backs ``GET
        /voucher-redemptions`` for the Vouchers screen.

        ``guest_sessions.voucher_id`` is the only link between a voucher
        and a device that exists: ``app.domains.voucher.models.Voucher``
        stores a self-reported ``redeemed_identifier`` string and
        deliberately no FK (see that model's own docstring). The join is
        therefore two hops -- session by ``voucher_id``, then device by
        ``session.device_id`` -- and it lives here because the guest
        domain owns both tables.

        A voucher may be multi-use (``VoucherBatch.max_uses_per_voucher``),
        so this returns the **most recent** session per voucher plus a
        total ``session_count``, not every session. Returning every
        session would make the result unbounded in the one dimension the
        caller cannot predict, and the Vouchers screen needs a single
        cell; a caller wanting the full history has ``GET
        /guest-sessions?voucher_id=...`` already. ``session_count`` is
        what stops the UI presenting one device as *the* redeemer when
        there were several.

        Both the pick and the count are window functions over a single
        scan rather than a per-voucher subquery, so this stays one round
        trip regardless of how many vouchers are asked for.

        The device join is a LEFT join: a session that carried no
        ``device_id`` (a login that presented no MAC) still yields a row,
        with ``device_mac`` ``None`` and its IP intact -- dropping the
        row entirely would make a real redemption look like it never
        happened.

        Tenant scoping filters ``GuestSession.organization_id``
        directly -- unlike ``GuestDevice``, a session carries its own
        organization column, so no join through ``Guest`` is needed. A
        platform-level caller (``organization_id is None``) skips the
        filter, the same convention used throughout this repository."""
        if not voucher_ids:
            return []
        conditions = [
            GuestSession.voucher_id.in_(voucher_ids),
            GuestSession.is_deleted.is_(False),
        ]
        if organization_id is not None:
            conditions.append(GuestSession.organization_id == organization_id)
        ranked = (
            select(
                GuestSession.voucher_id.label("voucher_id"),
                GuestSession.id.label("session_id"),
                GuestSession.guest_id.label("guest_id"),
                GuestSession.ip_address.label("ip_address"),
                GuestSession.started_at.label("started_at"),
                GuestDevice.mac_address.label("device_mac"),
                func.row_number()
                .over(
                    partition_by=GuestSession.voucher_id,
                    order_by=(GuestSession.started_at.desc(), GuestSession.id.desc()),
                )
                .label("rank"),
                func.count()
                .over(partition_by=GuestSession.voucher_id)
                .label("session_count"),
            )
            .select_from(GuestSession)
            .join(
                GuestDevice,
                (GuestDevice.id == GuestSession.device_id)
                & (GuestDevice.is_deleted.is_(False)),
                isouter=True,
            )
            .where(*conditions)
            .subquery()
        )
        statement = select(ranked).where(ranked.c.rank == 1)
        result = await self.session.execute(statement)
        return [
            VoucherRedemptionRow(
                voucher_id=row.voucher_id,
                session_count=row.session_count,
                session_id=row.session_id,
                guest_id=row.guest_id,
                device_mac=row.device_mac,
                ip_address=row.ip_address,
                started_at=row.started_at,
            )
            for row in result
        ]

    # -- sessions ------------------------------------------------------------------

    async def create_session(self, **fields: object) -> GuestSession:
        return await self.sessions.create(fields)

    async def get_session_by_id(
        self, session_id: uuid.UUID, *, include_deleted: bool = False
    ) -> GuestSession | None:
        return await self.sessions.get_by_id(
            session_id, include_deleted=include_deleted
        )

    async def update_session(
        self, session: GuestSession, data: dict[str, object]
    ) -> GuestSession:
        return await self.sessions.update(session, data)

    async def list_sessions(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[GuestSession], PaginationMeta]:
        return await self.sessions.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_sessions_in_range(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        page: int,
        page_size: int,
    ) -> tuple[list[GuestSession], PaginationMeta]:
        """Real server-side ``[start, end)`` filtering on ``started_at`` --
        ``list_sessions``/``GenericRepository.paginate`` above can't express
        a range (``apply_filters`` only ever emits ``column == value``/
        ``column.in_(...)``, see ``app.database.utils.filters
        .apply_filters``), which previously forced callers needing a real
        date-bounded session listing (``cloudguest-foundation``'s Bandwidth
        & Cost / Bandwidth by Location reports) to over-fetch the most
        recent N sessions and filter client-side -- silently truncating any
        older-but-in-range day once a location's session volume exceeded
        that client-side page cap. A hand-written statement instead, the
        same "``GenericRepository`` can't express this" precedent
        ``app.domains.voucher.repository.VoucherRepository
        .list_redeemed_vouchers`` already established for its own
        domain."""
        conditions = [
            GuestSession.organization_id == organization_id,
            GuestSession.started_at >= start,
            GuestSession.started_at < end,
            GuestSession.is_deleted.is_(False),
        ]
        if location_id is not None:
            conditions.append(GuestSession.location_id == location_id)

        count_statement = (
            select(func.count()).select_from(GuestSession).where(*conditions)
        )
        total_items = int((await self.session.execute(count_statement)).scalar_one())

        statement = (
            select(GuestSession)
            .where(*conditions)
            .order_by(GuestSession.started_at.desc(), GuestSession.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        result = await self.session.execute(statement)
        rows = list(result.scalars().all())
        params = PageParams(page=page, page_size=page_size)
        meta = PaginationMeta.from_total(params, total_items)
        return rows, meta

    async def list_sessions_for_guest(
        self, guest_id: uuid.UUID, *, limit: int | None = None
    ) -> list[GuestSession]:
        return await self.sessions.get_all(
            filters={"guest_id": guest_id},
            sort_by="started_at",
            sort_order=SortOrder.DESC,
            limit=limit,
        )

    async def get_latest_session_for_guest(
        self, guest_id: uuid.UUID
    ) -> GuestSession | None:
        results = await self.list_sessions_for_guest(guest_id, limit=1)
        return results[0] if results else None

    async def get_latest_terminated_session_for_guest(
        self, guest_id: uuid.UUID
    ) -> GuestSession | None:
        statement = (
            select(GuestSession)
            .where(
                GuestSession.guest_id == guest_id,
                GuestSession.status == GuestSessionStatus.TERMINATED.value,
                GuestSession.is_deleted.is_(False),
            )
            .order_by(GuestSession.ended_at.desc())
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def count_active_sessions_for_guest(self, guest_id: uuid.UUID) -> int:
        """Guest Session Engine (Phase 1): how many ``ACTIVE`` sessions
        ``guest_id`` currently holds -- backs
        ``GuestService._enforce_concurrent_session_limit``. A plain
        equality-filtered count ``GenericRepository.count`` already
        supports natively; no hand-written SQL needed, unlike
        ``get_batch_status_counts``'s grouped-count shape in
        ``app.domains.voucher.repository`` (that one needs a `GROUP BY`
        this single-status count does not)."""
        return await self.sessions.count(
            filters={
                "guest_id": guest_id,
                "status": GuestSessionStatus.ACTIVE.value,
            }
        )

    async def count_active_devices_for_guest(
        self, *, guest_id: uuid.UUID, exclude_device_id: uuid.UUID | None = None
    ) -> int:
        """Guest Session Engine (Phase 1): how many **distinct** devices
        ``guest_id`` currently has ``ACTIVE`` sessions on -- backs
        ``GuestService._enforce_device_limit``'s "connected devices, not
        registered devices" basis. ``GenericRepository`` can only express
        equality-filtered counts, never a ``COUNT(DISTINCT column)`` (its
        grouped-count precedent is ``app.domains.voucher.repository``'s
        ``get_batch_status_counts``), so this is hand-written: distinct
        non-null ``device_id`` among the guest's ACTIVE sessions,
        optionally excluding one device id -- the device currently logging
        in, so a reconnect/refresh of an already-online device never counts
        against itself."""
        query = (
            select(func.count(func.distinct(GuestSession.device_id)))
            .where(
                GuestSession.guest_id == guest_id,
                GuestSession.status == GuestSessionStatus.ACTIVE.value,
                GuestSession.device_id.is_not(None),
                GuestSession.is_deleted.is_(False),
            )
        )
        if exclude_device_id is not None:
            query = query.where(GuestSession.device_id != exclude_device_id)
        result = await self.session.execute(query)
        return int(result.scalar_one())

    async def get_latest_ended_session_for_device(
        self,
        *,
        router_id: uuid.UUID,
        device_id: uuid.UUID,
        statuses: Sequence[str],
        ended_after: datetime,
    ) -> GuestSession | None:
        """The most recently ended session this device held on this
        router, provided it ended after ``ended_after`` and in one of
        ``statuses`` -- backs the captive portal's "you were
        disconnected" screen via
        ``service.GuestService.get_last_ended_session_for_device``.

        Hand-written for the same reason ``list_sessions_in_range`` above
        is: ``GenericRepository.paginate``'s ``apply_filters`` only emits
        ``column == value`` / ``column.in_(...)`` and cannot express the
        ``ended_at >= ended_after`` bound. That bound is not a
        convenience -- it is the privacy boundary. Doing the window in
        Python after fetching the newest row would mean the database
        happily returning a months-old session to anyone holding the MAC,
        and one refactor later somebody returns it. Here it cannot be
        skipped by accident.

        ``statuses`` is passed in rather than hardcoded so the caller --
        which is the thing that has actually reasoned about which
        lifecycle states a guest may be told about -- stays the single
        place that decision lives.

        Ordered by ``ended_at`` (never ``started_at``): sessions are
        append-only history and a device that reconnected several times
        can hold rows whose start and end orders differ. The question
        here is only ever "what ended most recently".
        """
        if not statuses:
            return None
        statement = (
            select(GuestSession)
            .where(
                GuestSession.router_id == router_id,
                GuestSession.device_id == device_id,
                GuestSession.status.in_(list(statuses)),
                GuestSession.ended_at.isnot(None),
                GuestSession.ended_at >= ended_after,
                GuestSession.is_deleted.is_(False),
            )
            .order_by(GuestSession.ended_at.desc(), GuestSession.id)
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def list_timed_out_sessions(self, *, now: datetime) -> list[GuestSession]:
        """Active sessions whose ``last_activity_at`` plus their own
        ``session_timeout_minutes`` has already passed ``now`` -- a
        per-row-varying comparison ``GenericRepository``'s equality-filter
        support cannot express, hence hand-written here. Uses Postgres's
        ``make_interval`` so the comparison happens entirely server-side
        (real SQL, not a Python-side scan) regardless of how many active
        sessions exist."""
        statement = select(GuestSession).where(
            GuestSession.status == GuestSessionStatus.ACTIVE.value,
            GuestSession.session_timeout_minutes.isnot(None),
            GuestSession.is_deleted.is_(False),
            GuestSession.last_activity_at
            + func.make_interval(0, 0, 0, 0, 0, GuestSession.session_timeout_minutes)
            < now,
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_active_sessions_for_guest(
        self, guest_id: uuid.UUID
    ) -> list[GuestSession]:
        """Every currently ``ACTIVE`` session for ``guest_id`` -- backs
        ``tasks.run_fup_time_accrual_sweep``'s "disconnect every active
        session" step once a guest's cumulative time usage has just
        crossed a configured FUP limit."""
        return await self.sessions.get_all(
            filters={"guest_id": guest_id, "status": GuestSessionStatus.ACTIVE.value}
        )

    async def list_active_sessions_for_router(
        self, router_id: uuid.UUID
    ) -> list[GuestSession]:
        """Every currently ``ACTIVE`` session tied to ``router_id`` -- backs
        ``service.close_sessions_for_nas_restart``'s "close every session
        this platform still thinks is live against a NAS that just told us
        it rebooted" step (RADIUS Accounting-On, RFC 2866 §5.13). Mirrors
        ``list_active_sessions_for_guest``'s identical equality-filter
        shape, just scoped by router instead of guest."""
        return await self.sessions.get_all(
            filters={"router_id": router_id, "status": GuestSessionStatus.ACTIVE.value}
        )

    async def list_active_guest_org_pairs(self) -> list[ActiveGuestOrgPair]:
        """Every distinct ``(guest_id, organization_id, location_id)``
        triple with at least one currently ``ACTIVE`` session -- backs
        ``tasks.run_fup_time_accrual_sweep``'s per-guest sweep loop.
        ``organization_id`` and ``location_id`` both come straight off
        ``GuestSession`` itself (see that model's own denormalization
        docstring) -- no join through ``guests`` needed at all.

        ``location_id`` joined the projection so the sweep can resolve a
        LOCATION-scoped FUP policy; before that it resolved with
        ``location_id=None`` and could not see one. Adding it to the
        ``DISTINCT`` can return more than one row for the same guest -- one
        per location they hold an active session at, which is rare but
        real (a guest on two sites of the same organization). That is
        handled in ``run_fup_time_accrual``, which groups the rows back
        together per guest so a guest's minutes are still accrued exactly
        once; see its docstring for why time, unlike bytes, must never be
        summed across concurrent sessions."""
        statement = (
            select(
                GuestSession.guest_id,
                GuestSession.organization_id,
                GuestSession.location_id,
            )
            .where(
                GuestSession.status == GuestSessionStatus.ACTIVE.value,
                GuestSession.is_deleted.is_(False),
            )
            .distinct()
        )
        result = await self.session.execute(statement)
        return [
            ActiveGuestOrgPair(
                guest_id=row[0], organization_id=row[1], location_id=row[2]
            )
            for row in result.all()
        ]

    # -- FUP quota usage ---------------------------------------------------------

    async def get_quota_usage(
        self, guest_id: uuid.UUID, period_type: str
    ) -> GuestQuotaUsage | None:
        results = await self.quota_usages.get_all(
            filters={"guest_id": guest_id, "period_type": period_type}, limit=1
        )
        return results[0] if results else None

    async def get_quota_usages(
        self, guest_id: uuid.UUID, period_types: list[str]
    ) -> list[GuestQuotaUsage]:
        """Every quota row this guest has for the named periods, in one
        ``IN (...)`` query.

        Design spec §5 S9: ``GuestService._enforce_fup_quota`` runs on the
        guest-login request path and needs all three periods
        (daily/weekly/monthly) every time. Fetching them one at a time was
        three round trips against the same table, for the same guest, to
        answer one question."""
        if not period_types:
            return []
        statement = select(GuestQuotaUsage).where(
            GuestQuotaUsage.guest_id == guest_id,
            GuestQuotaUsage.period_type.in_(period_types),
            GuestQuotaUsage.is_deleted.is_(False),
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def create_quota_usage(self, **fields: object) -> GuestQuotaUsage:
        return await self.quota_usages.create(fields)

    async def update_quota_usage(
        self, usage: GuestQuotaUsage, data: dict[str, object]
    ) -> GuestQuotaUsage:
        return await self.quota_usages.update(usage, data)

    async def list_all_quota_usages_with_org_timezone(
        self,
    ) -> list[QuotaUsageWithOrgTimezone]:
        """Every non-deleted ``GuestQuotaUsage`` row, paired with its own
        organization's ``timezone`` in a single joined query -- backs
        ``tasks.run_quota_reset_sweep``'s proactive rollover walk, avoiding
        an N+1 organization lookup per row."""
        statement = select(GuestQuotaUsage, Organization.timezone).join(
            Organization, Organization.id == GuestQuotaUsage.organization_id
        )
        result = await self.session.execute(statement)
        return [
            QuotaUsageWithOrgTimezone(usage=row[0], organization_timezone=row[1])
            for row in result.all()
        ]

    async def get_organization_timezone(self, organization_id: uuid.UUID) -> str:
        """A single-column read of ``Organization.timezone`` -- used by the
        two request-triggered FUP call sites (login-time enforcement,
        ``record_usage``'s per-accounting-call bump) that only have an
        ``organization_id`` on hand, not a joined row. Falls back to
        ``"UTC"`` if the organization row is somehow missing (defensive;
        every caller's ``organization_id`` was already resolved via a real
        FK earlier in the same request) -- mirrors
        ``Organization.timezone``'s own ``default="UTC"``."""
        statement = select(Organization.timezone).where(
            Organization.id == organization_id
        )
        result = await self.session.execute(statement)
        timezone = result.scalar_one_or_none()
        return timezone or "UTC"

    # -- login history ---------------------------------------------------------

    async def create_login_history(self, **fields: object) -> GuestLoginHistory:
        return await self.login_history.create(fields)

    # -- consents ----------------------------------------------------------------

    async def create_consent(self, **fields: object) -> GuestConsent:
        return await self.consents.create(fields)

    # -- RADIUS NAS clients --------------------------------------------------------

    async def create_nas_client(self, **fields: object) -> RadiusNasClient:
        return await self.nas_clients.create(fields)

    async def get_nas_client_by_identifier(
        self, nas_identifier: str
    ) -> RadiusNasClient | None:
        results = await self.nas_clients.get_all(
            filters={"nas_identifier": nas_identifier}, limit=1
        )
        return results[0] if results else None

    async def get_nas_client_by_router(
        self, router_id: uuid.UUID
    ) -> RadiusNasClient | None:
        results = await self.nas_clients.get_all(
            filters={"router_id": router_id}, limit=1
        )
        return results[0] if results else None

    async def get_nas_client_by_id(
        self, nas_id: uuid.UUID, *, include_deleted: bool = False
    ) -> RadiusNasClient | None:
        return await self.nas_clients.get_by_id(nas_id, include_deleted=include_deleted)

    async def update_nas_client(
        self, nas_client: RadiusNasClient, data: dict[str, object]
    ) -> RadiusNasClient:
        return await self.nas_clients.update(nas_client, data)

    async def soft_delete_nas_client(
        self, nas_client: RadiusNasClient
    ) -> RadiusNasClient:
        """GenericRepository.update() deliberately refuses to set
        is_deleted/deleted_at (see its `protected` fields) -- only this
        dedicated soft_delete() path actually flips them."""
        return await self.nas_clients.soft_delete(nas_client)

    async def list_nas_clients(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[RadiusNasClient], PaginationMeta]:
        return await self.nas_clients.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    # -- analytics -----------------------------------------------------------------

    def _session_scope_clause(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[object]:
        clauses: list[object] = [
            GuestSession.organization_id == organization_id,
            GuestSession.started_at >= start,
            GuestSession.started_at <= end,
            GuestSession.is_deleted.is_(False),
        ]
        if location_id is not None:
            clauses.append(GuestSession.location_id == location_id)
        return clauses

    async def get_session_aggregate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> SessionAggregate:
        duration_seconds = func.extract(
            "epoch",
            func.coalesce(GuestSession.ended_at, func.now()) - GuestSession.started_at,
        )
        statement = select(
            func.count(GuestSession.id),
            func.count(func.distinct(GuestSession.guest_id)),
            func.avg(duration_seconds),
            func.coalesce(
                func.sum(GuestSession.bytes_uploaded + GuestSession.bytes_downloaded),
                0,
            ),
        ).where(
            *self._session_scope_clause(
                organization_id=organization_id,
                location_id=location_id,
                start=start,
                end=end,
            )
        )
        result = await self.session.execute(statement)
        visitors, unique_guests, avg_duration, total_bandwidth = result.one()
        return SessionAggregate(
            visitors=int(visitors or 0),
            unique_guests=int(unique_guests or 0),
            avg_duration_seconds=float(avg_duration)
            if avg_duration is not None
            else None,
            total_bandwidth_bytes=int(total_bandwidth or 0),
        )

    async def get_returning_guest_count(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int:
        statement = (
            select(func.count(func.distinct(GuestSession.guest_id)))
            .select_from(GuestSession)
            .join(Guest, Guest.id == GuestSession.guest_id)
            .where(
                *self._session_scope_clause(
                    organization_id=organization_id,
                    location_id=location_id,
                    start=start,
                    end=end,
                ),
                Guest.total_visit_count > 1,
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one() or 0)

    async def get_top_locations(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[LocationSessionCount]:
        statement = (
            select(
                GuestSession.location_id,
                Location.name,
                func.count(GuestSession.id).label("session_count"),
            )
            .select_from(GuestSession)
            .join(Location, Location.id == GuestSession.location_id)
            .where(
                *self._session_scope_clause(
                    organization_id=organization_id,
                    location_id=None,
                    start=start,
                    end=end,
                )
            )
            .group_by(GuestSession.location_id, Location.name)
            .order_by(func.count(GuestSession.id).desc())
            .limit(limit)
        )
        result = await self.session.execute(statement)
        return [
            LocationSessionCount(
                location_id=location_id, location_name=name, session_count=int(count)
            )
            for location_id, name, count in result.all()
        ]

    async def get_top_devices(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[DeviceSessionCount]:
        statement = (
            select(
                GuestSession.device_id,
                GuestDevice.mac_address,
                func.count(GuestSession.id).label("session_count"),
                func.count(func.distinct(GuestSession.guest_id)).label(
                    "unique_guest_count"
                ),
            )
            .select_from(GuestSession)
            .join(GuestDevice, GuestDevice.id == GuestSession.device_id)
            .where(
                *self._session_scope_clause(
                    organization_id=organization_id,
                    location_id=None,
                    start=start,
                    end=end,
                ),
                GuestSession.device_id.isnot(None),
            )
            .group_by(GuestSession.device_id, GuestDevice.mac_address)
            .order_by(func.count(GuestSession.id).desc())
            .limit(limit)
        )
        result = await self.session.execute(statement)
        return [
            DeviceSessionCount(
                device_id=row.device_id,
                mac_address=row.mac_address,
                session_count=int(row.session_count),
                unique_guest_count=int(row.unique_guest_count),
            )
            for row in result.all()
        ]

    async def get_login_history_outcome_counts(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        auth_methods: Sequence[str],
    ) -> AuthMethodOutcomeCounts:
        clauses: list[object] = [
            GuestLoginHistory.organization_id == organization_id,
            GuestLoginHistory.attempted_at >= start,
            GuestLoginHistory.attempted_at <= end,
            GuestLoginHistory.auth_method.in_(list(auth_methods)),
            GuestLoginHistory.is_deleted.is_(False),
        ]
        if location_id is not None:
            clauses.append(GuestLoginHistory.location_id == location_id)
        statement = select(
            func.count(GuestLoginHistory.id),
            func.count(GuestLoginHistory.id).filter(
                GuestLoginHistory.success.is_(True)
            ),
        ).where(*clauses)
        result = await self.session.execute(statement)
        total, successful = result.one()
        return AuthMethodOutcomeCounts(
            total_attempts=int(total or 0), successful_attempts=int(successful or 0)
        )

    async def list_login_history(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[GuestLoginHistory], PaginationMeta]:
        """Real, paginated ``GuestLoginHistory`` read -- the tenant-scoped
        read source ``app.domains.controller_logs`` composes for its own
        "Authentication Logs" (guest side) category. Unlike
        ``app.domains.auth.LoginAttempt``, this table already carries
        ``organization_id``/``location_id``, so it is genuinely
        tenant-filterable."""
        filters: dict[str, object] = {}
        if organization_id is not None:
            filters["organization_id"] = organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        if guest_id is not None:
            filters["guest_id"] = guest_id
        return await self.login_history.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by="attempted_at",
            sort_order=SortOrder.DESC,
        )

    async def list_login_history_in_range(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        page: int,
        page_size: int,
    ) -> tuple[list[GuestLoginHistory], PaginationMeta]:
        """Real, server-side ``[start, end)`` filtering on ``attempted_at``
        for the Login/Access Attempt Log report -- mirrors
        ``list_sessions_in_range``'s identical "``GenericRepository`` can't
        express a range" reasoning, applied to ``GuestLoginHistory``
        instead of ``GuestSession``."""
        conditions = [
            GuestLoginHistory.organization_id == organization_id,
            GuestLoginHistory.attempted_at >= start,
            GuestLoginHistory.attempted_at < end,
            GuestLoginHistory.is_deleted.is_(False),
        ]
        if location_id is not None:
            conditions.append(GuestLoginHistory.location_id == location_id)

        count_statement = (
            select(func.count()).select_from(GuestLoginHistory).where(*conditions)
        )
        total_items = int((await self.session.execute(count_statement)).scalar_one())

        statement = (
            select(GuestLoginHistory)
            .where(*conditions)
            .order_by(GuestLoginHistory.attempted_at.desc(), GuestLoginHistory.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        result = await self.session.execute(statement)
        rows = list(result.scalars().all())
        params = PageParams(page=page, page_size=page_size)
        meta = PaginationMeta.from_total(params, total_items)
        return rows, meta

    async def get_session_auth_method_aggregate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        auth_method: str,
    ) -> SessionAggregate:
        duration_seconds = func.extract(
            "epoch",
            func.coalesce(GuestSession.ended_at, func.now()) - GuestSession.started_at,
        )
        statement = select(
            func.count(GuestSession.id),
            func.count(func.distinct(GuestSession.guest_id)),
            func.avg(duration_seconds),
            func.coalesce(
                func.sum(GuestSession.bytes_uploaded + GuestSession.bytes_downloaded),
                0,
            ),
        ).where(
            *self._session_scope_clause(
                organization_id=organization_id,
                location_id=location_id,
                start=start,
                end=end,
            ),
            GuestSession.auth_method == auth_method,
        )
        result = await self.session.execute(statement)
        visitors, unique_guests, avg_duration, total_bandwidth = result.one()
        return SessionAggregate(
            visitors=int(visitors or 0),
            unique_guests=int(unique_guests or 0),
            avg_duration_seconds=float(avg_duration)
            if avg_duration is not None
            else None,
            total_bandwidth_bytes=int(total_bandwidth or 0),
        )


class RadiusNasCodeCounterRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``nas_number_generator.NasCodeCounterRepositoryProtocol`` -- mirrors
    ``app.domains.location.repository.LocationCodeCounterRepository``
    exactly (see ``nas_number_generator.py``'s own module docstring for the
    full concurrency-safety write-up)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def increment_and_get_next(self, counter_key: str) -> int:
        statement = (
            pg_insert(RadiusNasCodeCounter)
            .values(counter_key=counter_key, last_value=1)
            .on_conflict_do_update(
                index_elements=[RadiusNasCodeCounter.counter_key],
                set_={
                    "last_value": RadiusNasCodeCounter.last_value + 1,
                    "version": RadiusNasCodeCounter.version + 1,
                },
            )
            .returning(RadiusNasCodeCounter.last_value)
        )
        result = await self.session.execute(statement)
        await self.session.flush()
        return int(result.scalar_one())


__all__ = [
    "GuestRepositoryProtocol",
    "GuestRepository",
    "RadiusNasCodeCounterRepository",
    "SessionAggregate",
    "LocationSessionCount",
    "DeviceSessionCount",
    "AuthMethodOutcomeCounts",
]
