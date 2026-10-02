"""Data access for prepaid credits (§13.2).

The ledger half of this repository is **append-only by construction**: it
has ``insert_entry`` and reads, and no method that updates or deletes a
``credit_ledger_entries`` row. Migration 0136's trigger enforces the same
rule at the database for anything that bypasses this class.

Nothing here commits. ``CreditWalletService`` runs lock -> check -> insert ->
update inside the caller's transaction, so a campaign debit (BE-12b) can
share one transaction with the recipient status change it pays for.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import (
    BigInteger,
    and_,
    case,
    cast,
    false,
    func,
    literal,
    not_,
    select,
    true,
    union_all,
)
from sqlalchemy.dialects.postgresql import aggregate_order_by, array_agg, insert
from sqlalchemy.ext.asyncio import AsyncSession

from .credits_constants import LEDGER_AGGREGATION_TIMEZONE, CreditEntryType
from .models import CreditLedgerEntry, CreditWallet, Invoice


@dataclass(frozen=True)
class LedgerQuery:
    organization_id: uuid.UUID
    bucket: str
    entry_types: tuple[str, ...] | None = None
    campaign_id: uuid.UUID | None = None
    created_from: datetime | None = None
    created_before: datetime | None = None
    aggregate_recipient_debits: bool = True


@dataclass(frozen=True)
class LedgerRow:
    """One row of a ledger listing. For an aggregated per-campaign-per-day
    debit row, ``entry`` is the group's latest entry (so its running balances
    are the balances after the whole group) and the ``*_override`` fields
    carry the group's sums."""

    entry: CreditLedgerEntry
    aggregated_count: int | None
    delta_available_minor: int
    delta_reserved_minor: int
    units: int | None
    unit_price_minor: int | None


@dataclass(frozen=True)
class CampaignReservation:
    campaign_id: uuid.UUID
    reserved_minor: int
    debited_minor: int


@dataclass(frozen=True)
class WalletMismatch:
    organization_id: uuid.UUID
    bucket: str
    available_minor: int
    reserved_minor: int
    ledger_available_minor: int
    ledger_reserved_minor: int


@dataclass(frozen=True)
class CampaignReservationMismatch:
    organization_id: uuid.UUID
    bucket: str
    campaign_id: uuid.UUID
    campaign_status: str
    net_reserved_minor: int


class CreditRepositoryProtocol(Protocol):
    async def lock_wallet(
        self, organization_id: uuid.UUID, bucket: str
    ) -> CreditWallet: ...

    async def get_wallet(
        self, organization_id: uuid.UUID, bucket: str
    ) -> CreditWallet | None: ...

    async def get_entry_by_key(
        self, organization_id: uuid.UUID, bucket: str, idempotency_key: str
    ) -> CreditLedgerEntry | None: ...

    async def insert_entry(self, **fields: object) -> CreditLedgerEntry: ...

    async def save_wallet(self, wallet: CreditWallet) -> CreditWallet: ...

    async def count_campaign_entries(
        self,
        organization_id: uuid.UUID,
        bucket: str,
        campaign_id: uuid.UUID,
        entry_type: str,
        *,
        key_prefix: str | None = None,
    ) -> int: ...

    async def campaign_reserved_outstanding(
        self, organization_id: uuid.UUID, bucket: str, campaign_id: uuid.UUID
    ) -> int: ...


class CreditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- wallet ---------------------------------------------------------------

    async def lock_wallet(
        self, organization_id: uuid.UUID, bucket: str
    ) -> CreditWallet:
        """The wallet row under ``SELECT ... FOR UPDATE``, created at 0 first
        if this is the organization's first write.

        ``INSERT ... ON CONFLICT DO NOTHING`` makes the lazy create safe
        against a concurrent first write: both inserts race, one wins, and
        both then queue on the same row lock. ``populate_existing`` matters:
        without it a wallet already in this session's identity map would be
        returned with the *cached* balances, not the ones just locked.
        """
        await self.session.execute(
            insert(CreditWallet)
            .values(id=uuid.uuid4(), organization_id=organization_id, bucket=bucket)
            .on_conflict_do_nothing(constraint="uq_credit_wallets_org_bucket")
        )
        result = await self.session.execute(
            select(CreditWallet)
            .where(
                CreditWallet.organization_id == organization_id,
                CreditWallet.bucket == bucket,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return result.scalar_one()

    async def get_wallet(
        self, organization_id: uuid.UUID, bucket: str
    ) -> CreditWallet | None:
        result = await self.session.execute(
            select(CreditWallet)
            .where(
                CreditWallet.organization_id == organization_id,
                CreditWallet.bucket == bucket,
            )
            .execution_options(populate_existing=True)
        )
        return result.scalar_one_or_none()

    async def save_wallet(self, wallet: CreditWallet) -> CreditWallet:
        await self.session.flush()
        return wallet

    # -- ledger (append-only) -------------------------------------------------

    async def get_entry_by_key(
        self, organization_id: uuid.UUID, bucket: str, idempotency_key: str
    ) -> CreditLedgerEntry | None:
        result = await self.session.execute(
            select(CreditLedgerEntry).where(
                CreditLedgerEntry.organization_id == organization_id,
                CreditLedgerEntry.bucket == bucket,
                CreditLedgerEntry.idempotency_key == idempotency_key,
            )
        )
        return result.scalar_one_or_none()

    async def insert_entry(self, **fields: object) -> CreditLedgerEntry:
        entry = CreditLedgerEntry(**fields)
        self.session.add(entry)
        await self.session.flush()
        return entry

    async def count_campaign_entries(
        self,
        organization_id: uuid.UUID,
        bucket: str,
        campaign_id: uuid.UUID,
        entry_type: str,
        *,
        key_prefix: str | None = None,
    ) -> int:
        e = CreditLedgerEntry
        conditions = [
            e.organization_id == organization_id,
            e.bucket == bucket,
            e.campaign_id == campaign_id,
            e.entry_type == entry_type,
        ]
        if key_prefix is not None:
            conditions.append(e.idempotency_key.startswith(key_prefix, autoescape=True))
        result = await self.session.execute(select(func.count()).where(*conditions))
        return int(result.scalar_one())

    async def campaign_reserved_outstanding(
        self, organization_id: uuid.UUID, bucket: str, campaign_id: uuid.UUID
    ) -> int:
        """Σ delta_reserved for the campaign: what it still holds."""
        e = CreditLedgerEntry
        result = await self.session.execute(
            select(func.coalesce(func.sum(e.delta_reserved_minor), 0)).where(
                e.organization_id == organization_id,
                e.bucket == bucket,
                e.campaign_id == campaign_id,
            )
        )
        return int(result.scalar_one())

    async def campaign_totals(
        self, organization_id: uuid.UUID, bucket: str, campaign_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, tuple[int, int, int]]:
        """``{campaign_id: (reserved, debited, released)}``, gross amounts.
        Test-send debits (from available) are not campaign debits."""
        ids = [cid for cid in set(campaign_ids) if cid is not None]
        if not ids:
            return {}
        e = CreditLedgerEntry

        def _gross(entry_type: CreditEntryType, column) -> Any:  # noqa: ANN001
            return cast(
                func.coalesce(
                    func.sum(
                        case(
                            (
                                and_(
                                    e.entry_type == entry_type.value,
                                    e.is_test_send.is_(False),
                                ),
                                column,
                            ),
                            else_=0,
                        )
                    ),
                    0,
                ),
                BigInteger,
            )

        result = await self.session.execute(
            select(
                e.campaign_id,
                _gross(CreditEntryType.RESERVE, e.delta_reserved_minor).label("r"),
                _gross(CreditEntryType.DEBIT, -e.delta_reserved_minor).label("d"),
                _gross(CreditEntryType.RELEASE, -e.delta_reserved_minor).label("l"),
            )
            .where(
                e.organization_id == organization_id,
                e.bucket == bucket,
                e.campaign_id.in_(ids),
            )
            .group_by(e.campaign_id)
        )
        return {row.campaign_id: (int(row.r), int(row.d), int(row.l)) for row in result}

    async def debits_for_recipients(
        self, organization_id: uuid.UUID, recipient_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, int]:
        """``{recipient_id: charged_minor}`` (the unique per-recipient debit)."""
        ids = [rid for rid in set(recipient_ids) if rid is not None]
        if not ids:
            return {}
        e = CreditLedgerEntry
        result = await self.session.execute(
            select(
                e.recipient_id, e.delta_reserved_minor, e.delta_available_minor
            ).where(
                e.organization_id == organization_id,
                e.entry_type == CreditEntryType.DEBIT.value,
                e.recipient_id.in_(ids),
            )
        )
        return {
            row.recipient_id: -(row.delta_reserved_minor + row.delta_available_minor)
            for row in result
        }

    # -- listings -------------------------------------------------------------

    async def list_entries(
        self, query: LedgerQuery, *, limit: int, offset: int
    ) -> tuple[list[LedgerRow], int]:
        """Newest first. With ``aggregate_recipient_debits`` (the default
        view, §13.7) every per-recipient ``debit`` collapses into one row per
        campaign per IST day; everything else is one row per entry."""
        e = CreditLedgerEntry
        filters = [e.organization_id == query.organization_id, e.bucket == query.bucket]
        if query.entry_types:
            filters.append(e.entry_type.in_(query.entry_types))
        if query.campaign_id is not None:
            filters.append(e.campaign_id == query.campaign_id)
        if query.created_from is not None:
            filters.append(e.created_at >= query.created_from)
        if query.created_before is not None:
            filters.append(e.created_at < query.created_before)

        recipient_debit = and_(
            e.entry_type == CreditEntryType.DEBIT.value, e.recipient_id.is_not(None)
        )
        raw_filters = list(filters)
        if query.aggregate_recipient_debits:
            raw_filters.append(not_(recipient_debit))

        raw = select(
            e.id.label("anchor_id"),
            e.created_at.label("at"),
            literal(1).label("n"),
            e.delta_available_minor.label("d_available"),
            e.delta_reserved_minor.label("d_reserved"),
            e.units.label("units"),
            e.unit_price_minor.label("price_min"),
            e.unit_price_minor.label("price_max"),
            false().label("is_aggregate"),
        ).where(*raw_filters)

        if query.aggregate_recipient_debits:
            day = func.date(func.timezone(LEDGER_AGGREGATION_TIMEZONE, e.created_at))
            grouped = (
                select(
                    array_agg(
                        aggregate_order_by(e.id, e.created_at.desc(), e.id.desc())
                    )[1].label("anchor_id"),
                    func.max(e.created_at).label("at"),
                    func.count().label("n"),
                    cast(func.sum(e.delta_available_minor), BigInteger).label(
                        "d_available"
                    ),
                    cast(func.sum(e.delta_reserved_minor), BigInteger).label(
                        "d_reserved"
                    ),
                    cast(func.sum(e.units), BigInteger).label("units"),
                    func.min(e.unit_price_minor).label("price_min"),
                    func.max(e.unit_price_minor).label("price_max"),
                    true().label("is_aggregate"),
                )
                .where(*filters, recipient_debit)
                .group_by(e.campaign_id, day)
            )
            combined = union_all(raw, grouped).subquery("ledger_rows")
        else:
            combined = raw.subquery("ledger_rows")

        total = (
            await self.session.execute(select(func.count()).select_from(combined))
        ).scalar_one()
        page = (
            await self.session.execute(
                select(combined)
                .order_by(combined.c.at.desc(), combined.c.anchor_id.desc())
                .limit(limit)
                .offset(offset)
            )
        ).all()
        if not page:
            return [], int(total)

        anchors = {
            entry.id: entry
            for entry in (
                await self.session.execute(
                    select(e).where(e.id.in_([row.anchor_id for row in page]))
                )
            ).scalars()
        }
        rows: list[LedgerRow] = []
        for row in page:
            entry = anchors[row.anchor_id]
            price = row.price_min if row.price_min == row.price_max else None
            rows.append(
                LedgerRow(
                    entry=entry,
                    aggregated_count=int(row.n) if row.is_aggregate else None,
                    delta_available_minor=int(row.d_available),
                    delta_reserved_minor=int(row.d_reserved),
                    units=int(row.units) if row.units is not None else None,
                    unit_price_minor=price,
                )
            )
        return rows, int(total)

    async def list_active_campaign_reservations(
        self, organization_id: uuid.UUID, bucket: str
    ) -> list[CampaignReservation]:
        e = CreditLedgerEntry
        reserved = cast(func.sum(e.delta_reserved_minor), BigInteger)
        debited = cast(
            func.sum(
                case(
                    (
                        e.entry_type == CreditEntryType.DEBIT.value,
                        -e.delta_reserved_minor,
                    ),
                    else_=0,
                )
            ),
            BigInteger,
        )
        result = await self.session.execute(
            select(e.campaign_id, reserved.label("reserved"), debited.label("debited"))
            .where(
                e.organization_id == organization_id,
                e.bucket == bucket,
                e.campaign_id.is_not(None),
            )
            .group_by(e.campaign_id)
            .having(func.sum(e.delta_reserved_minor) > 0)
            .order_by(e.campaign_id)
        )
        return [
            CampaignReservation(
                campaign_id=row.campaign_id,
                reserved_minor=int(row.reserved),
                debited_minor=int(row.debited),
            )
            for row in result
        ]

    # -- lookups for ledger display -------------------------------------------

    async def organization_exists(self, organization_id: uuid.UUID) -> bool:
        from app.domains.organization.models import Organization

        result = await self.session.execute(
            select(Organization.id).where(
                Organization.id == organization_id,
                Organization.is_deleted.is_(False),
            )
        )
        return result.scalar_one_or_none() is not None

    async def campaign_belongs_to(
        self, organization_id: uuid.UUID, campaign_id: uuid.UUID
    ) -> bool:
        # Read-only use of the marketing table, imported lazily so billing
        # keeps no import-time dependency on the marketing domain.
        from app.domains.marketing.models import MarketingCampaign

        result = await self.session.execute(
            select(MarketingCampaign.id).where(
                MarketingCampaign.id == campaign_id,
                MarketingCampaign.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none() is not None

    async def get_campaign_names(
        self, organization_id: uuid.UUID, campaign_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, str]:
        from app.domains.marketing.models import MarketingCampaign

        ids = [cid for cid in set(campaign_ids) if cid is not None]
        if not ids:
            return {}
        result = await self.session.execute(
            select(MarketingCampaign.id, MarketingCampaign.name).where(
                MarketingCampaign.id.in_(ids),
                MarketingCampaign.organization_id == organization_id,
            )
        )
        return {row.id: row.name for row in result}

    async def get_invoice_numbers(
        self, organization_id: uuid.UUID, invoice_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, str]:
        ids = [iid for iid in set(invoice_ids) if iid is not None]
        if not ids:
            return {}
        result = await self.session.execute(
            select(Invoice.id, Invoice.invoice_number).where(
                Invoice.id.in_(ids), Invoice.organization_id == organization_id
            )
        )
        return {row.id: row.invoice_number for row in result}

    async def get_user_names(self, user_ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
        from app.domains.auth.models import User

        ids = [uid for uid in set(user_ids) if uid is not None]
        if not ids:
            return {}
        result = await self.session.execute(
            select(User.id, User.first_name, User.last_name).where(User.id.in_(ids))
        )
        return {
            row.id: " ".join(part for part in (row.first_name, row.last_name) if part)
            for row in result
        }

    # -- reconciliation -------------------------------------------------------

    async def find_wallet_mismatches(self) -> list[WalletMismatch]:
        """Every wallet whose buckets differ from the sum of its ledger.

        One statement, so it reads one snapshot: a wallet update and the
        ledger row that explains it commit together and are seen together.
        """
        e = CreditLedgerEntry
        w = CreditWallet
        sums = (
            select(
                e.organization_id,
                e.bucket,
                cast(func.sum(e.delta_available_minor), BigInteger).label("available"),
                cast(func.sum(e.delta_reserved_minor), BigInteger).label("reserved"),
            )
            .group_by(e.organization_id, e.bucket)
            .subquery("ledger_sums")
        )
        ledger_available = func.coalesce(sums.c.available, 0)
        ledger_reserved = func.coalesce(sums.c.reserved, 0)
        wallet_side = (
            select(
                w.organization_id,
                w.bucket,
                w.available_minor,
                w.reserved_minor,
                ledger_available.label("ledger_available"),
                ledger_reserved.label("ledger_reserved"),
            )
            .select_from(
                w.__table__.outerjoin(
                    sums,
                    and_(
                        sums.c.organization_id == w.organization_id,
                        sums.c.bucket == w.bucket,
                    ),
                )
            )
            .where(
                (w.available_minor != ledger_available)
                | (w.reserved_minor != ledger_reserved)
            )
        )
        # Ledger rows with no wallet at all: impossible through the service
        # (the wallet row is created before the first entry), so a hit here
        # means someone deleted a wallet by hand.
        orphan_side = (
            select(
                sums.c.organization_id,
                sums.c.bucket,
                literal(0, BigInteger).label("available_minor"),
                literal(0, BigInteger).label("reserved_minor"),
                sums.c.available.label("ledger_available"),
                sums.c.reserved.label("ledger_reserved"),
            )
            .select_from(
                sums.outerjoin(
                    w.__table__,
                    and_(
                        sums.c.organization_id == w.organization_id,
                        sums.c.bucket == w.bucket,
                    ),
                )
            )
            .where(w.id.is_(None))
        )
        result = await self.session.execute(union_all(wallet_side, orphan_side))
        return [
            WalletMismatch(
                organization_id=row[0],
                bucket=row[1],
                available_minor=int(row[2]),
                reserved_minor=int(row[3]),
                ledger_available_minor=int(row[4]),
                ledger_reserved_minor=int(row[5]),
            )
            for row in result
        ]

    async def find_terminal_campaign_reservations(
        self, terminal_statuses: tuple[str, ...]
    ) -> list[CampaignReservationMismatch]:
        """Campaigns in a terminal state whose reservation does not net to
        zero (§13.4 step 6). Always empty until BE-12b writes reservations."""
        from app.domains.marketing.models import MarketingCampaign

        e = CreditLedgerEntry
        net = cast(func.sum(e.delta_reserved_minor), BigInteger)
        result = await self.session.execute(
            select(
                e.organization_id,
                e.bucket,
                e.campaign_id,
                MarketingCampaign.status,
                net.label("net"),
            )
            .join(MarketingCampaign, MarketingCampaign.id == e.campaign_id)
            .where(MarketingCampaign.status.in_(terminal_statuses))
            .group_by(
                e.organization_id, e.bucket, e.campaign_id, MarketingCampaign.status
            )
            .having(func.sum(e.delta_reserved_minor) != 0)
        )
        return [
            CampaignReservationMismatch(
                organization_id=row.organization_id,
                bucket=row.bucket,
                campaign_id=row.campaign_id,
                campaign_status=row.status,
                net_reserved_minor=int(row.net),
            )
            for row in result
        ]


__all__ = [
    "CampaignReservation",
    "CampaignReservationMismatch",
    "CreditRepository",
    "CreditRepositoryProtocol",
    "LedgerQuery",
    "LedgerRow",
    "WalletMismatch",
]
