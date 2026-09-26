"""Prepaid credits: the wallet service, the Master/customer read and write
paths, and the nightly reconciliation (§13, BE-12a).

## The one write path

Every balance change goes through ``CreditWalletService._apply``, in the
caller's transaction:

1. ``SELECT ... FROM credit_wallets ... FOR UPDATE`` (creating the row at 0
   on the organization's first write);
2. look the idempotency key up **under that lock** -- every writer for the
   same wallet queues on the same row, so check-then-insert cannot race. A
   hit that describes the same movement returns the original row
   (``created=False``); a hit that describes a different one is a 422;
3. compute both new balances and refuse anything that would go negative
   with the error the caller's situation calls for (402 for a charge, 409
   for an adjustment or an over-release);
4. insert the ledger row with the running balances, update the wallet.

The ``CHECK (>= 0)`` constraints and the unique idempotency index sit
underneath as a backstop for a bug in 3 or 2; they are not the mechanism.

## Who can touch which bucket (§13.4)

| operation | Δ available | Δ reserved |
|---|---|---|
| topup, refund | +N | 0 |
| reserve | −N | +N |
| release | +N | −N |
| debit (campaign) | 0 | −N |
| debit (test send) | −N | 0 |
| adjustment | ±N | 0 |

Nothing but a campaign's own release and debits ever reduces
``reserved_minor``, which is what makes mid-send exhaustion impossible. In
particular a negative adjustment is checked against ``available_minor``
only, and fails rather than dipping into the reservation.

Credits never expire: there is no expiry entry type and no task writes one.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol
from zoneinfo import ZoneInfo

from sqlalchemy.exc import IntegrityError

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.rbac.enums import AuditAction

from .credits_constants import (
    LEDGER_AGGREGATION_TIMEZONE,
    MASTER_IDEMPOTENCY_PREFIX,
    MASTER_RECENT_ENTRIES_LIMIT,
    MAX_ENTRY_AMOUNT_MINOR,
    MINOR_PER_CREDIT,
    CreditBucket,
    CreditEntryType,
)
from .credits_exceptions import (
    AdjustmentExceedsAvailableError,
    CreditReservationExceededError,
    CreditsCampaignNotFoundError,
    CreditsOrganizationNotFoundError,
    IdempotencyKeyReusedError,
    InsufficientCreditsError,
)
from .credits_repository import (
    CampaignReservationMismatch,
    CreditRepository,
    CreditRepositoryProtocol,
    LedgerQuery,
    LedgerRow,
    WalletMismatch,
)
from .models import CreditLedgerEntry, CreditWallet, Invoice

logger = logging.getLogger(__name__)

_ZONE = ZoneInfo(LEDGER_AGGREGATION_TIMEZONE)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


# ============================================================================
# Wallet service (the ledger core)
# ============================================================================


@dataclass(frozen=True)
class LedgerWrite:
    entry: CreditLedgerEntry
    wallet: CreditWallet
    #: False when the idempotency key already existed and ``entry`` is the
    #: original row -- nothing was written by this call.
    created: bool


BeforeWrite = Callable[[CreditWallet], Awaitable[Mapping[str, object]]]


class CreditWalletService:
    """Idempotent, row-locked balance changes. Never commits: the caller
    owns the transaction (a Master route commits after its audit row; BE-12b
    commits a debit together with the recipient status it pays for)."""

    def __init__(self, repository: CreditRepositoryProtocol) -> None:
        self.repository = repository

    async def topup(
        self,
        organization_id: uuid.UUID,
        amount_minor: int,
        *,
        idempotency_key: str,
        actor_user_id: uuid.UUID | None = None,
        reference: str | None = None,
        note: str | None = None,
        bucket: CreditBucket = CreditBucket.MARKETING,
        before_write: BeforeWrite | None = None,
    ) -> LedgerWrite:
        _require_positive(amount_minor)
        return await self._apply(
            organization_id,
            bucket,
            CreditEntryType.TOPUP,
            delta_available=amount_minor,
            delta_reserved=0,
            idempotency_key=idempotency_key,
            fields={
                "actor_user_id": actor_user_id,
                "reference": reference,
                "note": note,
            },
            before_write=before_write,
        )

    async def reserve(
        self,
        organization_id: uuid.UUID,
        amount_minor: int,
        *,
        idempotency_key: str,
        campaign_id: uuid.UUID,
        bucket: CreditBucket = CreditBucket.MARKETING,
    ) -> LedgerWrite:
        _require_positive(amount_minor)
        return await self._apply(
            organization_id,
            bucket,
            CreditEntryType.RESERVE,
            delta_available=-amount_minor,
            delta_reserved=amount_minor,
            idempotency_key=idempotency_key,
            fields={"campaign_id": campaign_id},
        )

    async def release(
        self,
        organization_id: uuid.UUID,
        amount_minor: int,
        *,
        idempotency_key: str,
        campaign_id: uuid.UUID,
        bucket: CreditBucket = CreditBucket.MARKETING,
    ) -> LedgerWrite:
        _require_positive(amount_minor)
        return await self._apply(
            organization_id,
            bucket,
            CreditEntryType.RELEASE,
            delta_available=amount_minor,
            delta_reserved=-amount_minor,
            idempotency_key=idempotency_key,
            fields={"campaign_id": campaign_id},
        )

    async def debit(
        self,
        organization_id: uuid.UUID,
        amount_minor: int,
        *,
        idempotency_key: str,
        campaign_id: uuid.UUID | None,
        recipient_id: uuid.UUID | None = None,
        unit_price_minor: int | None = None,
        units: int | None = None,
        is_test_send: bool = False,
        bucket: CreditBucket = CreditBucket.MARKETING,
    ) -> LedgerWrite:
        """A campaign debit comes out of ``reserved``; a test send (never
        reserved) comes out of ``available`` and 402s when it can't."""
        _require_positive(amount_minor)
        return await self._apply(
            organization_id,
            bucket,
            CreditEntryType.DEBIT,
            delta_available=-amount_minor if is_test_send else 0,
            delta_reserved=0 if is_test_send else -amount_minor,
            idempotency_key=idempotency_key,
            fields={
                "campaign_id": campaign_id,
                "recipient_id": recipient_id,
                "unit_price_minor": unit_price_minor,
                "units": units,
                "is_test_send": is_test_send,
            },
        )

    async def refund(
        self,
        organization_id: uuid.UUID,
        amount_minor: int,
        *,
        idempotency_key: str,
        campaign_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
        reference: str | None = None,
        note: str | None = None,
        bucket: CreditBucket = CreditBucket.MARKETING,
    ) -> LedgerWrite:
        _require_positive(amount_minor)
        return await self._apply(
            organization_id,
            bucket,
            CreditEntryType.REFUND,
            delta_available=amount_minor,
            delta_reserved=0,
            idempotency_key=idempotency_key,
            fields={
                "campaign_id": campaign_id,
                "actor_user_id": actor_user_id,
                "reference": reference,
                "note": note,
            },
        )

    async def adjust(
        self,
        organization_id: uuid.UUID,
        amount_minor: int,
        *,
        idempotency_key: str,
        actor_user_id: uuid.UUID | None = None,
        reference: str | None = None,
        note: str | None = None,
        bucket: CreditBucket = CreditBucket.MARKETING,
    ) -> LedgerWrite:
        """Signed. Touches ``available`` only: a negative adjustment larger
        than ``available_minor`` is 409 ``adjustment_exceeds_available`` even
        when ``available + reserved`` would cover it."""
        if amount_minor == 0 or abs(amount_minor) > MAX_ENTRY_AMOUNT_MINOR:
            raise ValueError("adjustment amount must be non-zero and in range")
        return await self._apply(
            organization_id,
            bucket,
            CreditEntryType.ADJUSTMENT,
            delta_available=amount_minor,
            delta_reserved=0,
            idempotency_key=idempotency_key,
            fields={
                "actor_user_id": actor_user_id,
                "reference": reference,
                "note": note,
            },
        )

    async def _apply(
        self,
        organization_id: uuid.UUID,
        bucket: CreditBucket,
        entry_type: CreditEntryType,
        *,
        delta_available: int,
        delta_reserved: int,
        idempotency_key: str,
        fields: Mapping[str, object],
        before_write: BeforeWrite | None = None,
    ) -> LedgerWrite:
        if not idempotency_key:
            raise ValueError("idempotency_key is required")
        wallet = await self.repository.lock_wallet(organization_id, bucket.value)

        existing = await self.repository.get_entry_by_key(
            organization_id, bucket.value, idempotency_key
        )
        if existing is not None:
            if (
                existing.entry_type != entry_type.value
                or existing.delta_available_minor != delta_available
                or existing.delta_reserved_minor != delta_reserved
                or existing.campaign_id != fields.get("campaign_id")
                or existing.recipient_id != fields.get("recipient_id")
            ):
                raise IdempotencyKeyReusedError(idempotency_key)
            return LedgerWrite(entry=existing, wallet=wallet, created=False)

        new_available = wallet.available_minor + delta_available
        new_reserved = wallet.reserved_minor + delta_reserved
        if new_available < 0:
            if entry_type == CreditEntryType.ADJUSTMENT:
                raise AdjustmentExceedsAvailableError(
                    amount_minor=delta_available,
                    available_minor=wallet.available_minor,
                )
            raise InsufficientCreditsError(
                needed_minor=-delta_available,
                available_minor=wallet.available_minor,
            )
        if new_reserved < 0:
            raise CreditReservationExceededError(
                amount_minor=-delta_reserved, reserved_minor=wallet.reserved_minor
            )

        extra = dict(await before_write(wallet)) if before_write else {}
        try:
            entry = await self.repository.insert_entry(
                organization_id=organization_id,
                bucket=bucket.value,
                entry_type=entry_type.value,
                delta_available_minor=delta_available,
                delta_reserved_minor=delta_reserved,
                balance_available_after_minor=new_available,
                balance_reserved_after_minor=new_reserved,
                idempotency_key=idempotency_key,
                created_by=fields.get("actor_user_id"),
                **{key: value for key, value in fields.items() if value is not None},
                **extra,
            )
            wallet.available_minor = new_available
            wallet.reserved_minor = new_reserved
            if (
                wallet.low_balance_notified_at is not None
                and new_available >= wallet.low_balance_threshold_minor
            ):
                # Re-arm the low-balance alert once the balance is back above
                # the threshold (§13.5); BE-12b fires it.
                wallet.low_balance_notified_at = None
            await self.repository.save_wallet(wallet)
        except IntegrityError as exc:
            if not _is_check_violation(exc):
                raise
            # Only reachable if the checks above are wrong: the CHECK (>= 0)
            # backstop surfaces as 402, never as a negative balance (§13.2).
            logger.error(
                "credit_ledger_integrity_error",
                extra={
                    "organization_id": str(organization_id),
                    "entry_type": entry_type.value,
                    "error": type(exc.orig).__name__ if exc.orig else "unknown",
                },
            )
            raise InsufficientCreditsError(
                needed_minor=max(0, -delta_available),
                available_minor=wallet.available_minor,
            ) from exc
        return LedgerWrite(entry=entry, wallet=wallet, created=True)


def _is_check_violation(exc: IntegrityError) -> bool:
    """SQLSTATE 23514. asyncpg exposes it as ``sqlstate``, psycopg as
    ``pgcode``; the message check covers a driver that exposes neither."""
    orig = exc.orig
    code = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    if code is not None:
        return str(code) == "23514"
    return "check constraint" in str(orig).lower()


def _require_positive(amount_minor: int) -> None:
    if not isinstance(amount_minor, int) or isinstance(amount_minor, bool):
        raise TypeError("credit amounts are integer minor units")
    if amount_minor <= 0 or amount_minor > MAX_ENTRY_AMOUNT_MINOR:
        raise ValueError("credit amount must be positive and in range")


# ============================================================================
# Reads and Master writes
# ============================================================================


class TopupInvoiceIssuer(Protocol):
    """Satisfied by ``service.InvoiceService``."""

    async def generate_invoice_for_credit_topup(
        self,
        *,
        organization_id: uuid.UUID,
        amount_paid_minor_inr: int,
        credits_minor: int,
        reference: str | None,
        actor_user_id: uuid.UUID | None,
    ) -> Invoice: ...


class AuditWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class Committer(Protocol):
    async def commit(self) -> None: ...


@dataclass(frozen=True)
class AdjustmentRequest:
    entry_type: CreditEntryType
    amount_minor: int
    note: str
    reference: str | None
    campaign_id: uuid.UUID | None
    issue_invoice: bool
    amount_paid_minor_inr: int | None
    idempotency_key: str


_AUDIT_BY_TYPE = {
    CreditEntryType.TOPUP: AuditAction.CREDITS_TOPUP,
    CreditEntryType.ADJUSTMENT: AuditAction.CREDITS_ADJUSTED,
    CreditEntryType.REFUND: AuditAction.CREDITS_REFUNDED,
}


def wallet_summary(wallet: CreditWallet | None) -> dict[str, Any]:
    """A missing wallet row reads as the zero wallet it will be created as."""
    from .credits_constants import DEFAULT_LOW_BALANCE_THRESHOLD_MINOR

    available = wallet.available_minor if wallet else 0
    reserved = wallet.reserved_minor if wallet else 0
    threshold = (
        wallet.low_balance_threshold_minor
        if wallet
        else DEFAULT_LOW_BALANCE_THRESHOLD_MINOR
    )
    return {
        "available_minor": available,
        "reserved_minor": reserved,
        "low_balance_threshold_minor": threshold,
        "is_low": available < threshold,
    }


class CreditsService:
    """The HTTP-facing half: customer balance and ledger, Master summary,
    adjustments and settings. The organization always arrives resolved --
    from ``CurrentOrganization`` on customer routes, from a GLOBAL-pinned
    path on Master routes -- and every query below is keyed on it."""

    def __init__(
        self,
        *,
        repository: CreditRepository,
        wallets: CreditWalletService,
        invoices: TopupInvoiceIssuer,
        audit_writer: AuditWriter,
        committer: Committer,
    ) -> None:
        self.repository = repository
        self.wallets = wallets
        self.invoices = invoices
        self.audit_writer = audit_writer
        self.committer = committer

    # -- customer -------------------------------------------------------------

    async def customer_balance(self, organization_id: uuid.UUID) -> dict[str, Any]:
        wallet = await self.repository.get_wallet(
            organization_id, CreditBucket.MARKETING.value
        )
        return {
            **wallet_summary(wallet),
            "minor_per_credit": MINOR_PER_CREDIT,
            # BE-12b (price book, BYO resolution) fills these. Until then
            # there is no price to show and nothing resolves to 0 credits.
            "prices": {},
            "byo_channels": [],
        }

    async def list_ledger(
        self,
        organization_id: uuid.UUID,
        *,
        entry_types: list[str] | None,
        campaign_id: uuid.UUID | None,
        date_from: date | None,
        date_to: date | None,
        detail_recipients: bool,
        page: int,
        page_size: int,
    ) -> tuple[list[dict[str, Any]], PaginationMeta]:
        params = PageParams(page=page, page_size=page_size)
        query = LedgerQuery(
            organization_id=organization_id,
            bucket=CreditBucket.MARKETING.value,
            entry_types=tuple(entry_types) if entry_types else None,
            campaign_id=campaign_id,
            created_from=_ist_day_start(date_from) if date_from else None,
            created_before=(
                _ist_day_start(date_to + timedelta(days=1)) if date_to else None
            ),
            aggregate_recipient_debits=not detail_recipients,
        )
        rows, total = await self.repository.list_entries(
            query, limit=params.page_size, offset=params.offset
        )
        items = await self._ledger_views(organization_id, rows)
        return items, PaginationMeta.from_total(params, total)

    # -- Master ---------------------------------------------------------------

    async def master_summary(self, organization_id: uuid.UUID) -> dict[str, Any]:
        await self._require_organization(organization_id)
        bucket = CreditBucket.MARKETING.value
        wallet = await self.repository.get_wallet(organization_id, bucket)
        rows, _total = await self.repository.list_entries(
            LedgerQuery(organization_id=organization_id, bucket=bucket),
            limit=MASTER_RECENT_ENTRIES_LIMIT,
            offset=0,
        )
        reservations = await self.repository.list_active_campaign_reservations(
            organization_id, bucket
        )
        names = await self.repository.get_campaign_names(
            organization_id, [r.campaign_id for r in reservations]
        )
        return {
            "wallet": wallet_summary(wallet),
            "prices": {},  # BE-12b
            "recent_entries": await self._ledger_views(organization_id, rows),
            "active_campaign_reservations": [
                {
                    "campaign_id": str(r.campaign_id),
                    "name": names.get(r.campaign_id),
                    "reserved_minor": r.reserved_minor,
                    "debited_minor": r.debited_minor,
                }
                for r in reservations
            ],
        }

    async def master_ledger(
        self, organization_id: uuid.UUID, **filters: Any
    ) -> tuple[list[dict[str, Any]], PaginationMeta]:
        await self._require_organization(organization_id)
        return await self.list_ledger(organization_id, **filters)

    async def post_adjustment(
        self,
        organization_id: uuid.UUID,
        request: AdjustmentRequest,
        *,
        actor_user_id: uuid.UUID,
    ) -> tuple[dict[str, Any], bool]:
        """Returns ``(payload, created)``. A retried request (same
        idempotency key, same movement) returns the original entry and
        writes nothing -- no second invoice, no second audit row."""
        await self._require_organization(organization_id)
        if request.campaign_id is not None and not (
            await self.repository.campaign_belongs_to(
                organization_id, request.campaign_id
            )
        ):
            raise CreditsCampaignNotFoundError(request.campaign_id)

        key = MASTER_IDEMPOTENCY_PREFIX + request.idempotency_key
        common = {
            "idempotency_key": key,
            "actor_user_id": actor_user_id,
            "reference": request.reference,
            "note": request.note,
        }
        if request.entry_type == CreditEntryType.TOPUP:

            async def issue_invoice(_wallet: CreditWallet) -> dict[str, object]:
                # Runs under the wallet lock, after the idempotency check, so
                # a retried request never issues a second invoice.
                paid = request.amount_paid_minor_inr
                if paid is None:  # the schema requires it with issue_invoice
                    raise ValueError("amount_paid_minor_inr is required")
                invoice = await self.invoices.generate_invoice_for_credit_topup(
                    organization_id=organization_id,
                    amount_paid_minor_inr=paid,
                    credits_minor=request.amount_minor,
                    reference=request.reference,
                    actor_user_id=actor_user_id,
                )
                return {"invoice_id": invoice.id}

            write = await self.wallets.topup(
                organization_id,
                request.amount_minor,
                before_write=issue_invoice if request.issue_invoice else None,
                **common,
            )
        elif request.entry_type == CreditEntryType.REFUND:
            write = await self.wallets.refund(
                organization_id,
                request.amount_minor,
                campaign_id=request.campaign_id,
                **common,
            )
        else:
            write = await self.wallets.adjust(
                organization_id, request.amount_minor, **common
            )

        if write.created:
            entry = write.entry
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=_AUDIT_BY_TYPE[request.entry_type].value,
                entity_type="credit_ledger_entry",
                entity_id=entry.id,
                organization_id=organization_id,
                location_id=None,
                description=(
                    f"Marketing credits {request.entry_type.value}: "
                    f"{_credits_label(entry.delta_available_minor)} credits"
                ),
                event_metadata={
                    "entry_type": entry.entry_type,
                    "delta_available_minor": entry.delta_available_minor,
                    "balance_available_after_minor": (
                        entry.balance_available_after_minor
                    ),
                    "reference": entry.reference,
                    "note": entry.note,
                    "campaign_id": str(entry.campaign_id)
                    if entry.campaign_id
                    else None,
                    "invoice_id": str(entry.invoice_id) if entry.invoice_id else None,
                },
            )
            await self.committer.commit()

        views = await self._ledger_views(
            organization_id,
            [
                LedgerRow(
                    entry=write.entry,
                    aggregated_count=None,
                    delta_available_minor=write.entry.delta_available_minor,
                    delta_reserved_minor=write.entry.delta_reserved_minor,
                    units=write.entry.units,
                    unit_price_minor=write.entry.unit_price_minor,
                )
            ],
        )
        view = views[0]
        return (
            {
                "entry": view,
                "wallet": {
                    "available_minor": write.wallet.available_minor,
                    "reserved_minor": write.wallet.reserved_minor,
                },
                "invoice": view["invoice"],
            },
            write.created,
        )

    async def update_settings(
        self,
        organization_id: uuid.UUID,
        *,
        low_balance_threshold_minor: int,
        actor_user_id: uuid.UUID,
    ) -> dict[str, Any]:
        await self._require_organization(organization_id)
        wallet = await self.repository.lock_wallet(
            organization_id, CreditBucket.MARKETING.value
        )
        previous = wallet.low_balance_threshold_minor
        wallet.low_balance_threshold_minor = low_balance_threshold_minor
        wallet.updated_by = actor_user_id
        if wallet.available_minor >= low_balance_threshold_minor:
            wallet.low_balance_notified_at = None
        await self.repository.save_wallet(wallet)
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=AuditAction.CREDITS_SETTINGS_UPDATED.value,
            entity_type="credit_wallet",
            entity_id=wallet.id,
            organization_id=organization_id,
            location_id=None,
            description=(
                "Marketing credits low-balance threshold set to "
                f"{_credits_label(low_balance_threshold_minor)} credits"
            ),
            event_metadata={
                "previous_low_balance_threshold_minor": previous,
                "low_balance_threshold_minor": low_balance_threshold_minor,
            },
        )
        await self.committer.commit()
        return wallet_summary(wallet)

    # -- helpers --------------------------------------------------------------

    async def _require_organization(self, organization_id: uuid.UUID) -> None:
        if not await self.repository.organization_exists(organization_id):
            raise CreditsOrganizationNotFoundError(organization_id)

    async def _ledger_views(
        self, organization_id: uuid.UUID, rows: list[LedgerRow]
    ) -> list[dict[str, Any]]:
        entries = [row.entry for row in rows]
        campaigns = await self.repository.get_campaign_names(
            organization_id, [e.campaign_id for e in entries if e.campaign_id]
        )
        invoices = await self.repository.get_invoice_numbers(
            organization_id, [e.invoice_id for e in entries if e.invoice_id]
        )
        actors = await self.repository.get_user_names(
            [e.actor_user_id for e in entries if e.actor_user_id]
        )
        return [ledger_view(row, campaigns, invoices, actors) for row in rows]


def ledger_view(
    row: LedgerRow,
    campaigns: Mapping[uuid.UUID, str],
    invoices: Mapping[uuid.UUID, str],
    actors: Mapping[uuid.UUID, str],
) -> dict[str, Any]:
    """The §13.7 ledger row. Never carries a recipient address; an
    aggregated row carries no ``recipient_id`` either, and says how many
    entries it summarizes in ``aggregated_count`` (additive)."""
    e = row.entry
    return {
        "id": str(e.id),
        "entry_type": e.entry_type,
        "created_at": _iso(e.created_at),
        "delta_available_minor": row.delta_available_minor,
        "delta_reserved_minor": row.delta_reserved_minor,
        "balance_available_after_minor": e.balance_available_after_minor,
        "balance_reserved_after_minor": e.balance_reserved_after_minor,
        "campaign": (
            {"id": str(e.campaign_id), "name": campaigns.get(e.campaign_id)}
            if e.campaign_id
            else None
        ),
        "is_test_send": bool(e.is_test_send),
        "unit_price_minor": row.unit_price_minor,
        "units": row.units,
        "reference": e.reference,
        "note": e.note,
        "invoice": (
            {"id": str(e.invoice_id), "invoice_number": invoices.get(e.invoice_id)}
            if e.invoice_id
            else None
        ),
        "actor": (
            {"id": str(e.actor_user_id), "name": actors.get(e.actor_user_id)}
            if e.actor_user_id
            else None
        ),
        "recipient_id": (
            str(e.recipient_id)
            if e.recipient_id and row.aggregated_count is None
            else None
        ),
        "aggregated_count": row.aggregated_count,
    }


def _credits_label(minor: int) -> str:
    sign = "-" if minor < 0 else ""
    whole, part = divmod(abs(minor), MINOR_PER_CREDIT)
    return f"{sign}{whole:,}.{part:02d}"


def _ist_day_start(day: date) -> datetime:
    return datetime(day.year, day.month, day.day, tzinfo=_ZONE).astimezone(UTC)


# ============================================================================
# Nightly reconciliation (§13.2)
# ============================================================================


@dataclass(frozen=True)
class ReconciliationReport:
    wallet_mismatches: list[WalletMismatch]
    campaign_mismatches: list[CampaignReservationMismatch]

    @property
    def ok(self) -> bool:
        return not self.wallet_mismatches and not self.campaign_mismatches


class ReconciliationSource(Protocol):
    async def find_wallet_mismatches(self) -> list[WalletMismatch]: ...

    async def find_terminal_campaign_reservations(
        self, terminal_statuses: tuple[str, ...]
    ) -> list[CampaignReservationMismatch]: ...


async def reconcile_credit_wallets(
    source: ReconciliationSource,
) -> ReconciliationReport:
    """Read-only. Every mismatch is logged at ERROR as
    ``credit_wallet_mismatch``; nothing is corrected -- a human posts a
    Master adjustment after finding out why (§13.2)."""
    from app.domains.marketing.constants import CampaignStatus

    terminal = (
        CampaignStatus.SENT.value,
        CampaignStatus.FAILED.value,
        CampaignStatus.CANCELLED.value,
    )
    wallets = await source.find_wallet_mismatches()
    campaigns = await source.find_terminal_campaign_reservations(terminal)
    for mismatch in wallets:
        logger.error(
            "credit_wallet_mismatch",
            extra={
                "kind": "wallet_balance",
                "organization_id": str(mismatch.organization_id),
                "bucket": mismatch.bucket,
                "available_minor": mismatch.available_minor,
                "ledger_available_minor": mismatch.ledger_available_minor,
                "reserved_minor": mismatch.reserved_minor,
                "ledger_reserved_minor": mismatch.ledger_reserved_minor,
            },
        )
    for mismatch in campaigns:
        logger.error(
            "credit_wallet_mismatch",
            extra={
                "kind": "terminal_campaign_reservation",
                "organization_id": str(mismatch.organization_id),
                "bucket": mismatch.bucket,
                "campaign_id": str(mismatch.campaign_id),
                "campaign_status": mismatch.campaign_status,
                "net_reserved_minor": mismatch.net_reserved_minor,
            },
        )
    return ReconciliationReport(
        wallet_mismatches=wallets, campaign_mismatches=campaigns
    )


def format_reconciliation_alert(report: ReconciliationReport) -> tuple[str, str]:
    """Subject and plain-text body for the platform alert. Ids and integer
    amounts only -- no names, notes or references."""
    subject = (
        f"[Wyfy] Credit ledger mismatch: {len(report.wallet_mismatches)} wallet(s), "
        f"{len(report.campaign_mismatches)} campaign reservation(s)"
    )
    lines = [
        "The nightly credit reconciliation found balances that do not match "
        "the ledger. Nothing was corrected automatically. Investigate, then "
        "fix with a Master adjustment.",
        "",
    ]
    for m in report.wallet_mismatches:
        lines.append(
            f"- org {m.organization_id} [{m.bucket}]: wallet available "
            f"{m.available_minor} vs ledger {m.ledger_available_minor}; "
            f"reserved {m.reserved_minor} vs ledger {m.ledger_reserved_minor} "
            "(minor units)"
        )
    for c in report.campaign_mismatches:
        lines.append(
            f"- org {c.organization_id} campaign {c.campaign_id} "
            f"({c.campaign_status}) still nets {c.net_reserved_minor} reserved"
        )
    return subject, "\n".join(lines)


__all__ = [
    "AdjustmentRequest",
    "CreditWalletService",
    "CreditsService",
    "LedgerWrite",
    "ReconciliationReport",
    "format_reconciliation_alert",
    "ledger_view",
    "reconcile_credit_wallets",
    "wallet_summary",
]
