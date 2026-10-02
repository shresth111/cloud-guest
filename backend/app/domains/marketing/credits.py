"""Marketing credits: the price book and the campaign charge flow (spec §13.3,
§13.4, BE-12b).

The ledger itself -- wallets, row locks, idempotency, append-only entries --
is billing's (``app.domains.billing.credits_service``). This module decides
*what* to reserve, debit and release for a campaign, and when:

1. **Schedule / send-now** (Wyfy provider only): freeze ``price_snapshot``
   ``{channel, unit, unit_price_minor, price_book_row_id,
   units_per_recipient_max}`` and reserve ``reachable x units_max x price``.
   Too little available is 402 ``insufficient_credits``; the campaign stays
   a draft. ``units_max`` for SMS is the worst-case segment count with the
   **real** unsubscribe-link budget (and the real review link), never the
   30-character assumption.
2. **Dispatch**: release the surplus if fewer are reachable, extend at the
   snapshot price if more are; recipients the wallet cannot cover are left
   out (ordered by ``last_seen_at`` desc) and counted in
   ``capped_by_credits``. A dispatched campaign is never failed for credits.
3. **Provider acceptance**: ``debit:{recipient_id}`` for ``actual_units x
   snapshot price``, out of *reserved*, in the transaction that marks the
   recipient ``submitted``. Skipped, failed and ``worker_lost`` recipients
   are never debited.
4. **Terminal state** (sent, failed, cancelled, locked): release what is
   left, holding back only recipients still mid-send (who may yet be
   debited); the worker releases that hold once they settle.
5. **Test sends** (Wyfy provider only) are debited from *available* per
   accepted message.

Own-provider (BYO) campaigns have no price, no reservation and no ledger
row, ever.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.billing.credits_constants import CreditBucket
from app.domains.billing.credits_exceptions import (
    CreditReservationExceededError,
    InsufficientCreditsError,
)
from app.domains.billing.credits_repository import CreditRepository
from app.domains.billing.credits_service import CreditWalletService
from app.domains.rbac.enums import AuditAction

from .constants import ACTIVE_CAMPAIGN_STATUSES, CHANNEL_ORDER, Channel
from .models import MarketingPriceBook
from .validators import render, sms_stats, sms_worst_case_segments

logger = logging.getLogger(__name__)

UNIT_BY_CHANNEL: dict[Channel, str] = {
    Channel.SMS: "segment",
    Channel.WHATSAPP: "message",
    Channel.EMAIL: "message",
}
MAX_UNIT_PRICE_MINOR = 10_000
_BUCKET = CreditBucket.MARKETING
_ACTIVE = {status.value for status in ACTIVE_CAMPAIGN_STATUSES}


# ============================================================================
# Price book
# ============================================================================


@dataclass(frozen=True)
class PriceQuote:
    channel: Channel
    unit: str
    unit_price_minor: int
    price_book_row_id: uuid.UUID | None
    source: str  # "platform" | "org_override"
    platform_unit_price_minor: int

    def as_price(self, *, platform: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "unit": self.unit,
            "unit_price_minor": self.unit_price_minor,
            "source": self.source,
        }
        if platform:
            data["platform_unit_price_minor"] = self.platform_unit_price_minor
        return data


class PriceRepository:
    """Reads and appends ``marketing_price_book``. No update, no delete."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def latest(
        self, organization_id: uuid.UUID | None, at: datetime
    ) -> dict[str, MarketingPriceBook]:
        """Latest row per channel with ``effective_from <= at`` for one owner
        (``None`` = platform)."""
        p = MarketingPriceBook
        owner = (
            p.organization_id.is_(None)
            if organization_id is None
            else p.organization_id == organization_id
        )
        result = await self.session.execute(
            select(p)
            .where(owner, p.effective_from <= at, p.is_deleted.is_(False))
            .order_by(p.channel, p.effective_from.desc())
            .distinct(p.channel)
        )
        return {row.channel: row for row in result.scalars()}

    async def history(self, limit: int) -> list[MarketingPriceBook]:
        p = MarketingPriceBook
        result = await self.session.execute(
            select(p)
            .where(p.organization_id.is_(None), p.is_deleted.is_(False))
            .order_by(p.effective_from.desc(), p.channel)
            .limit(limit)
        )
        return list(result.scalars())

    async def current_org_overrides(self, at: datetime) -> list[MarketingPriceBook]:
        """Every org's latest row per channel that still sets a price."""
        p = MarketingPriceBook
        latest = (
            select(p)
            .where(
                p.organization_id.is_not(None),
                p.effective_from <= at,
                p.is_deleted.is_(False),
            )
            .order_by(p.organization_id, p.channel, p.effective_from.desc())
            .distinct(p.organization_id, p.channel)
        )
        rows = (await self.session.execute(latest)).scalars()
        return [row for row in rows if row.unit_price_minor is not None]

    async def insert(self, **fields: Any) -> MarketingPriceBook:
        row = MarketingPriceBook(**fields)
        self.session.add(row)
        await self.session.flush()
        return row

    async def names(
        self, user_ids: list[uuid.UUID], organization_ids: list[uuid.UUID]
    ) -> tuple[dict[uuid.UUID, str], dict[uuid.UUID, str]]:
        from app.domains.auth.models import User
        from app.domains.organization.models import Organization

        users: dict[uuid.UUID, str] = {}
        orgs: dict[uuid.UUID, str] = {}
        uids = [u for u in set(user_ids) if u]
        if uids:
            result = await self.session.execute(
                select(User.id, User.first_name, User.last_name).where(
                    User.id.in_(uids)
                )
            )
            users = {
                r.id: " ".join(x for x in (r.first_name, r.last_name) if x)
                for r in result
            }
        oids = [o for o in set(organization_ids) if o]
        if oids:
            result = await self.session.execute(
                select(Organization.id, Organization.name).where(
                    Organization.id.in_(oids)
                )
            )
            orgs = {r.id: r.name for r in result}
        return users, orgs


class PriceBook:
    """Current prices, and the Master writes (append a row, never edit)."""

    def __init__(
        self,
        repository: PriceRepository,
        *,
        audit_writer: Any | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer
        self._now = now or (lambda: datetime.now(UTC))

    async def quotes(self, organization_id: uuid.UUID) -> dict[Channel, PriceQuote]:
        now = self._now()
        platform = await self.repository.latest(None, now)
        overrides = await self.repository.latest(organization_id, now)
        quotes: dict[Channel, PriceQuote] = {}
        for channel in CHANNEL_ORDER:
            base = platform.get(channel.value)
            if base is None:
                # No platform row at all (the seed was removed): refuse to
                # guess a price. 0 would be a silent free send.
                raise RuntimeError(f"marketing_price_book has no {channel.value} row")
            override = overrides.get(channel.value)
            if override is not None and override.unit_price_minor is not None:
                row, source = override, "org_override"
            else:
                row, source = base, "platform"
            quotes[channel] = PriceQuote(
                channel=channel,
                unit=UNIT_BY_CHANNEL[channel],
                unit_price_minor=int(row.unit_price_minor or 0),
                price_book_row_id=row.id,
                source=source,
                platform_unit_price_minor=int(base.unit_price_minor or 0),
            )
        return quotes

    async def prices(
        self, organization_id: uuid.UUID, *, platform: bool = False
    ) -> dict[str, Any]:
        quotes = await self.quotes(organization_id)
        return {
            channel.value: quote.as_price(platform=platform)
            for channel, quote in quotes.items()
        }

    async def platform_view(self) -> dict[str, Any]:
        now = self._now()
        current = await self.repository.latest(None, now)
        history = await self.repository.history(50)
        overrides = await self.repository.current_org_overrides(now)
        users, orgs = await self.repository.names(
            [r.set_by_user_id for r in [*current.values(), *history]],
            [r.organization_id for r in overrides],
        )

        def _row(row: MarketingPriceBook) -> dict[str, Any]:
            return {
                "channel": row.channel,
                "unit": row.unit,
                "unit_price_minor": row.unit_price_minor,
                "effective_from": _iso(row.effective_from),
                "set_by": {
                    "id": str(row.set_by_user_id),
                    "name": users.get(row.set_by_user_id),
                }
                if row.set_by_user_id
                else None,
                "note": row.note,
            }

        return {
            "platform": [
                _row(current[c.value]) for c in CHANNEL_ORDER if c.value in current
            ],
            "history": [_row(row) for row in history],
            "org_overrides": [
                {
                    "organization_id": str(row.organization_id),
                    "organization_name": orgs.get(row.organization_id),
                    "channel": row.channel,
                    "unit_price_minor": row.unit_price_minor,
                    "effective_from": _iso(row.effective_from),
                }
                for row in overrides
            ],
        }

    async def set_platform_prices(
        self,
        prices: list[tuple[Channel, int]],
        *,
        note: str | None,
        actor_user_id: uuid.UUID,
    ) -> dict[str, Any]:
        now = self._now()
        for channel, price in prices:
            await self.repository.insert(
                organization_id=None,
                channel=channel.value,
                unit=UNIT_BY_CHANNEL[channel],
                unit_price_minor=price,
                effective_from=now,
                set_by_user_id=actor_user_id,
                note=note,
                created_by=actor_user_id,
            )
        await self._audit(
            actor_user_id,
            AuditAction.MARKETING_PRICE_BOOK_UPDATED,
            organization_id=None,
            description="Marketing platform prices updated: "
            + ", ".join(f"{c.value}={p}" for c, p in prices),
            metadata={
                "prices": {c.value: p for c, p in prices},
                "note": note,
            },
        )
        return await self.platform_view()

    async def set_org_prices(
        self,
        organization_id: uuid.UUID,
        prices: list[tuple[Channel, int | None]],
        *,
        note: str | None,
        actor_user_id: uuid.UUID,
    ) -> dict[str, Any]:
        now = self._now()
        for channel, price in prices:
            await self.repository.insert(
                organization_id=organization_id,
                channel=channel.value,
                unit=UNIT_BY_CHANNEL[channel],
                unit_price_minor=price,
                effective_from=now,
                set_by_user_id=actor_user_id,
                note=note,
                created_by=actor_user_id,
            )
        await self._audit(
            actor_user_id,
            AuditAction.MARKETING_ORG_PRICES_UPDATED,
            organization_id=organization_id,
            description="Marketing price overrides updated: "
            + ", ".join(
                f"{c.value}={'inherit' if p is None else p}" for c, p in prices
            ),
            metadata={"prices": {c.value: p for c, p in prices}, "note": note},
        )
        return await self.prices(organization_id, platform=True)

    async def _audit(
        self,
        actor_user_id: uuid.UUID,
        action: AuditAction,
        *,
        organization_id: uuid.UUID | None,
        description: str,
        metadata: dict[str, Any],
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="marketing_price_book",
            entity_id=organization_id,
            organization_id=organization_id,
            location_id=None,
            description=description,
            event_metadata=metadata,
        )


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


# ============================================================================
# Campaign charge flow
# ============================================================================


def units_per_recipient_max(
    channel: Channel,
    snapshot: dict[str, Any],
    *,
    unsubscribe_link_budget: int,
) -> int:
    """SMS: worst-case segments with the real link lengths; else 1."""
    if channel is not Channel.SMS:
        return 1
    return sms_worst_case_segments(
        snapshot.get("sms_body") or "",
        unsubscribe_link_length=unsubscribe_link_budget,
        review_link_length=len(snapshot.get("review_link") or ""),
    )


def actual_units(
    channel: Channel, snapshot: dict[str, Any], values: dict[str, str], *, test: bool
) -> int:
    """SMS: segments of the body as rendered for this recipient (what the
    provider bills); else 1."""
    if channel is not Channel.SMS:
        return 1
    body = render(snapshot.get("sms_body"), values)
    if test:
        body = f"[TEST] {body}"
    return sms_stats(body).segments


def per_recipient_minor(price_snapshot: dict[str, Any] | None) -> int:
    if not price_snapshot:
        return 0
    return int(price_snapshot.get("units_per_recipient_max") or 0) * int(
        price_snapshot.get("unit_price_minor") or 0
    )


class CampaignCredits:
    """The §13.4 charge flow for one session. Never commits."""

    def __init__(
        self,
        *,
        prices: PriceBook,
        wallets: CreditWalletService,
        ledger: CreditRepository,
    ) -> None:
        self.prices = prices
        self.wallets = wallets
        self.ledger = ledger

    # -- reads ----------------------------------------------------------------

    async def available_minor(self, organization_id: uuid.UUID) -> int:
        wallet = await self.ledger.get_wallet(organization_id, _BUCKET.value)
        return wallet.available_minor if wallet else 0

    async def quote(
        self,
        organization_id: uuid.UUID,
        channel: Channel,
        snapshot: dict[str, Any],
        *,
        unsubscribe_link_budget: int,
    ) -> dict[str, Any]:
        """A fresh ``price_snapshot`` for a Wyfy-provider send now."""
        quote = (await self.prices.quotes(organization_id))[channel]
        return {
            "channel": channel.value,
            "unit": quote.unit,
            "unit_price_minor": quote.unit_price_minor,
            "price_book_row_id": str(quote.price_book_row_id)
            if quote.price_book_row_id
            else None,
            "units_per_recipient_max": units_per_recipient_max(
                channel, snapshot, unsubscribe_link_budget=unsubscribe_link_budget
            ),
        }

    async def totals(
        self, organization_id: uuid.UUID, campaign_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, tuple[int, int, int]]:
        return await self.ledger.campaign_totals(
            organization_id, _BUCKET.value, campaign_ids
        )

    async def recipient_charges(
        self, organization_id: uuid.UUID, recipient_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, int]:
        return await self.ledger.debits_for_recipients(organization_id, recipient_ids)

    # -- writes ---------------------------------------------------------------

    async def reserve_at_schedule(
        self, campaign: Any, price_snapshot: dict[str, Any], reachable: int
    ) -> int:
        """402 ``insufficient_credits`` (with the pricing numbers) when the
        wallet cannot cover the whole audience; nothing is written then."""
        per = per_recipient_minor(price_snapshot)
        needed = reachable * per
        if needed <= 0:
            return 0
        try:
            return await self.wallets.reserve_for_campaign(
                campaign.organization_id, campaign.id, needed
            )
        except InsufficientCreditsError as exc:
            raise InsufficientCreditsError(
                needed_minor=needed,
                available_minor=int(exc.data["available_minor"]),
                extra={
                    "unit_price_minor": price_snapshot["unit_price_minor"],
                    "units_per_recipient_max": price_snapshot[
                        "units_per_recipient_max"
                    ],
                    "reachable": reachable,
                },
            ) from exc

    async def adjust_at_dispatch(
        self, campaign: Any, reachable: int
    ) -> tuple[int, int]:
        """Fit the reservation to the audience as re-evaluated at dispatch.
        Returns ``(allowed, capped_by_credits)``."""
        per = per_recipient_minor(campaign.price_snapshot)
        if per <= 0 or campaign.provider_source == "own":
            return reachable, 0
        outstanding = await self.ledger.campaign_reserved_outstanding(
            campaign.organization_id, _BUCKET.value, campaign.id
        )
        covered = outstanding // per
        if reachable <= covered:
            surplus = outstanding - reachable * per
            if surplus > 0:
                await self.wallets.release_campaign_remainder(
                    campaign.organization_id,
                    campaign.id,
                    key_base=f"release:{campaign.id}:dispatch",
                    hold_minor=reachable * per,
                )
            return reachable, 0
        extra = await self.wallets.reserve_for_campaign(
            campaign.organization_id,
            campaign.id,
            (reachable - covered) * per,
            unit_minor=per,
        )
        allowed = covered + extra // per
        return allowed, reachable - allowed

    async def debit_recipient(
        self, campaign: Any, recipient_id: uuid.UUID, units: int
    ) -> int:
        """``debit:{recipient_id}`` out of reserved, at the snapshot price.
        Units are capped at the reserved worst case: the customer is never
        charged more than was held for this recipient."""
        snapshot = campaign.price_snapshot
        per = per_recipient_minor(snapshot)
        if per <= 0 or campaign.provider_source == "own":
            return 0
        units_max = int(snapshot["units_per_recipient_max"])
        if units > units_max:
            logger.warning(
                "marketing_credit_debit_capped",
                extra={
                    "campaign_id": str(campaign.id),
                    "units": units,
                    "units_per_recipient_max": units_max,
                },
            )
            units = units_max
        price = int(snapshot["unit_price_minor"])
        amount = units * price
        try:
            await self.wallets.debit(
                campaign.organization_id,
                amount,
                idempotency_key=f"debit:{recipient_id}",
                campaign_id=campaign.id,
                recipient_id=recipient_id,
                unit_price_minor=price,
                units=units,
            )
        except (CreditReservationExceededError, InsufficientCreditsError):
            # The message was accepted; failing here would roll back its
            # "submitted" status and invite a re-send. It goes uncharged and
            # loud instead (a bug if it ever fires -- the reservation bounds
            # every debit).
            logger.error(
                "marketing_credit_debit_failed",
                extra={
                    "campaign_id": str(campaign.id),
                    "recipient_id": str(recipient_id),
                },
            )
            return 0
        return amount

    async def settle(self, campaign: Any, in_flight: int) -> int:
        """Release what a terminal campaign still holds, keeping back
        ``in_flight x per-recipient`` for recipients still mid-send."""
        if campaign.status in _ACTIVE:
            return 0
        per = per_recipient_minor(campaign.price_snapshot)
        if per <= 0 or campaign.provider_source == "own":
            return 0
        return await self.wallets.release_campaign_remainder(
            campaign.organization_id,
            campaign.id,
            key_base=f"release:{campaign.id}:final",
            hold_minor=in_flight * per,
        )

    async def release_all(self, campaign: Any, key_base: str) -> int:
        """Unschedule: the campaign goes back to draft and holds nothing."""
        return await self.wallets.release_campaign_remainder(
            campaign.organization_id, campaign.id, key_base=key_base
        )

    async def charge_test_send(
        self,
        campaign: Any,
        *,
        request_id: str,
        address: str,
        unit_price_minor: int,
        units: int,
    ) -> int:
        amount = unit_price_minor * units
        if amount <= 0:
            return 0
        digest = hashlib.sha256(address.encode()).hexdigest()[:16]
        await self.wallets.debit(
            campaign.organization_id,
            amount,
            idempotency_key=f"test:{campaign.id}:{request_id}:{digest}",
            campaign_id=campaign.id,
            unit_price_minor=unit_price_minor,
            units=units,
            is_test_send=True,
        )
        return amount


class SettlingLockHook:
    """``AddonCampaignHookProtocol`` that also settles credits: locking the
    Guest Marketing add-on (every active campaign) or BYO (own-provider
    campaigns only) cancels them in the Master write's transaction and
    releases what each still holds (§13.4 step 6). An own-provider campaign
    holds nothing, so the BYO lock writes no ledger row."""

    def __init__(
        self,
        repository: Any,
        credits: CampaignCredits,
        *,
        own_only: bool = False,
        cancel_reason: str | None = None,
        last_error: str | None = None,
    ) -> None:
        self.repository = repository
        self.credits = credits
        self.own_only = own_only
        self.kwargs: dict[str, Any] = {"own_only": own_only}
        if cancel_reason is not None:
            self.kwargs["cancel_reason"] = cancel_reason
        if last_error is not None:
            self.kwargs["last_error"] = last_error

    async def count_active_campaigns(self, organization_id: uuid.UUID) -> int:
        return await self.repository.count_active_campaigns_for(
            organization_id, own_only=self.own_only
        )

    async def cancel_active_campaigns_for_lock(self, organization_id: uuid.UUID) -> int:
        ids = await self.repository.cancel_active_campaign_ids_for_lock(
            organization_id, **self.kwargs
        )
        for campaign_id in ids:
            campaign = await self.repository.get_campaign_for_worker(campaign_id)
            if campaign is None:
                continue
            await self.repository.refresh(campaign)
            in_flight = await self.repository.count_in_flight(campaign_id)
            await self.credits.settle(campaign, in_flight)
        return len(ids)


def build_campaign_credits(
    session: AsyncSession, *, audit_writer: Any | None = None
) -> CampaignCredits:
    from app.domains.billing.credits_notifications import LowBalanceNotifier

    ledger = CreditRepository(session)
    return CampaignCredits(
        prices=PriceBook(PriceRepository(session), audit_writer=audit_writer),
        wallets=CreditWalletService(
            ledger, low_balance_hook=LowBalanceNotifier(session)
        ),
        ledger=ledger,
    )


__all__ = [
    "SettlingLockHook",
    "CampaignCredits",
    "PriceBook",
    "PriceQuote",
    "PriceRepository",
    "UNIT_BY_CHANNEL",
    "actual_units",
    "build_campaign_credits",
    "per_recipient_minor",
    "units_per_recipient_max",
]
