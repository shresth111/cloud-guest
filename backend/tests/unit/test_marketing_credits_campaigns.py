"""Marketing credits x campaigns (BE-12b): the §13.4 charge flow end to end.

Contract: ``wyfy-specs/guest-marketing-campaigns.md`` §13.3-§13.7. Each test
drives the real ``MarketingService`` (schedule, dispatch, send_batch, cancel,
reap, test-send) over the in-memory marketing world of
``test_guest_marketing.py`` and the in-memory ledger of
``test_marketing_credits.py``, wired through the real ``CampaignCredits`` and
``CreditWalletService``. What must hold:

* skipped, failed and ``worker_lost`` recipients are never debited;
* a retried recipient is debited once;
* a price change after schedule does not change that campaign's debits;
* an own-provider (BYO) campaign writes zero ledger rows;
* a finished campaign nets its reservation to zero;
* concurrent campaigns cannot overdraw (also proven on real Postgres in
  ``test_marketing_credits_postgres.py``);
* a cancel mid-send releases exactly the remainder, holding back only what
  is still in flight until it settles.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.billing.credits_exceptions import InsufficientCreditsError
from app.domains.billing.credits_service import CreditWalletService
from app.domains.marketing.constants import (
    CampaignStatus,
    Channel,
    ChannelMode,
    RecipientStatus,
)
from app.domains.marketing.credits import (
    CampaignCredits,
    PriceBook,
    SettlingLockHook,
    units_per_recipient_max,
)
from app.domains.marketing.schemas import AudienceFilter, CampaignCreate
from app.domains.marketing.senders import (
    ChannelStatus,
    MarketingSenders,
    ProviderResult,
    SendError,
)
from app.domains.marketing.service import MarketingService
from app.domains.marketing.validators import sms_worst_case_segments
from tests.unit.test_guest_marketing import (
    NOW,
    ORG_A,
    FakeEmailSender,
    _row,
    _scope,
    _senders,
    _settings,
    _world,
)
from tests.unit.test_marketing_credits import FakeCreditRepository

PLATFORM = {"sms": 30, "whatsapp": 120, "email": 5}


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class LedgerRepo(FakeCreditRepository):
    """The in-memory ledger plus the campaign reads BE-12b adds."""

    async def count_campaign_entries(
        self, organization_id, bucket, campaign_id, entry_type, *, key_prefix=None
    ):
        return sum(
            1
            for e in self.entries
            if e.organization_id == organization_id
            and e.campaign_id == campaign_id
            and e.entry_type == entry_type
            and (key_prefix is None or e.idempotency_key.startswith(key_prefix))
        )

    async def campaign_reserved_outstanding(self, organization_id, bucket, campaign_id):
        return sum(
            e.delta_reserved_minor
            for e in self.entries
            if e.organization_id == organization_id and e.campaign_id == campaign_id
        )

    async def campaign_totals(self, organization_id, bucket, campaign_ids):
        out = {}
        for cid in campaign_ids:
            rows = [e for e in self.entries if e.campaign_id == cid]
            if not rows:
                continue
            out[cid] = (
                sum(e.delta_reserved_minor for e in rows if e.entry_type == "reserve"),
                sum(
                    -e.delta_reserved_minor
                    for e in rows
                    if e.entry_type == "debit" and not e.is_test_send
                ),
                sum(-e.delta_reserved_minor for e in rows if e.entry_type == "release"),
            )
        return out

    async def debits_for_recipients(self, organization_id, recipient_ids):
        return {
            e.recipient_id: -(e.delta_reserved_minor + e.delta_available_minor)
            for e in self.entries
            if e.entry_type == "debit" and e.recipient_id in set(recipient_ids)
        }

    def outstanding(self, campaign_id) -> int:
        return sum(
            e.delta_reserved_minor for e in self.entries if e.campaign_id == campaign_id
        )

    def rows_for(self, campaign_id, entry_type=None) -> list[Any]:
        return [
            e
            for e in self.entries
            if e.campaign_id == campaign_id
            and (entry_type is None or e.entry_type == entry_type)
        ]


@dataclass
class FakePriceRepository:
    rows: list[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        for channel, price in PLATFORM.items():
            self.add(None, channel, price, NOW - timedelta(days=1))

    def add(self, org, channel, price, at):
        unit = "segment" if channel == "sms" else "message"
        row = _row(
            organization_id=org,
            channel=channel,
            unit=unit,
            unit_price_minor=price,
            effective_from=at,
            set_by_user_id=None,
            note=None,
        )
        self.rows.append(row)
        return row

    async def latest(self, organization_id, at):
        out = {}
        for row in sorted(self.rows, key=lambda r: r.effective_from):
            if row.organization_id == organization_id and row.effective_from <= at:
                out[row.channel] = row
        return out

    async def history(self, limit):
        return [r for r in reversed(self.rows) if r.organization_id is None][:limit]

    async def current_org_overrides(self, at):
        latest = {}
        for row in sorted(self.rows, key=lambda r: r.effective_from):
            if row.organization_id is not None and row.effective_from <= at:
                latest[(row.organization_id, row.channel)] = row
        return [r for r in latest.values() if r.unit_price_minor is not None]

    async def insert(self, **fields):
        row = _row(**fields)
        self.rows.append(row)
        return row

    async def names(self, user_ids, organization_ids):
        return {}, {}


class Hook:
    def __init__(self) -> None:
        self.calls: list[int] = []

    async def __call__(self, wallet) -> None:
        self.calls.append(wallet.available_minor)


def _credits(ledger: LedgerRepo, prices: FakePriceRepository, hook=None, clock=None):
    clock = clock or [NOW]
    return CampaignCredits(
        prices=PriceBook(prices, now=lambda: clock[0]),  # type: ignore[arg-type]
        wallets=CreditWalletService(ledger, low_balance_hook=hook, now=lambda: NOW),  # type: ignore[arg-type]
        ledger=ledger,  # type: ignore[arg-type]
    )


def _extend(repo) -> None:
    """The marketing-repository reads BE-12b adds, on the shared fake."""

    async def count_in_flight(campaign_id):
        return sum(
            1
            for r in repo.recipients.values()
            if r.campaign_id == campaign_id and r.status == RecipientStatus.SENDING.value
        )

    async def skip_pending_recipients(campaign_id, reason):
        count = 0
        for r in repo.recipients.values():
            if r.campaign_id == campaign_id and r.status == RecipientStatus.PENDING.value:
                r.status = RecipientStatus.SKIPPED.value
                r.skip_reason = reason
                count += 1
        repo.campaigns[campaign_id].count_pending -= count
        repo.campaigns[campaign_id].count_skipped += count
        return count

    async def due_campaign_ids(now):
        return [
            c.id
            for c in repo.campaigns.values()
            if c.status == CampaignStatus.SCHEDULED.value and c.scheduled_at <= now
        ]

    async def sending_campaigns_without_progress(started_before):
        return []

    async def reap_stuck_recipients(stuck_before):
        ids = []
        for r in repo.recipients.values():
            if r.status == RecipientStatus.SENDING.value:
                r.status = RecipientStatus.FAILED.value
                r.error_code = "worker_lost"
                repo.campaigns[r.campaign_id].count_failed += 1
                ids.append(r.campaign_id)
        return list(dict.fromkeys(ids))

    async def cancel_active_campaign_ids_for_lock(organization_id, **kwargs):
        ids = []
        for c in repo.campaigns.values():
            if c.organization_id != organization_id or c.status not in (
                CampaignStatus.SCHEDULED.value,
                CampaignStatus.SENDING.value,
            ):
                continue
            if kwargs.get("own_only") and c.provider_source != "own":
                continue
            c.status = CampaignStatus.CANCELLED.value
            c.cancel_reason = kwargs.get("cancel_reason", "addon_locked")
            await skip_pending_recipients(c.id, "addon_locked")
            ids.append(c.id)
        return ids

    for fn in (
        count_in_flight,
        skip_pending_recipients,
        due_campaign_ids,
        sending_campaigns_without_progress,
        reap_stuck_recipients,
        cancel_active_campaign_ids_for_lock,
    ):
        setattr(repo, fn.__name__, fn)


@dataclass
class Rig:
    world: Any
    ledger: LedgerRepo
    prices: FakePriceRepository
    credits: CampaignCredits
    hook: Hook
    now: list = field(default_factory=lambda: [NOW])

    def service(self, email=None, **kwargs) -> MarketingService:
        async def _entitled(org):
            return True

        return MarketingService(
            self.world.repo,
            settings=_settings(),
            senders=_senders(email or self.world.email),
            now=lambda: self.now[0],
            entitlement_check=_entitled,
            credits=self.credits,
            **kwargs,
        )

    async def topup(self, amount, key="seed", org=ORG_A):
        await self.credits.wallets.topup(org, amount, idempotency_key=key)

    def wallet(self, org=ORG_A):
        return self.ledger.wallets[(org, "marketing")]


def _rig(world=None) -> Rig:
    world = world or _world()
    _extend(world.repo)
    for c in world.repo.campaigns.values():
        c.provider_source = "wyfy"
    ledger = LedgerRepo(use_locks=False)
    prices = FakePriceRepository()
    hook = Hook()
    clock = [NOW]
    return Rig(world, ledger, prices, _credits(ledger, prices, hook, clock), hook, clock)


async def _create(rig: Rig, *, channel=Channel.EMAIL, template=None) -> uuid.UUID:
    created = await rig.service().create_campaign(
        _scope(ORG_A),
        CampaignCreate(
            name="Weekend",
            channel=channel,
            template_id=(template or rig.world.template_a).id,
            audience_filter=AudienceFilter(channel=channel),
        ),
    )
    campaign = rig.world.repo.campaigns[uuid.UUID(created["id"])]
    campaign.provider_source = "wyfy"
    campaign.price_snapshot = None
    campaign.capped_by_credits = 0
    return campaign.id


async def _send_now(rig: Rig, service=None) -> uuid.UUID:
    campaign_id = await _create(rig)
    await (service or rig.service()).schedule(
        _scope(ORG_A),
        campaign_id,
        scheduled_at=None,
        idempotency_key="idem-" + uuid.uuid4().hex,
    )
    return campaign_id


def _add_guest(rig: Rig, name: str, *, days_ago: int = 0) -> None:
    repo = rig.world.repo
    guest = _row(
        organization_id=ORG_A,
        identifier=f"{name}@guest.in",
        email=None,
        display_name=name,
        is_blocked=False,
        last_seen_at=NOW - timedelta(days=days_ago),
        total_visit_count=1,
    )
    repo.guests[guest.id] = guest
    repo.visits.add((guest.id, next(iter(repo.locations))))
    repo.consents[(guest.id, "email")] = _row(status="opted_in", source="captive_portal")


# The default world has two reachable email guests (a1_in, a2_in); email
# costs 5 minor per message.


# ============================================================================
# Schedule: snapshot and reserve, or 402 and stay a draft
# ============================================================================


async def test_schedule_snapshots_the_price_and_reserves_the_audience() -> None:
    rig = _rig()
    await rig.topup(1_000)
    campaign_id = await _create(rig)
    detail = await rig.service().schedule(
        _scope(ORG_A),
        campaign_id,
        scheduled_at=NOW + timedelta(hours=3),
        idempotency_key="idem-sched-1",
    )
    assert detail["status"] == "scheduled"
    assert detail["credits"] == {
        "price_snapshot": {"channel": "email", "unit": "message", "unit_price_minor": 5},
        "reserved_minor": 10,
        "debited_minor": 0,
        "released_minor": 0,
    }
    assert (rig.wallet().available_minor, rig.wallet().reserved_minor) == (990, 10)
    [reserve] = rig.ledger.rows_for(campaign_id, "reserve")
    assert reserve.idempotency_key == f"reserve:{campaign_id}:0"


async def test_insufficient_credits_is_402_and_the_campaign_stays_a_draft() -> None:
    rig = _rig()
    await rig.topup(7)
    campaign_id = await _create(rig)
    with pytest.raises(InsufficientCreditsError) as info:
        await rig.service().schedule(
            _scope(ORG_A), campaign_id, scheduled_at=None, idempotency_key="idem-402-1"
        )
    assert info.value.status_code == 402
    assert info.value.data == {
        "error_code": "insufficient_credits",
        "needed_minor": 10,
        "available_minor": 7,
        "shortfall_minor": 3,
        "unit_price_minor": 5,
        "units_per_recipient_max": 1,
        "reachable": 2,
    }
    assert rig.world.repo.campaigns[campaign_id].status == CampaignStatus.DRAFT.value
    assert rig.ledger.rows_for(campaign_id) == []
    assert rig.world.email.sent == []


async def test_unschedule_releases_everything_and_reschedule_reserves_afresh() -> None:
    rig = _rig()
    await rig.topup(1_000)
    campaign_id = await _create(rig)
    service = rig.service()
    at = NOW + timedelta(hours=3)
    await service.schedule(_scope(ORG_A), campaign_id, scheduled_at=at, idempotency_key="k-one-1")
    await service.unschedule(_scope(ORG_A), campaign_id)
    assert rig.ledger.outstanding(campaign_id) == 0
    assert rig.world.repo.campaigns[campaign_id].price_snapshot is None
    await service.schedule(_scope(ORG_A), campaign_id, scheduled_at=at, idempotency_key="k-two-2")
    keys = [e.idempotency_key for e in rig.ledger.rows_for(campaign_id)]
    assert keys == [
        f"reserve:{campaign_id}:0",
        f"release:{campaign_id}:unschedule",
        f"reserve:{campaign_id}:1",
    ]
    assert rig.ledger.outstanding(campaign_id) == 10


# ============================================================================
# Sending: per-recipient debit, and never for skipped/failed/lost
# ============================================================================


async def test_a_finished_campaign_debits_each_accepted_recipient_and_nets_to_zero(
) -> None:
    rig = _rig()
    await rig.topup(1_000)
    service = rig.service()
    campaign_id = await _send_now(rig, service)
    await service.send_batch(campaign_id)
    campaign = rig.world.repo.campaigns[campaign_id]
    assert campaign.status == CampaignStatus.SENT.value
    debits = rig.ledger.rows_for(campaign_id, "debit")
    assert sorted(e.idempotency_key for e in debits) == sorted(
        f"debit:{r.id}" for r in rig.world.repo.recipients.values()
    )
    assert all((e.units, e.unit_price_minor) == (1, 5) for e in debits)
    assert rig.ledger.outstanding(campaign_id) == 0
    assert (rig.wallet().available_minor, rig.wallet().reserved_minor) == (990, 0)
    detail = await service.get_campaign(_scope(ORG_A), campaign_id)
    assert detail["credits"]["debited_minor"] == 10
    items, _ = await service.list_recipients(
        _scope(ORG_A), campaign_id, statuses=None, page=1, page_size=25
    )
    assert [i["charged_minor"] for i in items] == [5, 5]


async def test_skipped_failed_and_lost_recipients_are_never_debited() -> None:
    rig = _rig()
    for name in ("c_skip", "d_fail", "e_lost"):
        _add_guest(rig, name, days_ago=10)
    await rig.topup(1_000)

    class Flaky(FakeEmailSender):
        async def send(self, email, **kwargs):
            if email.startswith("d_fail"):
                raise SendError("provider_rejected", "bad", permanent=True)
            return await super().send(email, **kwargs)

    service = rig.service(email=Flaky())
    campaign_id = await _send_now(rig, service)
    repo = rig.world.repo
    by_name = {r.address.split("@")[0]: r for r in repo.recipients.values()}
    # c_skip opts out after materialization; e_lost is claimed by a worker
    # that dies (left in "sending"), then reaped.
    repo.consents[(by_name["c_skip"].guest_id, "email")] = _row(
        status="opted_out", source="unsubscribe_link"
    )
    by_name["e_lost"].status = RecipientStatus.SENDING.value
    await service.send_batch(campaign_id)
    # Finished, but e_lost is still "sending": its share stays held.
    assert repo.campaigns[campaign_id].status == CampaignStatus.SENT.value
    assert rig.ledger.outstanding(campaign_id) == 5
    await service.reap_stuck()

    charged = {e.recipient_id for e in rig.ledger.rows_for(campaign_id, "debit")}
    assert charged == {by_name["a1_in"].id, by_name["a2_in"].id}
    assert by_name["c_skip"].status == RecipientStatus.SKIPPED.value
    assert by_name["d_fail"].status == RecipientStatus.FAILED.value
    assert by_name["e_lost"].error_code == "worker_lost"
    assert repo.campaigns[campaign_id].status == CampaignStatus.SENT.value
    # Reserved 5 x 5, debited 2 x 5, the rest released: nets to zero.
    assert rig.ledger.outstanding(campaign_id) == 0
    assert rig.wallet().available_minor == 1_000 - 10


async def test_a_retried_recipient_is_debited_once() -> None:
    rig = _rig()
    await rig.topup(1_000)
    attempts: dict[str, int] = {}

    class TransientOnce(FakeEmailSender):
        async def send(self, email, **kwargs):
            attempts[email] = attempts.get(email, 0) + 1
            if attempts[email] == 1:
                raise SendError("timeout", "try again", permanent=False)
            return await super().send(email, **kwargs)

    service = rig.service(email=TransientOnce())
    campaign_id = await _send_now(rig, service)
    await service.send_batch(campaign_id)  # every recipient: transient
    assert rig.ledger.rows_for(campaign_id, "debit") == []
    await service.send_batch(campaign_id)  # retry: accepted
    debits = rig.ledger.rows_for(campaign_id, "debit")
    assert len(debits) == 2
    # A duplicate worker (or a redelivered task) debiting the same recipient
    # again finds the key and writes nothing.
    campaign = rig.world.repo.campaigns[campaign_id]
    recipient = next(iter(rig.world.repo.recipients.values()))
    campaign.status = CampaignStatus.SENDING.value  # as a racing worker saw it
    await rig.credits.debit_recipient(campaign, recipient.id, 1)
    assert len(rig.ledger.rows_for(campaign_id, "debit")) == 2


async def test_a_price_change_after_schedule_does_not_change_debits() -> None:
    rig = _rig()
    await rig.topup(1_000)
    campaign_id = await _create(rig)
    service = rig.service()
    await service.schedule(
        _scope(ORG_A),
        campaign_id,
        scheduled_at=NOW + timedelta(hours=1),
        idempotency_key="idem-price-1",
    )
    # Master raises email tenfold before dispatch.
    rig.prices.add(None, "email", 50, NOW + timedelta(minutes=1))
    rig.now[0] = NOW + timedelta(hours=1, minutes=1)
    await service.dispatch_due()
    await service.send_batch(campaign_id)
    debits = rig.ledger.rows_for(campaign_id, "debit")
    assert [e.unit_price_minor for e in debits] == [5, 5]
    assert rig.ledger.outstanding(campaign_id) == 0
    # A campaign scheduled now gets the new price.
    later = await _create(rig)
    detail = await service.schedule(
        _scope(ORG_A), later, scheduled_at=None, idempotency_key="idem-price-2"
    )
    assert detail["credits"]["price_snapshot"]["unit_price_minor"] == 50


async def test_a_cancel_mid_send_releases_exactly_the_remainder() -> None:
    rig = _rig()
    _add_guest(rig, "c_third", days_ago=10)
    await rig.topup(1_000)
    holder: dict[str, Any] = {}

    class CancelsDuringFirstSend(FakeEmailSender):
        async def send(self, email, **kwargs):
            if not self.sent:
                # The venue owner cancels while the first message is with
                # the provider; the other two are claimed but unsent.
                await holder["service"].cancel(_scope(ORG_A), holder["id"])
                holder["after_cancel_outstanding"] = rig.ledger.outstanding(
                    holder["id"]
                )
            return await super().send(email, **kwargs)

    service = rig.service(email=CancelsDuringFirstSend())
    holder["service"] = service
    campaign_id = await _send_now(rig, service)
    holder["id"] = campaign_id
    assert rig.ledger.outstanding(campaign_id) == 15
    await service.send_batch(campaign_id)

    # At cancel time all three were in flight: nothing could be released yet.
    assert holder["after_cancel_outstanding"] == 15
    campaign = rig.world.repo.campaigns[campaign_id]
    assert campaign.status == CampaignStatus.CANCELLED.value
    # The one accepted message is charged; the two skipped are released.
    debits = rig.ledger.rows_for(campaign_id, "debit")
    releases = rig.ledger.rows_for(campaign_id, "release")
    assert sum(-e.delta_reserved_minor for e in debits) == 5
    assert sum(-e.delta_reserved_minor for e in releases) == 10
    assert rig.ledger.outstanding(campaign_id) == 0
    assert rig.wallet().available_minor == 1_000 - 5


async def test_a_cancel_between_batches_releases_everything_unsent() -> None:
    rig = _rig()
    await rig.topup(1_000)
    service = rig.service()
    campaign_id = await _send_now(rig, service)
    await service.cancel(_scope(ORG_A), campaign_id)
    [release] = rig.ledger.rows_for(campaign_id, "release")
    assert release.idempotency_key == f"release:{campaign_id}:final"
    assert -release.delta_reserved_minor == 10
    assert rig.ledger.outstanding(campaign_id) == 0


# ============================================================================
# Dispatch: surplus, extension, cap
# ============================================================================


async def test_dispatch_extends_at_the_snapshot_price_and_caps_what_it_cannot_cover(
) -> None:
    rig = _rig()
    await rig.topup(15)  # 3 recipients at 5
    campaign_id = await _create(rig)
    service = rig.service()
    await service.schedule(
        _scope(ORG_A),
        campaign_id,
        scheduled_at=NOW + timedelta(hours=1),
        idempotency_key="idem-cap-1",
    )
    assert rig.ledger.outstanding(campaign_id) == 10
    for name, days in (("n1", 20), ("n2", 21), ("n3", 22)):
        _add_guest(rig, name, days_ago=days)  # 5 reachable now
    rig.prices.add(None, "email", 50, NOW + timedelta(minutes=1))  # ignored
    rig.now[0] = NOW + timedelta(hours=1, minutes=1)
    await service.dispatch_due()
    campaign = rig.world.repo.campaigns[campaign_id]
    # 2 covered + 1 affordable at the snapshot price (5); 2 left out.
    assert campaign.recipient_count == 3
    assert campaign.capped_by_credits == 2
    assert rig.ledger.outstanding(campaign_id) == 15
    extension = rig.ledger.rows_for(campaign_id, "reserve")[-1]
    assert extension.idempotency_key == f"reserve:{campaign_id}:1"
    # The most recently seen guests were kept.
    kept = {r.address.split("@")[0] for r in rig.world.repo.recipients.values()}
    assert kept == {"a1_in", "a2_in", "n1"}
    detail = await service.get_campaign(_scope(ORG_A), campaign_id)
    assert detail["stats"]["capped_by_credits"] == 2
    await service.send_batch(campaign_id)
    assert campaign.status == CampaignStatus.SENT.value  # never failed for credits
    assert rig.ledger.outstanding(campaign_id) == 0


async def test_dispatch_releases_the_surplus_when_fewer_are_reachable() -> None:
    rig = _rig()
    await rig.topup(1_000)
    campaign_id = await _create(rig)
    service = rig.service()
    await service.schedule(
        _scope(ORG_A),
        campaign_id,
        scheduled_at=NOW + timedelta(hours=1),
        idempotency_key="idem-surplus",
    )
    rig.world.repo.consents[(rig.world.guest_ids["a2_in"], "email")] = _row(
        status="opted_out", source="unsubscribe_link"
    )
    rig.now[0] = NOW + timedelta(hours=1, minutes=1)
    await service.dispatch_due()
    [release] = rig.ledger.rows_for(campaign_id, "release")
    assert release.idempotency_key == f"release:{campaign_id}:dispatch"
    assert -release.delta_reserved_minor == 5
    assert rig.ledger.outstanding(campaign_id) == 5


async def test_a_campaign_cancelled_at_dispatch_for_a_locked_addon_releases() -> None:
    rig = _rig()
    await rig.topup(1_000)
    campaign_id = await _create(rig)
    await rig.service().schedule(
        _scope(ORG_A),
        campaign_id,
        scheduled_at=NOW + timedelta(hours=1),
        idempotency_key="idem-lock-1",
    )

    async def _locked(org):
        return False

    service = MarketingService(
        rig.world.repo,
        settings=_settings(),
        senders=_senders(rig.world.email),
        now=lambda: NOW + timedelta(hours=2),
        entitlement_check=_locked,
        credits=rig.credits,
    )
    await service.dispatch_due()
    assert rig.world.repo.campaigns[campaign_id].status == "cancelled"
    assert rig.ledger.outstanding(campaign_id) == 0


@pytest.mark.parametrize("own_only", [False, True])
async def test_locking_the_addon_settles_credits(own_only: bool) -> None:
    rig = _rig()
    await rig.topup(1_000)
    campaign_id = await _create(rig)
    await rig.service().schedule(
        _scope(ORG_A),
        campaign_id,
        scheduled_at=NOW + timedelta(hours=1),
        idempotency_key="idem-lock-2",
    )
    hook = SettlingLockHook(rig.world.repo, rig.credits, own_only=own_only)
    cancelled = await hook.cancel_active_campaigns_for_lock(ORG_A)
    if own_only:
        # The BYO lock touches own-provider campaigns only; this one keeps
        # its reservation and stays scheduled.
        assert cancelled == 0
        assert rig.ledger.outstanding(campaign_id) == 10
    else:
        assert cancelled == 1
        assert rig.ledger.outstanding(campaign_id) == 0


# ============================================================================
# Own provider: zero credits, zero ledger rows
# ============================================================================


async def test_an_own_provider_campaign_writes_zero_ledger_rows() -> None:
    from tests.unit.test_marketing_byo import _add_verified_smtp, _byo_world

    world, own_email = _byo_world()
    rig = _rig(world)
    await _add_verified_smtp(world)
    service = world.service(credits=rig.credits)
    campaign_id = await _create(rig)
    detail = await service.schedule(
        _scope(ORG_A), campaign_id, scheduled_at=None, idempotency_key="idem-own-1"
    )
    assert detail["provider"]["source"] == "own"
    assert detail["credits"] is None
    await service.send_batch(campaign_id)
    assert len(own_email.sent) == 2
    test = await service.test_send(_scope(ORG_A), campaign_id, ["t@x.in"], None)
    assert test["results"][0]["charged_minor"] == 0
    assert rig.ledger.entries == []  # not even a wallet movement
    estimate = await service.estimate(_scope(ORG_A), campaign_id)
    assert (estimate["provider_source"], estimate["estimated_max_minor"]) == ("own", 0)


# ============================================================================
# Test sends: from available, 402 when short
# ============================================================================


async def test_test_sends_are_charged_from_available() -> None:
    rig = _rig()
    await rig.topup(100)
    campaign_id = await _create(rig)
    result = await rig.service().test_send(
        _scope(ORG_A), campaign_id, ["t1@x.in", "t2@x.in"], None
    )
    assert [r["charged_minor"] for r in result["results"]] == [5, 5]
    tests = rig.ledger.rows_for(campaign_id, "debit")
    assert all(e.is_test_send and e.delta_available_minor == -5 for e in tests)
    assert rig.wallet().reserved_minor == 0
    assert rig.wallet().available_minor == 90


async def test_a_test_send_with_too_little_available_is_402_and_sends_nothing() -> None:
    rig = _rig()
    await rig.topup(4)
    campaign_id = await _create(rig)
    with pytest.raises(InsufficientCreditsError):
        await rig.service().test_send(_scope(ORG_A), campaign_id, ["t@x.in"], None)
    assert rig.world.email.sent == []


# ============================================================================
# Concurrency: two campaigns racing for one wallet
# ============================================================================


async def test_concurrent_campaigns_cannot_overdraw() -> None:
    """Ten campaigns, each needing 10, race for a wallet of 50: exactly five
    reserve, five get 402 and stay drafts. The in-memory ledger holds its
    wallet lock across the reserve like SELECT ... FOR UPDATE; the real
    row-lock version is in test_marketing_credits_postgres.py."""
    rig = _rig()
    rig.ledger.use_locks = True
    await rig.credits.wallets.topup(ORG_A, 50, idempotency_key="seed")
    rig.ledger.end_transaction()
    ids = [await _create(rig) for _ in range(10)]

    async def schedule(campaign_id):
        try:
            return await rig.service().schedule(
                _scope(ORG_A),
                campaign_id,
                scheduled_at=NOW + timedelta(hours=1),
                idempotency_key=f"idem-{campaign_id}",
            )
        finally:
            rig.ledger.end_transaction()

    results = await asyncio.gather(*(schedule(i) for i in ids), return_exceptions=True)
    ok = [r for r in results if isinstance(r, dict)]
    refused = [r for r in results if isinstance(r, InsufficientCreditsError)]
    assert (len(ok), len(refused)) == (5, 5)
    assert (rig.wallet().available_minor, rig.wallet().reserved_minor) == (0, 50)
    drafts = [c for c in rig.world.repo.campaigns.values() if c.status == "draft"]
    assert len(drafts) == 5


# ============================================================================
# SMS: the worst case uses the real link budget; the rendering bound
# ============================================================================


def test_sms_units_use_the_real_unsubscribe_link_budget_not_30() -> None:
    service = MarketingService(
        _world().repo, settings=_settings(), senders=_senders(FakeEmailSender())
    )
    budget = service.sms_unsubscribe_link_budget()
    assert budget > 30
    # 110 GSM characters + the link: one segment at 30, two at the real length.
    body = ("x" * 110) + " {{unsubscribe_link}}"
    assert sms_worst_case_segments(body, unsubscribe_link_length=30) == 1
    units = units_per_recipient_max(
        Channel.SMS, {"sms_body": body}, unsubscribe_link_budget=budget
    )
    assert units == 2
    # A long review link is budgeted at its real length too.
    body2 = ("x" * 215) + " {{review_link}} {{unsubscribe_link}}"
    long_review = "https://g.page/r/" + "a" * 60
    assert (
        units_per_recipient_max(
            Channel.SMS,
            {"sms_body": body2, "review_link": long_review},
            unsubscribe_link_budget=budget,
        )
        > units_per_recipient_max(
            Channel.SMS, {"sms_body": body2}, unsubscribe_link_budget=budget
        )
    )


async def test_sms_debit_is_the_rendered_segments_at_the_snapshot_price() -> None:
    rig = _rig()
    await rig.topup(10_000)
    sms_sent: list[str] = []

    class Sms:
        provider = "exotel"

        async def send(self, to, body, *, dlt_template_id):
            sms_sent.append(body)
            return ProviderResult("exotel", f"s-{len(sms_sent)}")

    senders = MarketingSenders(
        sms=Sms(),
        whatsapp=None,
        email=None,
        statuses={
            Channel.SMS: ChannelStatus(Channel.SMS, True, "exotel", ChannelMode.LIVE, None),
            Channel.WHATSAPP: ChannelStatus(
                Channel.WHATSAPP, False, None, ChannelMode.LOGGING, "off"
            ),
            Channel.EMAIL: ChannelStatus(
                Channel.EMAIL, False, None, ChannelMode.LOGGING, "off"
            ),
        },
    )
    repo = rig.world.repo
    template = await repo.create_template(
        organization_id=ORG_A,
        system_key=None,
        name="Long SMS",
        category="offer",
        description=None,
        sms_body=("Big weekend offer at our cafe. " * 4) + "{{unsubscribe_link}}",
        sms_dlt_template_id="1107000000000000001",
        whatsapp_approval_status="not_submitted",
    )
    for key in ("a1_in", "a2_in"):
        guest = repo.guests[rig.world.guest_ids[key]]
        guest.identifier = "+9198" + str(abs(hash(key)))[:8].ljust(8, "1")
        repo.consents[(guest.id, "sms")] = _row(status="opted_in", source="captive_portal")

    async def _entitled(org):
        return True

    service = MarketingService(
        repo,
        settings=_settings(),
        senders=senders,
        now=lambda: NOW,
        entitlement_check=_entitled,
        credits=rig.credits,
    )
    campaign_id = await _create(rig, channel=Channel.SMS, template=template)
    detail = await service.schedule(
        _scope(ORG_A), campaign_id, scheduled_at=None, idempotency_key="idem-sms-1"
    )
    snapshot = repo.campaigns[campaign_id].price_snapshot
    assert snapshot["units_per_recipient_max"] == 2
    assert detail["credits"]["reserved_minor"] == 2 * 2 * 30
    await service.send_batch(campaign_id)
    debits = rig.ledger.rows_for(campaign_id, "debit")
    assert [(e.units, e.unit_price_minor) for e in debits] == [(2, 30), (2, 30)]
    assert rig.ledger.outstanding(campaign_id) == 0


# ============================================================================
# Low balance: once per crossing
# ============================================================================


async def test_low_balance_alert_fires_once_per_crossing() -> None:
    rig = _rig()
    wallets = rig.credits.wallets
    await wallets.topup(ORG_A, 12_000, idempotency_key="t1")
    assert rig.hook.calls == []  # top-ups never alert
    campaign = uuid.uuid4()
    await wallets.reserve(ORG_A, 3_000, idempotency_key="r1", campaign_id=campaign)
    assert rig.hook.calls == [9_000]  # crossed below 10,000
    await wallets.reserve(ORG_A, 1_000, idempotency_key="r2", campaign_id=campaign)
    assert rig.hook.calls == [9_000]  # still below: no second alert
    await wallets.topup(ORG_A, 5_000, idempotency_key="t2")  # back above: re-armed
    assert rig.wallet().low_balance_notified_at is None
    await wallets.adjust(ORG_A, -4_000, idempotency_key="a1")
    assert rig.hook.calls == [9_000, 9_000]


# ============================================================================
# Estimate, preview, customer credits payload
# ============================================================================


async def test_estimate_and_preview_estimate() -> None:
    rig = _rig()
    await rig.topup(7)
    service = rig.service()
    campaign_id = await _create(rig)
    estimate = await service.estimate(_scope(ORG_A), campaign_id)
    assert estimate == {
        "provider_source": "wyfy",
        "reachable": 2,
        "unit": "message",
        "unit_price_minor": 5,
        "units_per_recipient_max": 1,
        "estimated_max_minor": 10,
        "available_minor": 7,
        "sufficient": False,
    }
    preview = await service.audience_preview(
        _scope(ORG_A), AudienceFilter(channel=Channel.EMAIL)
    )
    assert preview["credit_estimate"] == {
        "provider_source": "wyfy",
        "unit": "message",
        "unit_price_minor": 5,
        "estimated_minor_per_unit_recipient": 5,
    }


async def test_org_override_and_inherit_in_the_price_book() -> None:
    prices = FakePriceRepository()
    book = PriceBook(prices, now=lambda: NOW)  # type: ignore[arg-type]
    await book.set_org_prices(
        ORG_A, [(Channel.SMS, 20)], note="deal", actor_user_id=uuid.uuid4()
    )
    quotes = await book.quotes(ORG_A)
    assert (quotes[Channel.SMS].unit_price_minor, quotes[Channel.SMS].source) == (
        20,
        "org_override",
    )
    assert quotes[Channel.EMAIL].source == "platform"
    book._now = lambda: NOW + timedelta(seconds=1)  # noqa: SLF001
    cleared = await book.set_org_prices(
        ORG_A, [(Channel.SMS, None)], note=None, actor_user_id=uuid.uuid4()
    )
    assert cleared["sms"] == {
        "unit": "segment",
        "unit_price_minor": 30,
        "source": "platform",
        "platform_unit_price_minor": 30,
    }
    view = await book.platform_view()
    assert [p["unit_price_minor"] for p in view["platform"]] == [30, 120, 5]
    assert view["org_overrides"] == []


async def test_customer_credits_payload_carries_prices_and_byo_channels() -> None:
    from tests.unit.test_marketing_credits import _service as credits_service

    service, *_ = credits_service()

    async def pricing(org, platform):
        return {"email": {"unit": "message", "unit_price_minor": 5, "source": "platform"}}, [
            "sms"
        ]

    service.pricing = pricing
    payload = await service.customer_balance(ORG_A)
    assert payload["prices"]["email"]["unit_price_minor"] == 5
    assert payload["byo_channels"] == ["sms"]


def test_draft_campaign_resource_has_null_credits() -> None:
    from app.domains.marketing.service import _campaign_credits

    draft = SimpleNamespace(status="draft", provider_source="wyfy", price_snapshot=None)
    assert _campaign_credits(draft, None) is None
    own = SimpleNamespace(status="sent", provider_source="own", price_snapshot=None)
    assert _campaign_credits(own, None) is None


# ============================================================================
# Master price-book routes: pinned GLOBAL
# ============================================================================

PRICE_ROUTES = [
    ("GET", "/api/v1/platform/marketing/price-book", "billing.read", None),
    (
        "PUT",
        "/api/v1/platform/marketing/price-book",
        "billing.manage",
        {"prices": [{"channel": "sms", "unit_price_minor": 25}]},
    ),
    (
        "PUT",
        "/api/v1/platform/organizations/{organization_id}/marketing-prices",
        "billing.manage",
        {"prices": [{"channel": "sms", "unit_price_minor": None}]},
    ),
]


@pytest.mark.parametrize(("method", "path", "permission", "_body"), PRICE_ROUTES)
def test_price_routes_pin_global_scope(method, path, permission, _body) -> None:
    from tests.unit.test_marketing_credits import _closure, _route

    route = _route(method, path)
    [dep] = [
        d.call
        for d in route.dependant.dependencies
        if getattr(d.call, "__qualname__", "").startswith("RequirePermission")
    ]
    assert {permission, "global"} <= _closure(dep)


@pytest.mark.parametrize(("method", "path", "permission", "body"), PRICE_ROUTES)
def test_org_scoped_billing_holder_gets_403_on_price_routes(
    method, path, permission, body
) -> None:
    from app.domains.rbac.enums import ScopeType
    from tests.unit.test_marketing_credits import ORG_B, _client

    client, seen = _client(granted_scope=ScopeType.ORGANIZATION, organization_id=ORG_B)
    response = client.request(
        method,
        path.replace("{organization_id}", str(ORG_B)),
        json=body,
        headers={"X-Organization-Id": str(ORG_B)},
    )
    assert response.status_code == 403, response.text
    assert seen == [(permission, ScopeType.GLOBAL)]


@pytest.mark.parametrize(
    "body",
    [
        {"prices": []},
        {"prices": [{"channel": "sms", "unit_price_minor": -1}]},
        {"prices": [{"channel": "sms", "unit_price_minor": 10_001}]},
        {"prices": [{"channel": "sms", "unit_price_minor": 1.5}]},
        {"prices": [{"channel": "fax", "unit_price_minor": 1}]},
        {
            "prices": [
                {"channel": "sms", "unit_price_minor": 1},
                {"channel": "sms", "unit_price_minor": 2},
            ]
        },
        {"prices": [{"channel": "sms", "unit_price_minor": None}]},  # platform: no null
    ],
)
def test_price_book_update_schema_refuses(body) -> None:
    from pydantic import ValidationError

    from app.domains.marketing.schemas import PriceBookUpdate

    with pytest.raises(ValidationError):
        PriceBookUpdate(**body)
