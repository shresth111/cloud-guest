"""Renewal Engine (BE-013 Part 2): due-date detection, real per-subscription
renewal processing, grace-period-then-expire composition with Part 1's
deferred ``LicenseService.expire_license``, and renewal/expiry reminder
emails.

## The ``PaymentGatewayProtocol`` seam -- read this first

A real subscription renewal for a paid plan needs to actually charge money.
BE-013 Part 3 (Payment Service + real Stripe/Razorpay SDK integration +
webhooks) is what will build that -- it does not exist yet, and this part
must not build any part of it itself (out of scope, and this part has no
way to test against a real gateway anyway). This is exactly the same kind
of forward-looking seam this codebase has built before:

* BE-009 Part 2 built ``app.domains.router_provisioning.service
  .RouterProvisioningService.complete_provisioning_job`` as an explicit,
  documented, not-yet-called seam for BE-010's ``router_agent`` to call
  later -- and BE-010 then genuinely called it, unmodified.
* ``app.domains.otp.service.EmailProviderProtocol`` /
  ``LoggingEmailProvider`` is the identical shape one level removed: a
  narrow ``Protocol`` plus an honest interim default, reused here verbatim
  (see below) rather than rebuilt.

``process_renewal`` does **everything real it can do today**: it determines
whether a renewal is genuinely due, computes the real charge amount (the
plan's own ``base_price`` -- see the "coupon applies once" decision in
``service.CouponService``'s own docstring for why no per-renewal coupon
recomputation happens here), and -- on success -- extends
``current_period_end`` by a real, calendar-correct billing cycle and clears
any ``PAST_DUE`` status. For the one step it genuinely cannot do honestly
yet -- "actually charge the customer" -- it calls through
:class:`PaymentGatewayProtocol`, a ``Protocol`` with exactly one method,
wired via dependency injection (``dependencies.get_payment_gateway``) to
:class:`UnconfiguredPaymentGateway`, the honest default implementation this
part ships:

* A zero-amount charge (a ``FREE_TRIAL`` plan, or any plan whose
  ``base_price`` is ``0``) genuinely needs no real payment -- it
  auto-succeeds.
* Any real (non-zero) charge raises ``PaymentGatewayNotConfiguredError`` --
  a clear, typed, honestly-labelled error, never a silently-faked
  "success".

**What BE-013 Part 3 needs to do to plug in real billing, precisely:**
implement :class:`PaymentGatewayProtocol` against the real Stripe/Razorpay
SDK (a class with one async ``charge(...) -> PaymentResult`` method), and
override the ``dependencies.get_payment_gateway`` FastAPI dependency (and
the equivalent construction in ``tasks.py``'s Celery bridge) to return it
instead of ``UnconfiguredPaymentGateway()``. Nothing in ``process_renewal``,
``process_due_renewals``, or any caller of either needs to change -- the
seam is the entire integration point, by design.

## Grace period + expiry -- finally calling Part 1's deferred ``expire_license``

Part 1's own ``docs/billing/FLOW.md`` §6 explicitly deferred wiring any
automatic Celery Beat sweep for ``LicenseService.expire_license`` to "the
Renewal engine (a later BE-013 part)", precisely because what should happen
the instant a license lapses is a policy question only a real renewal
concept can answer. This module is that later part:
``expire_lapsed_subscriptions`` is the real, configurable-grace-period
policy -- a subscription that has been ``PAST_DUE`` for longer than
``Settings.subscription_renewal_grace_period_days`` finally has its License
hard-expired via a genuine call to ``LicenseService.expire_license``
(unmodified, exactly as Part 1 built and tested it), and the ``Subscription``
itself transitions to ``CANCELLED``.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Protocol

from app.domains.otp.service import EmailProviderProtocol, LoggingEmailProvider
from app.domains.rbac.enums import AuditAction

from .constants import RENEWABLE_SUBSCRIPTION_STATUSES, SubscriptionStatus
from .events import (
    ExpiryReminderSent,
    RenewalReminderSent,
    SubscriptionCancelled,
    SubscriptionExpiredAfterGracePeriod,
    SubscriptionRenewalFailed,
    SubscriptionRenewed,
)
from .exceptions import (
    InvalidSubscriptionStatusForRenewalError,
    PaymentGatewayNotConfiguredError,
    PlanNotFoundError,
    SubscriptionNotFoundError,
)
from .models import Subscription
from .repository import PlanRepositoryProtocol, SubscriptionRepositoryProtocol
from .service import AuditLogWriter, LicenseLifecycleProtocol
from .validators import add_billing_cycle

logger = logging.getLogger(__name__)


# ============================================================================
# The PaymentGatewayProtocol seam
# ============================================================================


@dataclass(frozen=True, slots=True)
class PaymentResult:
    """The outcome of one real (or honestly-simulated) charge attempt.
    ``success=False`` is a legitimate, expected business outcome (a card
    declined, insufficient funds, ...) -- distinct from
    ``PaymentGatewayNotConfiguredError``, which signals "this seam itself
    has not been wired to a real gateway yet" (an infrastructure/
    configuration state, not a payment decision), and is therefore raised
    as an exception rather than returned as a failed :class:`PaymentResult`.
    """

    success: bool
    reference: str | None = None
    failure_reason: str | None = None


class PaymentGatewayProtocol(Protocol):
    """The narrow seam BE-013 Part 3 plugs a real Stripe/Razorpay-backed
    implementation into, via dependency injection
    (``dependencies.get_payment_gateway``) -- see module docstring for the
    full write-up. Exactly one method, by design: this part's own renewal
    logic (due-date detection, amount computation, period extension) is
    real and stays here; only the literal "move money" step is behind this
    seam."""

    async def charge(
        self,
        *,
        organization_id: uuid.UUID,
        amount: Decimal,
        currency: str,
        subscription_id: uuid.UUID,
    ) -> PaymentResult: ...


class UnconfiguredPaymentGateway:
    """The honest default :class:`PaymentGatewayProtocol` implementation
    this part wires in (see module docstring). A zero-amount charge (a
    ``FREE_TRIAL`` renewal, or any plan whose ``base_price`` is genuinely
    ``0``) needs no real payment processor and auto-succeeds; any real,
    non-zero charge raises :class:`PaymentGatewayNotConfiguredError` -- a
    clear, typed signal that BE-013 Part 3's real gateway has not been
    wired in yet, never a silently-faked success."""

    async def charge(
        self,
        *,
        organization_id: uuid.UUID,
        amount: Decimal,
        currency: str,
        subscription_id: uuid.UUID,
    ) -> PaymentResult:
        if amount <= 0:
            logger.info(
                "billing_payment_gateway_zero_amount_auto_succeeded",
                extra={
                    "organization_id": str(organization_id),
                    "subscription_id": str(subscription_id),
                },
            )
            return PaymentResult(success=True)
        raise PaymentGatewayNotConfiguredError(
            organization_id=organization_id, amount=amount, currency=currency
        )


# ============================================================================
# Narrow cross-domain lookups
# ============================================================================


class OrganizationContactLookupProtocol(Protocol):
    """The single method ``RenewalService`` needs to send a reminder email
    -- satisfied by the real ``app.domains.organization.service
    .OrganizationService`` directly (its returned ``Organization`` carries
    a real, required ``contact_email`` column)."""

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class RenewalSweepResult:
    subscriptions_checked: int
    renewed: int
    failed: list[tuple[uuid.UUID, str]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RenewalSweepReport:
    """The full result of one ``RenewalService.run_renewal_sweep`` tick --
    what the Celery Beat task (``tasks.run_subscription_renewal_sweep``)
    logs/returns."""

    renewal: RenewalSweepResult
    expired_subscription_ids: list[uuid.UUID]
    renewal_reminders_sent: int
    expiry_reminders_sent: int


class RenewalService:
    """Real due-date detection + renewal processing, grace-period-then-
    expire composition with Part 1's ``LicenseService.expire_license``, and
    renewal/expiry reminder dispatch. See module docstring for the full
    ``PaymentGatewayProtocol`` seam write-up."""

    def __init__(
        self,
        repository: SubscriptionRepositoryProtocol,
        plan_repository: PlanRepositoryProtocol,
        *,
        license_service: LicenseLifecycleProtocol,
        organization_lookup: OrganizationContactLookupProtocol,
        payment_gateway: PaymentGatewayProtocol | None = None,
        email_provider: EmailProviderProtocol | None = None,
        audit_writer: AuditLogWriter | None = None,
        grace_period_days: int = 7,
        renewal_reminder_days_before: int = 3,
        expiry_reminder_days_before: int = 3,
    ) -> None:
        self.repository = repository
        self.plan_repository = plan_repository
        self.license_service = license_service
        self.organization_lookup = organization_lookup
        self.payment_gateway: PaymentGatewayProtocol = (
            payment_gateway or UnconfiguredPaymentGateway()
        )
        self.email_provider: EmailProviderProtocol = (
            email_provider or LoggingEmailProvider()
        )
        self.audit_writer = audit_writer
        self.grace_period_days = grace_period_days
        self.renewal_reminder_days_before = renewal_reminder_days_before
        self.expiry_reminder_days_before = expiry_reminder_days_before

    # ========================================================================
    # Renewal processing
    # ========================================================================

    async def process_renewal(self, subscription_id: uuid.UUID) -> Subscription:
        """Real due-date check (via the ``cancel_at_period_end`` fast path)
        + real charge-amount computation + the ``PaymentGatewayProtocol``
        seam call. On success: extends ``current_period_end`` by a real,
        calendar-correct billing cycle and clears ``PAST_DUE``. On failure
        (including "not configured"): transitions to ``PAST_DUE`` and
        records why."""
        subscription = await self.repository.get_by_id(subscription_id)
        if subscription is None:
            raise SubscriptionNotFoundError(subscription_id)

        status = SubscriptionStatus(subscription.status)
        if status not in RENEWABLE_SUBSCRIPTION_STATUSES:
            raise InvalidSubscriptionStatusForRenewalError(subscription.status)

        now = datetime.now(UTC)
        if subscription.cancel_at_period_end and subscription.current_period_end <= now:
            return await self._finalize_scheduled_cancellation(subscription)

        plan = await self.plan_repository.get_by_id(subscription.plan_id)
        if plan is None:
            raise PlanNotFoundError(subscription.plan_id)

        # Coupon applies once, at signup, never re-applied on renewal --
        # see service.CouponService's own docstring for the full decision.
        charge_amount = plan.base_price

        try:
            result = await self.payment_gateway.charge(
                organization_id=subscription.organization_id,
                amount=charge_amount,
                currency=plan.currency,
                subscription_id=subscription.id,
            )
        except PaymentGatewayNotConfiguredError as exc:
            return await self._mark_past_due(subscription, reason=str(exc))

        if not result.success:
            return await self._mark_past_due(
                subscription, reason=result.failure_reason or "payment_declined"
            )
        return await self._mark_renewed(subscription, plan, charge_amount)

    async def process_due_renewals(self) -> RenewalSweepResult:
        """Queries every subscription with ``current_period_end <= now``,
        ``auto_renew=True``, a cyclic ``billing_cycle``, and a renewable
        ``status`` -- then processes each via ``process_renewal`` with real
        per-subscription failure isolation (mirroring BE-012 Part 1's exact
        resilience pattern: one subscription's renewal blowing up never
        aborts the sweep for every other due subscription)."""
        now = datetime.now(UTC)
        due = await self.repository.list_due_for_renewal(now=now)
        renewed = 0
        failed: list[tuple[uuid.UUID, str]] = []
        for subscription in due:
            try:
                result = await self.process_renewal(subscription.id)
                if result.status == SubscriptionStatus.ACTIVE.value:
                    renewed += 1
            except Exception as exc:  # noqa: BLE001 -- per-subscription isolation
                logger.exception(
                    "billing_subscription_renewal_sweep_item_failed",
                    extra={"subscription_id": str(subscription.id)},
                )
                failed.append((subscription.id, str(exc)))
        return RenewalSweepResult(
            subscriptions_checked=len(due), renewed=renewed, failed=failed
        )

    # ========================================================================
    # BE-013 Part 3: real-gateway webhook confirmation seam
    #
    # A real Stripe charge is not always synchronous -- an off-session
    # renewal charge can require additional authentication (SCA/3-D Secure)
    # and only resolve, asynchronously, via a later
    # payment_intent.succeeded/payment_intent.payment_failed webhook (see
    # payment_gateways.py's own module docstring). These two narrow,
    # additive public methods are the composition point
    # webhooks.py's handlers call once a provider webhook confirms that
    # outcome -- they do nothing but call this class's own existing,
    # already-tested _mark_renewed/_mark_past_due transitions (never a
    # second, parallel reimplementation of period-extension/past-due
    # bookkeeping).
    # ========================================================================

    async def confirm_renewal_payment_succeeded(
        self, subscription_id: uuid.UUID
    ) -> Subscription:
        """Called by ``webhooks.py`` once a provider webhook confirms an
        (async) charge tied to this subscription's renewal succeeded.
        Composes with -- never reimplements -- ``_mark_renewed``, the exact
        same transition ``process_renewal``'s own synchronous success path
        already performs."""
        subscription = await self.repository.get_by_id(subscription_id)
        if subscription is None:
            raise SubscriptionNotFoundError(subscription_id)
        plan = await self.plan_repository.get_by_id(subscription.plan_id)
        if plan is None:
            raise PlanNotFoundError(subscription.plan_id)
        return await self._mark_renewed(subscription, plan, plan.base_price)

    async def confirm_renewal_payment_failed(
        self, subscription_id: uuid.UUID, *, reason: str
    ) -> Subscription:
        """Called by ``webhooks.py`` once a provider webhook confirms an
        (async) charge tied to this subscription's renewal failed. Composes
        with -- never reimplements -- ``_mark_past_due``, the exact same
        transition ``process_renewal``'s own synchronous failure path
        already performs."""
        subscription = await self.repository.get_by_id(subscription_id)
        if subscription is None:
            raise SubscriptionNotFoundError(subscription_id)
        return await self._mark_past_due(subscription, reason=reason)

    async def _mark_renewed(
        self, subscription: Subscription, plan: object, charge_amount: Decimal
    ) -> Subscription:
        now = datetime.now(UTC)
        updated = await self.repository.update_subscription(
            subscription,
            {
                "status": SubscriptionStatus.ACTIVE.value,
                "current_period_start": now,
                "current_period_end": add_billing_cycle(
                    now, subscription.billing_cycle
                ),
                "past_due_at": None,
            },
        )
        event = SubscriptionRenewed(
            subscription_id=updated.id,
            organization_id=updated.organization_id,
            amount_charged=str(charge_amount),
        )
        logger.info("billing_subscription_renewed", extra=_event_extra(event))
        await self._audit(
            AuditAction.SUBSCRIPTION_RENEWED,
            updated,
            description=(
                f"Subscription {updated.id} renewed "
                f"(charged {charge_amount} {getattr(plan, 'currency', '')})"
            ),
        )
        return updated

    async def _mark_past_due(
        self, subscription: Subscription, *, reason: str
    ) -> Subscription:
        data: dict[str, object] = {"status": SubscriptionStatus.PAST_DUE.value}
        if subscription.past_due_at is None:
            data["past_due_at"] = datetime.now(UTC)
        updated = await self.repository.update_subscription(subscription, data)
        event = SubscriptionRenewalFailed(
            subscription_id=updated.id,
            organization_id=updated.organization_id,
            reason=reason,
        )
        logger.warning("billing_subscription_renewal_failed", extra=_event_extra(event))
        await self._audit(
            AuditAction.SUBSCRIPTION_RENEWAL_FAILED,
            updated,
            description=f"Subscription {updated.id} renewal failed: {reason}",
        )
        return updated

    async def _finalize_scheduled_cancellation(
        self, subscription: Subscription
    ) -> Subscription:
        now = datetime.now(UTC)
        updated = await self.repository.update_subscription(
            subscription,
            {
                "status": SubscriptionStatus.CANCELLED.value,
                "cancelled_at": now,
                "auto_renew": False,
                "past_due_at": None,
            },
        )
        await self.license_service.suspend_license(
            actor_user_id=None,
            license_id=updated.license_id,
            reason="Subscription's scheduled (cancel-at-period-end) cancellation "
            "took effect",
        )
        event = SubscriptionCancelled(
            subscription_id=updated.id,
            organization_id=updated.organization_id,
            immediate=False,
        )
        logger.info(
            "billing_subscription_scheduled_cancellation_finalized",
            extra=_event_extra(event),
        )
        await self._audit(
            AuditAction.SUBSCRIPTION_CANCELLED,
            updated,
            description=(
                f"Subscription {updated.id}'s scheduled cancel-at-period-end "
                "took effect"
            ),
        )
        return updated

    # ========================================================================
    # Grace period -> license expiry (composes Part 1's deferred
    # LicenseService.expire_license -- see module docstring)
    # ========================================================================

    async def expire_lapsed_subscriptions(self) -> list[uuid.UUID]:
        """For every ``PAST_DUE`` subscription whose grace period
        (``past_due_at + Settings.subscription_renewal_grace_period_days``)
        has elapsed: calls Part 1's real, unmodified
        ``LicenseService.expire_license`` and transitions the subscription
        to ``CANCELLED``. Per-subscription failure isolation, same as
        ``process_due_renewals``."""
        now = datetime.now(UTC)
        past_due = await self.repository.list_by_status(
            [SubscriptionStatus.PAST_DUE.value]
        )
        expired_ids: list[uuid.UUID] = []
        for subscription in past_due:
            if subscription.past_due_at is None:
                continue
            grace_deadline = subscription.past_due_at + timedelta(
                days=self.grace_period_days
            )
            if grace_deadline > now:
                continue
            try:
                await self.license_service.expire_license(
                    license_id=subscription.license_id
                )
                updated = await self.repository.update_subscription(
                    subscription,
                    {
                        "status": SubscriptionStatus.CANCELLED.value,
                        "cancelled_at": now,
                        "auto_renew": False,
                        "past_due_at": None,
                    },
                )
            except Exception:  # noqa: BLE001 -- per-subscription isolation
                logger.exception(
                    "billing_subscription_grace_period_expiry_failed",
                    extra={"subscription_id": str(subscription.id)},
                )
                continue
            expired_ids.append(updated.id)
            event = SubscriptionExpiredAfterGracePeriod(
                subscription_id=updated.id,
                organization_id=updated.organization_id,
                license_id=updated.license_id,
            )
            logger.warning(
                "billing_subscription_expired_after_grace_period",
                extra=_event_extra(event),
            )
            await self._audit(
                AuditAction.SUBSCRIPTION_EXPIRED_AFTER_GRACE_PERIOD,
                updated,
                description=(
                    f"Subscription {updated.id}'s license expired after its "
                    f"{self.grace_period_days}-day grace period lapsed"
                ),
            )
        return expired_ids

    # ========================================================================
    # Reminders
    # ========================================================================

    async def send_renewal_reminders(self) -> int:
        """Upcoming-renewal reminder -- once per billing period (see
        ``Subscription.last_renewal_reminder_sent_at``), for every renewable
        subscription whose ``current_period_end`` falls within
        ``Settings.subscription_renewal_reminder_days_before`` days."""
        now = datetime.now(UTC)
        window_end = now + timedelta(days=self.renewal_reminder_days_before)
        candidates = await self.repository.list_by_status(
            [SubscriptionStatus.TRIALING.value, SubscriptionStatus.ACTIVE.value]
        )
        sent = 0
        for subscription in candidates:
            if not subscription.auto_renew:
                continue
            if not (now <= subscription.current_period_end <= window_end):
                continue
            already_reminded_this_period = (
                subscription.last_renewal_reminder_sent_at is not None
                and subscription.last_renewal_reminder_sent_at
                >= subscription.current_period_start
            )
            if already_reminded_this_period:
                continue
            await self._send_reminder_email(
                subscription,
                subject="Your CloudGuest subscription renews soon",
                body=(
                    f"Your subscription is scheduled to renew on "
                    f"{subscription.current_period_end.isoformat()}."
                ),
            )
            await self.repository.update_subscription(
                subscription, {"last_renewal_reminder_sent_at": now}
            )
            event = RenewalReminderSent(
                subscription_id=subscription.id,
                organization_id=subscription.organization_id,
            )
            logger.info("billing_renewal_reminder_sent", extra=_event_extra(event))
            sent += 1
        return sent

    async def send_expiry_reminders(self) -> int:
        """License-expiring-soon reminder -- once per past-due episode (see
        ``Subscription.last_expiry_reminder_sent_at``), for every
        ``PAST_DUE`` subscription whose grace-period deadline falls within
        ``Settings.subscription_expiry_reminder_days_before`` days."""
        now = datetime.now(UTC)
        past_due = await self.repository.list_by_status(
            [SubscriptionStatus.PAST_DUE.value]
        )
        sent = 0
        for subscription in past_due:
            if subscription.past_due_at is None:
                continue
            grace_deadline = subscription.past_due_at + timedelta(
                days=self.grace_period_days
            )
            if grace_deadline <= now:
                continue  # already past deadline -- expire_lapsed_subscriptions' job
            if grace_deadline - now > timedelta(days=self.expiry_reminder_days_before):
                continue
            already_reminded_this_episode = (
                subscription.last_expiry_reminder_sent_at is not None
                and subscription.last_expiry_reminder_sent_at
                >= subscription.past_due_at
            )
            if already_reminded_this_episode:
                continue
            await self._send_reminder_email(
                subscription,
                subject="Action needed: your CloudGuest license will expire soon",
                body=(
                    "Your most recent renewal attempt failed. Unless resolved, "
                    f"your license will expire on {grace_deadline.isoformat()}."
                ),
            )
            await self.repository.update_subscription(
                subscription, {"last_expiry_reminder_sent_at": now}
            )
            event = ExpiryReminderSent(
                subscription_id=subscription.id,
                organization_id=subscription.organization_id,
            )
            logger.info("billing_expiry_reminder_sent", extra=_event_extra(event))
            sent += 1
        return sent

    async def _send_reminder_email(
        self, subscription: Subscription, *, subject: str, body: str
    ) -> None:
        organization = await self.organization_lookup.get_organization(
            subscription.organization_id
        )
        await self.email_provider.send(organization.contact_email, subject, body)

    # ========================================================================
    # The single Beat-scheduled entrypoint (tasks.run_subscription_renewal_sweep)
    # ========================================================================

    async def run_renewal_sweep(self) -> RenewalSweepReport:
        """The one method the Celery Beat task calls -- runs every phase in
        a defensible order (renew due subscriptions first, then expire
        whichever ones have now exhausted their grace period, then send
        both kinds of reminder for whatever remains), with each phase
        isolated from the others' failures the same way each phase already
        isolates one subscription's failure from its siblings."""
        renewal_result = RenewalSweepResult(subscriptions_checked=0, renewed=0)
        try:
            renewal_result = await self.process_due_renewals()
        except Exception:  # noqa: BLE001 -- phase isolation
            logger.exception(
                "billing_renewal_sweep_phase_failed", extra={"phase": "renew"}
            )

        expired_ids: list[uuid.UUID] = []
        try:
            expired_ids = await self.expire_lapsed_subscriptions()
        except Exception:  # noqa: BLE001 -- phase isolation
            logger.exception(
                "billing_renewal_sweep_phase_failed", extra={"phase": "expire"}
            )

        renewal_reminders_sent = 0
        try:
            renewal_reminders_sent = await self.send_renewal_reminders()
        except Exception:  # noqa: BLE001 -- phase isolation
            logger.exception(
                "billing_renewal_sweep_phase_failed",
                extra={"phase": "renewal_reminders"},
            )

        expiry_reminders_sent = 0
        try:
            expiry_reminders_sent = await self.send_expiry_reminders()
        except Exception:  # noqa: BLE001 -- phase isolation
            logger.exception(
                "billing_renewal_sweep_phase_failed",
                extra={"phase": "expiry_reminders"},
            )

        return RenewalSweepReport(
            renewal=renewal_result,
            expired_subscription_ids=expired_ids,
            renewal_reminders_sent=renewal_reminders_sent,
            expiry_reminders_sent=expiry_reminders_sent,
        )

    async def _audit(
        self,
        action: AuditAction,
        subscription: Subscription,
        *,
        description: str,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=None,
                action=action.value,
                entity_type="subscription",
                entity_id=subscription.id,
                description=description,
                event_metadata={},
                organization_id=subscription.organization_id,
                location_id=None,
            )
        logger.info(
            "billing_renewal_service_audit_event", extra={"action": action.value}
        )


def _event_extra(event: object) -> dict[str, object]:
    """Identical reflection trick to ``service._event_extra`` -- duplicated
    (not imported) so this module has no import-time dependency on
    ``service.py`` beyond the one narrow ``LicenseLifecycleProtocol``/
    ``AuditLogWriter`` types it already imports from there."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


__all__ = [
    "PaymentResult",
    "PaymentGatewayProtocol",
    "UnconfiguredPaymentGateway",
    "OrganizationContactLookupProtocol",
    "RenewalSweepResult",
    "RenewalSweepReport",
    "RenewalService",
]
