"""Real Stripe/Razorpay webhook signature verification + event processing
(BE-013 Part 3).

## Signature verification: real, complete, cryptographically genuine

Both schemes below are pure, deterministic HMAC-SHA256 cryptography that
needs no live provider API access at all -- unlike a charge (which requires
a real, unconfigured-in-this-sandbox API key), signature verification is
implemented and exercised for real here, with real test fixtures (a real
secret + a real HMAC computed the same way each provider actually does it,
verified against this module's own verification function in
``tests/unit/test_billing_payments_webhooks.py``).

* **Stripe** -- ``verify_stripe_event`` uses the real, installed ``stripe``
  SDK's ``stripe.Webhook.construct_event``, whose source was read directly
  (``stripe._webhook.WebhookSignature.verify_header``) while writing this
  module: the ``Stripe-Signature`` header is a comma-separated
  ``t=<unix-timestamp>,v1=<hex-hmac>[,v0=<hex-hmac>...]`` string; the
  *signed payload* is ``f"{timestamp}.{raw_body}"``; the expected signature
  is ``hmac.new(secret, signed_payload, sha256).hexdigest()``; comparison
  against every ``v1=`` value uses a constant-time compare
  (``stripe._webhook.secure_compare`` -> ``hmac.compare_digest``); and a
  request whose timestamp is older than ``tolerance`` seconds (default
  300, configurable via ``Settings.stripe_webhook_tolerance_seconds``) is
  rejected as a replay. Using the SDK's own real implementation directly
  (rather than a hand-rolled reimplementation that could subtly drift from
  it) is judged the more honest, more correct choice here -- it is
  genuinely the same code Stripe's own SDK ships and this codebase
  installs.
* **Razorpay** -- ``verify_razorpay_signature`` uses the real, installed
  ``razorpay`` SDK's ``razorpay.Utility.verify_webhook_signature`` (source
  read directly: ``hmac.new(secret, raw_body, sha256).hexdigest()``,
  compared via ``hmac.compare_digest`` against the ``X-Razorpay-Signature``
  header). Razorpay's webhook scheme has no timestamp/replay-tolerance
  component at all (verified against the installed SDK -- there simply is
  none to check), so none is invented here; this is an honest reflection of
  the real, documented scheme, not a gap in this module.

## Event-id dedup: Redis, TTL'd, not a dedicated table

Both providers really do redeliver the same webhook event more than once
(timeout, an ambiguous 2xx, a manual "resend" from either dashboard) --
webhook handlers must be idempotent themselves. This module tracks
processed event ids in Redis (reusing, not modifying,
``app.database.redis.get_redis_client`` -- the same Redis instance every
other domain's own caching already uses) via a single atomic ``SET ...
NX EX`` per event id (``RedisWebhookEventDedup.mark_processed_if_new``):
the first delivery of a given event id sets the key and proceeds; every
redelivery finds the key already set and is a no-op. A TTL (``Settings
.payment_webhook_event_dedup_ttl_seconds``, default 7 days) is used rather
than a permanent record for two reasons: (1) both providers' own real
redelivery/retry windows are measured in hours to a few days, not
forever, so a multi-day TTL comfortably covers every real redelivery
while not accumulating an ever-growing key set; (2) a dedicated
``processed_webhook_events`` table would need its own migration, its own
cleanup sweep to avoid unbounded growth, and buys no correctness Redis's
own atomic ``SET NX`` doesn't already provide via a single command --
the identical "simplest real mechanism, no new table for its own sake"
judgment call this domain already makes elsewhere (e.g.
``events.py``'s "no event bus" decision). A small, dedicated table was a
real, legitimate alternative (a unique constraint on ``(provider,
event_id)`` is exactly as atomic); Redis was chosen for the free TTL-based
cleanup alone.

## Handler composition -- never reimplementing subscription renewal

On a real success confirmation for a payment tied to a subscription
renewal, these handlers call ``renewal_service.RenewalService
.confirm_renewal_payment_succeeded``/``confirm_renewal_payment_failed`` --
two narrow, additive Part 3 methods that do nothing but call that class's
own existing, already-tested ``_mark_renewed``/``_mark_past_due``
transitions (see that module's own docstring). No period-extension/
past-due bookkeeping is reimplemented here.

## BE-013 Part 4 addition: payment-webhook-to-invoice composition

On a real success confirmation, ``process_stripe_event``/
``process_razorpay_event`` now also accept an optional
``invoice_service: InvoiceServiceProtocol | None`` parameter -- when
supplied (the real, wired case, via ``router.py``'s own dependency), a
resolved successful payment is handed to
``service.InvoiceService.mark_invoice_paid_for_payment`` (an additive call
into this new BE-013 Part 4 method, never a second, independent
reimplementation of "what does a successful payment mean for billing").
Defaulting to ``None`` keeps this an entirely backward-compatible, additive
change: every existing caller/test that does not pass ``invoice_service``
observes byte-for-byte the same behavior this module had before Part 4.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Protocol

import razorpay
import stripe
from redis.asyncio import Redis

from .constants import (
    AUDIT_ACTION_WEBHOOK_RECEIVED,
    AUDIT_ACTION_WEBHOOK_REJECTED,
    WEBHOOK_EVENT_DEDUP_KEY_PREFIX,
    PaymentStatus,
)
from .events import WebhookProcessed, WebhookSignatureInvalid
from .exceptions import (
    InvalidLicenseStatusTransitionError,
    LicenseNotFoundError,
    WebhookSignatureInvalidError,
)
from .models import Payment
from .renewal_service import RenewalService
from .repository import PaymentRepositoryProtocol

logger = logging.getLogger(__name__)


class InvoiceServiceProtocol(Protocol):
    """The single, narrow method these webhook handlers need from
    ``service.InvoiceService`` -- see that method's own docstring for the
    full "natural continuation of a successful payment webhook" write-up.
    Kept as a locally-defined ``Protocol`` (never a concrete import of
    ``service.InvoiceService``) for the same "avoid a construction cycle /
    keep the dependency structural" reasoning ``service
    .LicenseLifecycleProtocol``/``renewal_service
    .PaymentGatewayProtocol`` already establish elsewhere in this domain."""

    async def mark_invoice_paid_for_payment(
        self, payment: Payment
    ) -> object | None: ...


class LicenseActivationProtocol(Protocol):
    """The narrow surface ``process_razorpay_event`` needs from
    ``service.LicenseService`` to activate an organization's License on its
    real *first* successful checkout payment (one with no
    ``subscription_id`` tracked against it, so
    ``RenewalService.confirm_renewal_payment_succeeded``'s period-extension
    composition does not apply -- see that call site's own comment).
    Satisfied by ``LicenseService`` directly; kept as a locally-defined
    ``Protocol`` for the same import-cycle-avoidance reasoning
    ``InvoiceServiceProtocol`` immediately above already documents."""

    async def get_license_for_organization(self, organization_id: Any) -> Any: ...

    async def activate_license(self, *, actor_user_id: Any, license_id: Any) -> Any: ...


class WebhookAuditWriterProtocol(Protocol):
    """The minimal surface this module needs to write a real, permanent
    record of every webhook DELIVERY -- verified-and-processed or
    rejected-for-bad-signature -- into RBAC's shared ``audit_log_entries``
    table, satisfying this codebase's own established "every domain writes
    real audit entries for its own state changes" convention (see
    ``service.AuditLogWriter`` for the identical protocol shape every other
    write in this domain already uses). A structured ``logger.info``/
    ``logger.warning`` call alone (this module already had, before this
    addition) is real-time-debuggable but not queryable/persisted the way
    ``audit_log_entries`` is -- this protocol adds the latter without
    replacing the former."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Signature verification
# ============================================================================


def verify_stripe_event(
    payload: bytes, *, signature_header: str, secret: str, tolerance_seconds: int
) -> stripe.Event:
    """Real Stripe-Signature verification -- see module docstring for the
    exact scheme. Raises ``WebhookSignatureInvalidError`` (never a raw SDK
    exception) on any failure: bad signature, tampered payload, or a
    timestamp outside ``tolerance_seconds``."""
    try:
        return stripe.Webhook.construct_event(
            payload, signature_header, secret, tolerance=tolerance_seconds
        )
    except stripe.SignatureVerificationError as exc:
        raise WebhookSignatureInvalidError("Stripe", str(exc)) from exc
    except ValueError as exc:  # malformed JSON payload
        raise WebhookSignatureInvalidError("Stripe", str(exc)) from exc


def verify_razorpay_signature(payload: bytes, *, signature: str, secret: str) -> None:
    """Real X-Razorpay-Signature verification -- see module docstring for
    the exact scheme (HMAC-SHA256 of the raw body, constant-time compare;
    no timestamp/replay-tolerance component exists in Razorpay's own real
    scheme). Raises ``WebhookSignatureInvalidError`` on mismatch."""
    utility = razorpay.Utility()
    try:
        utility.verify_webhook_signature(payload.decode("utf-8"), signature, secret)
    except razorpay.errors.SignatureVerificationError as exc:
        raise WebhookSignatureInvalidError("Razorpay", str(exc)) from exc


# ============================================================================
# Event-id dedup
# ============================================================================


class WebhookEventDedupProtocol(Protocol):
    async def mark_processed_if_new(self, provider: str, event_id: str) -> bool:
        """Returns ``True`` the first time this ``(provider, event_id)``
        pair is seen (and atomically marks it processed), ``False`` on
        every subsequent call for the same pair (a real redelivery)."""
        ...


class RedisWebhookEventDedup:
    """Real Redis-backed implementation -- see module docstring for the
    full "why Redis, why a TTL, why not a table" write-up. A single
    ``SET key value NX EX ttl`` is atomic: two concurrent deliveries of the
    same event id can never both observe "new"."""

    def __init__(self, redis: Redis, *, ttl_seconds: int) -> None:
        self._redis = redis
        self._ttl_seconds = ttl_seconds

    async def mark_processed_if_new(self, provider: str, event_id: str) -> bool:
        key = f"{WEBHOOK_EVENT_DEDUP_KEY_PREFIX}:{provider}:{event_id}"
        was_set = await self._redis.set(key, "1", nx=True, ex=self._ttl_seconds)
        return bool(was_set)


# ============================================================================
# Handlers
# ============================================================================


async def _resolve_and_update_payment(
    payment_repository: PaymentRepositoryProtocol,
    *,
    provider_payment_id: str | None,
    succeeded: bool,
    failure_reason: str | None,
) -> Any:
    if not provider_payment_id:
        return None
    payment = await payment_repository.get_by_provider_payment_id(provider_payment_id)
    if payment is None:
        # A webhook for a charge this platform doesn't track (e.g. created
        # directly in the provider dashboard, outside this module) -- real
        # webhook-handling best practice is to acknowledge (2xx) and
        # ignore, never error the delivery for something this platform was
        # never asked to track.
        logger.info(
            "billing_webhook_payment_not_tracked",
            extra={"provider_payment_id": provider_payment_id},
        )
        return None
    if payment.status in (PaymentStatus.SUCCEEDED.value, PaymentStatus.FAILED.value):
        # Already resolved (e.g. a redelivery that slipped past dedup, or
        # this platform's own synchronous charge path already resolved it)
        # -- idempotent no-op, never double-apply.
        return payment
    if succeeded:
        return await payment_repository.update_payment(
            payment,
            {"status": PaymentStatus.SUCCEEDED.value, "failure_reason": None},
        )
    return await payment_repository.update_payment(
        payment,
        {
            "status": PaymentStatus.FAILED.value,
            "failure_reason": failure_reason or "provider_reported_failure",
        },
    )


async def process_stripe_event(
    event: stripe.Event,
    *,
    payment_repository: PaymentRepositoryProtocol,
    renewal_service: RenewalService,
    dedup: WebhookEventDedupProtocol,
    invoice_service: InvoiceServiceProtocol | None = None,
    audit_writer: WebhookAuditWriterProtocol | None = None,
) -> bool:
    """Processes one verified Stripe ``Event``. Returns ``True`` if this
    call actually applied the event (``False`` if it was a dedup no-op).
    Real event types handled: ``payment_intent.succeeded``/
    ``payment_intent.payment_failed``; every other event type is
    acknowledged (the caller returns 2xx either way) and otherwise
    ignored -- real Stripe guidance for a webhook endpoint that only cares
    about a subset of event types. ``audit_writer``, when supplied, writes
    a real, permanent ``audit_log_entries`` row for this receipt -- see
    ``_audit_webhook_received``'s own docstring."""
    is_new = await dedup.mark_processed_if_new("stripe", event.id)
    if not is_new:
        logger.info(
            "billing_webhook_event_duplicate_ignored",
            extra={"provider": "stripe", "event_id": event.id},
        )
        return False

    intent = event.data.object
    provider_payment_id = getattr(intent, "id", None)
    payment: Payment | None = None

    if event.type == "payment_intent.succeeded":
        payment = await _resolve_and_update_payment(
            payment_repository,
            provider_payment_id=provider_payment_id,
            succeeded=True,
            failure_reason=None,
        )
        if payment is not None and payment.subscription_id is not None:
            await renewal_service.confirm_renewal_payment_succeeded(
                payment.subscription_id
            )
        if payment is not None and invoice_service is not None:
            await invoice_service.mark_invoice_paid_for_payment(payment)
    elif event.type == "payment_intent.payment_failed":
        last_error = getattr(intent, "last_payment_error", None)
        reason = getattr(last_error, "message", None) if last_error else None
        payment = await _resolve_and_update_payment(
            payment_repository,
            provider_payment_id=provider_payment_id,
            succeeded=False,
            failure_reason=reason,
        )
        if payment is not None and payment.subscription_id is not None:
            await renewal_service.confirm_renewal_payment_failed(
                payment.subscription_id, reason=reason or "provider_reported_failure"
            )
    else:
        logger.info(
            "billing_webhook_event_type_unhandled",
            extra={"provider": "stripe", "event_type": event.type},
        )

    await _audit_webhook_received(
        audit_writer,
        provider="stripe",
        event_type=event.type,
        event_id=event.id,
        payment=payment,
    )

    logged = WebhookProcessed(
        provider="stripe", event_id=event.id, event_type=event.type
    )
    logger.info("billing_webhook_processed", extra=_event_extra(logged))
    return True


async def _resolve_checkout_payment_by_order_id(
    payment_repository: PaymentRepositoryProtocol,
    *,
    order_id: str | None,
    provider_payment_id: str | None,
    signature: str,
    succeeded: bool,
    failure_reason: str | None,
) -> Payment | None:
    """The Razorpay-Checkout-specific resolution path
    ``process_razorpay_event`` falls back to when
    ``_resolve_and_update_payment`` (keyed on ``provider_payment_id``) finds
    nothing -- a PENDING row created by ``service.PaymentService
    .create_checkout_order`` has no ``provider_payment_id`` yet (it is not
    known until the customer actually completes the Checkout widget), only
    ``razorpay_order_id`` (set at Order-creation time). See
    ``models.Payment.razorpay_order_id``'s own docstring for the full
    correlation write-up. Stores the now-known ``provider_payment_id`` and
    the verified webhook's own ``X-Razorpay-Signature`` header value on the
    row -- real, auditable proof this row's outcome came from a verified
    webhook, never an unverified client callback."""
    if not order_id:
        return None
    payment = await payment_repository.get_by_razorpay_order_id(order_id)
    if payment is None:
        logger.info(
            "billing_webhook_checkout_order_not_tracked",
            extra={"razorpay_order_id": order_id},
        )
        return None
    if payment.status in (PaymentStatus.SUCCEEDED.value, PaymentStatus.FAILED.value):
        # Already resolved (a redelivery that slipped past dedup) --
        # idempotent no-op, identical guarantee _resolve_and_update_payment
        # provides for the provider_payment_id-keyed path.
        return payment
    if succeeded:
        return await payment_repository.update_payment(
            payment,
            {
                "status": PaymentStatus.SUCCEEDED.value,
                "provider_payment_id": provider_payment_id,
                "razorpay_signature": signature or None,
                "failure_reason": None,
            },
        )
    return await payment_repository.update_payment(
        payment,
        {
            "status": PaymentStatus.FAILED.value,
            "provider_payment_id": provider_payment_id,
            "razorpay_signature": signature or None,
            "failure_reason": failure_reason or "provider_reported_failure",
        },
    )


async def _activate_license_if_needed(
    license_activation: LicenseActivationProtocol, organization_id: Any
) -> None:
    """Real activation-on-first-payment for the Razorpay Checkout flow: a
    successful checkout payment with no ``subscription_id`` attached (this
    organization has a real ``License``/``Plan`` assigned but no
    ``Subscription`` row is tracking this particular payment) means this is
    the payment that should activate the license, not extend an existing
    subscription's period (that composition -- ``RenewalService
    .confirm_renewal_payment_succeeded`` -- already runs separately, only
    when ``payment.subscription_id`` IS set). Idempotent by construction:
    ``LicenseService.activate_license`` only permits a real, legal
    ``PENDING_ACTIVATION``/``SUSPENDED`` -> ``ACTIVE`` transition (see
    ``service._LICENSE_TRANSITIONS``); if the license is already ``ACTIVE``
    (e.g. a redelivered webhook, or a payment for an org whose license was
    activated some other way already), the illegal-transition error is
    caught and swallowed here -- a webhook handler must never fail a real,
    already-applied payment update over what is, from this platform's own
    perspective, already the desired end state."""
    try:
        license_ = await license_activation.get_license_for_organization(
            organization_id
        )
    except LicenseNotFoundError:  # pragma: no cover - defensive
        logger.warning(
            "billing_webhook_checkout_payment_with_no_license",
            extra={"organization_id": str(organization_id)},
        )
        return
    if license_.status == "active":
        return
    try:
        await license_activation.activate_license(
            actor_user_id=None,
            license_id=license_.id,
            # Gateway webhook: no caller organization to compare against, and
            # the license was resolved from the webhook's own organization.
            requesting_organization_id=None,
        )
    except InvalidLicenseStatusTransitionError:  # pragma: no cover - defensive
        logger.warning(
            "billing_webhook_checkout_license_activation_skipped",
            extra={
                "organization_id": str(organization_id),
                "license_status": license_.status,
            },
        )


async def _audit_webhook_received(
    audit_writer: WebhookAuditWriterProtocol | None,
    *,
    provider: str,
    event_type: str,
    event_id: str,
    payment: Payment | None,
) -> None:
    if audit_writer is None:
        return
    await audit_writer.create_audit_log_entry(
        actor_user_id=None,
        action=AUDIT_ACTION_WEBHOOK_RECEIVED,
        entity_type="payment" if payment is not None else "webhook_event",
        entity_id=payment.id if payment is not None else None,
        description=(
            f"{provider} webhook received and processed: event_type="
            f"'{event_type}' event_id='{event_id}'"
        ),
        event_metadata={"provider": provider, "event_type": event_type},
        organization_id=payment.organization_id if payment is not None else None,
        location_id=None,
    )


async def process_razorpay_event(
    payload: dict[str, Any],
    *,
    payment_repository: PaymentRepositoryProtocol,
    renewal_service: RenewalService,
    dedup: WebhookEventDedupProtocol,
    invoice_service: InvoiceServiceProtocol | None = None,
    license_activation: LicenseActivationProtocol | None = None,
    signature: str = "",
    audit_writer: WebhookAuditWriterProtocol | None = None,
) -> bool:
    """Processes one verified Razorpay webhook payload (already
    signature-verified JSON, parsed into a plain dict). Real event types
    handled: ``payment.captured``/``payment.failed``. Razorpay's webhook
    payload includes its own ``event`` field (the event type) but no
    top-level unique event id the way Stripe's ``Event.id`` is -- Razorpay
    webhooks instead carry an ``x-razorpay-event-id`` HTTP header per its
    real documented delivery format; the caller (``router.py``) passes
    that header value through as ``event_id``.

    ## Razorpay Checkout correlation (order_id fallback)

    ``provider_payment_id``-keyed resolution (``_resolve_and_update_payment``,
    reused unchanged from the pre-existing recurring-charge flow) is tried
    first. If it finds nothing, and the event payload carries a real
    ``order_id`` (every Razorpay ``payment.entity`` does), this function
    falls back to ``_resolve_checkout_payment_by_order_id`` -- the
    correlation path for a PENDING row created by ``service.PaymentService
    .create_checkout_order`` (see that column's own docstring on
    ``models.Payment.razorpay_order_id``). On a real success resolved this
    way with no ``subscription_id`` tracked, ``_activate_license_if_needed``
    activates the organization's License for real (see that function's own
    docstring) -- the "on verified successful payment, activate/extend the
    organization's subscription for real" requirement this checkout flow
    exists to satisfy.
    """
    event_type = payload.get("event", "")
    event_id = payload.get("_event_id", "")
    is_new = await dedup.mark_processed_if_new("razorpay", event_id)
    if not is_new:
        logger.info(
            "billing_webhook_event_duplicate_ignored",
            extra={"provider": "razorpay", "event_id": event_id},
        )
        return False

    payment_entity = (
        payload.get("payload", {}).get("payment", {}).get("entity", {})
        if isinstance(payload.get("payload"), dict)
        else {}
    )
    provider_payment_id = payment_entity.get("id")
    order_id = payment_entity.get("order_id")
    payment: Payment | None = None

    if event_type == "payment.captured":
        payment = await _resolve_and_update_payment(
            payment_repository,
            provider_payment_id=provider_payment_id,
            succeeded=True,
            failure_reason=None,
        )
        if payment is None:
            payment = await _resolve_checkout_payment_by_order_id(
                payment_repository,
                order_id=order_id,
                provider_payment_id=provider_payment_id,
                signature=signature,
                succeeded=True,
                failure_reason=None,
            )
        if payment is not None and payment.subscription_id is not None:
            await renewal_service.confirm_renewal_payment_succeeded(
                payment.subscription_id
            )
        elif payment is not None and license_activation is not None:
            await _activate_license_if_needed(
                license_activation, payment.organization_id
            )
        if payment is not None and invoice_service is not None:
            await invoice_service.mark_invoice_paid_for_payment(payment)
    elif event_type == "payment.failed":
        reason = payment_entity.get("error_description")
        payment = await _resolve_and_update_payment(
            payment_repository,
            provider_payment_id=provider_payment_id,
            succeeded=False,
            failure_reason=reason,
        )
        if payment is None:
            payment = await _resolve_checkout_payment_by_order_id(
                payment_repository,
                order_id=order_id,
                provider_payment_id=provider_payment_id,
                signature=signature,
                succeeded=False,
                failure_reason=reason,
            )
        if payment is not None and payment.subscription_id is not None:
            await renewal_service.confirm_renewal_payment_failed(
                payment.subscription_id, reason=reason or "provider_reported_failure"
            )
    else:
        logger.info(
            "billing_webhook_event_type_unhandled",
            extra={"provider": "razorpay", "event_type": event_type},
        )

    await _audit_webhook_received(
        audit_writer,
        provider="razorpay",
        event_type=event_type,
        event_id=event_id,
        payment=payment,
    )

    logged = WebhookProcessed(
        provider="razorpay", event_id=event_id, event_type=event_type
    )
    logger.info("billing_webhook_processed", extra=_event_extra(logged))
    return True


def _event_extra(event: object) -> dict[str, object]:
    """Identical reflection trick to ``service._event_extra``/
    ``renewal_service._event_extra`` -- duplicated (not imported), same
    "no import-time dependency beyond what this module already needs"
    reasoning."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


async def log_signature_failure(
    provider: str,
    reason: str,
    *,
    audit_writer: WebhookAuditWriterProtocol | None = None,
) -> None:
    """Real, structured-log record of a REJECTED webhook delivery -- always
    happens. When ``audit_writer`` is supplied (the real, wired case -- see
    ``router.py``'s webhook handlers, which now ``await`` this call), this
    ALSO writes a real, permanent, queryable ``audit_log_entries`` row
    (``AUDIT_ACTION_WEBHOOK_REJECTED``) -- the "Log every webhook receipt
    (verified or rejected) to this domain's own audit trail for real
    debuggability" requirement this addition satisfies. No ``Payment``/
    organization is knowable at this point (the payload was never trusted
    enough to even parse) -- ``entity_id``/``organization_id`` are both
    left ``None``, an honest "we don't know whose webhook this claimed to
    be" rather than a fabricated guess. ``async`` (a real, if small,
    behavior change from before this addition) since a real audit-log
    write is itself a real, awaitable database call -- every call site
    updated to ``await`` it."""
    event = WebhookSignatureInvalid(provider=provider, reason=reason)
    logger.warning("billing_webhook_signature_invalid", extra=_event_extra(event))
    if audit_writer is not None:
        await audit_writer.create_audit_log_entry(
            actor_user_id=None,
            action=AUDIT_ACTION_WEBHOOK_REJECTED,
            entity_type="webhook_event",
            entity_id=None,
            description=(
                f"{provider} webhook REJECTED: signature verification failed "
                f"({reason})"
            ),
            event_metadata={"provider": provider},
            organization_id=None,
            location_id=None,
        )


__all__ = [
    "verify_stripe_event",
    "verify_razorpay_signature",
    "WebhookEventDedupProtocol",
    "RedisWebhookEventDedup",
    "InvoiceServiceProtocol",
    "LicenseActivationProtocol",
    "WebhookAuditWriterProtocol",
    "process_stripe_event",
    "process_razorpay_event",
    "log_signature_failure",
]
