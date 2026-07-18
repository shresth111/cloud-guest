"""Voucher business logic: batch lifecycle (create/submit/approve/activate/
revoke), bulk code generation, validation/redemption, CSV export, pre-
printed code import, and per-batch statistics.

Design notes worth calling out up front (see ``docs/voucher/FLOW.md`` for
the full write-up):

## Plaintext code storage

See ``models.py``'s module docstring for the full reasoning: a voucher code
is a physical/verbally-communicated artifact the platform must be able to
display/export, unlike OTP codes or provisioning tokens -- hashing it would
defeat this module's core function, and the actual threat (a guest
guessing/leaking a valid code) is mitigated by generation entropy and
redemption rate limiting, not by secrecy of the stored row.

## Approval workflow shape: no separate "submit" or "activate" endpoint

This module's required API surface (``POST /voucher-batches``,
``.../approve``, ``.../revoke``, ...) has no dedicated "submit for
approval" or "activate" endpoint. Rather than leave ``DRAFT`` as a state
only reachable by direct repository manipulation, ``create_batch`` performs
the ``DRAFT -> PENDING_APPROVAL`` submission itself, in the same call, right
after the row (and its vouchers) are created -- so every batch's audit trail
always shows a real, distinct submission event, even though a caller only
ever makes one HTTP call to get there.

Symmetrically, ``approve_batch`` (the ``POST .../approve`` handler) performs
**both** the ``-> APPROVED`` and ``APPROVED -> ACTIVE`` transitions in one
call via ``_approve_and_activate`` -- there is no operational scenario in
this module's own scope where an approved-but-not-yet-active batch needs to
sit idle before going live (unlike ``app.domains.router``, where a device
must physically check in before ``PROVISIONING -> ONLINE``): a paper/print
vendor is not waiting on a distinct "turn it on" signal separate from
"approve it". Both transitions are still independently validated against
``constants.VOUCHER_BATCH_STATUS_TRANSITIONS`` and independently logged/
audited (``VOUCHER_BATCH_APPROVED`` then ``VOUCHER_BATCH_ACTIVATED``), so
the full graph the module brief asked for is real and exercised, just not
independently reachable over HTTP.

## The `voucher.manage` fast path

A caller who holds ``voucher.manage`` (a strictly broader grant than
``voucher.create`` -- see ``app.domains.rbac.seed.expand_grant_level``:
``OPERATE`` includes ``APPROVE`` but not ``MANAGE``/``DELETE``; only
``FULL`` includes ``MANAGE``) may create a batch that skips the
``PENDING_APPROVAL`` queue entirely, going straight from ``DRAFT`` to
``APPROVED``-then-``ACTIVE`` via the same ``_approve_and_activate`` helper
the ``approve_batch`` endpoint uses -- ``router.py`` determines whether the
caller holds ``voucher.manage`` (a non-raising ``AccessValidator
.has_permission`` check, distinct from the mandatory ``voucher.create``
``RequirePermission`` gate on the route itself) and passes the result in as
``has_manage_permission``. This mirrors BE-009's own "create + approve both
required, but a sufficiently-privileged actor can do both" precedent for
router enrollment, adapted to a single-call rather than two-call shape
since vouchers have no physical device to wait on either.

## `expires_at` computed at first redemption, not generation

See ``models.py``'s module docstring for the full reasoning -- in short,
``VoucherBatch.validity_minutes`` is a *post-redemption* duration, not a
wall-clock deadline fixed at generation time.

## Audit-volume judgment call -- and why vouchers differ from OTP here

OTP's own audit-volume judgment call (see ``app.domains.otp.service``'s
module docstring) does **not** audit the routine "request a code" event at
all, reasoning that it is a high-volume, unauthenticated action with no
distinguishable value per call. This module makes a genuinely different
call for its analogous "value-transfer" moment:

**Every successful ``redeem_voucher`` call is written to
``audit_log_entries`` (``AuditAction.VOUCHER_REDEEMED``).** Unlike an OTP
*request* (which grants nothing by itself -- it is only step one of a
two-step login), a voucher redemption **is** the moment real network access
is granted, often standing in for a real monetary/access transaction a
business may be legally or operationally required to have an audit trail
for (e.g. "who used voucher code X, when, from what device"). This is
consistent with, not a departure from, OTP's own precedent that a genuine
*success*/value-transfer event (``OTP_VERIFIED``) is audited -- the
difference is that a voucher's redemption *is* that success moment, where
OTP's *request* is not.

Batch lifecycle events (created/submitted/approved/activated/revoked,
pre-printed code imports) are audited for the same reason every other
domain's own lifecycle events are (``ROUTER_CREATED``,
``ORGANIZATION_CREATED``, ...): moderate-volume, human-attributable,
admin-reviewable actions.

What is **not** audited: read-only ``validate_voucher`` calls (no state
changes, and a captive portal may legitimately poll this before committing
to a redemption) and *routine* (non-adversarial) redemption failures --
mirroring OTP's own tiering, only ``revoked``/``exhausted`` (an attempted
reuse of a voucher already known to be dead) are audited
(``AuditAction.VOUCHER_REDEMPTION_FAILED``); ``not_found``/
``batch_not_active``/``expired`` are routine guest-side churn (a guest
found an old, dead code, or tried before the batch went live) logged via
the structured logger but never written to the audit table.

## Guest-facing rate limiting

Both ``validate_voucher`` and ``redeem_voucher`` are guarded by
``VoucherRedemptionRateLimiter``, a Redis-backed, per-``source`` (the
caller's presumed IP address, supplied by ``router.py``) INCR+EXPIRE+TTL
throttle -- the identical mechanism ``app.domains.otp.service
.OtpRateLimiter`` already established, reused in shape (not literally
shared code, since it protects a different resource key) rather than
reinvented. Scoped by source rather than by presented code: the risk is one
source trying many codes, not one code being tried by many sources (a
legitimate front-desk device validating a stack of printed vouchers in
quick succession must not be choked by a per-code limit).
"""

from __future__ import annotations

import csv
import dataclasses
import io
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import choice as secrets_choice
from typing import Protocol

from redis.asyncio import Redis

from app.database.constants import MAX_BULK_CREATE_SIZE
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction

from .constants import (
    CODE_GENERATION_MAX_ROUNDS,
    CSV_EXPORT_HEADERS,
    DEFAULT_REDEMPTION_MAX_ATTEMPTS_PER_WINDOW,
    DEFAULT_REDEMPTION_WINDOW_MINUTES,
    VOUCHER_CODE_ALPHABET,
    VOUCHER_REDEMPTION_RATE_LIMIT_KEY_TEMPLATE,
    VoucherBatchStatus,
    VoucherStatus,
)
from .events import (
    VoucherBatchActivated,
    VoucherBatchApproved,
    VoucherBatchCreated,
    VoucherBatchRevoked,
    VoucherBatchSubmitted,
    VoucherCodesImported,
    VoucherRedeemed,
    VoucherRedemptionFailed,
)
from .exceptions import (
    CrossOrganizationVoucherBatchAccessError,
    VoucherBatchNotActiveError,
    VoucherBatchNotFoundError,
    VoucherBatchQuantityExceededError,
    VoucherCodeGenerationExhaustedError,
    VoucherExhaustedError,
    VoucherExpiredError,
    VoucherNotFoundError,
    VoucherRedemptionRateLimitExceededError,
    VoucherRevokedError,
)
from .models import Voucher, VoucherBatch
from .repository import VoucherRepositoryProtocol
from .validators import (
    normalize_redeemed_identifier,
    validate_batch_status_transition,
    validate_code_length,
    validate_quantity,
)

logger = logging.getLogger(__name__)

# Adversarially-relevant redemption-failure reasons -- see module docstring's
# audit-volume judgment call. not_found/batch_not_active/expired are
# deliberately excluded (routine guest-side churn, not an attack signal).
_AUDITED_FAILURE_REASONS = frozenset({"revoked", "exhausted"})


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class OrganizationLookupProtocol(Protocol):
    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization: ...


class LocationLookupProtocol(Protocol):
    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table -- the same narrow, duck-typed protocol
    shape every other domain's service already defines for itself."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Redemption rate limiting
# ============================================================================


class VoucherRedemptionRateLimiter:
    """Static-method facade over Redis for guest-facing voucher
    validate/redeem rate limiting -- see module docstring."""

    @staticmethod
    async def check_and_increment(
        redis: Redis,
        source: str,
        *,
        max_attempts: int,
        window_minutes: int,
    ) -> None:
        key = VOUCHER_REDEMPTION_RATE_LIMIT_KEY_TEMPLATE.format(source=source)
        current = await redis.incr(key)
        if current == 1:
            await redis.expire(key, window_minutes * 60)
        if current > max_attempts:
            ttl = await redis.ttl(key)
            raise VoucherRedemptionRateLimitExceededError(
                ttl if ttl and ttl > 0 else window_minutes * 60
            )


# ============================================================================
# Read models
# ============================================================================


@dataclass(frozen=True, slots=True)
class VoucherValidationResult:
    """Returned by ``validate_voucher`` -- a read-only view of whether a
    code is currently redeemable, without mutating anything."""

    voucher: Voucher
    batch: VoucherBatch
    is_first_use: bool
    uses_remaining: int


@dataclass(frozen=True, slots=True)
class VoucherBatchStats:
    batch_id: uuid.UUID
    total: int
    unused: int
    active: int
    exhausted: int
    expired: int
    revoked: int
    redemption_rate: float


@dataclass(frozen=True, slots=True)
class VoucherImportResult:
    imported: list[Voucher]
    rejected: list[tuple[str, str]]


# ============================================================================
# Service
# ============================================================================


class VoucherService:
    """Core Voucher business logic."""

    def __init__(
        self,
        repository: VoucherRepositoryProtocol,
        redis: Redis,
        organization_lookup: OrganizationLookupProtocol,
        location_lookup: LocationLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        redemption_max_attempts_per_window: int = (
            DEFAULT_REDEMPTION_MAX_ATTEMPTS_PER_WINDOW
        ),
        redemption_window_minutes: int = DEFAULT_REDEMPTION_WINDOW_MINUTES,
    ) -> None:
        self.repository = repository
        self.redis = redis
        self.organization_lookup = organization_lookup
        self.location_lookup = location_lookup
        self.audit_writer = audit_writer
        self.redemption_max_attempts_per_window = redemption_max_attempts_per_window
        self.redemption_window_minutes = redemption_window_minutes

    # ========================================================================
    # Batch lifecycle
    # ========================================================================

    async def create_batch(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        name: str,
        quantity: int,
        code_length: int,
        code_prefix: str | None,
        validity_minutes: int,
        batch_expires_at: datetime | None,
        max_uses_per_voucher: int,
        data_limit_mb: int | None,
        notes: str | None,
        has_manage_permission: bool,
    ) -> VoucherBatch:
        validate_quantity(quantity)
        validate_code_length(code_length)

        organization = await self.organization_lookup.get_organization(organization_id)
        if (
            requesting_organization_id is not None
            and organization.id != requesting_organization_id
        ):
            raise CrossOrganizationVoucherBatchAccessError()
        if location_id is not None:
            await self.location_lookup.get_location(
                location_id, requesting_organization_id=organization.id
            )

        batch = await self.repository.create_batch(
            name=name,
            organization_id=organization.id,
            location_id=location_id,
            quantity=quantity,
            code_length=code_length,
            code_prefix=code_prefix,
            validity_minutes=validity_minutes,
            batch_expires_at=batch_expires_at,
            max_uses_per_voucher=max_uses_per_voucher,
            data_limit_mb=data_limit_mb,
            status=VoucherBatchStatus.DRAFT.value,
            created_by_user_id=actor_user_id,
            approved_by_user_id=None,
            approved_at=None,
            notes=notes,
            created_by=actor_user_id,
        )
        event = VoucherBatchCreated(
            batch_id=batch.id, organization_id=organization.id, quantity=quantity
        )
        logger.info("voucher_batch_created", extra=_event_extra(event))
        await self._audit_batch(
            actor_user_id,
            AuditAction.VOUCHER_BATCH_CREATED,
            batch,
            f"Voucher batch '{batch.name}' created ({quantity} vouchers requested)",
        )

        if quantity > 0:
            codes = await self._generate_codes(
                quantity=quantity, code_length=code_length, code_prefix=code_prefix
            )
            rows = [
                {
                    "batch_id": batch.id,
                    "code": code,
                    "status": VoucherStatus.UNUSED.value,
                    "use_count": 0,
                    "created_by": actor_user_id,
                }
                for code in codes
            ]
            await self.repository.bulk_create_vouchers(rows)

        batch = await self._submit_batch(batch, actor_user_id=actor_user_id)
        if has_manage_permission:
            batch = await self._approve_and_activate(batch, actor_user_id=actor_user_id)
        return batch

    async def _submit_batch(
        self, batch: VoucherBatch, *, actor_user_id: uuid.UUID | None
    ) -> VoucherBatch:
        current = VoucherBatchStatus(batch.status)
        validate_batch_status_transition(
            current=current, target=VoucherBatchStatus.PENDING_APPROVAL
        )
        updated = await self.repository.update_batch(
            batch,
            {
                "status": VoucherBatchStatus.PENDING_APPROVAL.value,
                "updated_by": actor_user_id,
            },
        )
        event = VoucherBatchSubmitted(batch_id=updated.id)
        logger.info("voucher_batch_submitted", extra=_event_extra(event))
        return updated

    async def _approve_and_activate(
        self, batch: VoucherBatch, *, actor_user_id: uuid.UUID | None
    ) -> VoucherBatch:
        now = datetime.now(UTC)
        current = VoucherBatchStatus(batch.status)
        validate_batch_status_transition(
            current=current, target=VoucherBatchStatus.APPROVED
        )
        approved = await self.repository.update_batch(
            batch,
            {
                "status": VoucherBatchStatus.APPROVED.value,
                "approved_by_user_id": actor_user_id,
                "approved_at": now,
                "updated_by": actor_user_id,
            },
        )
        approved_event = VoucherBatchApproved(
            batch_id=approved.id, approved_by_user_id=actor_user_id
        )
        logger.info("voucher_batch_approved", extra=_event_extra(approved_event))
        await self._audit_batch(
            actor_user_id,
            AuditAction.VOUCHER_BATCH_APPROVED,
            approved,
            f"Voucher batch '{approved.name}' approved",
        )

        validate_batch_status_transition(
            current=VoucherBatchStatus.APPROVED, target=VoucherBatchStatus.ACTIVE
        )
        activated = await self.repository.update_batch(
            approved,
            {"status": VoucherBatchStatus.ACTIVE.value, "updated_by": actor_user_id},
        )
        activated_event = VoucherBatchActivated(batch_id=activated.id)
        logger.info("voucher_batch_activated", extra=_event_extra(activated_event))
        await self._audit_batch(
            actor_user_id,
            AuditAction.VOUCHER_BATCH_ACTIVATED,
            activated,
            f"Voucher batch '{activated.name}' activated",
        )
        return activated

    async def approve_batch(
        self,
        *,
        batch_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> VoucherBatch:
        batch = await self.get_batch(
            batch_id, requesting_organization_id=requesting_organization_id
        )
        return await self._approve_and_activate(batch, actor_user_id=actor_user_id)

    async def revoke_batch(
        self,
        *,
        batch_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        reason: str | None = None,
    ) -> VoucherBatch:
        batch = await self.get_batch(
            batch_id, requesting_organization_id=requesting_organization_id
        )
        current = VoucherBatchStatus(batch.status)
        validate_batch_status_transition(
            current=current, target=VoucherBatchStatus.REVOKED
        )

        updated = await self.repository.update_batch(
            batch,
            {"status": VoucherBatchStatus.REVOKED.value, "updated_by": actor_user_id},
        )
        revoked_count = await self.repository.bulk_revoke_vouchers_for_batch(batch.id)

        event = VoucherBatchRevoked(
            batch_id=updated.id, revoked_vouchers_count=revoked_count
        )
        logger.info("voucher_batch_revoked", extra=_event_extra(event))
        description = f"Voucher batch '{updated.name}' revoked"
        if reason:
            description += f": {reason}"
        await self._audit_batch(
            actor_user_id, AuditAction.VOUCHER_BATCH_REVOKED, updated, description
        )
        return updated

    async def get_batch(
        self,
        batch_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> VoucherBatch:
        batch = await self.repository.get_batch(batch_id)
        if batch is None:
            raise VoucherBatchNotFoundError(batch_id)
        if (
            requesting_organization_id is not None
            and batch.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationVoucherBatchAccessError()
        return await self._refresh_batch_expiry(batch)

    async def list_batches(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[VoucherBatch], object]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        batches, meta = await self.repository.list_batches(
            page=page, page_size=page_size, filters=filters or None
        )
        refreshed = [await self._refresh_batch_expiry(batch) for batch in batches]
        return refreshed, meta

    async def _refresh_batch_expiry(self, batch: VoucherBatch) -> VoucherBatch:
        """Lazily flips ``ACTIVE -> EXPIRED`` once ``batch_expires_at`` has
        passed -- checked on every read, not swept by a background job,
        mirroring ``app.domains.otp.models.OtpRequest.is_expired``'s
        identical "checked on read" posture."""
        now = datetime.now(UTC)
        if VoucherBatchStatus(
            batch.status
        ) == VoucherBatchStatus.ACTIVE and batch.is_batch_expired(now=now):
            return await self.repository.update_batch(
                batch, {"status": VoucherBatchStatus.EXPIRED.value}
            )
        return batch

    # ========================================================================
    # Code generation
    # ========================================================================

    @staticmethod
    def _random_code(code_length: int, code_prefix: str | None) -> str:
        body = "".join(
            secrets_choice(VOUCHER_CODE_ALPHABET) for _ in range(code_length)
        )
        return f"{code_prefix}{body}" if code_prefix else body

    async def _generate_codes(
        self, *, quantity: int, code_length: int, code_prefix: str | None
    ) -> list[str]:
        """Bulk-generates ``quantity`` unique codes, retrying on collision
        both in-memory (within this same batch) and against the database
        (any code ever generated/imported for any batch) -- see module
        docstring."""
        generated: set[str] = set()
        for _ in range(CODE_GENERATION_MAX_ROUNDS):
            needed = quantity - len(generated)
            if needed <= 0:
                break
            candidates = {
                self._random_code(code_length, code_prefix) for _ in range(needed)
            }
            candidates -= generated
            if not candidates:
                continue
            existing = set(await self.repository.find_existing_codes(list(candidates)))
            generated.update(candidates - existing)

        if len(generated) < quantity:
            raise VoucherCodeGenerationExhaustedError(quantity, len(generated))
        return list(generated)[:quantity]

    # ========================================================================
    # Validation / redemption
    # ========================================================================

    async def _get_voucher_and_batch(self, code: str) -> tuple[Voucher, VoucherBatch]:
        voucher = await self.repository.get_voucher_by_code(code)
        if voucher is None:
            raise VoucherNotFoundError()
        batch = await self.repository.get_batch(voucher.batch_id)
        if batch is None:  # pragma: no cover -- FK guarantees this in practice
            raise VoucherBatchNotFoundError(voucher.batch_id)
        return voucher, await self._refresh_batch_expiry(batch)

    def _redemption_failure_reason(
        self, voucher: Voucher, batch: VoucherBatch, *, now: datetime
    ) -> str | None:
        """Note: a batch whose ``batch_expires_at`` has passed is caught by
        the ``batch_not_active`` branch below, not a dedicated
        ``expired``/``batch_expired`` reason -- ``_get_voucher_and_batch``
        always runs the batch through ``_refresh_batch_expiry`` first, which
        lazily flips an ``ACTIVE`` batch past its expiry to ``EXPIRED``
        *before* this method ever sees it. See
        ``exceptions.VoucherBatchNotActiveError``'s docstring, which
        documents this explicitly ("covers a batch still awaiting approval,
        or one that has expired/been revoked")."""
        if voucher.status == VoucherStatus.REVOKED.value:
            return "revoked"
        if voucher.status == VoucherStatus.EXHAUSTED.value:
            return "exhausted"
        if voucher.status == VoucherStatus.EXPIRED.value:
            return "expired"
        if VoucherBatchStatus(batch.status) != VoucherBatchStatus.ACTIVE:
            return "batch_not_active"
        if (
            voucher.status == VoucherStatus.ACTIVE.value
            and voucher.is_post_redemption_expired(now=now)
        ):
            return "expired"
        return None

    @staticmethod
    def _raise_for_reason(reason: str, *, batch_status: str) -> None:
        if reason == "revoked":
            raise VoucherRevokedError()
        if reason == "exhausted":
            raise VoucherExhaustedError()
        if reason == "expired":
            raise VoucherExpiredError()
        raise VoucherBatchNotActiveError(batch_status)

    async def _record_redemption_failure(
        self, voucher: Voucher | None, *, reason: str
    ) -> None:
        event = VoucherRedemptionFailed(
            voucher_id=voucher.id if voucher else None, reason=reason
        )
        logger.warning("voucher_redemption_failed", extra=_event_extra(event))
        if reason not in _AUDITED_FAILURE_REASONS or self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=None,
            action=AuditAction.VOUCHER_REDEMPTION_FAILED.value,
            entity_type="voucher",
            entity_id=voucher.id if voucher else None,
            description=f"Voucher redemption attempt rejected (reason={reason})",
            event_metadata={"reason": reason},
            organization_id=None,
            location_id=None,
        )

    async def _enforce_redemption_rate_limit(self, source: str) -> None:
        await VoucherRedemptionRateLimiter.check_and_increment(
            self.redis,
            source,
            max_attempts=self.redemption_max_attempts_per_window,
            window_minutes=self.redemption_window_minutes,
        )

    async def validate_voucher(
        self, *, code: str, source: str
    ) -> VoucherValidationResult:
        """Read-only check: raises the same distinct exceptions
        ``redeem_voucher`` would, but never mutates anything -- useful for a
        future captive portal to show "is this code still good" before
        committing to a redemption."""
        await self._enforce_redemption_rate_limit(source)
        voucher, batch = await self._get_voucher_and_batch(code.strip())
        now = datetime.now(UTC)
        reason = self._redemption_failure_reason(voucher, batch, now=now)
        if reason is not None:
            await self._record_redemption_failure(voucher, reason=reason)
            self._raise_for_reason(reason, batch_status=batch.status)
        return VoucherValidationResult(
            voucher=voucher,
            batch=batch,
            is_first_use=voucher.use_count == 0,
            uses_remaining=batch.max_uses_per_voucher - voucher.use_count,
        )

    async def redeem_voucher(
        self, *, code: str, identifier: str, source: str
    ) -> tuple[Voucher, VoucherBatch]:
        await self._enforce_redemption_rate_limit(source)
        voucher, batch = await self._get_voucher_and_batch(code.strip())
        now = datetime.now(UTC)
        reason = self._redemption_failure_reason(voucher, batch, now=now)
        if reason is not None:
            await self._record_redemption_failure(voucher, reason=reason)
            self._raise_for_reason(reason, batch_status=batch.status)

        is_first_use = voucher.status == VoucherStatus.UNUSED.value
        new_use_count = voucher.use_count + 1
        will_exhaust = new_use_count >= batch.max_uses_per_voucher
        update_data: dict[str, object] = {
            "use_count": new_use_count,
            "last_used_at": now,
            "status": (
                VoucherStatus.EXHAUSTED if will_exhaust else VoucherStatus.ACTIVE
            ).value,
        }
        if is_first_use:
            update_data["redeemed_at"] = now
            update_data["redeemed_identifier"] = normalize_redeemed_identifier(
                identifier
            )
            update_data["expires_at"] = now + timedelta(minutes=batch.validity_minutes)

        updated = await self.repository.update_voucher(voucher, update_data)
        event = VoucherRedeemed(
            voucher_id=updated.id,
            batch_id=batch.id,
            is_first_use=is_first_use,
            use_count=updated.use_count,
        )
        logger.info("voucher_redeemed", extra=_event_extra(event))
        await self._audit_batch(
            None,
            AuditAction.VOUCHER_REDEEMED,
            batch,
            f"Voucher '{updated.code}' redeemed (use {updated.use_count}/"
            f"{batch.max_uses_per_voucher})",
            entity_type="voucher",
            entity_id=updated.id,
        )
        return updated, batch

    # ========================================================================
    # Listing / stats
    # ========================================================================

    async def list_vouchers(
        self,
        *,
        batch_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Voucher], object]:
        batch = await self.get_batch(
            batch_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_vouchers_for_batch(
            batch.id, page=page, page_size=page_size
        )

    async def get_batch_stats(
        self,
        *,
        batch_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> VoucherBatchStats:
        batch = await self.get_batch(
            batch_id, requesting_organization_id=requesting_organization_id
        )
        counts = await self.repository.get_batch_status_counts(batch.id)
        unused = counts.get(VoucherStatus.UNUSED.value, 0)
        active = counts.get(VoucherStatus.ACTIVE.value, 0)
        exhausted = counts.get(VoucherStatus.EXHAUSTED.value, 0)
        expired = counts.get(VoucherStatus.EXPIRED.value, 0)
        revoked = counts.get(VoucherStatus.REVOKED.value, 0)
        total = unused + active + exhausted + expired + revoked
        redeemed = total - unused
        redemption_rate = (redeemed / total) if total else 0.0
        return VoucherBatchStats(
            batch_id=batch.id,
            total=total,
            unused=unused,
            active=active,
            exhausted=exhausted,
            expired=expired,
            revoked=revoked,
            redemption_rate=redemption_rate,
        )

    # ========================================================================
    # Export / import
    # ========================================================================

    async def export_batch_csv(
        self,
        *,
        batch_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> str:
        """Builds a batch's voucher codes as in-memory CSV text (stdlib
        ``csv``, no new dependency) -- see module docstring / ``router.py``
        for the transport decision (a raw ``text/csv`` response, not the
        standard ``ApiResponse`` envelope: a downloadable file a print
        vendor opens directly cannot usefully be JSON-wrapped)."""
        batch = await self.get_batch(
            batch_id, requesting_organization_id=requesting_organization_id
        )
        vouchers = await self.repository.list_all_vouchers_for_batch(batch.id)

        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(CSV_EXPORT_HEADERS)
        for voucher in vouchers:
            writer.writerow(
                [
                    voucher.code,
                    voucher.status,
                    voucher.use_count,
                    batch.max_uses_per_voucher,
                    voucher.redeemed_at.isoformat() if voucher.redeemed_at else "",
                    voucher.last_used_at.isoformat() if voucher.last_used_at else "",
                    voucher.expires_at.isoformat() if voucher.expires_at else "",
                    voucher.redeemed_identifier or "",
                ]
            )
        return buffer.getvalue()

    async def import_vouchers(
        self,
        *,
        batch_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        codes: list[str],
    ) -> VoucherImportResult:
        """Bulk-imports pre-printed voucher codes generated by an external
        system/print vendor into an existing batch -- see module docstring
        for why this is the meaning this module gives to
        ``voucher.import``. Partial success is reported (accepted codes are
        inserted; rejected codes -- duplicates within the request, or
        already present in the database -- are reported with a reason)
        rather than an all-or-nothing failure, since a real print run
        commonly has a handful of genuinely-duplicate codes among an
        otherwise-good batch."""
        batch = await self.get_batch(
            batch_id, requesting_organization_id=requesting_organization_id
        )
        if VoucherBatchStatus(batch.status) in (
            VoucherBatchStatus.EXPIRED,
            VoucherBatchStatus.REVOKED,
        ):
            raise VoucherBatchNotActiveError(batch.status)
        if len(codes) > MAX_BULK_CREATE_SIZE:
            raise VoucherBatchQuantityExceededError(len(codes), MAX_BULK_CREATE_SIZE)

        rejected: list[tuple[str, str]] = []
        seen_in_request: set[str] = set()
        candidates: list[str] = []
        for raw_code in codes:
            code = raw_code.strip().upper()
            if not code:
                rejected.append((raw_code, "empty code"))
                continue
            if code in seen_in_request:
                rejected.append((code, "duplicate within import request"))
                continue
            seen_in_request.add(code)
            candidates.append(code)

        existing = set(await self.repository.find_existing_codes(candidates))
        to_insert = [code for code in candidates if code not in existing]
        rejected.extend(
            (code, "code already exists") for code in candidates if code in existing
        )

        imported: list[Voucher] = []
        if to_insert:
            rows = [
                {
                    "batch_id": batch.id,
                    "code": code,
                    "status": VoucherStatus.UNUSED.value,
                    "use_count": 0,
                    "created_by": actor_user_id,
                }
                for code in to_insert
            ]
            imported = await self.repository.bulk_create_vouchers(rows)

        event = VoucherCodesImported(
            batch_id=batch.id,
            imported_count=len(imported),
            rejected_count=len(rejected),
        )
        logger.info("voucher_codes_imported", extra=_event_extra(event))
        if imported:
            await self._audit_batch(
                actor_user_id,
                AuditAction.VOUCHER_CODES_IMPORTED,
                batch,
                f"{len(imported)} pre-printed voucher codes imported "
                f"({len(rejected)} rejected)",
            )
        return VoucherImportResult(imported=imported, rejected=rejected)

    # ========================================================================
    # Internal: audit helper
    # ========================================================================

    async def _audit_batch(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        batch: VoucherBatch,
        description: str,
        *,
        entity_type: str = "voucher_batch",
        entity_id: uuid.UUID | None = None,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type=entity_type,
            entity_id=entity_id or batch.id,
            description=description,
            event_metadata={"batch_status": batch.status},
            organization_id=batch.organization_id,
            location_id=batch.location_id,
        )


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick to ``app.domains.otp.service._event_extra``."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


__all__ = [
    "VoucherService",
    "VoucherRedemptionRateLimiter",
    "OrganizationLookupProtocol",
    "LocationLookupProtocol",
    "AuditLogWriter",
    "VoucherValidationResult",
    "VoucherBatchStats",
    "VoucherImportResult",
]
