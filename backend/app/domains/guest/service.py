"""Guest business logic: the guest WiFi login orchestration that ties
OTP/Voucher/Captive-Portal/Router together into a real login journey
(``GuestService``), session lifecycle management (disconnect/terminate/
reconnect/usage tracking/timeout+quota detection, also on ``GuestService``),
the FreeRADIUS ``rlm_rest`` HTTP integration (``RadiusService``), and
read-only tenant-scoped aggregate analytics (``GuestAnalyticsService``).

This is BE-010's final module -- its entire value is composing every prior
domain, never reimplementing a piece of it. ``GuestService`` never verifies
an OTP code, redeems a voucher, or checks a captive portal's enabled-methods
flags itself; it calls ``OtpService.verify_otp``/``VoucherService
.redeem_voucher``/``CaptivePortalService.resolve_portal_config`` through
narrow, duck-typed protocols (the exact "``ServiceX`` depends on a Protocol
satisfied by the real ``ServiceY``" pattern every prior BE-010 part
established) and only adds what those services genuinely have no notion of:
a returning-guest identity, a device, a session, and this module's own
lifecycle/analytics/RADIUS surface.

## FreeRADIUS integration: ``rlm_rest``, not raw RADIUS-UDP

There is no real FreeRADIUS server, no ``pyrad``/RADIUS-protocol library,
and no live network in this sandbox. The realistic, actually-deployed way to
integrate a Python HTTP backend with FreeRADIUS is via FreeRADIUS's own
``rlm_rest`` module, which lets FreeRADIUS call out to an HTTP API for its
Authorize/Accounting phases instead of (or alongside) its normal RADIUS-
protocol backends -- this module implements exactly that shape (plain HTTP
endpoints ``rlm_rest`` would be configured to POST to), not a raw UDP RADIUS
server. A UDP server would be the wrong transport for a FastAPI app, and
nothing in this sandbox could exercise the real RADIUS wire protocol
anyway -- the honest, useful boundary is the HTTP contract a real FreeRADIUS
deployment's ``rlm_rest`` module would actually call, same interim-design
posture as ``app.domains.wireguard``'s simulated tunnel health and
``app.domains.router_provisioning``/``app.domains.router_agent``'s
simulated device dispatch.

``RadiusService.authenticate_nas`` -- the auth scheme for all three
RADIUS-facing endpoints -- is a shared-secret comparison against a
registered ``RadiusNasClient``, **not** RBAC's ``RequirePermission``:
FreeRADIUS is not a platform user and has no JWT/session to present, exactly
the same posture ``app.domains.router_agent``'s ``CurrentAgent`` (device
credential) and BE-008's own provisioning check-in already established for
their own non-platform-user callers. The shared secret is Fernet-encrypted
via ``app.domains.router.crypto.encrypt_secret``/``decrypt_secret`` (reused,
not reimplemented) rather than hashed: unlike a bearer token, a RADIUS
shared secret must be recoverable in plaintext to compare against what
``rlm_rest`` presents on every single call -- see ``models.RadiusNasClient``'s
docstring for the full reasoning (mirrors ``Router.api_credentials_encrypted
``'s identical "must decrypt for live use" posture).

``RadiusService.accounting_start`` does **not** create a brand-new
``GuestSession`` from nothing. In this module's design, a ``GuestSession``
is always originated by this module's own guest-facing login endpoints
(``login_via_otp``/``login_via_voucher``/``login_via_password``) or --
the one deliberate exception, see ``RadiusService.authorize``'s own
docstring -- by ``RadiusService.authorize`` itself, when a NAS-asserted
``Calling-Station-Id`` matches a real MAC-whitelist entry. Either way, a
``GuestSession`` is never originated from an unauthenticated claim: the
former is a guest interactively proving an OTP/voucher/password over a
rate-limited, purpose-built flow; the latter only ever runs behind
``dependencies.CurrentNas``'s shared-secret authentication, i.e. the MAC
value is the NAS's own assertion, not a browser's.

Accounting resolves *which* session by ``username`` (RADIUS User-Name),
the same ``_find_active_session_for_identifier`` lookup ``authorize``
itself uses -- **not** by treating the NAS's own ``Acct-Session-Id`` as
this platform's ``GuestSession.id``. Confirmed live via
``freeradius -X`` against a real MikroTik hotspot: RouterOS originates
Acct-Session-Id locally (an internal counter, e.g. ``"80000006"``) --
there is no hotspot-login-form field through which this platform's own
session id could ever reach the NAS to be echoed back. An earlier
version of this module assumed otherwise (see git history) and every
real Accounting-Request failed UUID validation as a result --
``accounting_start``'s job is to confirm an ACTIVE session exists for
this NAS/username pair, not to fabricate one or to look one up by an id
the NAS never actually has.

## ``data_limit_mb``/``session_timeout_minutes``: copied, not referenced

Mirrors ``app.domains.voucher.models.Voucher.expires_at``'s identical
reasoning: a ``GuestSession`` created via ``login_via_voucher`` copies the
redeeming voucher's ``batch.data_limit_mb``/``batch.validity_minutes`` onto
the session at creation time, rather than the session holding a live
reference back to the voucher batch. A later change to the batch's own
`data_limit_mb`` (an admin editing an in-flight campaign) must never
retroactively alter an already-in-progress guest's quota -- the session's
own copied values are its permanent, immutable-after-creation contract with
that one guest for that one connection interval. For a voucher-authenticated
session, ``session_timeout_minutes`` is populated from
``batch.validity_minutes`` -- a deliberate repurposing of "inactivity
timeout" into "this session's overall remaining lifetime since redemption",
since a voucher's whole point is a bounded total access window, not merely
an idle-disconnect threshold. For an OTP-authenticated session, no voucher
exists to copy from, so ``session_timeout_minutes`` falls back to
``constants.DEFAULT_SESSION_TIMEOUT_MINUTES`` (a portal/location-independent
platform default -- this module's own scope has no per-location default
config of its own to source a more specific value from) and
``data_limit_mb`` is left ``None`` (unlimited).

## Reconnect creates a new session, never resurrects the old one

See ``models.py``'s module docstring ("Sessions are append-only") for the
full reasoning. ``reconnect`` derives a *new* ``GuestSession`` row from the
guest's most recent (terminal) session -- same device/router/auth_method/
copied quota+timeout values -- rather than flipping the old row back to
``ACTIVE``. This is bounded by ``constants.RECONNECT_GRACE_MINUTES`` (a
grace window since the prior session ended) and, if the guest's *most
recent* session was an admin ``terminate_session`` (punitive), by
``constants.TERMINATION_RECONNECT_COOLDOWN_MINUTES`` (see
``exceptions.SessionTerminationCooldownError``). If the guest already has an
``ACTIVE`` session, ``reconnect`` is an idempotent no-op returning it rather
than creating a duplicate concurrent session for the same guest.

**Honest scope limitation:** for a voucher-derived prior session,
``reconnect`` does **not** re-run the voucher's own remaining-uses/validity
check against the original code -- this module never retains a voucher's
plaintext code on a ``GuestSession`` (nothing after redemption needs it, and
storing it would be a needless secret-retention regression), and
``VoucherService.validate_voucher``/``redeem_voucher`` are both keyed by
code, not by ``voucher_id``. A caller that needs a hard revalidation
guarantee for a voucher-derived reconnect should have the guest present the
voucher code again via ``login_via_voucher`` instead; ``reconnect`` grants a
low-friction path bounded purely by the grace window, trusting that the
original ``redeem_voucher`` call already established the grant.

## Timeout/quota: a DB-level status-transition sweep, now paired with a
## real live Disconnect-Request (Phase 1 BhaiFi-parity #16)

``GuestService.enforce_timeouts`` is, and remains, a status-transition/
reporting mechanism (flips ``ACTIVE`` sessions whose inactivity has
exceeded their own ``session_timeout_minutes`` to ``EXPIRED``), the same
honest "simulated, DB-tracked signal" posture ``app.domains.wireguard``'s
tunnel-health computation and ``app.domains.router``'s heartbeat-derived
online/offline status already document -- nothing in this module *decides*
a session is over by watching live traffic. What changed for Phase 1: the
moment this module's own records decide a session has ended (via this
sweep, ``run_fup_time_accrual``, ``record_usage``'s quota checks, or an
admin's ``disconnect_session``/``terminate_session``/``pause_session``),
``issue_live_disconnect`` now also sends a real RFC 2865/5176
Disconnect-Request to the guest's NAS (see ``radius_coa.py``'s own module
docstring for exactly what "real" means here and what this sandbox still
cannot verify) -- replacing what used to be a documented no-op. A real
deployment would additionally pair this with FreeRADIUS's own
Session-Timeout reply attribute (already returned by
``RadiusService.authorize``).

## Audit-volume judgment call

Guest logins (``login_via_otp``/``login_via_voucher``) are high-volume,
guest-facing traffic -- the identical profile ``app.domains.otp``'s own
*request* tiering already establishes. This module writes **no** audit
entry of its own for a routine successful or failed login: the composed
services it calls already write their own audit entries for the moments
that matter (``OtpService.verify_otp`` writes ``OTP_VERIFIED``/
``OTP_VERIFICATION_FAILED``; ``VoucherService.redeem_voucher`` writes
``VOUCHER_REDEEMED``/``VOUCHER_REDEMPTION_FAILED``) -- writing a second,
guest-flavoured audit row for the same underlying event would be pure
duplication, not new signal. Every attempt is still recorded, at guest-
module granularity, in ``GuestLoginHistory`` (a purpose-built, high-volume
table, not RBAC's audit table -- mirrors ``app.domains.router_provisioning
.models.RouterEvent``'s identical "separate table for high-frequency
domain-specific history" precedent) and logged via the structured logger.

Guest blocking/unblocking and session termination **are** audited
(``AuditAction.GUEST_BLOCKED``/``GUEST_UNBLOCKED``/
``GUEST_SESSION_TERMINATED``) -- low-volume, always admin-initiated,
exactly the "moderate-volume, human-attributable, admin-reviewable" profile
every other domain's own lifecycle events already meet. An ordinary
``disconnect_session`` is audited only when it is admin-initiated
(``actor_user_id`` supplied) -- a system-initiated disconnect (RADIUS
Accounting-Stop, ``enforce_timeouts``) is routine operational churn, not an
admin action, so it is logged but not audited, mirroring
``app.domains.router.service.RouterService.heartbeat``'s identical
"frequent device telemetry, not an admin-driven event" reasoning.
``RadiusNasRegistered`` (NAS registration) is audited on every call -- a
low-volume, admin-initiated infrastructure change.

## Composing analytics without touching otp/voucher tables

``GuestAnalyticsService.get_otp_success_rate``/``get_voucher_usage`` are
derived entirely from this module's **own** tables (``GuestLoginHistory``,
``GuestSession``), never by re-querying ``otp_requests``/``vouchers``
directly, and without adding any new method to
``app.domains.otp``/``app.domains.voucher``. This module's own login
orchestration already records every OTP-driven attempt (success or
failure) it brokers into ``GuestLoginHistory``, and every voucher-
authenticated session into ``GuestSession`` -- that data is not just
sufficient for "guest WiFi OTP success rate"/"voucher usage", it is *more*
precisely scoped to this module's own guest-login traffic than a naive
aggregate over ``otp_requests`` would be (that table also carries any other
``OtpPurpose`` value and any request that was rate-limited before a
``verify_otp`` call ever happened). This was a deliberate check-first
decision per the module brief's "prefer composing over adding" guidance:
no method was added to ``otp``/``voucher``'s repository or service layer.

## FUP quota tracking (Phase 1 BhaiFi-parity)

``models.GuestQuotaUsage`` holds one row per ``(guest_id, period_type)``
(daily/weekly/monthly) -- the guest-level aggregate a single
``GuestSession``'s own ``bytes_uploaded``/``bytes_downloaded`` cannot
express (see that model's own docstring). Every read/write of a row goes
through the single module-level ``get_or_reset_quota_usage`` helper, which
first checks whether real wall-clock time (in the guest's own
organization's ``Organization.timezone``, via ``validators
.compute_period_start``) has already carried the row past its own
``period_start`` -- if so, the row's counters are zeroed and
``period_start`` advances before the caller ever sees it. Both
request-triggered call sites (``GuestService._enforce_fup_quota``, the
login-time gate; ``GuestService.record_usage``'s per-accounting-call byte
bump) and the two Celery Beat sweeps (``tasks.run_fup_time_accrual_sweep``/
``tasks.run_quota_reset_sweep``) share this one function, so there is
exactly one definition of "has this guest's day/week/month rolled over" in
this codebase.

Bytes are bumped incrementally on every RADIUS Interim-Update
(``record_usage`` -> ``_track_fup_data_usage``), riding for free on a call
that already happens on its own schedule. Minutes have no equivalent
"delta" RADIUS ever pushes, so guest-level *connected time* (deliberately
not summed across a guest's concurrent sessions -- two simultaneous
devices connected for 10 minutes is 10 minutes of usage, not 20) is instead
accrued by a dedicated periodic sweep, ``tasks.run_fup_time_accrual_sweep``.
Both a data cap and a time cap being crossed mid-session lead to the exact
same outcome: the offending session(s) are flipped to ``EXPIRED`` (a
system-initiated ending, mirroring ``enforce_session_timeouts``'s own
``EXPIRED``-not-``DISCONNECTED`` choice), never blocked at accounting-call
time (that would drop the RADIUS response instead of accepting it, exactly
the failure mode ``_enforce_fup_quota``'s login-time gate exists to avoid
paying twice for). ``_enforce_fup_quota`` -- the real, never-swallowed
enforcement checkpoint -- runs once at the start of ``login_via_otp``/
``login_via_voucher``, exactly where ``_enforce_device_limit``/
``_enforce_concurrent_session_limit`` already run; the mid-session paths
above are best-effort, additive tightening on top of that, not a
replacement for it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import math
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from redis.asyncio import Redis

from app.common.exceptions import CloudGuestError
from app.database.constants import SortOrder
from app.domains.auth.password import (
    PasswordManager,
    PasswordStrengthError,
    PasswordVerificationError,
)
from app.domains.captive_portal.service import ResolvedPortalConfig
from app.domains.captive_portal.validators import compute_terms_version, is_open_now
from app.domains.guest_access.exceptions import (
    GuestAccessDeniedError,
    WhitelistOnlyAccessDeniedError,
)
from app.domains.guest_access.service import AccessDecision
from app.domains.location.models import Location
from app.domains.mac_authorization.exceptions import MacAuthorizationError
from app.domains.mac_authorization.validators import (
    normalize_mac_address as normalize_whitelist_mac_address,
)
from app.domains.monitoring.constants import RealtimeMessageType
from app.domains.otp.constants import OtpPurpose
from app.domains.otp.models import OtpRequest
from app.domains.policy.constants import PolicyType
from app.domains.queue_management.constants import QueueTargetType
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.location_scope import (
    LocationScope,
    enforce_entity_location,
)
from app.domains.router.crypto import (
    RouterCredentialDecryptionError,
    decrypt_secret,
    encrypt_secret,
)
from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router
from app.domains.voucher.models import Voucher, VoucherBatch

from .constants import (
    BYTES_PER_MB,
    DEFAULT_IDLE_TIMEOUT_MINUTES,
    DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST,
    DEFAULT_MAX_DEVICES_PER_GUEST,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    LAST_ENDED_SESSION_WINDOW_MINUTES,
    MAX_BULK_DEVICE_LOOKUP_IDS,
    MAX_BULK_VOUCHER_LOOKUP_IDS,
    NAS_SHARED_SECRET_DEFAULT_LENGTH_BYTES,
    PIN_LENGTH,
    PIN_LOCKOUT_MINUTES,
    PIN_MAX_ATTEMPTS,
    PIN_STALE_AFTER_DAYS,
    RECONNECT_GRACE_MINUTES,
    SET_PASSWORD_SESSION_WINDOW_MINUTES,
    TERMINATION_RECONNECT_COOLDOWN_MINUTES,
    WHITELIST_ONLY_LOGIN_FAILURE_REASON,
    GuestAuthMethod,
    GuestSessionEndedReason,
    GuestSessionStatus,
    NasStatus,
    QuotaPeriodType,
    RadiusNasDevicePushStatus,
)
from .device_adapters import (
    RadiusNasCredentials,
    RadiusNasDeviceConfig,
    get_radius_nas_adapter,
)
from .events import (
    GuestBlocked,
    GuestConsentRecorded,
    GuestLoggedIn,
    GuestLoginFailed,
    GuestSessionCreated,
    GuestSessionDisconnected,
    GuestSessionExpired,
    GuestSessionExtended,
    GuestSessionPaused,
    GuestSessionResumed,
    GuestSessionTerminated,
    GuestUnblocked,
    RadiusNasActivated,
    RadiusNasDeleted,
    RadiusNasDisabled,
    RadiusNasRegistered,
    RadiusNasSecretRegenerated,
    RadiusNasUpdated,
    WhitelistOnlyGateFailedOpen,
    WhitelistOnlyLoginRefused,
)
from .exceptions import (
    ConcurrentSessionLimitExceededError,
    CrossLocationGuestAccessError,
    CrossOrganizationGuestAccessError,
    CrossOrganizationNasAccessError,
    FairUsagePolicyExceededError,
    GuestAuthMethodNotEnabledError,
    GuestBlockedError,
    GuestDeviceLimitExceededError,
    GuestNotFoundError,
    GuestPasswordLoginFailedError,
    GuestPasswordSetupNotAuthorizedError,
    GuestPasswordTooWeakError,
    GuestPinLockedError,
    GuestPinLoginFailedError,
    GuestPinSetupNotAuthorizedError,
    GuestPinTooWeakError,
    GuestProfileFieldNotCollectedError,
    GuestProfileUpdateNotAuthorizedError,
    GuestReviewLinkOpenedNotAuthorizedError,
    GuestSelfDisconnectNotAuthorizedError,
    GuestSessionNotFoundError,
    GuestTeamSharedQuotaExceededError,
    InvalidSessionStatusTransitionError,
    MacAddressNotAuthorizedError,
    NoReconnectableSessionError,
    RadiusNasAlreadyRegisteredError,
    RadiusNasAuthenticationError,
    RadiusNasClientNotFoundError,
    RadiusNasMissingCredentialsError,
    RadiusNasNotFoundError,
    RadiusNasNotSyncedError,
    RouterNotEligibleForGuestSessionError,
    SessionTerminationCooldownError,
    TooManyDeviceIdsError,
    TooManyVoucherIdsError,
    VenueClosedError,
)
from .models import (
    Guest,
    GuestConsent,
    GuestDevice,
    GuestLoginHistory,
    GuestQuotaUsage,
    GuestSession,
    RadiusNasClient,
)
from .nas_number_generator import (
    NasCodeCounterRepositoryProtocol,
    generate_nas_code,
    generate_shared_secret,
)
from .radius_coa import (
    RADIUS_CODE_DISCONNECT_ACK,
    RADIUS_CODE_DISCONNECT_REQUEST,
    build_packet,
    build_session_identifier_attributes,
    parse_response_code,
    send_packet,
)
from .repository import (
    DeviceSessionCount,
    GuestRepositoryProtocol,
    LocationSessionCount,
    VoucherRedemptionRow,
)
from .validators import (
    compute_period_start,
    has_session_reached_time_limit,
    is_concurrent_session_limit_reached,
    is_device_limit_reached,
    is_fup_usage_exceeded,
    is_quota_exceeded,
    is_session_timed_out,
    is_weak_pin,
    normalize_identifier,
    normalize_mac_address,
    validate_date_range,
    validate_extension_minutes,
    validate_nas_status_transition,
    validate_session_status_transition,
)

logger = logging.getLogger(__name__)

# A real Argon2id hash of a fixed, never-issued dummy password -- computed
# once at import time and verified against whenever ``login_via_password``
# has no real ``Guest.hashed_password`` to compare against (guest doesn't
# exist, or exists but never called ``set_guest_password``). Without this,
# a missing-guest/missing-password login would return in microseconds while
# a real-guest-wrong-password login pays Argon2id's real verify cost,
# letting a timing side-channel answer "does this phone number have a
# password set?" even though ``GuestPasswordLoginFailedError``'s own
# message is deliberately generic -- see ``GuestService
# ._verify_guest_password``.
_DUMMY_PASSWORD_HASH = PasswordManager.hash("Dummy-Guest-Password-000!")

# The identical dummy-hash trick above, sized for a PIN instead of a
# password -- see ``GuestService._verify_guest_pin``. Hashed via
# ``PasswordManager.hash_raw``, not ``PasswordManager.hash``: a 6-digit
# value could never pass ``validate_strength`` (see that method's own
# docstring for why ``set_guest_pin`` hashes real guest PINs the same way).
_DUMMY_PIN_HASH = PasswordManager.hash_raw("047183")

# Sentinel distinguishing "caller has no already-fetched GuestDevice to
# hand in" from a real, meaningful ``None`` (a fresh lookup came back
# empty) -- see ``GuestService.get_or_create_device``'s ``known_device``
# parameter. Every login method calls ``_enforce_device_limit`` (which
# already performs a real ``get_device_by_mac`` for this exact MAC) and
# then, moments later with no intervening write to ``guest_devices``,
# ``_maybe_get_or_create_device``/``get_or_create_device`` for the *same*
# MAC -- previously a second, identical query every single login with a
# device MAC made. Threading the first lookup's result through via
# ``known_device`` removes that redundant round trip; a caller that never
# ran ``_enforce_device_limit`` (a brand-new guest, whose MAC might still
# already exist under some *other* guest_id) leaves this at the sentinel,
# getting the original real, fresh lookup.
_DEVICE_NOT_PREFETCHED: Any = object()

# Redis key template for GuestPinSecurity's brute-force lockout counter --
# scoped by (organization_id, identifier), mirroring
# app.domains.auth.security.AuthSecurity's own ``_RATE_LIMIT_KEY``
# (email+ip_address) and app.domains.otp.service
# .OTP_REQUEST_RATE_LIMIT_KEY_TEMPLATE (identifier alone)'s identical
# per-module key-namespacing convention.
_PIN_LOCKOUT_KEY_TEMPLATE = "guest_pin:lockout:{organization_id}:{identifier}"


class GuestPinSecurity:
    """Static facade over Redis for ``GuestService.login_via_pin``'s
    brute-force lockout -- mirrors ``app.domains.auth.security
    .AuthSecurity.check_rate_limit``/``record_login_attempt``'s and
    ``app.domains.otp.service.OtpRateLimiter``'s identical INCR+EXPIRE+TTL
    convention, reusing the existing Redis client
    (``app.database.redis``) rather than introducing a new cache
    abstraction.

    **Why this exists at all, when ``login_via_password`` has no
    equivalent:** a real password is drawn from a keyspace large enough
    that online brute-forcing it is impractical even with zero lockout --
    a genuine, confirmed gap in ``login_via_password`` today, but not one
    this class fixes (out of scope for Portal PIN). A ``constants
    .PIN_LENGTH``-digit numeric PIN is a completely different story: its
    entire keyspace is ``10 ** PIN_LENGTH`` values, small enough that an
    unthrottled attacker could realistically exhaust it. This class is
    what makes that impractical instead: ``PIN_MAX_ATTEMPTS`` failures
    against one ``(organization_id, identifier)`` pair lock it out for
    ``PIN_LOCKOUT_MINUTES``, raising ``GuestPinLockedError`` (423) on
    every further attempt until the window expires -- without ever
    touching the presented PIN or paying a real Argon2id verify cost,
    the identical "reject before doing the expensive/sensitive part"
    discipline ``_verify_guest_password``'s own dummy-hash trick
    establishes for *timing*, applied here to *attempt volume*.

    Scoped by ``(organization_id, identifier)``, not ``identifier``
    alone -- the same tenant-scoping every other guest-identity lookup in
    this module already applies (mirrors ``Guest``'s own
    ``uq_guests_organization_id_identifier`` uniqueness: the same phone
    number reused across two different organizations' guest lists is two
    different ``Guest`` rows, and must be two different lockout
    counters)."""

    @staticmethod
    def _key(organization_id: uuid.UUID, identifier: str) -> str:
        return _PIN_LOCKOUT_KEY_TEMPLATE.format(
            organization_id=organization_id, identifier=identifier
        )

    @staticmethod
    async def check_lockout(
        redis: Redis, *, organization_id: uuid.UUID, identifier: str
    ) -> None:
        """Raises ``GuestPinLockedError`` if this ``(organization_id,
        identifier)`` pair already has ``constants.PIN_MAX_ATTEMPTS`` (or
        more) recorded failures within the current lockout window."""
        key = GuestPinSecurity._key(organization_id, identifier)
        attempts = await redis.get(key)
        if attempts and int(attempts) >= PIN_MAX_ATTEMPTS:
            ttl = await redis.ttl(key)
            locked_until = datetime.now(UTC) + timedelta(
                seconds=ttl if ttl and ttl > 0 else PIN_LOCKOUT_MINUTES * 60
            )
            raise GuestPinLockedError(locked_until)

    @staticmethod
    async def record_attempt(
        redis: Redis, *, organization_id: uuid.UUID, identifier: str, success: bool
    ) -> None:
        """Clears the failure counter entirely on a successful login, or
        increments it (starting a fresh ``constants.PIN_LOCKOUT_MINUTES``
        window on the very first failure) -- mirrors ``AuthSecurity
        .record_login_attempt``'s identical shape."""
        key = GuestPinSecurity._key(organization_id, identifier)
        if success:
            await redis.delete(key)
            return
        current = await redis.incr(key)
        if current == 1:
            await redis.expire(key, PIN_LOCKOUT_MINUTES * 60)


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick to ``app.domains.voucher.service._event_extra``."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


async def enforce_session_timeouts(
    repository: GuestRepositoryProtocol,
) -> list[GuestSession]:
    """Guest Session Engine (Phase 1): the actual idle/session-timeout
    sweep, pulled out of ``GuestService.enforce_timeouts`` to module scope
    so ``tasks.run_session_timeout_sweep`` (the Celery Beat-scheduled
    caller -- see that module's own docstring for why this was previously
    dead code) can invoke it with nothing but a ``GuestRepository`` bound to
    a fresh session, rather than constructing a full ``GuestService`` and
    its entire ``otp_service``/``voucher_service``/``captive_portal_service``/
    ``router_lookup`` dependency chain purely to reach a method that never
    actually touches any of them. ``GuestService.enforce_timeouts`` itself
    now just delegates here, so every existing caller (including this
    module's pre-existing tests) is unaffected.

    See the module docstring's "a reporting mechanism, not live
    enforcement" write-up for what this sweep does and does not do. Returns
    every session just flipped to ``EXPIRED``.
    """
    now = datetime.now(UTC)
    candidates = await repository.list_timed_out_sessions(now=now)
    expired: list[GuestSession] = []
    for session in candidates:
        if not is_session_timed_out(session, now=now):
            continue  # defensive re-check against the SQL-level filter
        updated = await repository.update_session(
            session,
            {
                "status": GuestSessionStatus.EXPIRED.value,
                "ended_at": now,
                "disconnect_reason": "inactivity_timeout",
            },
        )
        event = GuestSessionExpired(session_id=updated.id)
        logger.info("guest_session_expired_timeout", extra=_event_extra(event))
        await issue_live_disconnect(repository, session=updated)
        expired.append(updated)
    return expired


async def close_sessions_for_nas_restart(
    repository: GuestRepositoryProtocol,
    *,
    router_id: uuid.UUID,
    reason: str,
    now: datetime | None = None,
) -> list[GuestSession]:
    """RADIUS Accounting-On/Accounting-Off (RFC 2866 §5.13): a NAS sends
    Accounting-On once, right after it boots, and Accounting-Off once,
    right before a controlled shutdown -- in both cases, the NAS's own
    local accounting state (which sessions it believes are actually live)
    was just reset/lost, so every ``GuestSession`` this platform still has
    ``ACTIVE`` against that router is now stale on *our* side too. Pulled
    to module scope for the identical "RadiusService method + test suite
    share one real implementation" reason ``enforce_session_timeouts``/
    ``run_fup_time_accrual`` were.

    Deliberately **never** calls ``issue_live_disconnect`` (unlike
    ``enforce_session_timeouts``'s/``run_fup_time_accrual``'s own calls
    for an *unexpected* stale session): sending a RADIUS CoA-Disconnect
    back to a NAS that just told us it is rebooting/shutting down is
    pointless -- it has no live session left to disconnect, and may not
    even be ready to process a CoA packet yet (Accounting-On) or may
    already be gone (Accounting-Off). Only this platform's own
    bookkeeping needs correcting here; closing the row is enough. Returns
    every session just flipped to ``DISCONNECTED``."""
    now = now or datetime.now(UTC)
    sessions = await repository.list_active_sessions_for_router(router_id)
    closed: list[GuestSession] = []
    for session in sessions:
        updated = await repository.update_session(
            session,
            {
                "status": GuestSessionStatus.DISCONNECTED.value,
                "ended_at": now,
                "disconnect_reason": reason,
            },
        )
        event = GuestSessionDisconnected(session_id=updated.id, reason=reason)
        logger.info("guest_session_closed_nas_restart", extra=_event_extra(event))
        closed.append(updated)
    return closed


async def get_or_reset_quota_usage(
    repository: GuestRepositoryProtocol,
    *,
    guest_id: uuid.UUID,
    organization_id: uuid.UUID,
    period_type: QuotaPeriodType,
    tz_name: str,
    now: datetime,
) -> GuestQuotaUsage:
    """The one, single place a :class:`~.models.GuestQuotaUsage` row's
    "has this row's period rolled over" rollover logic lives -- pulled out
    to module scope for the exact same reason ``enforce_session_timeouts``
    was: both the request-triggered call sites
    (``GuestService._enforce_fup_quota``/``GuestService.record_usage``)
    *and* the two Celery Beat sweeps (``tasks.run_fup_time_accrual_sweep``/
    ``tasks.run_quota_reset_sweep``) need to apply this identical
    comparison, and none of them should risk it silently diverging across
    two hand-copied implementations.

    Creates a fresh, zeroed row (this guest's first-ever usage in this
    period type) if none exists yet. If one exists but its own
    ``period_start`` is older than the period boundary ``now`` currently
    falls in (per ``validators.compute_period_start``), resets
    ``bytes_used``/``minutes_used`` to zero and advances ``period_start`` --
    real wall-clock time has moved the guest into a new day/week/month
    since this row was last touched. Otherwise returns the row unchanged."""
    current_period_start = compute_period_start(period_type, now=now, tz_name=tz_name)
    usage = await repository.get_quota_usage(guest_id, period_type.value)
    if usage is None:
        return await repository.create_quota_usage(
            guest_id=guest_id,
            organization_id=organization_id,
            period_type=period_type.value,
            period_start=current_period_start,
            bytes_used=0,
            minutes_used=0,
            last_accrued_at=None,
        )
    if usage.period_start < current_period_start:
        return await repository.update_quota_usage(
            usage,
            {
                "period_start": current_period_start,
                "bytes_used": 0,
                "minutes_used": 0,
                "last_accrued_at": None,
            },
        )
    return usage


async def get_or_reset_quota_usages(
    repository: GuestRepositoryProtocol,
    *,
    guest_id: uuid.UUID,
    organization_id: uuid.UUID,
    period_types: Sequence[QuotaPeriodType],
    tz_name: str,
    now: datetime,
) -> dict[QuotaPeriodType, GuestQuotaUsage]:
    """``get_or_reset_quota_usage`` for several periods at once, reading
    them all in a single ``IN (...)`` query.

    Design spec §5 S9. Callers that need every period -- which is every
    caller, since a FUP policy can cap any combination of daily/weekly/
    monthly -- were issuing one SELECT per period against the same table
    for the same guest. On the guest-login request path that was three
    round trips where one does.

    Identical semantics to the singular helper, applied per period: a
    missing row is created zeroed, a row whose own ``period_start``
    predates the boundary ``now`` falls in is reset and advanced, and
    anything else is returned untouched. Only the *read* is batched --
    the create/update calls that follow are per-row by necessity, and in
    steady state (every row present and current) there are none.
    """
    existing = {
        QuotaPeriodType(row.period_type): row
        for row in await repository.get_quota_usages(
            guest_id, [period_type.value for period_type in period_types]
        )
    }
    resolved: dict[QuotaPeriodType, GuestQuotaUsage] = {}
    for period_type in period_types:
        current_period_start = compute_period_start(
            period_type, now=now, tz_name=tz_name
        )
        usage = existing.get(period_type)
        if usage is None:
            resolved[period_type] = await repository.create_quota_usage(
                guest_id=guest_id,
                organization_id=organization_id,
                period_type=period_type.value,
                period_start=current_period_start,
                bytes_used=0,
                minutes_used=0,
                last_accrued_at=None,
            )
        elif usage.period_start < current_period_start:
            resolved[period_type] = await repository.update_quota_usage(
                usage,
                {
                    "period_start": current_period_start,
                    "bytes_used": 0,
                    "minutes_used": 0,
                    "last_accrued_at": None,
                },
            )
        else:
            resolved[period_type] = usage
    return resolved


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class OtpVerifyProtocol(Protocol):
    async def verify_otp(
        self, *, identifier: str, code: str, purpose: OtpPurpose
    ) -> OtpRequest: ...


class VoucherRedeemProtocol(Protocol):
    async def redeem_voucher(
        self, *, code: str, identifier: str, source: str
    ) -> tuple[Voucher, VoucherBatch]: ...

    async def get_plan_queue_profile_id(
        self, plan_id: uuid.UUID
    ) -> uuid.UUID | None: ...


class CaptivePortalLookupProtocol(Protocol):
    async def resolve_portal_config(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> ResolvedPortalConfig: ...

    async def get_config(
        self,
        config_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Any:
        """The one config the caller names by id, rather than the one that
        resolves for an organization and location.

        Needed by ``record_consent`` alone, and only because a consent row
        is written against a specific ``captive_portal_config_id`` the
        portal already resolved -- stamping it with the version of a
        *differently* resolved config would be a worse record than no
        version at all. Satisfied structurally by the real
        ``CaptivePortalService``.
        """
        ...


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        """The router's API password, decrypted, for a real device push.

        Synchronous and separate from ``get_router`` on purpose: it is
        Fernet work on an already-loaded row, not a query, and the
        push path is the only caller. Satisfied structurally by the real
        ``RouterService``, exactly as ``vlan``/``qos`` already rely on.
        """
        ...


class LocationLookupProtocol(Protocol):
    """The narrow surface ``RadiusService`` needs to resolve a router's own
    ``Location.location_code`` for ``nas_number_generator.generate_nas_code``
    -- satisfied structurally by the real ``LocationService``, the same
    "narrow Protocol, composed via dependency injection" shape every other
    cross-domain composition in this codebase already uses."""

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
    shape every other domain's service defines for itself."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


class GuestSessionBroadcastProtocol(Protocol):
    """The single method ``GuestService``'s ``login_via_otp``/
    ``login_via_voucher`` hook needs from the real
    ``app.domains.monitoring.service.MonitoringService`` (BE-011 Part 3's
    Real-Time Engine) -- reused directly, never reimplemented. See
    ``GuestService.__init__``'s docstring for the full write-up of why this
    hook exists and why it is additive, not a behavior change."""

    async def broadcast_guest_session_event(
        self,
        *,
        message_type: RealtimeMessageType,
        session_id: uuid.UUID,
        guest_id: uuid.UUID,
        router_id: uuid.UUID,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        auth_method: str,
        is_new_guest: bool,
    ) -> None: ...


class AccessDecisionProtocol(Protocol):
    """Guest Access Control (Phase 1): the single method ``GuestService``'s
    optional ``access_control_hook`` needs from the real
    ``app.domains.guest_access.service.GuestAccessService`` -- reused
    directly, never reimplemented, the identical composition
    ``GuestSessionBroadcastProtocol``/``monitoring_hook`` above already
    establishes for the Real-Time Engine. See
    ``GuestService.__init__``'s docstring for why this hook is additive
    (``None``-by-default) rather than a required dependency.

    ``whitelist_only_enabled`` travels *down* this protocol rather than
    being looked up behind it. ``app.domains.guest_access`` documents its
    own acyclic module graph as a design constraint and must never import
    ``app.domains.captive_portal``, where the flag lives -- and the caller
    on this side has the resolved config in hand already (see
    ``_enforce_access_control``). So the boolean is an argument, and the
    resolver stays a pure function."""

    async def check_access(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        identifier: str | None,
        mac_address: str | None,
        whitelist_only_enabled: bool = False,
    ) -> AccessDecision: ...


class MacAuthorizationLookupProtocol(Protocol):
    """The single method ``GuestService``'s optional
    ``mac_authorization_hook`` needs from the real
    ``app.domains.mac_authorization.service.MacAuthorizationService`` --
    reused directly, never reimplemented, the identical composition
    ``AccessDecisionProtocol``/``QueueAssignmentProtocol`` above already
    establish for their own real collaborators. ``None``-by-default (see
    ``GuestService.__init__``'s own docstring): a deployment with no MAC
    Authorization integration wired simply has
    ``login_via_mac_whitelist`` always reject, exactly like
    ``policy_lookup``'s absent-hook fallback -- never a crash."""

    async def is_mac_authorized(
        self,
        mac_address: str,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None = None,
    ) -> bool: ...


class TeamQuotaLookupProtocol(Protocol):
    """The single method ``GuestService``'s optional ``team_quota_hook``
    needs from ``app.domains.guest_teams.quota.SharedQuotaResolver``.

    A resolver rather than the full ``GuestTeamService`` because that service
    composes the concrete ``GuestService``, so depending on it here would
    close a DI cycle (``get_guest_service -> get_guest_team_service ->
    get_guest_service``). ``None``-by-default, exactly like every other hook
    on this class: a deployment with no guest-teams integration wired simply
    never checks a pooled quota, and no venue that does not use teams pays
    anything for this."""

    async def is_over_shared_quota(self, guest_id: uuid.UUID) -> bool: ...


class QueueAssignmentProtocol(Protocol):
    """The methods ``GuestService``'s optional ``queue_assignment_hook``
    needs from the real ``app.domains.queue_management.service
    .QueueManagementService`` -- reused directly, never reimplemented, the
    identical composition ``GuestSessionBroadcastProtocol``/
    ``AccessDecisionProtocol`` above already establish for their own real
    collaborators. Additive (``None``-by-default, best-effort, wrapped in a
    blanket try/except -- see ``_assign_guest_queue``'s own docstring): a
    bandwidth-assignment failure must never block a guest's login, the
    identical posture ``monitoring_hook`` already established, **not**
    ``access_control_hook``'s "a real gate" posture -- queueing is a
    quality-of-service concern, not an authorization decision.

    ``resolve_and_assign_queue`` backs ``_assign_guest_queue`` (a
    policy-resolved bandwidth cap for the session itself).
    ``create_assignment``/``apply_queue`` -- the two lower-level, already
    real ``QueueManagementService`` methods this Protocol also exposes --
    back ``_assign_voucher_queue`` instead: a voucher-linked assignment
    needs an *explicit*, already-known ``queue_profile_id`` (from
    ``VoucherPlan.queue_profile_id``), never a policy-resolved one, so it
    cannot use ``resolve_and_assign_queue`` (which always resolves
    ``PolicyType.BANDWIDTH`` internally and has no override parameter).
    See that method's own docstring for the full write-up."""

    async def resolve_and_assign_queue(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID,
        target_type: QueueTargetType,
        target_id: uuid.UUID,
        device_target: str,
        actor_user_id: uuid.UUID | None = None,
        auto_apply: bool = True,
        guest_id: uuid.UUID | None = None,
    ) -> object: ...

    async def create_assignment(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        target_type: QueueTargetType,
        target_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        device_target: str | None = None,
        queue_profile_id: uuid.UUID | None = None,
        queue_schedule_id: uuid.UUID | None = None,
        priority_override: int | None = None,
        expires_at: datetime | None = None,
    ) -> object: ...

    async def apply_queue(
        self,
        assignment_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> object: ...


class QueueAssignmentDispatcherProtocol(Protocol):
    """Publishes the bandwidth-queue assignment to the background worker
    instead of performing it inline -- design spec §5 S9.

    Satisfied by ``tasks.enqueue_guest_queue_assignment``, which is what
    ``dependencies.get_guest_service`` wires in. Kept as a Protocol so
    this module never imports Celery (``tasks.py`` already imports *this*
    module, so the reverse would be circular) and so tests can observe
    the dispatch without a broker.
    """

    async def __call__(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        router_id: uuid.UUID,
        session_id: uuid.UUID,
        device_target: str,
        guest_id: uuid.UUID | None,
    ) -> None: ...


class ResolvedDevicePolicyProtocol(Protocol):
    rules: dict[str, Any]


class PolicyLookupProtocol(Protocol):
    """The single method ``GuestService``'s optional ``policy_lookup``
    hook needs from the real
    ``app.domains.policy.service.PolicyService`` -- reused directly,
    never reimplemented. ``None``-by-default (see
    ``GuestService.__init__``'s own docstring): a deployment with no
    Policy Engine configured simply falls back to
    ``constants.DEFAULT_MAX_DEVICES_PER_GUEST``, exactly today's
    behavior."""

    async def resolve_effective_policy(
        self,
        *,
        policy_type: PolicyType,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        guest_id: uuid.UUID | None = None,
    ) -> ResolvedDevicePolicyProtocol: ...


async def run_fup_time_accrual(
    repository: GuestRepositoryProtocol,
    policy_lookup: PolicyLookupProtocol,
    *,
    now: datetime,
) -> dict[str, int]:
    """Guest-level FUP time-quota accrual + enforcement, pulled out to
    module scope for the exact same reason ``enforce_session_timeouts``
    was: ``tasks.run_fup_time_accrual_sweep``'s Celery Beat-scheduled
    caller can invoke this with nothing but a ``GuestRepository`` and a
    real ``PolicyService`` bound to a fresh session, and this codebase's
    own test suite can exercise the exact same logic against fakes with no
    live Postgres/Celery broker needed at all.

    For every distinct guest with at least one currently ``ACTIVE``
    session, resolves that guest's own ``PolicyType.FUP`` time limits; if
    none are configured at all, the guest is skipped entirely (no accrual
    round trip is worth paying for a guest whose organization never opted
    into time-based quotas -- unlike byte usage, which is tracked
    unconditionally in ``GuestService.record_usage`` because it rides for
    free on a call that already happens regardless). Otherwise, for each
    configured period, adds the wall-clock minutes elapsed since the row's
    own ``last_accrued_at`` (or ``period_start``) into ``minutes_used`` --
    guest-level connected time, not summed across concurrent sessions (see
    ``models.GuestQuotaUsage``'s own docstring for why). A guest whose
    accrued usage now meets or exceeds a configured limit has every one of
    their currently ``ACTIVE`` sessions expired. Returns a summary dict
    (rows accrued into, sessions expired).

    ## Resolution passes the guest's real location, and used not to

    This resolved with a hardcoded ``location_id=None``.
    ``repository.list_candidate_assignments`` only adds its LOCATION-scope
    predicate when a real ``location_id`` arrives, so a ``PolicyAssignment``
    with ``scope_type=location`` on an FUP policy was never a candidate
    here -- the identical defect ``GuestService._enforce_fup_quota``'s own
    docstring describes, in the one place it mattered most.

    It mattered most here because these two halves are not independent.
    ``_enforce_fup_quota`` is a login-time *gate*: it reads
    ``minutes_used`` and refuses a guest who has already spent their
    allowance. This sweep is the only thing that ever *writes*
    ``minutes_used``. So a venue that assigned its FUP policy to a location
    -- which is exactly what the dashboard's Guest WiFi Limits screen does,
    it has no other scope to offer -- got a sweep that resolved no limits,
    skipped the guest, and never accrued a minute. ``minutes_used`` stayed
    0 for ever, so the login gate (fixed earlier, and correct) had nothing
    to gate on and also never fired. Fixing either half alone leaves a
    daily time limit that still does nothing; this is the other half.

    ## One accrual per guest, even across locations

    ``list_active_guest_org_pairs`` now returns one row per distinct
    ``(guest, organization, location)``, so a guest holding active sessions
    at two of an organization's locations appears twice. Accruing per row
    would double their elapsed minutes and expire them at half their real
    allowance. The rows are therefore grouped back together by guest, and
    each guest is accrued exactly once.

    Their limits are merged across those locations by taking the strictest
    (smallest) configured value for each period. A guest connected at two
    sites is genuinely subject to both venues' rules, and of the available
    readings this is the only one that cannot let a guest exceed a limit
    somebody actually set. The case is rare; picking a defensible answer
    for it is cheaper than leaving it to row ordering.
    """
    pairs = await repository.list_active_guest_org_pairs()
    accrued_rows = 0
    expired_sessions = 0
    locations_by_guest: dict[tuple[uuid.UUID, uuid.UUID], list[uuid.UUID | None]] = {}
    for pair in pairs:
        locations_by_guest.setdefault((pair.guest_id, pair.organization_id), []).append(
            pair.location_id
        )
    for (guest_id, organization_id), location_ids in locations_by_guest.items():
        tz_name = await repository.get_organization_timezone(organization_id)
        time_limits: dict[QuotaPeriodType, int | None] = dict.fromkeys(
            FUP_TIME_LIMIT_RULE_KEYS
        )
        for location_id in location_ids:
            resolved = await policy_lookup.resolve_effective_policy(
                policy_type=PolicyType.FUP,
                organization_id=organization_id,
                location_id=location_id,
                guest_id=guest_id,
            )
            for period_type, rule_key in FUP_TIME_LIMIT_RULE_KEYS.items():
                candidate = resolved.rules.get(rule_key)
                if candidate is None:
                    continue
                current = time_limits[period_type]
                time_limits[period_type] = (
                    candidate if current is None else min(current, candidate)
                )
        if not any(time_limits.values()):
            continue
        violated_period: str | None = None
        for period_type, limit_minutes in time_limits.items():
            usage = await get_or_reset_quota_usage(
                repository,
                guest_id=guest_id,
                organization_id=organization_id,
                period_type=period_type,
                tz_name=tz_name,
                now=now,
            )
            accrue_from = usage.last_accrued_at or usage.period_start
            elapsed_minutes = max(0, int((now - accrue_from).total_seconds() // 60))
            if elapsed_minutes > 0:
                usage = await repository.update_quota_usage(
                    usage,
                    {
                        "minutes_used": usage.minutes_used + elapsed_minutes,
                        "last_accrued_at": now,
                    },
                )
                accrued_rows += 1
            if (
                violated_period is None
                and limit_minutes is not None
                and is_fup_usage_exceeded(used=usage.minutes_used, limit=limit_minutes)
            ):
                violated_period = period_type.value
        if violated_period is not None:
            active_sessions = await repository.list_active_sessions_for_guest(guest_id)
            reason = f"fup_time_quota_exceeded_{violated_period}"
            for active_session in active_sessions:
                updated_session = await repository.update_session(
                    active_session,
                    {
                        "status": GuestSessionStatus.EXPIRED.value,
                        "ended_at": now,
                        "disconnect_reason": reason,
                    },
                )
                await issue_live_disconnect(repository, session=updated_session)
                expired_sessions += 1
    return {"accrued_rows": accrued_rows, "expired_sessions": expired_sessions}


async def run_quota_reset(
    repository: GuestRepositoryProtocol, *, now: datetime
) -> dict[str, int]:
    """Proactive ``GuestQuotaUsage`` rollover sweep, pulled out to module
    scope for the identical "Celery task + test suite share one real
    implementation, no live Postgres needed for the latter" reason
    ``run_fup_time_accrual``/``enforce_session_timeouts`` were. Walks
    every ``GuestQuotaUsage`` row in the platform, resetting any whose own
    ``period_start`` has fallen behind the current period boundary (per
    its organization's own timezone) -- the exact same comparison
    ``get_or_reset_quota_usage`` applies lazily on the request-triggered
    path, applied here proactively so e.g. an admin's "quota remaining"
    view reflects a fresh allowance even for a guest who has not yet
    reconnected/sent traffic in the new period. Idempotent: a row already
    reset for the current period is left untouched (a second run within
    the same period is a no-op). Returns a summary dict (rows reset)."""
    entries = await repository.list_all_quota_usages_with_org_timezone()
    reset_count = 0
    for entry in entries:
        usage = entry.usage
        period_type = QuotaPeriodType(usage.period_type)
        current_period_start = compute_period_start(
            period_type, now=now, tz_name=entry.organization_timezone
        )
        if usage.period_start < current_period_start:
            await repository.update_quota_usage(
                usage,
                {
                    "period_start": current_period_start,
                    "bytes_used": 0,
                    "minutes_used": 0,
                    "last_accrued_at": None,
                },
            )
            reset_count += 1
    return {"reset_count": reset_count}


async def issue_live_disconnect(
    repository: GuestRepositoryProtocol, *, session: GuestSession
) -> bool | None:
    """Phase 1 BhaiFi-parity (#16): a real RFC 2865/5176 Disconnect-Request,
    sent whenever ``session`` ends (``disconnect_session``/
    ``terminate_session``/``pause_session``, and the two system-driven
    sweeps -- ``enforce_session_timeouts``/``run_fup_time_accrual``) --
    replaces this module's previously-documented "nothing ... ever issues a
    live CoA-Disconnect packet" sandbox no-op. Pulled to module scope for
    the identical "Celery sweep + service method + test suite share one
    real implementation" reason ``get_or_reset_quota_usage``/
    ``run_fup_time_accrual`` were.

    Best-effort and never raises: a live network send is a real-world
    addition on top of the DB-level status transition that has *already*
    committed by the time this is called (see every call site below),
    never a gate on it -- an unreachable/misconfigured NAS must never
    prevent an admin (or the system) from ending a session in this
    platform's own records. Returns ``True``/``False`` once a real
    Disconnect-ACK/NAK comes back, or ``None`` when there is no registered
    ``RadiusNasClient`` for ``session.router_id``, that NAS has no
    ``ip_address`` on record, or the send itself failed/timed out (the
    expected outcome in this sandbox -- see ``radius_coa``'s own module
    docstring)."""
    nas_client = await repository.get_nas_client_by_router(session.router_id)
    if nas_client is None or not nas_client.ip_address:
        return None
    guest = await repository.get_guest_by_id(session.guest_id)
    if guest is None:
        return None
    try:
        shared_secret = decrypt_secret(nas_client.shared_secret_encrypted)
        attributes = build_session_identifier_attributes(
            username=guest.identifier,
            acct_session_id=str(session.id),
            nas_ip_address=nas_client.ip_address,
            framed_ip_address=session.ip_address,
        )
        packet = build_packet(
            code=RADIUS_CODE_DISCONNECT_REQUEST,
            attributes=attributes,
            shared_secret=shared_secret,
        )
        response = await asyncio.to_thread(
            send_packet, packet, host=nas_client.ip_address
        )
    except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
        logger.warning(
            "guest_live_disconnect_failed",
            extra={"session_id": str(session.id), "error": str(exc)},
        )
        return None
    if response is None:
        logger.info(
            "guest_live_disconnect_no_response",
            extra={"session_id": str(session.id), "nas_ip": nas_client.ip_address},
        )
        return None
    acknowledged = parse_response_code(response) == RADIUS_CODE_DISCONNECT_ACK
    logger.info(
        "guest_live_disconnect_response",
        extra={"session_id": str(session.id), "acknowledged": acknowledged},
    )
    return acknowledged


# ============================================================================
# Read models
# ============================================================================


@dataclass(frozen=True, slots=True)
class GuestLoginResult:
    guest: Guest
    session: GuestSession
    device: GuestDevice | None
    is_new_guest: bool


#: The single ``disconnect_reason`` literal that means "this session ran
#: out of time" -- written only by ``enforce_session_timeouts`` above.
#: Matched exactly, never by prefix or substring: the other ``EXPIRED``
#: reasons (``data_limit_exceeded``, ``fup_data_quota_exceeded_daily``,
#: ...) are quota exhaustion, which is a different thing to tell a guest
#: and is deliberately not told to them here at all.
SESSION_TIMEOUT_DISCONNECT_REASON = "inactivity_timeout"

#: RFC 2866 §5.10 ``Acct-Terminate-Cause`` value 5, forwarded verbatim by
#: FreeRADIUS (``ops/freeradius/rest.conf``) into ``disconnect_reason``
#: when a NAS stops accounting because its own ``Session-Timeout`` ran
#: out. This is the founder's case as it actually arrives: RouterOS
#: enforces the ``Session-Timeout`` this platform put in the Access-Accept
#: and then reports the stop, so the session lands as ``DISCONNECTED``
#: with this string -- **not** as ``EXPIRED``, which only the platform's
#: own idle sweep ever writes.
#:
#: Matching a NAS-supplied string is safe in a way that matching an
#: operator-supplied one would not be: it is compared, never returned,
#: and it arrives from a NAS already authenticated by its shared secret,
#: from a closed RFC enumeration rather than a free-text field.
#:
#: ``Idle-Timeout`` (cause 4) is not here, and has its own constant
#: directly below. It used to be excluded outright, on the reasoning that
#: "RouterOS's own hotspot profile carries ``idle-timeout: 30m``
#: independently of anything this platform sends, and 'your device was
#: idle' is what the generic disconnected copy already describes well."
#: That reasoning was correct for as long as its premise held, and the
#: premise has since stopped holding: this platform now *sends*
#: ``Idle-Timeout`` on every Access-Accept, from the venue's own SESSION
#: policy (``GuestService._resolve_idle_timeout_minutes``). Cause 4 no
#: longer reports a number nobody chose -- it reports the venue's own
#: setting firing, which is a different and tellable event.
#:
#: The two stay separate constants rather than becoming one set, because
#: they must not collapse into one message. A guest whose Session-Timeout
#: ran out has used their full allotted time and can sign straight back
#: in; a guest whose Idle-Timeout fired was not using the connection at
#: all and is usually surprised to find themselves signed out. Telling
#: either of them the other's story is worse than telling them nothing.
RADIUS_SESSION_TIMEOUT_TERMINATE_CAUSE = "Session-Timeout"

#: RFC 2866 s5.10 ``Acct-Terminate-Cause`` value 4, arriving by the exact
#: same route as ``RADIUS_SESSION_TIMEOUT_TERMINATE_CAUSE`` above (the NAS
#: sets it, FreeRADIUS forwards it verbatim into ``disconnect_reason``, and
#: the session lands ``DISCONNECTED``). It means the device passed no
#: traffic for longer than the ``Idle-Timeout`` this platform put in the
#: Access-Accept.
#:
#: Same safety argument as its sibling: compared, never returned, from a
#: closed RFC enumeration, arriving from a NAS already authenticated by its
#: shared secret.
#:
#: Honest limit, worth stating: a router provisioned before this platform
#: sent the attribute -- or one whose hotspot profile still carries its own
#: ``idle-timeout`` and whose firmware ignores the RADIUS value -- also
#: reports cause 4. The guest is then shown "you were idle", which remains
#: true; only the *number* on the screen (this session's recorded
#: ``idle_timeout_minutes``) might not be the one the device applied. The
#: copy is written to survive that: it names the venue's setting, and a
#: session with no recorded value shows no number at all.
RADIUS_IDLE_TIMEOUT_TERMINATE_CAUSE = "Idle-Timeout"

#: The exact ``disconnect_reason`` literals ``run_fup_time_accrual`` writes
#: when a guest has spent their venue-configured connected-time allowance
#: for a period. Built from ``QuotaPeriodType`` rather than typed out, so a
#: new period can never be added with an ending the portal silently fails
#: to recognise.
#:
#: A frozenset of exact strings, matched by membership and never by prefix
#: -- the same discipline ``SESSION_TIMEOUT_DISCONNECT_REASON`` keeps, and
#: for the same reason: the neighbouring ``fup_data_quota_exceeded_*``
#: reasons share this stem, and they are a different thing to tell a guest
#: (data spent, not time spent).
FUP_TIME_QUOTA_DISCONNECT_REASONS = frozenset(
    f"fup_time_quota_exceeded_{period.value}" for period in QuotaPeriodType
)

#: Which ``FUPPolicyRules`` field carries each period's connected-time cap.
#: Module scope so ``run_fup_time_accrual`` does not rebuild it once per
#: guest, and so the mapping is stated once rather than spelled out at each
#: of the two places that read these rules.
FUP_TIME_LIMIT_RULE_KEYS: dict[QuotaPeriodType, str] = {
    QuotaPeriodType.DAILY: "daily_time_limit_minutes",
    QuotaPeriodType.WEEKLY: "weekly_time_limit_minutes",
    QuotaPeriodType.MONTHLY: "monthly_time_limit_minutes",
}


def _ended_session_reason(session: GuestSession) -> GuestSessionEndedReason | None:
    """Map an already-ended ``GuestSession`` to the coarse, guest-safe
    vocabulary the captive portal is allowed to see, or ``None`` when a
    guest should be told nothing at all about this ending.

    Module scope, not a private method, so the whole decision table can
    be tested against real ``GuestSession`` rows without standing up a
    ``GuestService`` and its dependency chain -- the same reason
    ``enforce_session_timeouts`` and ``is_session_timed_out`` live where
    they do.

    Fails closed by construction: the returns are an allowlist, and
    anything not named -- a new status, a new ``EXPIRED`` reason -- falls
    through to ``None`` and shows an ordinary sign-in page. The failure
    mode of a missing case is a guest who is told nothing, which is
    today's behaviour and is merely unhelpful. The failure mode of an
    open default would be a guest told something false about why their
    internet stopped.

    See ``GuestService.get_last_ended_session_for_device`` for why each
    branch is what it is.
    """
    if session.status == GuestSessionStatus.DISCONNECTED.value:
        # The founder's case arrives here, not in the EXPIRED branch
        # below: the router enforced the Session-Timeout and told us so
        # via Accounting-Stop, which ends the session as DISCONNECTED and
        # carries the NAS's own terminate cause. Reading it is what makes
        # "your time is up" available instead of the vaguer "you were
        # disconnected" -- the two are different messages to a guest, and
        # only one of them explains a venue's 30-minute limit.
        if session.disconnect_reason == RADIUS_SESSION_TIMEOUT_TERMINATE_CAUSE:
            return GuestSessionEndedReason.TIMED_OUT
        # The venue's own idle timeout, enforced on the device and reported
        # back as cause 4. Checked before the DISCONNECTED fall-through
        # rather than folded into it: since this platform started sending
        # Idle-Timeout, this is the venue's setting firing, not an
        # unattributable drop. See RADIUS_IDLE_TIMEOUT_TERMINATE_CAUSE.
        if session.disconnect_reason == RADIUS_IDLE_TIMEOUT_TERMINATE_CAUSE:
            return GuestSessionEndedReason.IDLE_TIMED_OUT
        return GuestSessionEndedReason.DISCONNECTED
    if session.status == GuestSessionStatus.EXPIRED.value:
        if session.disconnect_reason == SESSION_TIMEOUT_DISCONNECT_REASON:
            return GuestSessionEndedReason.TIMED_OUT
        # The venue's daily/weekly/monthly connected-time allowance, spent.
        # Separated from TIMED_OUT because the advice differs: a timed-out
        # guest signs back in and carries on, whereas this guest cannot get
        # back on until the period rolls over, and telling them to "sign in
        # again" would send them round a loop that refuses them.
        if session.disconnect_reason in FUP_TIME_QUOTA_DISCONNECT_REASONS:
            return GuestSessionEndedReason.TIME_LIMIT_REACHED
    return None


@dataclass(frozen=True, slots=True)
class GuestLastEndedSessionResult:
    """What ``GuestService.get_last_ended_session_for_device`` hands back.

    Carries no ``Guest`` and no ``GuestSession`` on purpose. Every other
    read model in this module returns the ORM rows and lets the router
    pick fields off them; this one cannot, because its consumer is an
    unauthenticated endpoint and the rows carry an unmasked
    ``identifier`` and a ``disconnect_reason`` holding operators' private
    notes. Handing the router those rows would make leaking them a
    one-line mistake in a file where that one line looks exactly like
    every neighbouring line. The redaction is done here, once, by
    construction -- what does not travel cannot be serialised.
    """

    reason: GuestSessionEndedReason
    session_timeout_minutes: int | None
    # The idle timeout this session actually carried, so a guest idled out
    # can be told the venue's real number rather than whatever happens to be
    # configured by the time they read the screen. None for a session that
    # recorded none (every row predating the column), in which case the
    # portal shows the reason without a number rather than inventing one.
    #
    # Safe by the same test every other field on this model had to pass: it
    # is venue policy, identical for every guest at the location, so it
    # tells a stranger holding an observed MAC nothing about the guest.
    idle_timeout_minutes: int | None = None


@dataclass(frozen=True, slots=True)
class RadiusAuthorizeResult:
    authorized: bool
    session_timeout_seconds: int | None
    data_limit_mb: int | None
    # RFC 2865 s5.28 Idle-Timeout, in seconds -- how long the NAS lets this
    # device pass zero bytes before closing the session. None means "send no
    # attribute", which leaves whatever the device's own hotspot profile
    # says standing; that is the behaviour every session had before this
    # platform sent the attribute, and is what a session row predating
    # GuestSession.idle_timeout_minutes still gets.
    #
    # Unlike session_timeout_seconds this is NOT a remaining allowance and
    # must never be turned into one. An idle timeout is a rolling window the
    # NAS resets on every packet, so the full configured value is the
    # correct thing to send on every re-authorization; sending "what is
    # left" would be a category error that shrank a guest's idle allowance
    # each time anything spoke to RADIUS.
    idle_timeout_seconds: int | None = None
    # A real Mikrotik-Rate-Limit RADIUS reply-attribute value (see
    # app.domains.queue_management.service.format_mikrotik_rate_limit),
    # or None when no queue_lookup hook is wired or the session has no
    # queue assignment -- see RadiusService.__init__'s own docstring.
    rate_limit: str | None = None


@dataclass(frozen=True, slots=True)
class GuestAnalyticsSummary:
    visitors: int
    unique_guests: int
    returning_guests: int
    average_session_duration_seconds: float | None
    total_bandwidth_bytes: int


@dataclass(frozen=True, slots=True)
class OtpSuccessRateResult:
    total_attempts: int
    successful_attempts: int
    success_rate: float


@dataclass(frozen=True, slots=True)
class VoucherUsageResult:
    sessions: int
    unique_guests: int
    total_bandwidth_bytes: int


# ============================================================================
# GuestService: login orchestration + session lifecycle
# ============================================================================


class GuestService:
    """Core Guest business logic: login orchestration and session lifecycle.

    ## BE-011 Part 3 addition: an additive, optional real-time broadcast hook

    ``monitoring_hook`` is a new, keyword-only, ``None``-by-default
    constructor parameter (``GuestSessionBroadcastProtocol``, duck-typed
    against ``app.domains.monitoring.service.MonitoringService`` -- the same
    narrow-protocol composition style ``otp_service``/``voucher_service``/
    ``captive_portal_service``/``router_lookup``/``audit_writer`` already
    use). It is called from ``login_via_otp``/``login_via_voucher`` *after*
    their existing session-creation logic has already succeeded (see
    ``_broadcast_guest_session_started`` below) to publish a
    ``guest_session_started`` event onto the monitoring domain's real-time
    WebSocket channel (``WS /monitoring/ws/sessions``).

    This is additive, not a behavior change, for three reasons: (1) the
    parameter defaults to ``None`` and every existing caller/test that
    constructs ``GuestService`` without it (including this module's own
    existing test suite) behaves exactly as before -- no broadcast attempt
    at all; (2) it changes no existing parameter, return type, or exception
    contract of ``login_via_otp``/``login_via_voucher``; (3) the broadcast
    call itself is wrapped in a try/except that only ever logs a warning,
    never raises -- a monitoring-side failure (Redis down, a bug in the
    hook) can never break a real guest's login, mirroring
    ``NotificationService.dispatch_notification``'s identical resilience
    posture for Part 2's alert notifications. This mirrors the discipline
    ``app.domains.router_agent``'s existing heartbeat -> ``HeartbeatLog``
    hook (BE-011 Part 1) already established for composing a *different*
    domain's lifecycle event into this module -- small, additive,
    documented, and never changing the composed-into method's own contract.
    The one difference: that hook lives in ``router_agent``'s own endpoint
    (a single call site), while this one lives inside ``GuestService``'s own
    method bodies, since guest login is reachable through more than one
    caller and every one of them should broadcast, not just whichever
    endpoint happens to call it first.

    ``access_control_hook`` (Guest Access Control, Phase 1) is a second,
    independently optional, ``None``-by-default constructor parameter --
    additive for the identical three reasons ``monitoring_hook`` is,
    above. It is duck-typed against
    ``app.domains.guest_access.service.GuestAccessService`` via
    ``AccessDecisionProtocol``. **Unlike** ``monitoring_hook``, a wired
    ``access_control_hook`` can change ``login_via_otp``/
    ``login_via_voucher``'s outcome: it is a real authorization gate, not a
    best-effort side broadcast, so its call is deliberately **not**
    wrapped in a blanket try/except -- a genuine
    ``GuestAccessDeniedError`` from a resolved ``BLOCKLIST`` decision must
    propagate and block the login, the same way ``GuestBlockedError``
    already does for the guest-level ``Guest.is_blocked`` flag. It is
    called immediately after that existing blocked-guest check, before any
    concurrent-session check or OTP/voucher verification -- see
    ``_enforce_access_control``'s own docstring for the exact placement
    reasoning.

    ``queue_assignment_hook`` (Queue Management Engine) is a third,
    independently optional, ``None``-by-default constructor parameter --
    additive for the identical three reasons ``monitoring_hook`` is,
    above, and duck-typed against
    ``app.domains.queue_management.service.QueueManagementService`` via
    ``QueueAssignmentProtocol``. Like ``monitoring_hook`` (and **unlike**
    ``access_control_hook``), its call is wrapped in a blanket try/except
    that only ever logs a warning, never raises -- a bandwidth-queue
    assignment failure (a MikroTik queue command failing, the router
    being briefly unreachable) is a quality-of-service concern, not an
    authorization decision, and must never block a real guest's login.
    Called from ``login_via_otp``/``login_via_voucher`` immediately after
    ``_broadcast_guest_session_started``, once the real session row (and
    its own ``ip_address``, the only thing that makes a real device queue
    assignment possible) already exists.

    ``policy_lookup`` (Phase 1 BhaiFi-parity: per-guest device limit) is a
    fourth, independently optional, ``None``-by-default constructor
    parameter, duck-typed against
    ``app.domains.policy.service.PolicyService`` via
    ``PolicyLookupProtocol``. Used only by ``_enforce_device_limit`` to
    resolve ``PolicyType.DEVICE``'s own ``max_devices_per_guest`` --
    **unlike** ``queue_assignment_hook``, a resolution failure here is
    **not** swallowed: a real device-limit violation
    (``GuestDeviceLimitExceededError``) must still block the login the
    same way it always has, so only the *lookup* is optional (falling back
    to ``constants.DEFAULT_MAX_DEVICES_PER_GUEST`` when no hook is wired),
    never the enforcement itself.

    ``mac_authorization_hook`` (real MAC-whitelist bypass) is a fifth,
    independently optional, ``None``-by-default constructor parameter,
    duck-typed against
    ``app.domains.mac_authorization.service.MacAuthorizationService`` via
    ``MacAuthorizationLookupProtocol``. Used only by
    ``login_via_mac_whitelist`` -- **unlike** ``queue_assignment_hook``,
    an absent hook doesn't just skip a nice-to-have side effect, it makes
    that entire method always reject (see its own docstring): this hook
    gates a whole login path, not an auxiliary effect of one of the other
    three.

    ``redis`` (Portal PIN) is a sixth, independently optional,
    ``None``-by-default constructor parameter -- the one exception to
    every parameter above being a narrow, duck-typed ``Protocol`` wrapping
    another domain's real service. ``login_via_pin``'s brute-force
    lockout (``GuestPinSecurity``, a static facade, not a stateful
    collaborator) needs nothing from another domain's service, only the
    same raw ``redis.asyncio.Redis`` client ``app.domains.otp.service
    .OtpService``/``app.domains.auth.security.AuthSecurity`` already use
    directly for their own rate limiting -- wrapping it in a Protocol
    would add an indirection with no real collaborator behind it. Additive
    for the identical reason every hook above is: defaults to ``None``, so
    every existing caller/test that constructs ``GuestService`` without it
    (this module's entire pre-Portal-PIN test suite included) is
    unaffected, and when unset, ``login_via_pin`` simply skips the
    ``GuestPinSecurity`` lockout check/record entirely -- a deployment
    that forgets to wire this loses brute-force protection, not the
    ability to log in, mirroring every other optional hook's own
    fail-open-to-"feature simply off" posture rather than fail-closed. The
    real running application always wires it (see
    ``dependencies.get_guest_service``) -- this default only matters for
    tests and any other caller that has no real Redis available.
    """

    def __init__(
        self,
        repository: GuestRepositoryProtocol,
        otp_service: OtpVerifyProtocol,
        voucher_service: VoucherRedeemProtocol,
        captive_portal_service: CaptivePortalLookupProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        monitoring_hook: GuestSessionBroadcastProtocol | None = None,
        access_control_hook: AccessDecisionProtocol | None = None,
        queue_assignment_hook: QueueAssignmentProtocol | None = None,
        queue_assignment_dispatcher: QueueAssignmentDispatcherProtocol | None = None,
        policy_lookup: PolicyLookupProtocol | None = None,
        mac_authorization_hook: MacAuthorizationLookupProtocol | None = None,
        team_quota_hook: TeamQuotaLookupProtocol | None = None,
        redis: Redis | None = None,
        caller_location_scope: LocationScope = None,
    ) -> None:
        self.repository = repository
        self.otp_service = otp_service
        self.voucher_service = voucher_service
        self.captive_portal_service = captive_portal_service
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        self.monitoring_hook = monitoring_hook
        self.access_control_hook = access_control_hook
        self.queue_assignment_hook = queue_assignment_hook
        self.queue_assignment_dispatcher = queue_assignment_dispatcher
        self.policy_lookup = policy_lookup
        # Request-scoped memo for _resolve_session_policy_rules -- see its
        # own docstring. GuestService is constructed per request by
        # dependencies.get_guest_service, so this never outlives one login.
        self._session_policy_cache: dict[
            tuple[uuid.UUID | None, uuid.UUID | None, uuid.UUID | None],
            dict[str, Any],
        ] = {}
        self.mac_authorization_hook = mac_authorization_hook
        self.team_quota_hook = team_quota_hook
        self.redis = redis
        # Constructor-injected -- see `app.domains.rbac.location_scope`.
        self.caller_location_scope = caller_location_scope

    async def _broadcast_guest_session_started(
        self,
        *,
        session: GuestSession,
        guest: Guest,
        router: Router,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        auth_method: str,
        is_new_guest: bool,
    ) -> None:
        """Best-effort, additive real-time broadcast -- see ``GuestService``'s
        own docstring for the full write-up. A no-op when no
        ``monitoring_hook`` was wired (the default); never raises."""
        if self.monitoring_hook is None:
            return
        try:
            await self.monitoring_hook.broadcast_guest_session_event(
                message_type=RealtimeMessageType.GUEST_SESSION_STARTED,
                session_id=session.id,
                guest_id=guest.id,
                router_id=router.id,
                location_id=location_id,
                organization_id=organization_id,
                auth_method=auth_method,
                is_new_guest=is_new_guest,
            )
        except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
            logger.warning(
                "guest_session_broadcast_failed",
                extra={"session_id": str(session.id), "error": str(exc)},
            )

    async def _assign_guest_queue(
        self,
        *,
        session: GuestSession,
        router: Router,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
    ) -> None:
        """Best-effort, additive dynamic bandwidth-queue assignment -- see
        ``QueueAssignmentProtocol``'s own docstring for the full write-up.
        A no-op when no ``queue_assignment_hook`` was wired (the default);
        never raises. Targets the ``session`` itself (not
        the guest) -- a real RouterOS ``/queue simple`` entry is tied to
        one concrete IP address, and ``session.ip_address`` is the only
        one that is actually correct *right now*; a guest-level
        assignment would go stale the moment they reconnect with a new
        DHCP lease. ``session.guest_id`` is still passed through to the
        Policy Engine's resolution (Group Policies "Map users") so a
        GUEST-targeted bandwidth override for *this* guest outranks the
        location's own default when picking which queue profile to apply
        -- only the RouterOS-facing target stays session-scoped, the
        policy that determines its rate is guest-scoped.

        **Called on every login, not only when a session was created.**
        Every one of the five login methods runs this outside its own
        ``if created:`` block, unlike the real-time arrival broadcast and
        the visit counter, which describe an arrival that did not happen
        on a reused row.

        Speed is the one entitlement that does not live on the session
        row. ``_reuse_or_create_session`` deliberately re-resolves and
        writes ``session_timeout_minutes``, ``idle_timeout_minutes``,
        ``data_limit_mb``, ``auth_method`` and ``voucher_id`` onto a
        reused session, precisely so a returning guest gets what the venue
        has configured *now*. Speed instead lives in the SESSION-targeted
        ``QueueAssignment`` this method creates -- the row
        ``RadiusService.authorize`` reads to compose the
        ``Mikrotik-Rate-Limit`` reply attribute, and the row
        ``QueueManagementService.apply_queue`` turns into a real
        ``/queue simple`` entry. Resolving it only on ``created`` pinned a
        guest to the rate that applied the moment their session first
        opened.

        That was not a short window. A guest who keeps using the network
        never reaches that moment again: each re-login is a reuse, and a
        reuse bumps ``last_activity_at``, so the session is refreshed
        rather than replaced, indefinitely. Their speed could not change,
        whatever the dashboard showed and whatever the RADIUS reply
        recomputed around it. Bug report: "speed is only set to 20 and not
        updating".

        Running it on every login is safe because
        ``QueueManagementService.resolve_and_assign_queue`` is idempotent
        by construction: an unchanged rate resolves to the same
        ``QueueProfile``, finds this session's existing assignment already
        pointing at it, and returns without a single device call. Only a
        genuinely changed rate does work, and it does it through
        ``move_queue``, which applies the new ``/queue simple`` *before*
        pulling the old one -- so a guest is never left at zero bandwidth
        in between.

        ``_assign_voucher_queue`` deliberately did **not** move with it:
        it creates a fresh VOUCHER-targeted assignment on every call with
        no find-or-reuse step, so running it per login would accumulate
        duplicate assignments rather than converge on one."""
        if not session.ip_address:
            return

        # Design spec §5 S9. Applying the queue means opening a fresh TCP
        # connection to the venue's MikroTik -- no pooling, 10-second
        # timeout. Awaited inline, that sat between the guest entering a
        # correct OTP and seeing they were online: the failure was already
        # swallowed, but a swallowed 10-second timeout is still 10 seconds
        # of spinner. Handing it to the worker is the fix; queueing is a
        # quality-of-service concern, not an authorization one, so it is
        # correct for it to land a moment after the session rather than
        # before it.
        if self.queue_assignment_dispatcher is not None:
            await self.queue_assignment_dispatcher(
                organization_id=organization_id,
                location_id=location_id,
                router_id=router.id,
                session_id=session.id,
                device_target=session.ip_address,
                guest_id=session.guest_id,
            )
            return

        # No dispatcher wired -- run it inline, as before. This is the
        # path unit tests and any broker-less deployment take; the real
        # API always wires the dispatcher (see
        # ``dependencies.get_guest_service``), so no guest request reaches
        # here. Kept rather than made a no-op so that a deployment without
        # a worker still gets queues applied, just slowly, instead of
        # silently not at all.
        if self.queue_assignment_hook is None:
            return
        try:
            await self.queue_assignment_hook.resolve_and_assign_queue(
                requesting_organization_id=organization_id,
                location_id=location_id,
                router_id=router.id,
                target_type=QueueTargetType.SESSION,
                target_id=session.id,
                device_target=session.ip_address,
                guest_id=session.guest_id,
            )
        except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
            logger.warning(
                "guest_queue_assignment_failed",
                extra={"session_id": str(session.id), "error": str(exc)},
            )

    async def _assign_voucher_queue(
        self,
        *,
        voucher: Voucher,
        session: GuestSession,
        router: Router,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
    ) -> None:
        """Phase 1 BhaiFi-parity: best-effort, additive speed-linked
        voucher queue assignment -- creates a real
        ``QueueAssignment`` (``QueueTargetType.VOUCHER``, ``target_id=
        voucher.id``) using the *explicit* ``QueueProfile`` the redeemed
        voucher's own ``VoucherPlan`` names, distinct from
        ``_assign_guest_queue``'s policy-resolved, per-``SESSION``
        assignment (both fire on a voucher login; this one only when the
        voucher resolves to a real speed-link).

        **Why this lives on ``GuestService``, not
        ``VoucherService.redeem_voucher``:** a ``QueueAssignment`` targeting
        ``QueueTargetType.VOUCHER`` is device-bound (requires a real
        ``router_id``/``device_target``, per
        ``app.domains.queue_management.validators.validate_target``'s
        ``DEVICE_BOUND_TARGET_TYPES`` check) -- ``redeem_voucher`` is
        deliberately router-agnostic (a voucher code by itself names no
        router; only the guest login redeeming it does), so only this
        method, called after the session (and its router) already exist,
        has what a real assignment needs. ``VoucherService`` only ever
        exposes the narrow, read-only
        ``get_plan_queue_profile_id`` -- it never touches
        ``queue_management`` itself, keeping ``voucher`` a dependency-free
        leaf exactly as before.

        A no-op when no ``queue_assignment_hook`` was wired, when
        ``voucher.plan_id`` is unset (no plan link at all), when the plan
        itself carries no ``queue_profile_id`` (no speed entitlement), or
        when ``session.ip_address`` is unknown (mirrors
        ``_assign_guest_queue``'s identical "no known device IP" no-op).
        Never raises."""
        if (
            self.queue_assignment_hook is None
            or voucher.plan_id is None
            or not session.ip_address
        ):
            return
        try:
            queue_profile_id = await self.voucher_service.get_plan_queue_profile_id(
                voucher.plan_id
            )
            if queue_profile_id is None:
                return
            assignment = await self.queue_assignment_hook.create_assignment(
                actor_user_id=None,
                requesting_organization_id=organization_id,
                target_type=QueueTargetType.VOUCHER,
                target_id=voucher.id,
                router_id=router.id,
                location_id=location_id,
                device_target=session.ip_address,
                queue_profile_id=queue_profile_id,
            )
            await self.queue_assignment_hook.apply_queue(
                assignment.id,
                actor_user_id=None,
                requesting_organization_id=organization_id,
            )
        except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
            logger.warning(
                "guest_voucher_queue_assignment_failed",
                extra={"voucher_id": str(voucher.id), "error": str(exc)},
            )

    # ========================================================================
    # Login orchestration
    # ========================================================================

    async def login_via_otp(
        self,
        *,
        identifier: str,
        code: str,
        auth_method: GuestAuthMethod,
        purpose: OtpPurpose = OtpPurpose.GUEST_LOGIN,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        router_id: uuid.UUID,
        device_mac: str | None = None,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        accept_language: str | None = None,
    ) -> GuestLoginResult:
        if auth_method not in (
            GuestAuthMethod.OTP_SMS,
            GuestAuthMethod.OTP_EMAIL,
            GuestAuthMethod.OTP_WHATSAPP,
        ):
            raise GuestAuthMethodNotEnabledError(auth_method.value)

        identifier = normalize_identifier(identifier)
        resolved = await self._require_method_enabled(
            organization_id=organization_id,
            location_id=location_id,
            auth_method=auth_method,
        )
        resolved_org_id = resolved.config.organization_id

        existing_guest = await self.repository.get_guest_by_identifier(
            resolved_org_id, identifier
        )
        self._reject_if_blocked(existing_guest)
        await self._enforce_access_control(
            organization_id=resolved_org_id,
            location_id=location_id,
            identifier=identifier,
            device_mac=device_mac,
            auth_method=auth_method,
            guest=existing_guest,
            ip_address=ip_address,
            whitelist_only_enabled=bool(resolved.config.whitelist_only_enabled),
            whitelist_only_denied_message=(
                resolved.config.whitelist_only_denied_message
            ),
        )
        known_device: GuestDevice | None = _DEVICE_NOT_PREFETCHED
        if existing_guest is not None:
            # A brand-new guest (``existing_guest is None``) trivially holds
            # zero active sessions -- skip the query entirely rather than
            # counting against a guest_id that doesn't exist yet. Checked
            # before OTP verification below, not after, so a guest already
            # at the limit never spends a real (rate-limited, one-time) OTP
            # attempt on a login that was always going to be rejected.
            await self._enforce_concurrent_session_limit(
                existing_guest.id,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            # Same "brand-new guest trivially holds zero devices" skip --
            # see _enforce_device_limit's own docstring. Its return value
            # is threaded into _maybe_get_or_create_device below as
            # known_device, so that call doesn't repeat the identical
            # get_device_by_mac query verify_otp/_get_or_create_guest don't
            # touch in between.
            known_device = await self._enforce_device_limit(
                guest_id=existing_guest.id,
                mac_address=device_mac,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            # Same skip -- see _enforce_fup_quota's own docstring.
            await self._enforce_fup_quota(
                guest_id=existing_guest.id,
                organization_id=resolved_org_id,
                location_id=location_id,
            )

        router = await self._get_eligible_router(router_id)

        try:
            await self.otp_service.verify_otp(
                identifier=identifier, code=code, purpose=purpose
            )
        except CloudGuestError as exc:
            await self._record_login_failure(
                guest=existing_guest,
                identifier=identifier,
                auth_method=auth_method,
                organization_id=resolved_org_id,
                location_id=location_id,
                reason=type(exc).__name__,
                ip_address=ip_address,
            )
            raise

        guest, is_new = await self._get_or_create_guest(
            existing_guest,
            organization_id=resolved_org_id,
            location_id=location_id,
            identifier=identifier,
        )
        device = await self._maybe_get_or_create_device(
            guest_id=guest.id,
            mac_address=device_mac,
            device_name=device_name,
            known_device=known_device,
        )
        resolved_session_timeout = await self._resolve_session_timeout_minutes(
            organization_id=resolved_org_id,
            location_id=location_id,
            guest_id=guest.id,
        )
        resolved_idle_timeout = await self._resolve_idle_timeout_minutes(
            organization_id=resolved_org_id,
            location_id=location_id,
            guest_id=guest.id,
        )
        session, created = await self._reuse_or_create_session(
            guest=guest,
            device=device,
            router=router,
            location_id=location_id,
            auth_method=auth_method,
            voucher_id=None,
            ip_address=ip_address,
            user_agent=user_agent,
            accept_language=accept_language,
            data_limit_mb=None,
            session_timeout_minutes=resolved_session_timeout,
            idle_timeout_minutes=resolved_idle_timeout,
        )
        if created:
            # BE-011 Part 3: additive, best-effort real-time broadcast --
            # see GuestService's own docstring. Fires only after the real
            # session row above already exists. Skipped on a reused
            # session -- see _reuse_or_create_session's own docstring.
            await self._broadcast_guest_session_started(
                session=session,
                guest=guest,
                router=router,
                location_id=location_id,
                organization_id=resolved_org_id,
                auth_method=auth_method.value,
                is_new_guest=is_new,
            )
            await self._bump_guest_visit(guest)
        # Deliberately outside the ``if created:`` block above, unlike
        # every other side effect there -- see ``_assign_guest_queue``'s
        # own docstring for why, and for the bug that put it here. The
        # same call sits outside ``if created:`` in all five login
        # methods.
        await self._assign_guest_queue(
            session=session,
            router=router,
            location_id=location_id,
            organization_id=resolved_org_id,
        )

        await self._record_login_success(
            guest=guest,
            identifier=identifier,
            auth_method=auth_method,
            location_id=location_id,
            ip_address=ip_address,
        )

        event = GuestLoggedIn(
            guest_id=guest.id,
            identifier=identifier,
            auth_method=auth_method.value,
            session_id=session.id,
            is_new_guest=is_new,
        )
        logger.info("guest_logged_in", extra=_event_extra(event))
        return GuestLoginResult(
            guest=guest, session=session, device=device, is_new_guest=is_new
        )

    async def login_via_voucher(
        self,
        *,
        code: str,
        identifier: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        router_id: uuid.UUID,
        device_mac: str | None = None,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        accept_language: str | None = None,
    ) -> GuestLoginResult:
        identifier = normalize_identifier(identifier)
        resolved = await self._require_method_enabled(
            organization_id=organization_id,
            location_id=location_id,
            auth_method=GuestAuthMethod.VOUCHER,
        )
        resolved_org_id = resolved.config.organization_id

        existing_guest = await self.repository.get_guest_by_identifier(
            resolved_org_id, identifier
        )
        self._reject_if_blocked(existing_guest)
        await self._enforce_access_control(
            organization_id=resolved_org_id,
            location_id=location_id,
            identifier=identifier,
            device_mac=device_mac,
            auth_method=GuestAuthMethod.VOUCHER,
            guest=existing_guest,
            ip_address=ip_address,
            whitelist_only_enabled=bool(resolved.config.whitelist_only_enabled),
            whitelist_only_denied_message=(
                resolved.config.whitelist_only_denied_message
            ),
        )
        known_device: GuestDevice | None = _DEVICE_NOT_PREFETCHED
        if existing_guest is not None:
            # See the identical comment in login_via_otp: skip the query for
            # a brand-new guest, and check before the voucher is redeemed
            # below, not after, so a guest already at the limit never
            # spends a real (single-use) voucher on a login that was always
            # going to be rejected.
            await self._enforce_concurrent_session_limit(
                existing_guest.id,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            known_device = await self._enforce_device_limit(
                guest_id=existing_guest.id,
                mac_address=device_mac,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            await self._enforce_fup_quota(
                guest_id=existing_guest.id,
                organization_id=resolved_org_id,
                location_id=location_id,
            )

        router = await self._get_eligible_router(router_id)

        source = ip_address or "unknown"
        try:
            voucher, batch = await self.voucher_service.redeem_voucher(
                code=code, identifier=identifier, source=source
            )
        except CloudGuestError as exc:
            await self._record_login_failure(
                guest=existing_guest,
                identifier=identifier,
                auth_method=GuestAuthMethod.VOUCHER,
                organization_id=resolved_org_id,
                location_id=location_id,
                reason=type(exc).__name__,
                ip_address=ip_address,
            )
            raise

        guest, is_new = await self._get_or_create_guest(
            existing_guest,
            organization_id=resolved_org_id,
            location_id=location_id,
            identifier=identifier,
        )
        device = await self._maybe_get_or_create_device(
            guest_id=guest.id,
            mac_address=device_mac,
            device_name=device_name,
            known_device=known_device,
        )
        # A voucher batch carries its own validity and data allowance, so
        # those two come from the batch. It carries no idle timeout -- there
        # is no such field on a batch and no reason there should be: how long
        # a voucher is good for is a property of the voucher, whereas how long
        # a silent device may hold a slot is a property of the venue's
        # network. So this one resolves from the SESSION policy exactly as
        # every other login path does, which also means a voucher guest and
        # an OTP guest at the same location are treated identically.
        resolved_idle_timeout = await self._resolve_idle_timeout_minutes(
            organization_id=resolved_org_id,
            location_id=location_id,
            guest_id=guest.id,
        )
        # Copied, not referenced -- see module docstring.
        session, created = await self._reuse_or_create_session(
            guest=guest,
            device=device,
            router=router,
            location_id=location_id,
            auth_method=GuestAuthMethod.VOUCHER,
            voucher_id=voucher.id,
            ip_address=ip_address,
            user_agent=user_agent,
            accept_language=accept_language,
            data_limit_mb=batch.data_limit_mb,
            session_timeout_minutes=batch.validity_minutes,
            idle_timeout_minutes=resolved_idle_timeout,
        )
        if created:
            # BE-011 Part 3: additive, best-effort real-time broadcast --
            # see GuestService's own docstring. Fires only after the real
            # session row above already exists. Skipped on a reused
            # session -- see _reuse_or_create_session's own docstring.
            await self._broadcast_guest_session_started(
                session=session,
                guest=guest,
                router=router,
                location_id=location_id,
                organization_id=resolved_org_id,
                auth_method=GuestAuthMethod.VOUCHER.value,
                is_new_guest=is_new,
            )
            # Phase 1 BhaiFi-parity: additive, best-effort speed-linked
            # voucher assignment -- see _assign_voucher_queue's own
            # docstring.
            await self._assign_voucher_queue(
                voucher=voucher,
                session=session,
                router=router,
                location_id=location_id,
                organization_id=resolved_org_id,
            )
            await self._bump_guest_visit(guest)
        # Deliberately outside the ``if created:`` block above, unlike
        # every other side effect there -- see ``_assign_guest_queue``'s
        # own docstring for why, and for the bug that put it here. The
        # same call sits outside ``if created:`` in all five login
        # methods.
        await self._assign_guest_queue(
            session=session,
            router=router,
            location_id=location_id,
            organization_id=resolved_org_id,
        )

        await self._record_login_success(
            guest=guest,
            identifier=identifier,
            auth_method=GuestAuthMethod.VOUCHER,
            location_id=location_id,
            ip_address=ip_address,
        )

        event = GuestLoggedIn(
            guest_id=guest.id,
            identifier=identifier,
            auth_method=GuestAuthMethod.VOUCHER.value,
            session_id=session.id,
            is_new_guest=is_new,
        )
        logger.info("guest_logged_in", extra=_event_extra(event))
        return GuestLoginResult(
            guest=guest, session=session, device=device, is_new_guest=is_new
        )

    def _verify_guest_password(self, guest: Guest | None, password: str) -> bool:
        """Constant-effort password check for ``login_via_password`` -- see
        ``_DUMMY_PASSWORD_HASH``'s own module-level docstring for why a real
        Argon2id ``verify`` always runs, even when ``guest`` is ``None`` or
        has no password set, rather than short-circuiting straight to
        ``False``."""
        hashed = guest.hashed_password if guest and guest.hashed_password else None
        try:
            verified = PasswordManager.verify(password, hashed or _DUMMY_PASSWORD_HASH)
        except PasswordVerificationError:
            verified = False
        return verified if hashed is not None else False

    async def login_via_password(
        self,
        *,
        identifier: str,
        password: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        router_id: uuid.UUID,
        device_mac: str | None = None,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        accept_language: str | None = None,
    ) -> GuestLoginResult:
        """Returning-guest phone/email + password login -- the
        ``username_password`` auth method
        ``app.domains.captive_portal.models.CaptivePortalConfig
        .username_password_enabled`` was always a placeholder readiness flag
        for (see that column's own docstring). Only ever succeeds for a
        guest that has already called ``set_guest_password`` once (itself
        only reachable right after a real OTP login) -- there is no way to
        create a ``Guest`` row, or set its first password, through this
        method. Mirrors ``login_via_otp``'s/``login_via_voucher``'s exact
        blocked-guest/access-control/concurrent-session/device-limit/FUP-quota
        gate ordering (reject before touching anything credential-shaped),
        substituting a password comparison for OTP verification/voucher
        redemption -- the one difference is that a missing/wrong-password
        failure and a "no such guest at all" failure raise the exact same
        ``GuestPasswordLoginFailedError`` (see that exception's own
        docstring for why: distinguishing them here would let a caller
        enumerate which identifiers are registered guests)."""
        identifier = normalize_identifier(identifier)
        resolved = await self._require_method_enabled(
            organization_id=organization_id,
            location_id=location_id,
            auth_method=GuestAuthMethod.USERNAME_PASSWORD,
        )
        resolved_org_id = resolved.config.organization_id

        existing_guest = await self.repository.get_guest_by_identifier(
            resolved_org_id, identifier
        )
        self._reject_if_blocked(existing_guest)
        await self._enforce_access_control(
            organization_id=resolved_org_id,
            location_id=location_id,
            identifier=identifier,
            device_mac=device_mac,
            auth_method=GuestAuthMethod.USERNAME_PASSWORD,
            guest=existing_guest,
            ip_address=ip_address,
            whitelist_only_enabled=bool(resolved.config.whitelist_only_enabled),
            whitelist_only_denied_message=(
                resolved.config.whitelist_only_denied_message
            ),
        )
        known_device: GuestDevice | None = _DEVICE_NOT_PREFETCHED
        if existing_guest is not None:
            await self._enforce_concurrent_session_limit(
                existing_guest.id,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            known_device = await self._enforce_device_limit(
                guest_id=existing_guest.id,
                mac_address=device_mac,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            await self._enforce_fup_quota(
                guest_id=existing_guest.id,
                organization_id=resolved_org_id,
                location_id=location_id,
            )

        router = await self._get_eligible_router(router_id)

        if not self._verify_guest_password(existing_guest, password):
            await self._record_login_failure(
                guest=existing_guest,
                identifier=identifier,
                auth_method=GuestAuthMethod.USERNAME_PASSWORD,
                organization_id=resolved_org_id,
                location_id=location_id,
                reason="GuestPasswordLoginFailedError",
                ip_address=ip_address,
            )
            raise GuestPasswordLoginFailedError()

        guest = existing_guest
        assert guest is not None  # narrowed by _verify_guest_password above
        device = await self._maybe_get_or_create_device(
            guest_id=guest.id,
            mac_address=device_mac,
            device_name=device_name,
            known_device=known_device,
        )
        resolved_session_timeout = await self._resolve_session_timeout_minutes(
            organization_id=resolved_org_id,
            location_id=location_id,
            guest_id=guest.id,
        )
        resolved_idle_timeout = await self._resolve_idle_timeout_minutes(
            organization_id=resolved_org_id,
            location_id=location_id,
            guest_id=guest.id,
        )
        session, created = await self._reuse_or_create_session(
            guest=guest,
            device=device,
            router=router,
            location_id=location_id,
            auth_method=GuestAuthMethod.USERNAME_PASSWORD,
            voucher_id=None,
            ip_address=ip_address,
            user_agent=user_agent,
            accept_language=accept_language,
            data_limit_mb=None,
            session_timeout_minutes=resolved_session_timeout,
            idle_timeout_minutes=resolved_idle_timeout,
        )
        if created:
            await self._broadcast_guest_session_started(
                session=session,
                guest=guest,
                router=router,
                location_id=location_id,
                organization_id=resolved_org_id,
                auth_method=GuestAuthMethod.USERNAME_PASSWORD.value,
                is_new_guest=False,
            )
            await self._bump_guest_visit(guest)
        # Deliberately outside the ``if created:`` block above, unlike
        # every other side effect there -- see ``_assign_guest_queue``'s
        # own docstring for why, and for the bug that put it here. The
        # same call sits outside ``if created:`` in all five login
        # methods.
        await self._assign_guest_queue(
            session=session,
            router=router,
            location_id=location_id,
            organization_id=resolved_org_id,
        )

        await self._record_login_success(
            guest=guest,
            identifier=identifier,
            auth_method=GuestAuthMethod.USERNAME_PASSWORD,
            location_id=location_id,
            ip_address=ip_address,
        )

        event = GuestLoggedIn(
            guest_id=guest.id,
            identifier=identifier,
            auth_method=GuestAuthMethod.USERNAME_PASSWORD.value,
            session_id=session.id,
            is_new_guest=False,
        )
        logger.info("guest_logged_in", extra=_event_extra(event))
        return GuestLoginResult(
            guest=guest, session=session, device=device, is_new_guest=False
        )

    def _verify_guest_pin(self, guest: Guest | None, pin: str) -> bool:
        """Constant-effort PIN check for ``login_via_pin`` -- mirrors
        ``_verify_guest_password``'s identical "a real Argon2id ``verify``
        always runs, even with no real ``hashed_pin`` to compare against"
        discipline; see ``_DUMMY_PIN_HASH``'s own module-level docstring
        for why."""
        hashed = guest.hashed_pin if guest and guest.hashed_pin else None
        try:
            verified = PasswordManager.verify(pin, hashed or _DUMMY_PIN_HASH)
        except PasswordVerificationError:
            verified = False
        return verified if hashed is not None else False

    def _is_guest_pin_stale(self, guest: Guest, *, now: datetime) -> bool:
        """Whether ``guest``'s PIN has gone unused (never freshly set,
        never successfully logged in with) for longer than
        ``constants.PIN_STALE_AFTER_DAYS`` -- see that constant's own
        docstring for why the reference point is "more recent of
        ``pin_set_at``/``pin_last_used_at``", not just one or the other.
        Only meaningful when ``guest.hashed_pin`` is actually set; callers
        combine this with ``_verify_guest_pin`` rather than relying on it
        alone (a guest with no PIN at all already fails
        ``_verify_guest_pin``, regardless of what this returns)."""
        reference = guest.pin_last_used_at or guest.pin_set_at
        if reference is None:
            return True
        return now - reference > timedelta(days=PIN_STALE_AFTER_DAYS)

    async def _record_pin_attempt(
        self,
        *,
        guest: Guest | None,
        organization_id: uuid.UUID,
        identifier: str,
        success: bool,
        now: datetime,
    ) -> None:
        """Records one ``login_via_pin`` attempt in both places that need
        to know about it: ``GuestPinSecurity`` (Redis, the real,
        authoritative gate the *next* attempt is checked against -- see
        that class's own docstring), and ``Guest.pin_failed_attempts``/
        ``pin_locked_until``/``pin_last_used_at`` (a best-effort, durable,
        admin-visible mirror of that same state -- see
        ``Guest.pin_failed_attempts``'s own docstring for why this is
        never read back to make a real decision). A no-op on the Redis
        side when no ``redis`` client was wired (see ``GuestService``'s
        own docstring); a no-op on the ``Guest`` side entirely when
        ``guest`` is ``None`` (nothing to mirror onto yet -- an unknown
        identifier's failed attempts still count against
        ``GuestPinSecurity``'s own per-identifier counter above, just not
        onto any row)."""
        if self.redis is not None:
            await GuestPinSecurity.record_attempt(
                self.redis,
                organization_id=organization_id,
                identifier=identifier,
                success=success,
            )
        if guest is None:
            return
        if success:
            await self.repository.update_guest(
                guest,
                {
                    "pin_failed_attempts": 0,
                    "pin_locked_until": None,
                    "pin_last_used_at": now,
                },
            )
            return
        failed_attempts = (guest.pin_failed_attempts or 0) + 1
        update_data: dict[str, object] = {"pin_failed_attempts": failed_attempts}
        if failed_attempts >= PIN_MAX_ATTEMPTS:
            update_data["pin_locked_until"] = now + timedelta(
                minutes=PIN_LOCKOUT_MINUTES
            )
        await self.repository.update_guest(guest, update_data)

    async def login_via_pin(
        self,
        *,
        identifier: str,
        pin: str,
        device_mac: str | None,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        router_id: uuid.UUID,
        device_name: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        accept_language: str | None = None,
    ) -> GuestLoginResult:
        """Portal PIN: device-scoped quick-login via a guest's own,
        previously-set PIN -- the ``pin`` counterpart to
        ``login_via_password``, structurally mirroring that method's exact
        "reject before touching anything with a side effect" gate ordering
        (``_require_method_enabled`` -> blocked-guest/access-control ->
        concurrent-session/device-limit/FUP-quota, all before any real
        credential verification) with two deliberate differences:

        **Device-scoped.** Unlike password login, a successful PIN login
        also requires ``device_mac`` to match a real ``GuestDevice`` that
        already belongs to the resolved guest -- i.e. only a device that
        has previously completed a real OTP login for this guest may ever
        use PIN login at all. Deliberately never creates or reassigns a
        ``GuestDevice`` the way ``_maybe_get_or_create_device`` does for
        every other login method: a PIN login that doesn't already have a
        matching device has nothing legitimate to attach a session to, and
        must fail exactly like a wrong PIN, not silently register a new
        device. A missing/unrecognized ``device_mac`` collapses into the
        exact same generic ``GuestPinLoginFailedError`` as a wrong PIN or
        an unknown identifier (see that exception's own docstring) --
        never a distinct error that would let a caller learn "this
        identifier exists but I have the wrong device" from the response
        alone.

        **Brute-force lockout.** ``login_via_password`` has no
        per-identifier lockout at all today -- a real, confirmed gap this
        method does not inherit (see ``GuestPinSecurity``'s own docstring
        for why a PIN's small keyspace makes one necessary here
        specifically). ``GuestPinSecurity.check_lockout`` runs first,
        immediately after resolving which organization this login belongs
        to and before any of this method's own verification work --
        a locked-out ``(organization_id, identifier)`` pair raises
        ``GuestPinLockedError`` (423) without ever looking up the guest,
        the device, or touching ``pin``.

        A PIN that verifies correctly but has gone unused for longer than
        ``constants.PIN_STALE_AFTER_DAYS`` is treated exactly like a wrong
        PIN -- ``_is_guest_pin_stale``'s own docstring covers the full
        reasoning; the guest's remedy is the same either way, a fresh OTP
        login (which is also the only way to set a new PIN)."""
        identifier = normalize_identifier(identifier)
        resolved = await self._require_method_enabled(
            organization_id=organization_id,
            location_id=location_id,
            auth_method=GuestAuthMethod.PIN,
        )
        resolved_org_id = resolved.config.organization_id

        if self.redis is not None:
            await GuestPinSecurity.check_lockout(
                self.redis, organization_id=resolved_org_id, identifier=identifier
            )

        existing_guest = await self.repository.get_guest_by_identifier(
            resolved_org_id, identifier
        )
        self._reject_if_blocked(existing_guest)
        await self._enforce_access_control(
            organization_id=resolved_org_id,
            location_id=location_id,
            identifier=identifier,
            device_mac=device_mac,
            auth_method=GuestAuthMethod.PIN,
            guest=existing_guest,
            ip_address=ip_address,
            whitelist_only_enabled=bool(resolved.config.whitelist_only_enabled),
            whitelist_only_denied_message=(
                resolved.config.whitelist_only_denied_message
            ),
        )
        known_device: GuestDevice | None = _DEVICE_NOT_PREFETCHED
        if existing_guest is not None:
            await self._enforce_concurrent_session_limit(
                existing_guest.id,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            known_device = await self._enforce_device_limit(
                guest_id=existing_guest.id,
                mac_address=device_mac,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            await self._enforce_fup_quota(
                guest_id=existing_guest.id,
                organization_id=resolved_org_id,
                location_id=location_id,
            )

        router = await self._get_eligible_router(router_id)

        # _enforce_device_limit above already fetched this exact MAC's
        # GuestDevice moments earlier (nothing in between writes to
        # guest_devices) whenever existing_guest was resolved -- reused
        # directly here instead of a second, identical get_device_by_mac
        # query. Only a genuinely brand-new guest (never enforced above,
        # since a guest that doesn't exist yet has no PIN to ever match
        # anyway -- see this method's own device-scoped docstring) still
        # needs the real, fresh lookup.
        normalized_mac = normalize_mac_address(device_mac) if device_mac else None
        if known_device is not _DEVICE_NOT_PREFETCHED:
            device = known_device
        elif normalized_mac:
            device = await self.repository.get_device_by_mac(normalized_mac)
        else:
            device = None
        device_matches = (
            existing_guest is not None
            and device is not None
            and device.guest_id == existing_guest.id
        )
        pin_matches = self._verify_guest_pin(existing_guest, pin)
        now = datetime.now(UTC)
        is_stale = existing_guest is not None and self._is_guest_pin_stale(
            existing_guest, now=now
        )
        authenticated = device_matches and pin_matches and not is_stale

        await self._record_pin_attempt(
            guest=existing_guest,
            organization_id=resolved_org_id,
            identifier=identifier,
            success=authenticated,
            now=now,
        )
        if not authenticated:
            await self._record_login_failure(
                guest=existing_guest,
                identifier=identifier,
                auth_method=GuestAuthMethod.PIN,
                organization_id=resolved_org_id,
                location_id=location_id,
                reason="GuestPinLoginFailedError",
                ip_address=ip_address,
            )
            raise GuestPinLoginFailedError()

        guest = existing_guest
        assert guest is not None  # narrowed by `authenticated` above
        assert device is not None  # narrowed by `device_matches` above
        # Bump last_seen_at (and device_name, if the caller supplied a
        # fresher one) on the already-matched device -- the same "returning
        # device" update ``get_or_create_device`` applies for every other
        # login method, minus the create-or-reassign branch that method
        # also handles (impossible here: device_matches already proved this
        # exact device belongs to this exact guest).
        device_update: dict[str, object] = {"last_seen_at": now}
        if device_name is not None:
            device_update["device_name"] = device_name
        device = await self.repository.update_device(device, device_update)
        resolved_session_timeout = await self._resolve_session_timeout_minutes(
            organization_id=resolved_org_id,
            location_id=location_id,
            guest_id=guest.id,
        )
        resolved_idle_timeout = await self._resolve_idle_timeout_minutes(
            organization_id=resolved_org_id,
            location_id=location_id,
            guest_id=guest.id,
        )
        session, created = await self._reuse_or_create_session(
            guest=guest,
            device=device,
            router=router,
            location_id=location_id,
            auth_method=GuestAuthMethod.PIN,
            voucher_id=None,
            ip_address=ip_address,
            user_agent=user_agent,
            accept_language=accept_language,
            data_limit_mb=None,
            session_timeout_minutes=resolved_session_timeout,
            idle_timeout_minutes=resolved_idle_timeout,
        )
        if created:
            await self._broadcast_guest_session_started(
                session=session,
                guest=guest,
                router=router,
                location_id=location_id,
                organization_id=resolved_org_id,
                auth_method=GuestAuthMethod.PIN.value,
                is_new_guest=False,
            )
            await self._bump_guest_visit(guest)
        # Deliberately outside the ``if created:`` block above, unlike
        # every other side effect there -- see ``_assign_guest_queue``'s
        # own docstring for why, and for the bug that put it here. The
        # same call sits outside ``if created:`` in all five login
        # methods.
        await self._assign_guest_queue(
            session=session,
            router=router,
            location_id=location_id,
            organization_id=resolved_org_id,
        )

        await self._record_login_success(
            guest=guest,
            identifier=identifier,
            auth_method=GuestAuthMethod.PIN,
            location_id=location_id,
            ip_address=ip_address,
        )

        event = GuestLoggedIn(
            guest_id=guest.id,
            identifier=identifier,
            auth_method=GuestAuthMethod.PIN.value,
            session_id=session.id,
            is_new_guest=False,
        )
        logger.info("guest_logged_in", extra=_event_extra(event))
        return GuestLoginResult(
            guest=guest, session=session, device=device, is_new_guest=False
        )

    async def login_via_mac_whitelist(
        self,
        *,
        mac_address: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        router_id: uuid.UUID,
        ip_address: str | None = None,
        user_agent: str | None = None,
        accept_language: str | None = None,
    ) -> GuestLoginResult:
        """Real MAC-whitelist bypass -- an admin-pre-authorized device
        (``app.domains.mac_authorization``) connects without OTP,
        voucher, or password at all, the same "skip verification for a
        trusted device" feature that domain's own module docstring
        already names as its one deliberately-deferred integration seam.

        **How a MAC address legitimately reaches this method at all:**
        a real captive-portal redirect from a NAS/router encodes the
        connecting device's MAC as one of its query parameters (see
        ``src/routes/portal.tsx``'s own docstring on the frontend side,
        and this module's own ``radius_router``, which is the *other*,
        NAS-authenticated way device identity reaches this domain) --
        there is no live NAS in this environment to generate that
        redirect for real, so the guest-facing frontend instead reads an
        honest, optional ``mac`` search param when present and calls this
        method with it. Absent that param, this method is simply never
        called, and the sign-in card behaves exactly as it always did.

        **No ``CaptivePortalConfig`` enabled-method flag gates this**
        (unlike ``login_via_otp``/``login_via_voucher``/
        ``login_via_password``, each checked against its own boolean via
        ``_require_method_enabled``) -- see ``GuestAuthMethod
        .MAC_WHITELIST``'s own docstring for why: a whitelist entry's
        mere existence (real, admin-created, already gated by RBAC on
        ``app.domains.mac_authorization``'s own endpoints) is itself the
        per-device enable signal, and a second per-location toggle on top
        of that would only add a way to disable an *already-explicit*
        grant, not a meaningful new safeguard.

        Requires a real ``mac_authorization_hook`` to be wired in (see
        ``GuestService.__init__``'s docstring) -- with none wired (the
        default), or a real lookup that comes back ``False``, or a
        malformed ``mac_address``, this always raises
        ``MacAddressNotAuthorizedError``. That failure is deliberately
        **not** the trigger for any fallback OTP/voucher/password
        attempt here -- the guest-facing frontend that called this is
        the one responsible for silently falling back to its normal
        sign-in card, exactly the same "every other real method stays
        available" guarantee ``login_via_password`` already gives a
        guest who hasn't set a password yet."""
        try:
            normalized_mac = normalize_whitelist_mac_address(mac_address)
        except MacAuthorizationError as exc:
            raise MacAddressNotAuthorizedError(mac_address) from exc

        resolved = await self.captive_portal_service.resolve_portal_config(
            organization_id=organization_id, location_id=location_id
        )
        resolved_org_id = resolved.config.organization_id
        # Open Hours applies to this path too, even though the enabled-method
        # check above it deliberately does not -- see _require_venue_open.
        self._require_venue_open(resolved.config)

        if self.mac_authorization_hook is None:
            raise MacAddressNotAuthorizedError(normalized_mac)
        # location_id, not just the organization: a trust entry that names a
        # location applies only there. See is_mac_authorized's own docstring.
        authorized = await self.mac_authorization_hook.is_mac_authorized(
            normalized_mac,
            organization_id=resolved_org_id,
            location_id=location_id,
        )
        if not authorized:
            raise MacAddressNotAuthorizedError(normalized_mac)

        identifier = f"mac:{normalized_mac}"
        existing_guest = await self.repository.get_guest_by_identifier(
            resolved_org_id, identifier
        )
        self._reject_if_blocked(existing_guest)
        await self._enforce_access_control(
            organization_id=resolved_org_id,
            location_id=location_id,
            identifier=identifier,
            device_mac=normalized_mac,
            auth_method=GuestAuthMethod.MAC_WHITELIST,
            guest=existing_guest,
            ip_address=ip_address,
            whitelist_only_enabled=bool(resolved.config.whitelist_only_enabled),
            whitelist_only_denied_message=(
                resolved.config.whitelist_only_denied_message
            ),
            # `is_mac_authorized` returned True barely a dozen lines above,
            # for this exact MAC, organization and location. Passing that
            # answer down rather than letting the gate ask again is the
            # difference between one lookup and two on every whitelisted
            # device's login.
            device_mac_already_authorized=True,
        )
        known_device: GuestDevice | None = _DEVICE_NOT_PREFETCHED
        if existing_guest is not None:
            await self._enforce_concurrent_session_limit(
                existing_guest.id,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            known_device = await self._enforce_device_limit(
                guest_id=existing_guest.id,
                mac_address=normalized_mac,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            await self._enforce_fup_quota(
                guest_id=existing_guest.id,
                organization_id=resolved_org_id,
                location_id=location_id,
            )

        router = await self._get_eligible_router(router_id)

        guest, is_new = await self._get_or_create_guest(
            existing_guest,
            organization_id=resolved_org_id,
            location_id=location_id,
            identifier=identifier,
        )
        device = await self._maybe_get_or_create_device(
            guest_id=guest.id,
            mac_address=normalized_mac,
            device_name="Whitelisted device",
            known_device=known_device,
        )
        resolved_session_timeout = await self._resolve_session_timeout_minutes(
            organization_id=resolved_org_id,
            location_id=location_id,
            guest_id=guest.id,
        )
        resolved_idle_timeout = await self._resolve_idle_timeout_minutes(
            organization_id=resolved_org_id,
            location_id=location_id,
            guest_id=guest.id,
        )
        session, created = await self._reuse_or_create_session(
            guest=guest,
            device=device,
            router=router,
            location_id=location_id,
            auth_method=GuestAuthMethod.MAC_WHITELIST,
            voucher_id=None,
            ip_address=ip_address,
            user_agent=user_agent,
            accept_language=accept_language,
            data_limit_mb=None,
            session_timeout_minutes=resolved_session_timeout,
            idle_timeout_minutes=resolved_idle_timeout,
        )
        if created:
            await self._broadcast_guest_session_started(
                session=session,
                guest=guest,
                router=router,
                location_id=location_id,
                organization_id=resolved_org_id,
                auth_method=GuestAuthMethod.MAC_WHITELIST.value,
                is_new_guest=is_new,
            )
            await self._bump_guest_visit(guest)
        # Deliberately outside the ``if created:`` block above, unlike
        # every other side effect there -- see ``_assign_guest_queue``'s
        # own docstring for why, and for the bug that put it here. The
        # same call sits outside ``if created:`` in all five login
        # methods.
        await self._assign_guest_queue(
            session=session,
            router=router,
            location_id=location_id,
            organization_id=resolved_org_id,
        )

        await self._record_login_success(
            guest=guest,
            identifier=identifier,
            auth_method=GuestAuthMethod.MAC_WHITELIST,
            location_id=location_id,
            ip_address=ip_address,
        )

        event = GuestLoggedIn(
            guest_id=guest.id,
            identifier=identifier,
            auth_method=GuestAuthMethod.MAC_WHITELIST.value,
            session_id=session.id,
            is_new_guest=is_new,
        )
        logger.info("guest_logged_in", extra=_event_extra(event))
        return GuestLoginResult(
            guest=guest, session=session, device=device, is_new_guest=is_new
        )

    async def set_guest_password(
        self,
        *,
        guest_id: uuid.UUID,
        session_id: uuid.UUID,
        password: str,
    ) -> Guest:
        """Lets a guest opt in to password login, right after a real OTP
        verification -- the "set a password for next time?" prompt the
        guest-facing frontend shows immediately after ``login_via_otp``
        succeeds.

        **Authenticated by the just-completed OTP session, not a separate
        unauthenticated hole.** There is no platform-user JWT a guest could
        ever present (the same reason ``guest_router`` carries no
        ``RequirePermission``/``CurrentUser`` at all -- see ``router.py``'s
        module docstring), so proof of "this really is the guest who just
        verified an OTP code" has to come from something else: the
        ``GuestSession.id`` that same OTP login just returned, in
        ``GuestLoginResponse.session.id``. This method verifies every leg
        of that proof itself (composing ``repository.get_session_by_id``,
        never trusting the caller's say-so):

        * the session exists and belongs to ``guest_id``;
        * its ``auth_method`` is ``otp_sms``/``otp_email`` (not
          ``voucher``/an earlier ``username_password`` login -- a guest
          resetting their password with an *old* password is a genuinely
          different, not-yet-built feature, and a voucher redemption proves
          nothing about phone/email ownership the way an OTP does);
        * it is still ``ACTIVE`` (a disconnected/expired/terminated session
          is no longer live proof of anything);
        * it started within ``constants.SET_PASSWORD_SESSION_WINDOW_MINUTES``
          of now -- a deliberately short window (see that constant's own
          docstring) so this can never become "any OTP login, ever, is a
          standing license to set a password".

        Any failed leg raises ``GuestPasswordSetupNotAuthorizedError``
        (one generic message -- see that exception's own docstring for why).
        ``password`` is hashed via ``PasswordManager.hash`` (Argon2id,
        composed from ``app.domains.auth.password`` -- the exact same
        convention/cost parameters platform ``AuthUser`` passwords use, not
        reimplemented); a password failing
        ``PasswordManager.validate_strength`` raises
        ``GuestPasswordTooWeakError`` with that validator's own message,
        surfaced to the guest so they know exactly what to fix."""
        guest = await self._require_guest(guest_id)
        session = await self.repository.get_session_by_id(session_id)
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=SET_PASSWORD_SESSION_WINDOW_MINUTES)
        eligible = (
            session is not None
            and session.guest_id == guest.id
            and session.auth_method
            in (
                GuestAuthMethod.OTP_SMS.value,
                GuestAuthMethod.OTP_EMAIL.value,
                GuestAuthMethod.OTP_WHATSAPP.value,
            )
            and session.status == GuestSessionStatus.ACTIVE.value
            and session.started_at >= window_start
        )
        if not eligible:
            raise GuestPasswordSetupNotAuthorizedError()

        try:
            hashed = PasswordManager.hash(password)
        except PasswordStrengthError as exc:
            raise GuestPasswordTooWeakError(str(exc)) from exc

        updated = await self.repository.update_guest(guest, {"hashed_password": hashed})
        logger.info(
            "guest_password_set",
            extra={"event_guest_id": str(updated.id)},
        )
        return updated

    async def set_guest_pin(
        self,
        *,
        guest_id: uuid.UUID,
        session_id: uuid.UUID,
        pin: str,
    ) -> Guest:
        """Lets a guest opt in to Portal PIN login, right after a real OTP
        verification -- the ``pin`` counterpart to ``set_guest_password``,
        requiring the exact same proof of a just-completed, still-
        ``ACTIVE`` OTP-authenticated ``GuestSession`` that method's own
        docstring documents in full (session belongs to ``guest_id``, its
        ``auth_method`` is ``otp_sms``/``otp_email``/``otp_whatsapp``, it
        is still ``ACTIVE``, and it started within
        ``constants.SET_PASSWORD_SESSION_WINDOW_MINUTES`` of now) --
        reusing that identical window constant rather than inventing a
        separate one for an equivalent "prove you just logged in"
        guarantee. Any failed leg raises
        ``GuestPinSetupNotAuthorizedError`` (one generic message, for the
        identical reason ``GuestPasswordSetupNotAuthorizedError`` gives).

        ``pin`` must be exactly ``constants.PIN_LENGTH`` digits and must
        not be trivially guessable (``validators.is_weak_pin`` -- see that
        function's own docstring for exactly which two shapes are
        rejected); either failure raises ``GuestPinTooWeakError``. Hashed
        via ``PasswordManager.hash_raw`` -- the same Argon2id cost
        parameters ``set_guest_password`` gets from ``PasswordManager
        .hash``, without that method's password-composition strength
        policy (minimum length, upper/lower/digit/special), which a
        fixed-length numeric PIN could never satisfy; ``is_weak_pin``
        above is this method's own, PIN-appropriate strength check
        instead. Clears ``pin_failed_attempts``/``pin_locked_until`` (a
        guest setting a brand-new PIN gets a clean slate, not a lockout
        carried over from whatever PIN -- if any -- they had before)."""
        guest = await self._require_guest(guest_id)
        session = await self.repository.get_session_by_id(session_id)
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=SET_PASSWORD_SESSION_WINDOW_MINUTES)
        eligible = (
            session is not None
            and session.guest_id == guest.id
            and session.auth_method
            in (
                GuestAuthMethod.OTP_SMS.value,
                GuestAuthMethod.OTP_EMAIL.value,
                GuestAuthMethod.OTP_WHATSAPP.value,
            )
            and session.status == GuestSessionStatus.ACTIVE.value
            and session.started_at >= window_start
        )
        if not eligible:
            raise GuestPinSetupNotAuthorizedError()

        if len(pin) != PIN_LENGTH or not pin.isdigit():
            raise GuestPinTooWeakError(f"PIN must be exactly {PIN_LENGTH} digits")
        if is_weak_pin(pin):
            raise GuestPinTooWeakError()

        hashed = PasswordManager.hash_raw(pin)
        updated = await self.repository.update_guest(
            guest,
            {
                "hashed_pin": hashed,
                "pin_set_at": now,
                "pin_failed_attempts": 0,
                "pin_locked_until": None,
            },
        )
        logger.info("guest_pin_set", extra={"event_guest_id": str(updated.id)})
        return updated

    async def update_guest_profile(
        self,
        *,
        guest_id: uuid.UUID,
        session_id: uuid.UUID,
        display_name: str | None,
        email: str | None,
        declined: bool = False,
    ) -> Guest:
        """Lets a guest fill in their name/email right after a real OTP
        verification -- the skippable "tell us about yourself" prompt shown
        once, only to a brand-new guest, immediately after their first
        ``login_via_otp`` succeeds (mirrors ``set_guest_password``'s
        identical placement and purpose exactly).

        **Authenticated by the just-completed OTP session, not a separate
        unauthenticated hole** -- same proof-of-session eligibility check
        as ``set_guest_password`` (session belongs to this guest, is an
        OTP-authenticated session, is still ``ACTIVE``, started within
        ``SET_PASSWORD_SESSION_WINDOW_MINUTES``), reusing that same window
        constant rather than inventing a second one for an equivalent
        "prove you just logged in" guarantee. Any failed leg raises
        ``GuestProfileUpdateNotAuthorizedError``.

        Both fields are optional and independently settable (a guest may
        fill in only one) -- this call is only ever reached by choice; a
        guest who skips the prompt entirely never calls it at all, and
        network access is never gated on it.

        Two things this method gained after the first version shipped, both
        of which exist to move state out of the guest's browser and into
        the row:

        * ``declined=True`` records that the guest said no. That is the
          third way ``validators.guest_has_profile`` becomes true, and it
          is what lets the portal stop keeping a device-local "don't ask
          again" flag -- see ``Guest.profile_prompt_declined_at``'s own
          comment for why a ``localStorage`` flag was never a record on
          the surface that matters.
        * The venue's ``collect_guest_name``/``collect_guest_email`` flags
          are enforced here, not only in the UI.

        **Deliberately still post-connect only, and deliberately still
        hard to call early.** The eligibility check above requires an
        already-``ACTIVE`` OTP session; inside the login funnel, before the
        NAS gate opens, that session exists but the guest is not yet on the
        network, and the window this POST needs is the window the hotspot
        login POST is racing through. Moving the ask earlier would mean
        weakening this check or ordering two writes against a session
        mid-handoff. It was tried, in the funnel, and reverted on purpose:
        a third screen between a verified guest and their internet is where
        they close the sheet, and the venue loses the *connection*, which
        is the thing they are paying for. Keep it here."""
        guest = await self._require_guest(guest_id)
        session = await self.repository.get_session_by_id(session_id)
        now = datetime.now(UTC)
        window_start = now - timedelta(minutes=SET_PASSWORD_SESSION_WINDOW_MINUTES)
        eligible = (
            session is not None
            and session.guest_id == guest.id
            and session.auth_method
            in (
                GuestAuthMethod.OTP_SMS.value,
                GuestAuthMethod.OTP_EMAIL.value,
                GuestAuthMethod.OTP_WHATSAPP.value,
            )
            and session.status == GuestSessionStatus.ACTIVE.value
            and session.started_at >= window_start
        )
        if not eligible:
            raise GuestProfileUpdateNotAuthorizedError()

        # Per-venue enforcement: a field whose flag is off is refused
        # here, not merely hidden in the UI.
        #
        # This is the same shape `_require_method_enabled` gives the auth
        # flags, and it exists for the same reason: a hidden field that
        # still accepts a write is how a venue ends up holding personal
        # data it never agreed to hold. The venue is the Data Fiduciary
        # for a guest's name and email under DPDP; "off" has to mean off
        # on the server, or the flag is decoration.
        #
        # Resolved against the *session's* location, not the guest's.
        # `Guest.location_id` is a "home" location -- where the guest was
        # first seen -- and is explicitly never constrained to match the
        # session's (see that column's own comment). For a multi-location
        # chain, reading the guest's location would enforce the wrong
        # venue's settings.
        #
        # Only consulted when a field is actually being written. A pure
        # decline needs no config at all, so a guest can always say no,
        # even at a venue whose portal config has since been deleted --
        # refusing to record a refusal would be the wrong failure
        # direction.
        if display_name is not None or email is not None:
            resolved = await self.captive_portal_service.resolve_portal_config(
                organization_id=session.organization_id,
                location_id=session.location_id,
            )
            config = resolved.config
            if display_name is not None and not config.collect_guest_name:
                raise GuestProfileFieldNotCollectedError("name")
            if email is not None and not config.collect_guest_email:
                raise GuestProfileFieldNotCollectedError("email")

        update_data: dict[str, object] = {}
        if display_name is not None:
            update_data["display_name"] = display_name
        if email is not None:
            update_data["email"] = email
        # A decline is recorded only if the guest has not already answered
        # -- `has_profile` is already true once a field is on file, and
        # overwriting the timestamp on a later "not now" would mean the
        # column stopped answering "when did they first refuse".
        if declined and guest.profile_prompt_declined_at is None:
            update_data["profile_prompt_declined_at"] = now
        if not update_data:
            return guest

        updated = await self.repository.update_guest(guest, update_data)
        logger.info(
            "guest_profile_updated",
            extra={
                "event_guest_id": str(updated.id),
                "event_fields": list(update_data.keys()),
            },
        )
        return updated

    async def record_review_link_opened(
        self,
        *,
        guest_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> Guest:
        """Records that a guest tapped through to the venue's Google review
        link, so the card stops being shown to them.

        Without this the review card has no memory. It renders on arrival,
        every visit, forever -- including to the guest who already went and
        left the review, which is the one guest it must never ask again.
        That is the whole difference between a feature and a nag, and the
        record has to live here rather than in the browser because the
        browser cannot keep it: Web Storage throws inside Apple's Captive
        Network Assistant, so the device-local flag reads false every time.

        **Post-connect only, and it changes nothing about the connection.**
        Like every other ask in this family, it is reachable only from
        ``/portal/session``, which a guest sees after the RADIUS session is
        authorised and the NAS gate is open. Nothing here can affect
        whether, how fast, or how long anyone is connected -- and under
        Google's Rating Manipulation policy nothing may, in either
        direction: free WiFi is a "free good and/or service", so it can be
        conditioned neither on leaving a review nor on declining to.

        The write is idempotent in the only sense that matters -- a second
        tap moves the timestamp, and ``has_opened_review_link`` was already
        true -- so the portal can call it fire-and-forget without
        sequencing it against the navigation.

        ⚠ **This is not a review counter.** It records that a link was
        opened. Google exposes nothing that would let this platform learn
        whether a review was written, and it cannot see iOS at all: iPhone
        and iPad guests are sent to ``captive.apple.com/hotspot-detect
        .html`` after login rather than to ``/portal/session``, so they
        never reach the card. Any aggregate over this column counts
        Android and desktop guests who tapped a link. See
        ``models.Guest.review_link_opened_at``.
        """
        guest = await self._require_guest(guest_id)
        session = await self.repository.get_session_by_id(session_id)
        # Proof of a live session for this guest, and nothing more. See
        # ``GuestReviewLinkOpenedNotAuthorizedError`` for why this is
        # deliberately weaker than the profile write's check: there is no
        # auth-method filter and no recency window, because this stores
        # nothing about the guest and a refusal is invisible to the caller
        # while costing the guest another nag.
        eligible = (
            session is not None
            and session.guest_id == guest.id
            and session.status == GuestSessionStatus.ACTIVE.value
        )
        if not eligible:
            raise GuestReviewLinkOpenedNotAuthorizedError()

        updated = await self.repository.update_guest(
            guest, {"review_link_opened_at": datetime.now(UTC)}
        )
        logger.info(
            "guest_review_link_opened",
            extra={"event_guest_id": str(updated.id)},
        )
        return updated

    async def disconnect_own_session(
        self,
        *,
        guest_id: uuid.UUID,
        session_id: uuid.UUID,
        reason: str | None = None,
    ) -> GuestSession:
        """Lets a guest end their own connection from the captive portal's
        success screen -- the guest-facing counterpart to the admin-only
        ``disconnect_session`` (``POST /guest-sessions/{id}/disconnect``,
        RBAC-gated). Authenticated the same way
        ``set_guest_password`` is: there is no platform-user JWT a guest
        could ever present, so ``guest_id``/``session_id`` (both already
        known to whoever is holding the real, just-issued
        ``GuestLoginResponse``) stand in for one, and this method verifies
        the session actually belongs to that guest itself rather than
        trusting the caller's say-so -- a mismatch raises
        ``GuestSelfDisconnectNotAuthorizedError``.

        Otherwise behaves exactly like a system-initiated
        ``disconnect_session``: normal, non-punitive, never audited (no
        ``actor_user_id`` -- there is no admin actor here), and still
        issues a real RADIUS CoA-Disconnect via ``issue_live_disconnect``
        so the guest's device is actually cut off the network, not just
        marked disconnected in the database."""
        session = await self.repository.get_session_by_id(session_id)
        if session is None or session.guest_id != guest_id:
            raise GuestSelfDisconnectNotAuthorizedError()
        validate_session_status_transition(
            current=GuestSessionStatus(session.status),
            target=GuestSessionStatus.DISCONNECTED,
        )
        now = datetime.now(UTC)
        updated = await self.repository.update_session(
            session,
            {
                "status": GuestSessionStatus.DISCONNECTED.value,
                "ended_at": now,
                "disconnect_reason": reason or "guest_initiated",
            },
        )
        event = GuestSessionDisconnected(session_id=updated.id, reason=reason)
        logger.info("guest_session_disconnected", extra=_event_extra(event))
        await issue_live_disconnect(self.repository, session=updated)
        return updated

    async def record_consent(
        self,
        *,
        guest_id: uuid.UUID,
        captive_portal_config_id: uuid.UUID | None,
        terms_version: str | None,
        ip_address: str | None,
    ) -> GuestConsent:
        """Records a guest accepting a portal's terms.

        ``terms_version`` is derived server-side when the caller does not
        supply one -- see ``_resolve_terms_version``. Before that, every
        consent row in production had ``terms_version = NULL``, because
        the only caller (the portal's sign-in hook) posts a guest id and a
        config id and nothing else. The column existed; nothing ever filled
        it; the platform could prove *that* a guest consented and not *to
        what*."""
        guest = await self._require_guest(guest_id)
        if terms_version is None:
            terms_version = await self._resolve_terms_version(
                captive_portal_config_id=captive_portal_config_id,
                guest_organization_id=guest.organization_id,
            )
        consent = await self.repository.create_consent(
            guest_id=guest.id,
            captive_portal_config_id=captive_portal_config_id,
            consented_at=datetime.now(UTC),
            terms_version=terms_version,
            ip_address=ip_address,
        )
        event = GuestConsentRecorded(
            guest_id=guest.id,
            captive_portal_config_id=captive_portal_config_id,
            terms_version=terms_version,
        )
        logger.info("guest_consent_recorded", extra=_event_extra(event))
        return consent

    async def _resolve_terms_version(
        self,
        *,
        captive_portal_config_id: uuid.UUID | None,
        guest_organization_id: uuid.UUID,
    ) -> str | None:
        """The version string for the terms this portal was showing, or
        ``None`` when it genuinely cannot be established.

        Derived here rather than trusted from the request. The caller is
        an unauthenticated guest-facing endpoint; a version it supplied
        would be a claim about the venue's own documents made by the
        party the record exists to hold evidence *against*. The
        request-supplied value is still honoured when present -- it is the
        seam an admin backfill or a future consent-string registry would
        use -- but the portal itself sends none, so in practice this is
        the path every real consent takes.

        Three ways it returns ``None``, all of them honest:

        * **No config id.** Nothing to hash. A guest can consent without
          the portal telling us which config it rendered, and that
          possibility is not removed by pretending otherwise.
        * **The config does not exist, or belongs to another
          organization.** ``captive_portal_config_id`` arrives from an
          unauthenticated request body and is stored as a plain FK with no
          tenant check, so a caller can name any config in the platform.
          Stamping this guest's consent with *another tenant's* terms
          version would be a fabricated record -- strictly worse than a
          NULL, because it looks like evidence. Rejecting the whole
          consent instead would be the wrong failure direction: this runs
          on the sign-in path, and refusing to record a consent because
          the config id looked odd loses the record entirely.
        * **The config has no terms or privacy content at all.** Then what
          the guest saw came from the frontend's own hardcoded copy, which
          this layer cannot see -- see ``compute_terms_version``.

        A failure here never propagates. The consent row is the thing that
        matters; a missing version degrades it, an exception would lose
        it.
        """
        if captive_portal_config_id is None:
            return None
        try:
            config = await self.captive_portal_service.get_config(
                captive_portal_config_id
            )
        except Exception:  # noqa: BLE001 -- never lose a consent over this
            logger.warning(
                "guest_consent_terms_version_unresolved",
                extra={"event_config_id": str(captive_portal_config_id)},
            )
            return None
        if getattr(config, "organization_id", None) != guest_organization_id:
            logger.warning(
                "guest_consent_terms_version_cross_org",
                extra={"event_config_id": str(captive_portal_config_id)},
            )
            return None
        return compute_terms_version(
            terms_and_conditions_text=config.terms_and_conditions_text,
            terms_and_conditions_url=config.terms_and_conditions_url,
            privacy_policy_text=config.privacy_policy_text,
            privacy_policy_url=config.privacy_policy_url,
        )

    # ========================================================================
    # Guest / device lookups
    # ========================================================================

    async def get_guest(
        self,
        guest_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Guest:
        return await self._require_guest(
            guest_id, requesting_organization_id=requesting_organization_id
        )

    async def list_guests(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        is_blocked: bool | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Guest], object]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        if is_blocked is not None:
            filters["is_blocked"] = is_blocked
        return await self.repository.list_guests(
            page=page, page_size=page_size, filters=filters or None, search=search
        )

    async def get_guest_sessions(
        self,
        guest_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        limit: int | None = None,
    ) -> list[GuestSession]:
        guest = await self._require_guest(
            guest_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_sessions_for_guest(guest.id, limit=limit)

    async def block_guest(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        guest_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        reason: str | None,
    ) -> Guest:
        guest = await self._require_guest(
            guest_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_guest(
            guest,
            {"is_blocked": True, "blocked_reason": reason, "updated_by": actor_user_id},
        )
        event = GuestBlocked(guest_id=updated.id, reason=reason)
        logger.info("guest_blocked", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_BLOCKED,
            entity_id=updated.id,
            description=f"Guest '{updated.identifier}' blocked"
            + (f": {reason}" if reason else ""),
            organization_id=updated.organization_id,
            location_id=updated.location_id,
        )
        return updated

    async def unblock_guest(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        guest_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Guest:
        guest = await self._require_guest(
            guest_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_guest(
            guest,
            {"is_blocked": False, "blocked_reason": None, "updated_by": actor_user_id},
        )
        event = GuestUnblocked(guest_id=updated.id)
        logger.info("guest_unblocked", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_UNBLOCKED,
            entity_id=updated.id,
            description=f"Guest '{updated.identifier}' unblocked",
            organization_id=updated.organization_id,
            location_id=updated.location_id,
        )
        return updated

    async def list_devices_by_ids(
        self,
        *,
        device_ids: list[uuid.UUID],
        requesting_organization_id: uuid.UUID | None = None,
    ) -> list[GuestDevice]:
        """Bulk-resolve ``device_ids`` to their :class:`~.models.GuestDevice`
        rows (MAC address included) in one round trip -- backs ``GET
        /guest-devices``, the Network Activity Log v1 report's fix for
        ``GuestSessionResponse.device_id`` being a bare FK with no
        denormalized MAC address (see ``constants
        .MAX_BULK_DEVICE_LOOKUP_IDS``'s own docstring for the full
        "avoids an N+1 per-session device lookup" reasoning). Raises
        ``TooManyDeviceIdsError`` rather than silently truncating the
        list -- the same "a real, documented bound, never a silent
        truncation" discipline ``app.domains.controller_logs``'s own
        ``MAX_EXPORT_ROWS`` establishes for CSV export."""
        if len(device_ids) > MAX_BULK_DEVICE_LOOKUP_IDS:
            raise TooManyDeviceIdsError(
                requested=len(device_ids), limit=MAX_BULK_DEVICE_LOOKUP_IDS
            )
        return await self.repository.list_devices_by_ids(
            device_ids=device_ids, organization_id=requesting_organization_id
        )

    async def list_devices_for_session_ids(
        self,
        *,
        device_ids: list[uuid.UUID],
        requesting_organization_id: uuid.UUID | None = None,
    ) -> list[GuestDevice]:
        """Resolve device ids taken from an already-tenant-filtered session
        list -- backs ``GuestSessionResponse.device_mac``. See
        ``GuestRepository.list_devices_for_session_ids`` for why this asks
        a different tenancy question than ``list_devices_by_ids`` above.

        Bounded like its sibling, and for the same reason: the router
        chunks at ``MAX_BULK_DEVICE_LOOKUP_IDS`` before calling, so this
        raises only if a future caller forgets to."""
        if len(device_ids) > MAX_BULK_DEVICE_LOOKUP_IDS:
            raise TooManyDeviceIdsError(
                requested=len(device_ids), limit=MAX_BULK_DEVICE_LOOKUP_IDS
            )
        return await self.repository.list_devices_for_session_ids(
            device_ids=device_ids, organization_id=requesting_organization_id
        )

    async def list_devices_for_guest_ids(
        self,
        *,
        guest_ids: list[uuid.UUID],
        requesting_organization_id: uuid.UUID | None = None,
    ) -> dict[uuid.UUID, list[GuestDevice]]:
        """Resolve one page of guests to their devices, grouped by
        ``guest_id`` and newest-seen first within each group -- backs the
        ``mac_addresses``/``device_count`` fields on ``GuestResponse``.

        Deliberately takes no ``MAX_BULK_*`` bound of its own, unlike
        ``list_devices_by_ids`` above. That bound exists because ``GET
        /guest-devices`` lets an external caller choose the id list.
        Here the list is one page of ``GET /guests``, already capped at
        ``page_size <= 100`` by the route signature, so a second bound
        would be an unreachable branch pretending to be a safeguard.

        Returns a mapping rather than a flat list so the caller does no
        grouping of its own; the repository's SQL ordering is preserved
        within each group, which is what lets ``mac_addresses[0]`` mean
        "the guest's current device" without a Python-side sort."""
        devices = await self.repository.list_devices_for_guest_ids(
            guest_ids=guest_ids, organization_id=requesting_organization_id
        )
        grouped: dict[uuid.UUID, list[GuestDevice]] = {}
        for device in devices:
            grouped.setdefault(device.guest_id, []).append(device)
        return grouped

    async def list_voucher_redemptions(
        self,
        *,
        voucher_ids: list[uuid.UUID],
        requesting_organization_id: uuid.UUID | None = None,
    ) -> list[VoucherRedemptionRow]:
        """Resolve ``voucher_ids`` to the device/address each was actually
        redeemed on -- backs ``GET /voucher-redemptions`` for the Vouchers
        screen. See ``GuestRepository.list_voucher_redemptions`` for the
        two-hop join, and ``constants.MAX_BULK_VOUCHER_LOOKUP_IDS`` for
        why this resolution lives in the guest domain rather than the
        voucher one.

        Raises ``TooManyVoucherIdsError`` rather than truncating, for the
        identical reason ``list_devices_by_ids`` raises rather than
        truncating: a silently dropped id renders as an empty cell that
        is indistinguishable from "never redeemed"."""
        if len(voucher_ids) > MAX_BULK_VOUCHER_LOOKUP_IDS:
            raise TooManyVoucherIdsError(
                requested=len(voucher_ids), limit=MAX_BULK_VOUCHER_LOOKUP_IDS
            )
        return await self.repository.list_voucher_redemptions(
            voucher_ids=voucher_ids, organization_id=requesting_organization_id
        )

    async def get_or_create_device(
        self,
        *,
        guest_id: uuid.UUID,
        mac_address: str,
        device_name: str | None = None,
        known_device: GuestDevice | None = _DEVICE_NOT_PREFETCHED,
    ) -> GuestDevice:
        """Get-or-create a :class:`~.models.GuestDevice` by MAC address --
        see ``models.py``'s module docstring for why ``mac_address`` is
        globally unique with ``guest_id`` reassignable, not scoped per
        guest.

        ``known_device``, when passed (anything other than the
        ``_DEVICE_NOT_PREFETCHED`` sentinel default -- see that sentinel's
        own module-level docstring), is trusted as an already-fresh
        ``get_device_by_mac(mac_address)`` result a caller obtained
        moments earlier in the same request, skipping a second, identical
        query here.
        """
        mac = normalize_mac_address(mac_address)
        now = datetime.now(UTC)
        device = (
            await self.repository.get_device_by_mac(mac)
            if known_device is _DEVICE_NOT_PREFETCHED
            else known_device
        )
        if device is None:
            return await self.repository.create_device(
                guest_id=guest_id,
                mac_address=mac,
                device_name=device_name,
                first_seen_at=now,
                last_seen_at=now,
            )
        update_data: dict[str, object] = {"last_seen_at": now}
        if device.guest_id != guest_id:
            # Reassignment: this physical device is now presented alongside
            # a different guest identifier -- see module docstring.
            update_data["guest_id"] = guest_id
        if device_name is not None:
            update_data["device_name"] = device_name
        return await self.repository.update_device(device, update_data)

    async def adopt_nas_asserted_device(
        self, *, session: GuestSession, mac_address: str
    ) -> GuestSession:
        """Attach a ``GuestDevice`` to a session that was created without
        one, using a MAC the **NAS itself asserted**.

        ## The defect this exists to close

        ``device_mac`` is optional on the OTP/voucher/password login
        schemas -- deliberately, and in three places at once:
        ``GuestPinLoginRequest`` documents that its own ``device_mac`` is
        required "unlike every other login request schema's";
        ``_find_reusable_active_session`` documents the MAC-less case
        explicitly; and the captive portal's ``mac`` search param is
        optional because a stale bookmark, a hand-typed URL or a cropped
        QR code really does arrive without RouterOS's ``$(mac)``
        substitution. So a session with ``device_id IS NULL`` is a
        supported outcome, not corruption.

        What was **not** supported is what happened to it afterwards.
        Three separate consumers key on ``device_id`` and each one skips a
        NULL silently:

        1. ``get_active_session_for_device`` -- the captive portal's only
           "are you already connected?" check. It resolves a MAC to a
           device row and filters sessions on ``device_id``, so a session
           with none can never be returned, at any point in its life. The
           guest is online, the session is ``ACTIVE``, and the portal
           shows them the sign-in form anyway.
        2. ``_find_reusable_active_session`` -- returns ``None`` for a
           NULL ``device_id``, so the next login inserts a second row
           rather than reusing the first.
        3. ``app.domains.router_agent``'s ``/agent/authorized-macs`` --
           ``if session.device_id is None: continue``, so the session
           contributes no MAC to the router's ip-binding bypass list.

        Confirmed live: one guest, one iPhone, two OTP verifications 2m44s
        apart, because the session created by the first was invisible to
        the check that would have shown it to them.

        ## Why healing here, and not refusing the login

        Refusing a MAC-less login would turn "you occasionally sign in
        twice" into "guests on a link without ``$(mac)`` can never sign in
        at all" -- a documented, supported case, regressed into a hard
        failure. Widening the lookup is not available either: a session
        with no device stores no MAC anywhere, so there is no column to
        match ``get_active_session_for_device``'s ``device_mac`` against
        and no join path to one; and the portal, on a fresh load, knows
        nothing else about the guest to key on (the identifier is what it
        is about to ask for).

        That leaves backfilling, and there is exactly one trustworthy
        later source of the MAC: RFC 2865 Section 5.31
        ``Calling-Station-Id``, asserted by an already
        shared-secret-authenticated NAS at Authorize time. This module's
        own ``RadiusService.authorize`` docstring makes the argument for
        why that value -- and only that value -- can be trusted, in the
        write-up of why ``POST /guest/login/mac`` was removed as an
        authentication bypass. This method is that argument applied to a
        session that already exists.

        ## Bounds

        Idempotent: a session that already has a ``device_id`` is returned
        untouched, so the reauthentication a real NAS sends every few
        minutes costs one comparison. ``get_or_create_device`` owns the
        MAC-to-guest reassignment semantics, unchanged. The caller is
        responsible for never letting a failure here turn a valid
        authorize into a reject -- see ``RadiusService.authorize``.
        """
        if session.device_id is not None:
            return session
        device = await self.get_or_create_device(
            guest_id=session.guest_id, mac_address=mac_address
        )
        return await self.repository.update_session(session, {"device_id": device.id})

    async def get_active_session_for_device(
        self,
        *,
        router_id: uuid.UUID,
        device_mac: str,
    ) -> GuestLoginResult | None:
        """Real "is this device already connected?" check -- backs the
        captive portal's own re-visit case: a guest whose browser reopens
        the portal URL (a fresh RouterOS redirect, a re-scanned QR code, a
        bookmark) while their device already has a live, RADIUS-authorized
        session should see their existing session, not the sign-in form
        again. ``device_mac`` is the one MAC a captive-portal page can
        trust without RADIUS -- it's RouterOS's own ``$(mac)`` substitution
        that generated this very redirect (see
        ``app.domains.router_provisioning``'s bootstrap-script templating
        and this same reasoning already applied to
        ``ProvisioningCheckInRequest.wireguard_public_key``'s docstring).
        Returns ``None`` -- not an error -- when no device/active session
        matches, exactly like a normal first-time visit."""
        device = await self.repository.get_device_by_mac(
            normalize_mac_address(device_mac)
        )
        if device is None:
            return None
        sessions, _ = await self.repository.list_sessions(
            page=1,
            page_size=1,
            filters={
                "router_id": router_id,
                "device_id": device.id,
                "status": GuestSessionStatus.ACTIVE.value,
            },
            sort_by="started_at",
            sort_order=SortOrder.DESC,
        )
        if not sessions:
            return None
        session = sessions[0]
        # An ACTIVE row is not proof the guest is on the network. If the
        # venue set 30 minutes, the router dropped them at 30 minutes --
        # and this row only becomes DISCONNECTED when the NAS's
        # Accounting-Stop arrives, which is not guaranteed and is not
        # instant. In the gap, answering "yes, you're connected" sends a
        # guest with no internet to the "You're online" screen, which is
        # the single most frustrating thing this portal can do. The
        # session's own wall-clock limit is a fact we already hold, so
        # there is no reason to wait to be told.
        if has_session_reached_time_limit(session, now=datetime.now(UTC)):
            return None
        guest = await self.repository.get_guest_by_id(session.guest_id)
        if guest is None:
            return None
        return GuestLoginResult(
            guest=guest, session=session, device=device, is_new_guest=False
        )

    async def _active_session_past_its_limit(
        self,
        *,
        router_id: uuid.UUID,
        device_id: uuid.UUID,
        now: datetime,
    ) -> GuestSession | None:
        """The device's newest still-``ACTIVE`` session on this router, if
        it has already outlived its own ``session_timeout_minutes``.

        Bounded by the same freshness window as a genuinely-ended session,
        deliberately: a row abandoned ACTIVE for a week is a bookkeeping
        artefact, not something to greet a guest with. Without the bound
        this would be the one path that could report an arbitrarily old
        session, which is exactly the hole the SQL-level window on the
        ended-session query exists to close.
        """
        sessions, _ = await self.repository.list_sessions(
            page=1,
            page_size=1,
            filters={
                "router_id": router_id,
                "device_id": device_id,
                "status": GuestSessionStatus.ACTIVE.value,
            },
            sort_by="started_at",
            sort_order=SortOrder.DESC,
        )
        if not sessions:
            return None
        session = sessions[0]
        if not has_session_reached_time_limit(session, now=now):
            return None
        ended_at = session.started_at + timedelta(
            minutes=session.session_timeout_minutes or 0
        )
        if ended_at < now - timedelta(minutes=LAST_ENDED_SESSION_WINDOW_MINUTES):
            return None
        return session

    async def get_last_ended_session_for_device(
        self,
        *,
        router_id: uuid.UUID,
        device_mac: str,
        now: datetime | None = None,
    ) -> GuestLastEndedSessionResult | None:
        """ "This device had a session on this router, and it has just
        ended" -- the answer the captive portal needs to greet a
        returning guest with "you were disconnected" instead of the same
        blank sign-in form a first-time visitor gets.

        Same trust model as ``get_active_session_for_device`` above:
        ``device_mac`` is RouterOS's own ``$(mac)`` substitution, the one
        identity available before the guest types anything. It is weaker
        here than there, though, and the difference drives everything
        below: for an *active* session the MAC is corroborated by the
        device actually being authorised on the NAS right now, whereas a
        MAC whose session has ended is backed by nothing at all. So this
        method answers the narrowest question that still makes the screen
        possible, and returns ``None`` -- never an error -- for every
        other shape of "no".

        **Which endings a guest may be told about.** Not a taste
        judgement; it follows ``GuestSessionStatus``'s own contract:

        * ``DISCONNECTED`` -- yes. The enum defines this as "a normal,
          non-punitive end of use ... reconnecting immediately is
          allowed", which is exactly the precondition for a screen whose
          main button is "Sign in again". Covers the NAS's own
          Accounting-Stop (including the ``Lost-Service`` seen in
          production), a router reboot, an admin ending a session with
          no disciplinary intent, and the guest's own Disconnect tap.
        * ``EXPIRED`` **and** ``disconnect_reason == "inactivity_timeout"``
          -- yes, and this is the founder's case. The status alone is not
          enough: ``EXPIRED`` is also written for ``data_limit_exceeded``
          and for ``fup_{data,time}_quota_exceeded_*``. A guest who has
          exhausted their data allowance has not "timed out", and telling
          them to sign in again would send them round a loop that ends
          the same way. Matching the one literal this codebase writes for
          a real timeout is an allowlist, and it fails closed: any future
          ``EXPIRED`` reason is silently excluded until somebody decides
          what a guest should be told about it.
        * ``TERMINATED`` -- **never**, for two independent reasons,
          either of which alone would settle it. It is an operator's
          punitive kill, and it is how a blocklist rule ends a session
          (``guest_access.enforcement.BlocklistEnforcer`` writes exactly
          this status). A blocked guest must not be shown "your session
          expired": it is false, and it invites them to retry a sign-in
          that is guaranteed to be refused, replacing a clear refusal at
          the sign-in step with a confusing detour. Independently, this
          status carries ``TERMINATION_RECONNECT_COOLDOWN_MINUTES``, so
          "Sign in again" is an offer the platform will not honour. The
          right destination for these guests is the ordinary sign-in
          page, where ``_enforce_access_control`` refuses them properly
          -- and, since backend #169, without the operator's note.
        * ``PAUSED`` -- never. It is the one non-terminal status, has no
          ``ended_at`` at all, and an admin may resume it back to
          ``ACTIVE``. Nothing has ended, so there is nothing to report.
        * ``ACTIVE`` -- not this method's question;
          ``get_active_session_for_device`` above answers it, and the
          portal asks that one first.

        ``disconnect_reason`` is read here and never returned. It is free
        text from three mutually distrusting sources -- see
        ``GuestSessionEndedReason``'s docstring -- so it may inform a
        decision but may not itself become an answer.

        The ``LAST_ENDED_SESSION_WINDOW_MINUTES`` bound is applied in
        SQL (``repository.get_latest_ended_session_for_device``), not
        here, so no future caller can obtain an unbounded history of a
        device by skipping a Python-side check.
        """
        now = now or datetime.now(UTC)
        device = await self.repository.get_device_by_mac(
            normalize_mac_address(device_mac)
        )
        if device is None:
            return None
        # The exact mirror of the skip in `get_active_session_for_device`,
        # and it has to be here or that skip would make things worse
        # rather than better: a guest whose router-side session has run
        # out would stop being told "you're connected" (good) and start
        # getting a blank sign-in form with no explanation (which is the
        # bug this whole change exists to fix).
        #
        # This is also the case the feature has to survive on. If the NAS
        # never sends an Accounting-Stop -- a real possibility nobody has
        # been able to disprove on the device -- the row stays ACTIVE
        # indefinitely, because the idle sweep cannot expire it either
        # (see `has_session_reached_time_limit`). Deriving the answer from
        # the session's own elapsed life rather than from a disconnect
        # event means the screen works whether or not the router ever
        # tells us anything.
        overrun = await self._active_session_past_its_limit(
            router_id=router_id, device_id=device.id, now=now
        )
        if overrun is not None:
            return GuestLastEndedSessionResult(
                reason=GuestSessionEndedReason.TIMED_OUT,
                session_timeout_minutes=overrun.session_timeout_minutes,
                idle_timeout_minutes=overrun.idle_timeout_minutes,
            )
        session = await self.repository.get_latest_ended_session_for_device(
            router_id=router_id,
            device_id=device.id,
            statuses=(
                GuestSessionStatus.DISCONNECTED.value,
                GuestSessionStatus.EXPIRED.value,
            ),
            ended_after=now - timedelta(minutes=LAST_ENDED_SESSION_WINDOW_MINUTES),
        )
        if session is None:
            return None
        reason = _ended_session_reason(session)
        if reason is None:
            return None
        return GuestLastEndedSessionResult(
            reason=reason,
            session_timeout_minutes=session.session_timeout_minutes,
            idle_timeout_minutes=session.idle_timeout_minutes,
        )

    # ========================================================================
    # Session management
    # ========================================================================

    async def get_session(
        self,
        session_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> GuestSession:
        session = await self.repository.get_session_by_id(session_id)
        if session is None:
            raise GuestSessionNotFoundError(session_id)
        self._enforce_tenant_scope(session.organization_id, requesting_organization_id)
        enforce_entity_location(
            entity_location_id=getattr(session, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationGuestAccessError(),
        )
        return session

    async def list_sessions(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        status: GuestSessionStatus | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[GuestSession], object]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        if router_id is not None:
            filters["router_id"] = router_id
        if guest_id is not None:
            filters["guest_id"] = guest_id
        if status is not None:
            filters["status"] = status.value
        return await self.repository.list_sessions(
            page=page, page_size=page_size, filters=filters or None
        )

    async def list_sessions_in_range(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[GuestSession], object]:
        """Real ``[start, end)`` session listing -- see
        ``GuestRepository.list_sessions_in_range``'s own docstring for why
        this exists alongside ``list_sessions`` above rather than extending
        it."""
        return await self.repository.list_sessions_in_range(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
            page=page,
            page_size=page_size,
        )

    async def list_login_history(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[GuestLoginHistory], object]:
        """Backs ``GET /guest-login-history``'s default (no real date
        range) mode -- the Login/Access Attempt Log report's data source,
        mirroring ``list_sessions``'s identical "org-scoped caller vs.
        platform-level caller sees everything" convention. Composes the
        repository read ``app.domains.controller_logs`` already uses for
        its own, differently-audienced "Authentication Logs" admin-log
        category (see that domain's module docstring) -- the same
        underlying table, read through this module's own tenant-scoped
        entry point instead."""
        return await self.repository.list_login_history(
            organization_id=requesting_organization_id,
            location_id=location_id,
            guest_id=guest_id,
            page=page,
            page_size=page_size,
        )

    async def list_login_history_in_range(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None = None,
        start: datetime,
        end: datetime,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[GuestLoginHistory], object]:
        """Real ``[start, end)`` login-history listing -- see
        ``GuestRepository.list_login_history_in_range``'s own docstring,
        the exact same shape as ``list_sessions_in_range`` above applied to
        ``GuestLoginHistory``."""
        return await self.repository.list_login_history_in_range(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
            page=page,
            page_size=page_size,
        )

    async def disconnect_session(
        self,
        *,
        session_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> GuestSession:
        """Normal, non-punitive end of use -- see module docstring for the
        distinction from ``terminate_session``. Audited only when
        admin-initiated (``actor_user_id`` supplied); a system-initiated
        disconnect (RADIUS Accounting-Stop, ``enforce_timeouts``) is logged
        but not audited."""
        session = await self.get_session(
            session_id, requesting_organization_id=requesting_organization_id
        )
        validate_session_status_transition(
            current=GuestSessionStatus(session.status),
            target=GuestSessionStatus.DISCONNECTED,
        )
        now = datetime.now(UTC)
        updated = await self.repository.update_session(
            session,
            {
                "status": GuestSessionStatus.DISCONNECTED.value,
                "ended_at": now,
                "disconnect_reason": reason,
                "updated_by": actor_user_id,
            },
        )
        event = GuestSessionDisconnected(session_id=updated.id, reason=reason)
        logger.info("guest_session_disconnected", extra=_event_extra(event))
        if actor_user_id is not None:
            await self._audit(
                actor_user_id,
                AuditAction.GUEST_SESSION_DISCONNECTED,
                entity_id=updated.id,
                description=f"Guest session {updated.id} disconnected"
                + (f": {reason}" if reason else ""),
                organization_id=updated.organization_id,
                location_id=updated.location_id,
            )
        await issue_live_disconnect(self.repository, session=updated)
        return updated

    async def terminate_session(
        self,
        *,
        session_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> GuestSession:
        """Admin-driven, punitive, immediate kill -- distinct from
        ``disconnect_session``: always audited, and blocks the guest's
        ``reconnect`` for ``constants.TERMINATION_RECONNECT_COOLDOWN_MINUTES``
        (see ``exceptions.SessionTerminationCooldownError``). A normal
        ``disconnect_session`` imposes no such cooldown -- it represents an
        ordinary, non-disciplinary end of use the guest may immediately
        follow with a fresh login or (within the grace window)
        ``reconnect``."""
        session = await self.get_session(
            session_id, requesting_organization_id=requesting_organization_id
        )
        validate_session_status_transition(
            current=GuestSessionStatus(session.status),
            target=GuestSessionStatus.TERMINATED,
        )
        now = datetime.now(UTC)
        updated = await self.repository.update_session(
            session,
            {
                "status": GuestSessionStatus.TERMINATED.value,
                "ended_at": now,
                "disconnect_reason": reason,
                "updated_by": actor_user_id,
            },
        )
        event = GuestSessionTerminated(
            session_id=updated.id, guest_id=updated.guest_id, reason=reason
        )
        logger.info("guest_session_terminated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_SESSION_TERMINATED,
            entity_id=updated.id,
            description=f"Guest session {updated.id} terminated"
            + (f": {reason}" if reason else ""),
            organization_id=updated.organization_id,
            location_id=updated.location_id,
        )
        await issue_live_disconnect(self.repository, session=updated)
        return updated

    async def pause_session(
        self,
        *,
        session_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> GuestSession:
        """Phase 1 BhaiFi-parity: an admin-driven, *reversible* temporary
        suspension -- see ``constants.GuestSessionStatus.PAUSED``'s own
        docstring for the full "why this status alone survives to be
        resumed" write-up. Issues a real live Disconnect-Request the same
        way ``disconnect_session``/``terminate_session`` already do --
        pausing must actually cut the guest's live network access, not
        just flip a database flag."""
        session = await self.get_session(
            session_id, requesting_organization_id=requesting_organization_id
        )
        validate_session_status_transition(
            current=GuestSessionStatus(session.status),
            target=GuestSessionStatus.PAUSED,
        )
        updated = await self.repository.update_session(
            session,
            {
                "status": GuestSessionStatus.PAUSED.value,
                "disconnect_reason": reason,
                "updated_by": actor_user_id,
            },
        )
        event = GuestSessionPaused(session_id=updated.id, reason=reason)
        logger.info("guest_session_paused", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_SESSION_PAUSED,
            entity_id=updated.id,
            description=f"Guest session {updated.id} paused"
            + (f": {reason}" if reason else ""),
            organization_id=updated.organization_id,
            location_id=updated.location_id,
        )
        await issue_live_disconnect(self.repository, session=updated)
        return updated

    async def resume_session(
        self,
        *,
        session_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> GuestSession:
        """Reverses ``pause_session``, flipping ``PAUSED`` back to
        ``ACTIVE`` in place (the one status this module ever revives --
        see ``constants.GuestSessionStatus.PAUSED``'s own docstring).
        ``last_activity_at`` is refreshed to now so a just-resumed session
        is never immediately eligible for ``enforce_session_timeouts``.

        **Honest scope limitation:** this only flips CloudGuest's own
        authorization state back to ``ACTIVE`` (so the *next* RADIUS
        Authorize call succeeds again) -- it does not, and cannot in
        general, force the guest's device to reassociate with the NAS on
        its own. A real captive-portal deployment already expects a
        disconnected client to re-authenticate on its next connection
        attempt (the normal, expected flow after any Disconnect-Request,
        pause included); there is no universal "CoA reauth" RouterOS/
        FreeRADIUS hotspot deployments can rely on to force a client back
        online without that new attempt, so this module does not pretend
        to offer one."""
        session = await self.get_session(
            session_id, requesting_organization_id=requesting_organization_id
        )
        validate_session_status_transition(
            current=GuestSessionStatus(session.status),
            target=GuestSessionStatus.ACTIVE,
        )
        updated = await self.repository.update_session(
            session,
            {
                "status": GuestSessionStatus.ACTIVE.value,
                "disconnect_reason": None,
                "last_activity_at": datetime.now(UTC),
                "updated_by": actor_user_id,
            },
        )
        event = GuestSessionResumed(session_id=updated.id)
        logger.info("guest_session_resumed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_SESSION_RESUMED,
            entity_id=updated.id,
            description=f"Guest session {updated.id} resumed",
            organization_id=updated.organization_id,
            location_id=updated.location_id,
        )
        return updated

    async def extend_session(
        self,
        *,
        session_id: uuid.UUID,
        additional_minutes: int,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> GuestSession:
        """Phase 1 BhaiFi-parity: pushes ``session_timeout_minutes``
        (or, for a session with no timeout at all -- an unlimited grant --
        seeds one at exactly ``additional_minutes``) forward by
        ``additional_minutes``, and refreshes ``last_activity_at`` to now
        -- an admin-driven grant of more connected time, mirroring this
        module's existing "timeout is a reporting mechanism, not live
        enforcement" posture (see ``service.py``'s module docstring):
        purely a database-level extension, no RADIUS attribute is pushed
        to the NAS (unlike ``pause_session``'s live Disconnect-Request,
        there is no universally-supported CoA equivalent for "extend this
        session's remaining time" against a typical RouterOS hotspot
        deployment). Legal on ``ACTIVE`` or ``PAUSED`` (extending a paused
        session's allowance before it is resumed is a legitimate admin
        action) -- any other, terminal status raises
        ``InvalidSessionStatusTransitionError`` the same way
        ``pause_session``/``resume_session`` do, since "extend" is itself a
        transition-shaped operation even though the status value does not
        change."""
        validate_extension_minutes(additional_minutes)
        session = await self.get_session(
            session_id, requesting_organization_id=requesting_organization_id
        )
        current_status = GuestSessionStatus(session.status)
        if current_status not in (
            GuestSessionStatus.ACTIVE,
            GuestSessionStatus.PAUSED,
        ):
            raise InvalidSessionStatusTransitionError(
                current_status.value, current_status.value
            )
        new_timeout_minutes = (
            session.session_timeout_minutes or 0
        ) + additional_minutes
        updated = await self.repository.update_session(
            session,
            {
                "session_timeout_minutes": new_timeout_minutes,
                "last_activity_at": datetime.now(UTC),
                "updated_by": actor_user_id,
            },
        )
        event = GuestSessionExtended(
            session_id=updated.id, additional_minutes=additional_minutes
        )
        logger.info("guest_session_extended", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.GUEST_SESSION_EXTENDED,
            entity_id=updated.id,
            description=(
                f"Guest session {updated.id} extended by "
                f"{additional_minutes} minute(s)"
            ),
            organization_id=updated.organization_id,
            location_id=updated.location_id,
        )
        return updated

    async def reconnect(
        self,
        *,
        guest_id: uuid.UUID,
        router_id: uuid.UUID,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        device_mac: str | None = None,
        ip_address: str | None = None,
    ) -> GuestSession:
        """See module docstring's "Reconnect creates a new session" write-up."""
        guest = await self._require_guest(
            guest_id, requesting_organization_id=requesting_organization_id
        )
        self._reject_if_blocked(guest)

        now = datetime.now(UTC)
        latest_terminated = (
            await self.repository.get_latest_terminated_session_for_guest(guest.id)
        )
        if latest_terminated is not None and latest_terminated.ended_at is not None:
            cooldown_until = latest_terminated.ended_at + timedelta(
                minutes=TERMINATION_RECONNECT_COOLDOWN_MINUTES
            )
            if now < cooldown_until:
                remaining_minutes = max(
                    int((cooldown_until - now).total_seconds() // 60) + 1, 1
                )
                raise SessionTerminationCooldownError(remaining_minutes)

        prior = await self.repository.get_latest_session_for_guest(guest.id)
        if prior is None:
            raise NoReconnectableSessionError(guest.id)
        if prior.status == GuestSessionStatus.ACTIVE.value:
            return prior  # idempotent -- already connected, no duplicate session

        # The generic grace window only gates an ordinary ended session
        # (DISCONNECTED/EXPIRED) -- a TERMINATED prior session's own
        # eligibility is already fully governed by the cooldown check above
        # (which raises while still cooling down, and is deliberately
        # longer than RECONNECT_GRACE_MINUTES -- see constants.py). Applying
        # the grace window on top of that would make the cooldown pointless
        # in practice (it would always have already elapsed by the time the
        # cooldown does), silently turning a temporary punitive block into a
        # permanent one.
        if prior.status != GuestSessionStatus.TERMINATED.value:
            reference_time = prior.ended_at or prior.last_activity_at
            if now - reference_time > timedelta(minutes=RECONNECT_GRACE_MINUTES):
                raise NoReconnectableSessionError(guest.id)

        router = await self._get_eligible_router(router_id)
        device: GuestDevice | None = None
        if device_mac:
            device = await self.get_or_create_device(
                guest_id=guest.id, mac_address=device_mac
            )
        elif prior.device_id is not None:
            device = await self.repository.get_device_by_id(prior.device_id)

        session = await self._create_session(
            guest=guest,
            device=device,
            router=router,
            location_id=location_id,
            auth_method=GuestAuthMethod(prior.auth_method),
            voucher_id=prior.voucher_id,
            ip_address=ip_address,
            user_agent=prior.user_agent,
            accept_language=prior.accept_language,
            data_limit_mb=prior.data_limit_mb,
            session_timeout_minutes=prior.session_timeout_minutes,
            # Carried forward with the rest of the prior session's grant --
            # a reconnect continues an existing entitlement rather than
            # issuing a new one, so it must not quietly pick up a different
            # idle allowance than the session it derives from. A prior
            # session from before this column existed carries NULL, which
            # reads as "send no Idle-Timeout", i.e. exactly the behaviour
            # that prior session actually had.
            idle_timeout_minutes=prior.idle_timeout_minutes,
        )
        await self._bump_guest_visit(guest)
        return session

    async def record_usage(
        self,
        *,
        session_id: uuid.UUID,
        bytes_uploaded_delta: int,
        bytes_downloaded_delta: int,
    ) -> GuestSession:
        """Called by ``RadiusService`` on RADIUS Interim-Update accounting
        packets. A no-op on a session that is no longer ``ACTIVE`` (a stale
        interim update arriving after the session already ended).

        Phase 1 BhaiFi-parity addition: every positive byte delta is also
        bumped into the guest's own cumulative ``GuestQuotaUsage`` rows via
        ``_track_fup_data_usage`` (best-effort, riding along on this
        already-happening call -- see that method's own docstring), and a
        session whose guest has *just* crossed a configured FUP data cap is
        expired the same way one that just exceeded its own per-session
        ``data_limit_mb`` already was, before this addition."""
        session = await self.repository.get_session_by_id(session_id)
        if session is None:
            raise GuestSessionNotFoundError(session_id)
        if not session.is_active():
            return session

        now = datetime.now(UTC)
        updated = await self.repository.update_session(
            session,
            {
                "bytes_uploaded": session.bytes_uploaded + max(bytes_uploaded_delta, 0),
                "bytes_downloaded": session.bytes_downloaded
                + max(bytes_downloaded_delta, 0),
                "last_activity_at": now,
            },
        )
        total_delta_bytes = max(bytes_uploaded_delta, 0) + max(
            bytes_downloaded_delta, 0
        )
        violated_fup_period = await self._track_fup_data_usage(
            guest_id=updated.guest_id,
            organization_id=updated.organization_id,
            delta_bytes=total_delta_bytes,
            now=now,
        )
        if is_quota_exceeded(updated):
            updated = await self.repository.update_session(
                updated,
                {
                    "status": GuestSessionStatus.EXPIRED.value,
                    "ended_at": now,
                    "disconnect_reason": "data_limit_exceeded",
                },
            )
            event = GuestSessionExpired(session_id=updated.id)
            logger.info("guest_session_expired_quota", extra=_event_extra(event))
            await issue_live_disconnect(self.repository, session=updated)
            return updated
        if violated_fup_period is not None:
            reason = f"fup_data_quota_exceeded_{violated_fup_period}"
            updated = await self.repository.update_session(
                updated,
                {
                    "status": GuestSessionStatus.EXPIRED.value,
                    "ended_at": now,
                    "disconnect_reason": reason,
                },
            )
            event = GuestSessionExpired(session_id=updated.id)
            logger.info("guest_session_expired_fup_quota", extra=_event_extra(event))
            await issue_live_disconnect(self.repository, session=updated)
        return updated

    def check_quota_exceeded(self, session: GuestSession) -> bool:
        return is_quota_exceeded(session)

    async def enforce_timeouts(self) -> list[GuestSession]:
        """See module docstring's "a reporting mechanism, not live
        enforcement" write-up. Returns every session just flipped to
        ``EXPIRED``. A thin delegation to the module-level
        ``enforce_session_timeouts`` -- kept as a method (rather than
        removed) so every existing caller of ``GuestService.enforce_timeouts``
        (including this module's own pre-existing test suite) keeps working
        unchanged. See that function's own docstring for why the real logic
        was pulled out to module scope."""
        return await enforce_session_timeouts(self.repository)

    async def check_portal_admission(
        self,
        *,
        identifier: str,
        auth_method: GuestAuthMethod,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        device_mac: str | None = None,
        ip_address: str | None = None,
    ) -> None:
        """ "May this identifier begin a login at this property at all?" --
        asked *before* anything is spent on them.

        ## Why this exists

        The captive portal does not start at ``POST /guest/login/otp``. It
        starts at ``POST /otp/request``, which sends a real SMS, and only
        afterwards calls the login endpoint where
        ``_enforce_access_control`` runs. Gate only the second call and
        whitelist-only mode means: anyone who walks past the venue and
        types any phone number gets a real SMS at the owner's expense, and
        is then refused. That is a live bill and an abuse vector -- a
        stranger can drain a venue's SMS credit at will by typing numbers
        into a page that is, by design, open to the street.

        It is also simply the better guest experience. Someone who is not
        on the list should be told so immediately, not left waiting for a
        code that was never going to help them.

        ## Scope: only where the property opted in

        Returns immediately unless this property has
        ``whitelist_only_enabled`` on. A property that never switched the
        feature on sees no behaviour change here whatsoever -- in
        particular, this is deliberately **not** an opportunity to start
        enforcing blocklists at OTP-request time. That would be a real
        behaviour change (a blocked guest currently does receive a code and
        is refused at login) affecting every venue on the platform, and it
        belongs to its own PR with its own argument.

        Returns immediately, too, when the caller supplied neither an
        organization nor a location: with no property resolved there is no
        flag to read, and this is exactly the shape of the non-portal
        callers of ``POST /otp/request`` (e.g. an account-level code, which
        carries no venue at all).

        Note that the gate is deliberately **not** conditioned on the OTP's
        ``purpose``. ``purpose`` is client-supplied on an unauthenticated
        endpoint, so conditioning on it would leave the SMS spend one JSON
        field away from being unprotected -- and the check is about who is
        asking and where, which no purpose changes.

        ## The one new lookup, named honestly

        Unlike the login path -- where the portal config is already
        resolved by ``_require_method_enabled`` before the gate runs, and
        the flag costs nothing -- this method *does* resolve the config
        itself, because ``POST /otp/request`` had no reason to resolve one
        before. If that resolution raises, the guest is let through and a
        warning is logged, for the reason argued at length in
        ``_enforce_access_control``: a venue whose config lookup hiccups
        must not lose its WiFi entirely, and this path's fallback is
        precisely the behaviour every property had before the feature
        existed. The refusal still stands at login, which is the gate that
        was always there.
        """
        if organization_id is None and location_id is None:
            return
        identifier = normalize_identifier(identifier)
        try:
            resolved = await self.captive_portal_service.resolve_portal_config(
                organization_id=organization_id, location_id=location_id
            )
        except Exception as exc:
            event = WhitelistOnlyGateFailedOpen(
                organization_id=organization_id,
                location_id=location_id,
                identifier=identifier,
                auth_method=auth_method.value,
                detail=repr(exc),
            )
            logger.warning("whitelist_only_gate_failed_open", extra=_event_extra(event))
            return
        config = resolved.config
        if not config.whitelist_only_enabled:
            return
        await self._enforce_access_control(
            organization_id=config.organization_id,
            location_id=location_id,
            identifier=identifier,
            device_mac=device_mac,
            auth_method=auth_method,
            # No `guest=`: resolving one would be a second query run on
            # every OTP request at a whitelist-only property, including the
            # overwhelming majority that are about to be allowed, purely to
            # populate a nullable FK. `GuestLoginHistory.guest_id` is
            # nullable for exactly this case (see that model's docstring --
            # "failed attempts for an as-yet-unknown identifier"), and the
            # column an operator reads a refusal list by is `identifier`.
            ip_address=ip_address,
            whitelist_only_enabled=True,
            whitelist_only_denied_message=config.whitelist_only_denied_message,
        )

    async def check_otp_request_allowed(
        self,
        *,
        auth_method: GuestAuthMethod,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> None:
        """The login path's own venue gates, asked *before* an OTP code is
        spent on a guest -- ``POST /otp/request``'s counterpart to
        ``check_portal_admission``.

        ## Why this exists

        ``POST /otp/request`` is where the venue's money is spent: it sends
        a real SMS/email/WhatsApp before the guest ever reaches
        ``POST /guest/login/otp``. The login path enforces two venue gates
        *at login* -- the requested method's ``CaptivePortalConfig``
        enabled-flag (``otp_sms_enabled``/``otp_email_enabled``/
        ``otp_whatsapp_enabled``) and Open Hours -- via
        ``_require_method_enabled``. Gate only the login call and the venue
        pays for sends that can never succeed: a request for a channel the
        venue disabled, or made while the venue is closed, still delivers a
        real code that the later login step is guaranteed to refuse. That is
        the identical "gate the spend, not just the outcome" argument
        ``check_portal_admission`` makes for whitelist-only mode, and this
        method is its sibling for the per-channel/Open-Hours gates.

        It is a thin, public seam over the *same* ``_require_method_enabled``
        the login paths call -- no logic is reimplemented here, so the two
        call sites cannot drift. The raises are identical to login's:
        ``CaptivePortalConfigNotConfiguredError`` (404) when no config
        resolves for the location/organization, ``GuestAuthMethodNotEnabledError``
        (403) when the channel's flag is off, ``VenueClosedError`` (403)
        when ``business_hours_enabled`` is on and the venue is closed right
        now (failing open on disabled hours/bad timezone exactly as login
        does).

        ## No venue named means no gate

        Returns immediately when the caller supplied neither an organization
        nor a location -- with no property resolved there are no per-venue
        flags to read, the same no-op ``check_portal_admission`` already
        performs for the venue-less (non-portal) callers of
        ``POST /otp/request``.
        """
        if organization_id is None and location_id is None:
            return
        await self._require_method_enabled(
            organization_id=organization_id,
            location_id=location_id,
            auth_method=auth_method,
        )

    # ========================================================================
    # Internal helpers
    # ========================================================================

    async def _require_method_enabled(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        auth_method: GuestAuthMethod,
    ) -> ResolvedPortalConfig:
        resolved = await self.captive_portal_service.resolve_portal_config(
            organization_id=organization_id, location_id=location_id
        )
        config = resolved.config
        enabled_map = {
            GuestAuthMethod.OTP_SMS: config.otp_sms_enabled,
            GuestAuthMethod.OTP_EMAIL: config.otp_email_enabled,
            GuestAuthMethod.OTP_WHATSAPP: config.otp_whatsapp_enabled,
            GuestAuthMethod.VOUCHER: config.voucher_enabled,
            GuestAuthMethod.USERNAME_PASSWORD: config.username_password_enabled,
            GuestAuthMethod.PIN: config.pin_login_enabled,
        }
        if not enabled_map[auth_method]:
            raise GuestAuthMethodNotEnabledError(auth_method.value)

        self._require_venue_open(config)

        return resolved

    def _require_venue_open(self, config) -> None:
        """Open Hours, enforced rather than merely reported. Raises
        ``VenueClosedError`` when this location's own configured business
        hours say it is closed right now.

        Deliberately its own helper rather than inline in
        ``_require_method_enabled``. Open Hours arrived bolted onto that
        method because it was "the one chokepoint every authenticated login
        method passes through" -- but it is not: ``login_via_mac_whitelist``
        skips ``_require_method_enabled`` on purpose (a whitelist entry's
        mere existence is its own per-device enable signal -- see that
        method's own docstring).

        Open Hours does *not* share that exemption: whether a venue is open
        is a property of the venue, not of how a guest proves who they are,
        and ``login_via_mac_whitelist`` calls this helper explicitly
        (``RadiusService.authorize`` falls through to it to originate a
        session at RADIUS authorize time, so a whitelisted device connecting
        to a closed venue gets refused, the same as any other login method).

        ``is_open_now`` is deliberately forgiving: business hours disabled
        means always open, and a malformed stored timezone degrades to "open"
        rather than raising (see its own docstring). So the failure direction
        here is always "let the guest online", never "lock a venue out of its
        own WiFi because a row is bad"."""
        if not is_open_now(
            enabled=config.business_hours_enabled,
            timezone=config.business_hours_timezone,
            schedule=config.business_hours_schedule,
        ):
            raise VenueClosedError(config.business_hours_closed_message)

    async def _get_eligible_router(self, router_id: uuid.UUID) -> Router:
        router = await self.router_lookup.get_router(router_id)
        ineligible = {RouterStatus.DECOMMISSIONED.value, RouterStatus.SUSPENDED.value}
        if router.status in ineligible:
            raise RouterNotEligibleForGuestSessionError(router.id, router.status)
        return router

    def _reject_if_blocked(self, guest: Guest | None) -> None:
        """The admin's ``blocked_reason`` is logged here and nowhere else on
        this path -- it is not in the error's message or its ``data``, both of
        which reach the guest's own screen. An operator asking "why was this
        person turned away" reads it from here or from the guest row; the
        person it is about does not read it at all."""
        if guest is not None and guest.is_blocked:
            if guest.blocked_reason:
                logger.info(
                    "guest_blocked_login_refused",
                    extra={
                        "guest_id": str(guest.id),
                        "reason": guest.blocked_reason,
                    },
                )
            raise GuestBlockedError(guest.blocked_reason)

    async def _enforce_access_control(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        identifier: str,
        device_mac: str | None,
        auth_method: GuestAuthMethod,
        guest: Guest | None = None,
        ip_address: str | None = None,
        whitelist_only_enabled: bool = False,
        whitelist_only_denied_message: str | None = None,
        device_mac_already_authorized: bool = False,
    ) -> None:
        """Guest Access Control (Phase 1): a no-op when no
        ``access_control_hook`` was wired (the default -- see
        ``GuestService``'s own docstring). When wired, calls
        ``AccessDecisionResolver`` (via ``GuestAccessService.check_access``)
        and raises ``GuestAccessDeniedError`` on a resolved ``BLOCKLIST``
        decision.

        ## Whitelist-only mode

        ``whitelist_only_enabled`` is this property's own
        ``captive_portal_configs.whitelist_only_enabled``, read by the
        caller off the config ``_require_method_enabled`` already resolved
        on its way here. **It is threaded, not looked up**: no new query
        runs on the login path, so this feature adds no new way for a login
        to fail. (That is also why it lives on the captive-portal config
        rather than in the Phase 2 policy domain, which would have meant a
        second resolution -- and a second timeout -- in the middle of a
        guest signing in.)

        With it on, a guest who matched no rule gets ``_DEFAULT_DENY``
        instead of ``_DEFAULT_ALLOW`` and is refused with
        ``WhitelistOnlyAccessDeniedError``, carrying the property's own
        ``whitelist_only_denied_message``. Deliberately a different
        exception from ``GuestAccessDeniedError``: see that exception's
        docstring -- "an operator wrote a rule about you" and "an operator
        wrote a rule about everyone else" are different facts, and the
        portal has to be able to say different things.

        ## Trusted devices are reconciled, not duplicated

        A trusted device's authorisation lives in
        ``mac_authorization_entries``, a table ``check_access`` does not
        query at all -- it resolves ``guest_access_rules``/
        ``device_access_rules``. So switching a property to whitelist-only
        would otherwise refuse every device an operator had already
        trusted, on a list they can see in the dashboard, and the fix would
        be "type all of them into a second list as well". That is the
        silent-divergence shape this area is full of, so on a whitelist-only
        denial with a MAC present this consults
        ``mac_authorization_hook.is_mac_authorized`` before refusing.

        The consultation is scoped by ``organization_id`` **and**
        ``location_id`` -- a trust entry that names a location applies only
        there, exactly as ``login_via_mac_whitelist`` already passes it.
        It runs only on the denial path, so an ordinary property pays
        nothing for it. ``device_mac_already_authorized`` lets
        ``login_via_mac_whitelist`` skip the second lookup: that method has
        just performed the identical check and would otherwise ask the same
        question twice in one request.

        ## Failure direction: fail open, and say so

        If the rule lookup itself raises -- the connection pool is
        exhausted, the replica is briefly gone -- and this property is in
        whitelist-only mode, the guest is **allowed** and a WARNING is
        logged.

        This is uncomfortable and it is deliberate. The tension is real:
        the entire purpose of the feature is to refuse people, and here it
        admits someone it was told to refuse. But consider what failing
        closed actually does at a whitelist-only property: *nobody* gets
        online, including the guests who are on the list, including the
        owner, including whoever is trying to diagnose it -- a database
        hiccup becomes a total WiFi outage that looks, from the venue's
        side, exactly like the feature working. Failing open degrades to
        the behaviour every property on this platform had last week, which
        is a known, survivable state, and it leaves a log line saying
        precisely when it happened.

        The scope of that swallow is deliberately narrow: it applies
        **only** when ``whitelist_only_enabled`` is on. At every property
        that never opted in, a raising lookup propagates exactly as it
        always has -- a feature nobody switched on must not change how
        their errors behave.

        ## Every refusal is recorded

        A whitelist-only refusal writes a ``GuestLoginHistory`` row through
        the existing ``_record_login_failure`` path, with its own
        ``failure_reason``. Without it a venue has no way to discover their
        list is wrong -- and given that every rule written before PR #160
        was a bare national number with no country code, "who did we turn
        away?" is the first thing anyone will ask after switching this on.
        A BLOCKLIST denial is deliberately left as it was (no history row):
        changing that is a behaviour change for properties that never
        enabled this feature, and belongs to its own PR.

        Placement: called from ``login_via_otp``/``login_via_voucher``
        immediately after ``_reject_if_blocked`` and before
        ``_enforce_concurrent_session_limit``/OTP verification/voucher
        redemption -- a guest denied by an access-control rule should never
        reach a real OTP attempt or spend a voucher, the identical
        "reject before touching anything with a side effect" ordering
        ``_reject_if_blocked``/``_enforce_concurrent_session_limit`` already
        establish. ``organization_id`` is passed as both ``organization_id``
        and ``requesting_organization_id`` to ``check_access`` -- this is an
        internal, trusted call on behalf of the already-resolved captive
        portal's own organization, not a cross-tenant admin request, so
        there is no separate "requesting" identity to distinguish.

        **The unwired case is fail-open, and says so out loud.** Returning
        on a missing hook lets every guest online with no access-control
        decision made at all. That was defensible while the only rule
        types were VIP/TEMPORARY/BLOCKLIST -- an unwired hook meant
        blocklists silently did nothing, bad but visible to an operator
        who tried one. It stops being defensible under per-property
        whitelist-only mode, where the *entire* enforcement is "refuse
        whoever does not match": an unwired hook there is a venue that
        believes it is running closed and is in fact running wide open,
        with nothing on any screen to say so.

        The hook is wired by ``dependencies.get_guest_service`` for every
        real request, so this branch means a mis-composed service graph,
        not a configuration choice -- exactly the class of defect commit
        ``a0f1522`` records (see
        ``tests/unit/test_guest_login_composition.py``). It is logged at
        WARNING rather than raised because ``GuestService`` is legitimately
        constructed without the hook by Celery tasks and by this domain's
        own test suite, and turning those into hard failures would be a
        behaviour change this dark PR has no business making. The log line
        is the loud part; the composition test is the part that fails
        first."""
        if self.access_control_hook is None:
            logger.warning(
                "guest_access_control_hook_not_wired",
                extra={
                    "organization_id": str(organization_id),
                    "location_id": str(location_id),
                    "detail": (
                        "GuestService was composed without an "
                        "access_control_hook -- this login was allowed "
                        "with no access-control decision made at all "
                        "(fail-open). Every real request path wires it "
                        "via dependencies.get_guest_service."
                    ),
                },
            )
            return
        try:
            decision: AccessDecision = await self.access_control_hook.check_access(
                organization_id=organization_id,
                requesting_organization_id=organization_id,
                location_id=location_id,
                identifier=identifier,
                mac_address=device_mac,
                whitelist_only_enabled=whitelist_only_enabled,
            )
        except Exception as exc:
            # Fail open, loudly -- and only where this feature is on. See
            # this method's docstring for the argument; the short form is
            # that a whitelist-only property failing closed is a total WiFi
            # outage for a venue that cannot tell it from the feature
            # working, while failing open is last week's behaviour plus a
            # log line. A property that never opted in keeps propagating
            # exactly as it always has.
            if not whitelist_only_enabled:
                raise
            if isinstance(exc, GuestAccessDeniedError | WhitelistOnlyAccessDeniedError):
                # A real refusal that happened to travel as an exception --
                # never something to swallow.
                raise
            event = WhitelistOnlyGateFailedOpen(
                organization_id=organization_id,
                location_id=location_id,
                identifier=identifier,
                auth_method=auth_method.value,
                detail=repr(exc),
            )
            logger.warning("whitelist_only_gate_failed_open", extra=_event_extra(event))
            return
        if decision.allowed:
            return
        if not decision.is_whitelist_only_denial:
            # Same discipline as `_reject_if_blocked`: the matched rule's
            # `reason` is an operator's private note, so it is logged rather
            # than returned. The error carries neither it nor a `data` copy
            # of it, because the app-wide handler serialises `data` into the
            # response body the guest's browser reads.
            if decision.reason:
                logger.info(
                    "guest_access_rule_login_refused",
                    extra={
                        "organization_id": str(organization_id),
                        "location_id": str(location_id),
                        "identifier": identifier,
                        "reason": decision.reason,
                    },
                )
            raise GuestAccessDeniedError(decision.reason)

        # Whitelist-only, nothing matched. Before refusing, reconcile with
        # Trusted Devices -- see this method's docstring for why operators
        # must not have to keep the same device in two tables.
        trusted_device_consulted = False
        if device_mac is not None:
            if device_mac_already_authorized:
                return
            if self.mac_authorization_hook is not None:
                try:
                    # Normalized here rather than handed over raw. A guest
                    # arrives with whatever spelling their NAS reported
                    # ("aa-bb-cc-..."), the Trusted Devices table stores one
                    # canonical form, and a case-sensitive miss here would
                    # refuse a device the operator can see on their own
                    # trusted list. The real service normalizes internally
                    # too; doing it explicitly means the two cannot quietly
                    # disagree about which spellings match.
                    normalized = normalize_whitelist_mac_address(device_mac)
                except MacAuthorizationError:
                    # Not MAC-shaped at all -- nothing to reconcile
                    # against, and never a reason to admit someone.
                    normalized = None
                if normalized is not None:
                    trusted_device_consulted = True
                    if await self.mac_authorization_hook.is_mac_authorized(
                        normalized,
                        organization_id=organization_id,
                        location_id=location_id,
                    ):
                        return

        event = WhitelistOnlyLoginRefused(
            organization_id=organization_id,
            location_id=location_id,
            identifier=identifier,
            auth_method=auth_method.value,
            mac_address=device_mac,
            trusted_device_consulted=trusted_device_consulted,
        )
        logger.info("whitelist_only_login_refused", extra=_event_extra(event))
        await self._record_login_failure(
            guest=guest,
            identifier=identifier,
            auth_method=auth_method,
            organization_id=organization_id,
            location_id=location_id,
            reason=WHITELIST_ONLY_LOGIN_FAILURE_REASON,
            ip_address=ip_address,
        )
        raise WhitelistOnlyAccessDeniedError(whitelist_only_denied_message)

    async def _enforce_concurrent_session_limit(
        self,
        guest_id: uuid.UUID,
        *,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
    ) -> None:
        """Guest Session Engine (Phase 1): raises
        ``ConcurrentSessionLimitExceededError`` if ``guest_id`` already holds
        this location's resolved maximum (or more) ``ACTIVE`` sessions.
        Called from every login method after the guest identity is resolved
        but before a new ``GuestSession`` row is created -- mirrors
        ``_reject_if_blocked``'s placement (reject before any further
        side effect). Deliberately **not** called from ``reconnect``: that
        method is already idempotent against the guest's own existing
        ``ACTIVE`` session (see its docstring) and only ever derives a new
        row when the guest currently holds zero active sessions, so it can
        never itself push a guest over the limit.

        The limit comes from ``PolicyType.SESSION``'s own
        ``max_concurrent_sessions_per_guest``, resolved for this exact
        ``organization_id``/``location_id`` via
        ``_resolve_session_policy_rules`` -- the same lookup, same policy
        type, and same resolved ``rules`` dict
        ``_resolve_session_timeout_minutes`` already reads
        ``session_timeout_minutes`` out of. Until now only the timeout half
        was wired: a venue could publish a SESSION policy raising the
        concurrent-session allowance, see it resolve, and still have every
        login counted against the platform-wide
        ``constants.DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST`` (20),
        because this method never asked. That constant remains the fallback,
        so a venue with no SESSION policy assigned behaves exactly as before.

        ``organization_id``/``location_id`` default to ``None`` so a caller
        with neither (and any test constructed before this was resolvable)
        still gets the platform default rather than a signature error."""
        active_count = await self.repository.count_active_sessions_for_guest(guest_id)
        rules = await self._resolve_session_policy_rules(
            organization_id=organization_id,
            location_id=location_id,
            guest_id=guest_id,
        )
        limit = rules.get(
            "max_concurrent_sessions_per_guest",
            DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST,
        )
        if is_concurrent_session_limit_reached(
            active_count=active_count,
            limit=limit,
        ):
            raise ConcurrentSessionLimitExceededError(guest_id=guest_id, limit=limit)

    async def _resolve_device_limit(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        guest_id: uuid.UUID | None = None,
    ) -> int:
        """Resolves the real per-guest device limit via
        ``PolicyType.DEVICE`` when a ``policy_lookup`` hook is wired,
        falling back to ``constants.DEFAULT_MAX_DEVICES_PER_GUEST``
        otherwise (or if the resolved rules omit the field, e.g. a
        ``GenericPolicyRules``-shaped override). ``guest_id``, when given,
        additionally surfaces a Group Policies "Map users" override for
        this exact guest ahead of the location/organization default.

        A failing policy lookup falls back rather than propagating, for the
        reason ``_resolve_session_timeout_minutes`` states at length: this
        resolver sits on the login path (``_enforce_device_limit``, called
        by every login method), so the failure mode has to be "the default
        device limit" and not "no WiFi". ``resolve_effective_policy`` is a
        real database round trip that also validates the location against
        the resolving organization, so it has more than one way to raise;
        before this, any of them turned into a 500 on a guest login."""
        if self.policy_lookup is None:
            return DEFAULT_MAX_DEVICES_PER_GUEST
        try:
            resolved = await self.policy_lookup.resolve_effective_policy(
                policy_type=PolicyType.DEVICE,
                organization_id=organization_id,
                location_id=location_id,
                guest_id=guest_id,
            )
        except Exception:
            logger.warning(
                "device_policy_lookup_failed_using_default",
                extra={
                    "organization_id": str(organization_id),
                    "location_id": str(location_id),
                    "default_limit": DEFAULT_MAX_DEVICES_PER_GUEST,
                },
                exc_info=True,
            )
            return DEFAULT_MAX_DEVICES_PER_GUEST
        return resolved.rules.get(
            "max_devices_per_guest", DEFAULT_MAX_DEVICES_PER_GUEST
        )

    async def _resolve_session_timeout_minutes(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        guest_id: uuid.UUID | None = None,
    ) -> int:
        """Resolves how long this location's sessions last, via
        ``PolicyType.SESSION``.

        Mirrors ``_resolve_device_limit`` exactly, including its
        ``policy_lookup is None`` and missing-field fallbacks.

        Until now every non-voucher login -- OTP, password, PIN and
        MAC-whitelist -- passed the platform-wide
        ``constants.DEFAULT_SESSION_TIMEOUT_MINUTES`` (240) regardless of
        location, even though ``PolicyType.SESSION``, a typed
        ``SessionPolicyRules`` carrying ``session_timeout_minutes``, and
        LOCATION-scoped ``PolicyAssignment`` had all shipped. The type was
        simply never passed to ``resolve_effective_policy`` anywhere in the
        application, so a cafe and a hotel got the identical four hours. The
        homepage FAQ sells exactly that distinction ("a cafe usually wants a
        session that ends about when the coffee does. A hotel doesn't").

        240 remains the fallback, so a venue with no SESSION policy assigned
        -- which is every venue today -- behaves exactly as before.

        A failing policy lookup falls back rather than propagating, matching
        the contract ``record_usage``'s own FUP tracking already keeps (see
        ``test_never_raises_when_the_policy_lookup_itself_fails``): the policy
        service being unreachable must never be the reason a guest cannot get
        online. This resolver sits on the login path, so the failure mode has
        to be "the default session length" and not "no WiFi".
        """
        rules = await self._resolve_session_policy_rules(
            organization_id=organization_id,
            location_id=location_id,
            guest_id=guest_id,
        )
        return rules.get("session_timeout_minutes", DEFAULT_SESSION_TIMEOUT_MINUTES)

    async def _resolve_idle_timeout_minutes(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        guest_id: uuid.UUID | None = None,
    ) -> int:
        """Resolves how long a guest's device at this location may pass zero
        bytes before the NAS closes the session, via the same
        ``PolicyType.SESSION`` policy ``_resolve_session_timeout_minutes``
        above reads -- one policy lookup, memoized, serves both.

        The two are genuinely different settings and this is not a
        duplicate: ``session_timeout_minutes`` is absolute elapsed time from
        the session's start and ends a guest who is actively browsing;
        ``idle_timeout_minutes`` is time spent passing no traffic and never
        ends a guest who is using the WiFi. A venue can, and typically does,
        want both.

        Unlike the session timeout, this value was never merely defaulted --
        it was never sent at all. Every Access-Accept this platform has ever
        issued carried no ``Idle-Timeout``, so what actually governed a
        guest was whatever RouterOS's ``default`` hotspot user profile
        happened to say, which on a router provisioned by Master console is
        30 minutes and on one provisioned before that constant existed is
        ``none`` (i.e. never). The venue's own setting reached the device by
        no path whatsoever.

        ``DEFAULT_IDLE_TIMEOUT_MINUTES`` (30) is the fallback and is the
        same number the setup script writes onto the device, so a venue with
        no SESSION policy assigned sees no behaviour change -- the reply now
        merely states what its router was already doing. What changes is
        that the statement is now made by this platform, per session, so it
        no longer depends on the router's provisioning history.

        Falls back rather than propagating on a lookup failure, for the
        identical reason ``_resolve_session_timeout_minutes`` does: this sits
        on the login path, and the failure mode has to be "the default idle
        timeout", never "no WiFi".
        """
        rules = await self._resolve_session_policy_rules(
            organization_id=organization_id,
            location_id=location_id,
            guest_id=guest_id,
        )
        return rules.get("idle_timeout_minutes", DEFAULT_IDLE_TIMEOUT_MINUTES)

    async def _resolve_session_policy_rules(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        guest_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        """One ``PolicyType.SESSION`` lookup, shared by every field that
        policy type carries, so each new field does not re-copy the
        ``policy_lookup is None`` and never-raise fallbacks (and so a
        future one cannot quietly omit them -- which is exactly how
        ``max_concurrent_sessions_per_guest`` came to be read from a
        platform constant while ``session_timeout_minutes``, its neighbour
        in the same resolved ``rules`` dict, was read from the policy).

        Returns ``{}`` -- never raises, never ``None`` -- when no policy
        engine is wired or the lookup itself fails, leaving every caller
        to apply its own platform-constant default. See
        ``_resolve_session_timeout_minutes`` for why "the default" and
        never "no WiFi" is the only acceptable failure mode on a path
        every guest login runs through.

        Memoized for the life of this ``GuestService`` instance, which
        ``dependencies.get_guest_service`` builds per request. A single login
        reads this policy at two different moments -- the concurrent-session
        check before OTP verification, and the session length after it -- and
        ``resolve_effective_policy`` is several queries (location validation,
        candidate assignments, policy, version). Without the memo, wiring the
        second reader doubled that cost on the hottest path in the product,
        for a value that cannot meaningfully change mid-login. A failed lookup
        is deliberately *not* cached: it returns ``{}`` without storing it, so
        a transient policy-service blip degrades one call rather than pinning
        the whole login to defaults."""
        if self.policy_lookup is None:
            return {}
        cache_key = (organization_id, location_id, guest_id)
        cached = self._session_policy_cache.get(cache_key)
        if cached is not None:
            return cached
        try:
            resolved = await self.policy_lookup.resolve_effective_policy(
                policy_type=PolicyType.SESSION,
                organization_id=organization_id,
                location_id=location_id,
                guest_id=guest_id,
            )
        except Exception:
            logger.warning(
                "session_policy_lookup_failed_using_default",
                extra={
                    "organization_id": str(organization_id),
                    "location_id": str(location_id),
                },
                exc_info=True,
            )
            return {}
        # Drop null-valued keys so a caller's own ``.get(key, DEFAULT)`` is
        # correct for both an omitted field and an explicit ``null``.
        # ``SessionPolicyRules``' fields are all optional, and
        # ``PolicyService`` persists ``model_dump()`` -- so a policy that sets
        # only a session timeout is stored with the other three keys *present
        # and null*. Without this, ``.get`` would find those keys, return
        # ``None`` instead of the platform constant, and hand ``None`` to
        # arithmetic on the login path.
        rules = {k: v for k, v in resolved.rules.items() if v is not None}
        self._session_policy_cache[cache_key] = rules
        return rules

    async def _enforce_device_limit(
        self,
        *,
        guest_id: uuid.UUID,
        mac_address: str | None,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> GuestDevice | None:
        """Guest Session Engine (Phase 1): raises
        ``GuestDeviceLimitExceededError`` if this connection would put
        more of ``guest_id``'s devices **online at the same time** than
        the guest's own resolved device limit allows. The basis is
        currently-CONNECTED devices (distinct devices holding ``ACTIVE``
        sessions), **not** registered devices: a guest may have registered
        more devices than the limit over time (each was once connected),
        and a registered-but-idle device does not occupy the limit -- only
        devices with an ``ACTIVE`` session right now do. A no-op when
        ``mac_address`` is absent (no device to register at all).

        The device currently logging in is excluded from the count when it
        already belongs to this guest: if it is already online, this is a
        reconnect/refresh of one of the connected devices (its ``ACTIVE``
        session is reused, not added); if it is idle, excluding it is a
        no-op. A *new* device is therefore blocked exactly when ``limit``
        OTHER devices are already connected -- the cap this check exists to
        enforce. Mirrors ``get_or_create_device``'s own "reassignment"
        logic, checked here without mutating anything. Called from
        ``login_via_otp``/``login_via_voucher`` after
        ``_enforce_concurrent_session_limit``, before
        ``_maybe_get_or_create_device`` ever creates or reassigns a row --
        the identical "reject before touching anything with a side effect"
        ordering that method's own docstring establishes.

        Returns the real ``GuestDevice`` row this check already fetched by
        ``mac_address`` (``None`` when ``mac_address`` is absent) -- every
        caller passes this straight back into
        ``_maybe_get_or_create_device``'s/``get_or_create_device``'s own
        ``known_device`` moments later for the identical MAC, with no
        write to ``guest_devices`` happening in between, so that method
        doesn't re-run the exact same query a second time. See
        ``_DEVICE_NOT_PREFETCHED``'s own module-level docstring."""
        if not mac_address:
            return None
        existing_device = await self.repository.get_device_by_mac(
            normalize_mac_address(mac_address)
        )
        # Only this guest's OWN device id is excluded from the connected
        # count -- an existing own device that is online right now is being
        # reconnected (session reuse), never added as a new connection. A
        # device registered to another guest is not this guest's, so it
        # cannot be the device this login is about (it will be reassigned
        # by get_or_create_device) and excludes nothing.
        exclude_device_id = (
            existing_device.id
            if existing_device is not None and existing_device.guest_id == guest_id
            else None
        )
        connected_devices = await self.repository.count_active_devices_for_guest(
            guest_id=guest_id, exclude_device_id=exclude_device_id
        )
        limit = await self._resolve_device_limit(
            organization_id=organization_id, location_id=location_id, guest_id=guest_id
        )
        if is_device_limit_reached(device_count=connected_devices, limit=limit):
            raise GuestDeviceLimitExceededError(guest_id=guest_id, limit=limit)
        return existing_device

    async def _enforce_fup_quota(
        self,
        *,
        guest_id: uuid.UUID,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None = None,
    ) -> None:
        """Guest Session Engine (Phase 1): raises
        ``FairUsagePolicyExceededError`` if ``guest_id`` already meets or
        exceeds a ``PolicyType.FUP`` daily/weekly/monthly data or time cap
        resolved for ``organization_id``/``location_id``. Unlike
        ``_enforce_device_limit``/``_enforce_concurrent_session_limit``,
        there is no platform-wide fallback: a no-op entirely when no
        ``policy_lookup`` hook is wired, and (once resolved) a no-op for
        any period with no configured limit at all -- see
        ``exceptions.FairUsagePolicyExceededError``'s own docstring for why
        ``app.domains.policy`` seeds no default here. Called from
        ``login_via_otp``/``login_via_voucher`` alongside
        ``_enforce_device_limit``, the identical "reject before touching
        OTP/voucher verification" placement.

        Also enforces the *team* shared data limit, which is a different cap
        with the same shape: FUP bounds one guest, a guest team bounds a whole
        group against one pooled allowance. It is checked here rather than in
        its own call site so that every login path picks it up from the one
        place they all already go through, and so it is checked before OTP or
        voucher verification like every other rejection on this path.

        ``location_id`` is passed straight into the resolution. It used to be
        hardcoded ``None`` here, and ``repository.list_candidate_assignments``
        only adds its LOCATION-scope predicate when a real ``location_id``
        arrives -- so a ``PolicyAssignment`` with ``scope_type=location`` on an
        FUP policy was never a resolution candidate. A venue could create one,
        see it listed and active, and have it enforce nothing, with no error
        anywhere. Every sibling resolver on this path (``_resolve_device_limit``,
        ``_resolve_session_policy_rules``, and ``queue_management``'s own
        BANDWIDTH resolution) already passed the real location; FUP was the
        one that did not. Organization- and GLOBAL-scoped assignments resolved
        correctly throughout and are unaffected -- a location-scoped one simply
        now outranks them, which is the whole point of the scope.
        """
        if (
            self.team_quota_hook is not None
            and await self.team_quota_hook.is_over_shared_quota(guest_id)
        ):
            raise GuestTeamSharedQuotaExceededError()
        if self.policy_lookup is None:
            return
        resolved = await self.policy_lookup.resolve_effective_policy(
            policy_type=PolicyType.FUP,
            organization_id=organization_id,
            location_id=location_id,
            guest_id=guest_id,
        )
        rules = resolved.rules
        data_limits = {
            QuotaPeriodType.DAILY: rules.get("daily_data_limit_mb"),
            QuotaPeriodType.WEEKLY: rules.get("weekly_data_limit_mb"),
            QuotaPeriodType.MONTHLY: rules.get("monthly_data_limit_mb"),
        }
        time_limits = {
            period_type: rules.get(rule_key)
            for period_type, rule_key in FUP_TIME_LIMIT_RULE_KEYS.items()
        }
        if not any(data_limits.values()) and not any(time_limits.values()):
            return
        tz_name = await self.repository.get_organization_timezone(organization_id)
        now = datetime.now(UTC)
        # Design spec §5 S9: one IN (...) read for every period that
        # actually has a cap configured, instead of one SELECT per
        # period. Periods with no cap at all are not fetched -- the loop
        # below skipped them anyway, and materializing a row for a period
        # nothing limits would be a write this path never needed.
        capped_periods = [
            period_type
            for period_type in QuotaPeriodType
            if data_limits[period_type] is not None
            or time_limits[period_type] is not None
        ]
        usages = await get_or_reset_quota_usages(
            self.repository,
            guest_id=guest_id,
            organization_id=organization_id,
            period_types=capped_periods,
            tz_name=tz_name,
            now=now,
        )
        for period_type in capped_periods:
            limit_mb = data_limits[period_type]
            limit_minutes = time_limits[period_type]
            usage = usages[period_type]
            if limit_mb is not None and is_fup_usage_exceeded(
                used=usage.bytes_used, limit=limit_mb * BYTES_PER_MB
            ):
                raise FairUsagePolicyExceededError(
                    guest_id=guest_id,
                    period_type=period_type.value,
                    metric="data",
                    limit=limit_mb,
                    used=usage.bytes_used // BYTES_PER_MB,
                )
            if limit_minutes is not None and is_fup_usage_exceeded(
                used=usage.minutes_used, limit=limit_minutes
            ):
                raise FairUsagePolicyExceededError(
                    guest_id=guest_id,
                    period_type=period_type.value,
                    metric="time",
                    limit=limit_minutes,
                    used=usage.minutes_used,
                )

    async def _track_fup_data_usage(
        self,
        *,
        guest_id: uuid.UUID,
        organization_id: uuid.UUID,
        delta_bytes: int,
        now: datetime,
    ) -> str | None:
        """Best-effort, additive: bumps every ``GuestQuotaUsage`` period
        row's ``bytes_used`` by ``delta_bytes`` -- called from
        ``record_usage`` on every RADIUS Interim-Update, riding along for
        free on a call that already happens (unlike guest-level *time*
        usage, which needs its own dedicated sweep -- see
        ``tasks.run_fup_time_accrual_sweep``). A no-op when no
        ``policy_lookup`` hook is wired at all (mirrors
        ``_enforce_fup_quota``'s identical posture) or when
        ``delta_bytes`` is not positive. Never raises -- a RADIUS
        accounting call must never fail because the Policy Engine (or this
        tracking step itself) is unreachable; the real, never-swallowed
        enforcement checkpoint is ``_enforce_fup_quota`` at the *next*
        login, and the immediate mid-session cutoff below is a best-effort
        addition on top of that, not a replacement for it. Returns the
        ``period_type`` value of a data cap this bump just pushed the
        guest's usage to meet or exceed (letting ``record_usage`` decide
        whether to expire the session), or ``None``."""
        if self.policy_lookup is None or delta_bytes <= 0:
            return None
        try:
            tz_name = await self.repository.get_organization_timezone(organization_id)
            resolved = await self.policy_lookup.resolve_effective_policy(
                policy_type=PolicyType.FUP,
                organization_id=organization_id,
                location_id=None,
                guest_id=guest_id,
            )
            data_limits = {
                QuotaPeriodType.DAILY: resolved.rules.get("daily_data_limit_mb"),
                QuotaPeriodType.WEEKLY: resolved.rules.get("weekly_data_limit_mb"),
                QuotaPeriodType.MONTHLY: resolved.rules.get("monthly_data_limit_mb"),
            }
            violated_period: str | None = None
            # Same S9 batching as _enforce_fup_quota. This path runs on
            # every RADIUS Interim-Update, so it is the higher-volume of
            # the two even though it is not the latency-sensitive one.
            usages = await get_or_reset_quota_usages(
                self.repository,
                guest_id=guest_id,
                organization_id=organization_id,
                period_types=list(data_limits),
                tz_name=tz_name,
                now=now,
            )
            for period_type, limit_mb in data_limits.items():
                usage = usages[period_type]
                usage = await self.repository.update_quota_usage(
                    usage, {"bytes_used": usage.bytes_used + delta_bytes}
                )
                if (
                    violated_period is None
                    and limit_mb is not None
                    and is_fup_usage_exceeded(
                        used=usage.bytes_used, limit=limit_mb * BYTES_PER_MB
                    )
                ):
                    violated_period = period_type.value
            return violated_period
        except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
            logger.warning(
                "guest_fup_data_usage_tracking_failed",
                extra={"guest_id": str(guest_id), "error": str(exc)},
            )
            return None

    async def _get_or_create_guest(
        self,
        existing: Guest | None,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        identifier: str,
    ) -> tuple[Guest, bool]:
        if existing is not None:
            return existing, False
        now = datetime.now(UTC)
        guest = await self.repository.create_guest(
            organization_id=organization_id,
            location_id=location_id,
            identifier=identifier,
            display_name=None,
            first_seen_at=now,
            last_seen_at=now,
            total_visit_count=0,
            is_blocked=False,
            blocked_reason=None,
        )
        return guest, True

    async def _maybe_get_or_create_device(
        self,
        *,
        guest_id: uuid.UUID,
        mac_address: str | None,
        device_name: str | None,
        known_device: GuestDevice | None = _DEVICE_NOT_PREFETCHED,
    ) -> GuestDevice | None:
        if not mac_address:
            return None
        return await self.get_or_create_device(
            guest_id=guest_id,
            mac_address=mac_address,
            device_name=device_name,
            known_device=known_device,
        )

    async def _create_session(
        self,
        *,
        guest: Guest,
        device: GuestDevice | None,
        router: Router,
        location_id: uuid.UUID,
        auth_method: GuestAuthMethod,
        voucher_id: uuid.UUID | None,
        ip_address: str | None,
        data_limit_mb: int | None,
        session_timeout_minutes: int | None,
        idle_timeout_minutes: int | None = None,
        user_agent: str | None = None,
        accept_language: str | None = None,
    ) -> GuestSession:
        now = datetime.now(UTC)
        session = await self.repository.create_session(
            guest_id=guest.id,
            device_id=device.id if device else None,
            router_id=router.id,
            location_id=location_id,
            organization_id=guest.organization_id,
            auth_method=auth_method.value,
            voucher_id=voucher_id,
            status=GuestSessionStatus.ACTIVE.value,
            started_at=now,
            ended_at=None,
            last_activity_at=now,
            ip_address=ip_address,
            user_agent=user_agent,
            accept_language=accept_language,
            bytes_uploaded=0,
            bytes_downloaded=0,
            data_limit_mb=data_limit_mb,
            session_timeout_minutes=session_timeout_minutes,
            idle_timeout_minutes=idle_timeout_minutes,
            disconnect_reason=None,
        )
        event = GuestSessionCreated(
            session_id=session.id,
            guest_id=guest.id,
            router_id=router.id,
            auth_method=auth_method.value,
        )
        logger.info("guest_session_created", extra=_event_extra(event))
        return session

    async def _find_reusable_active_session(
        self,
        *,
        guest_id: uuid.UUID,
        router_id: uuid.UUID,
        device_id: uuid.UUID | None,
    ) -> GuestSession | None:
        """Whether ``guest_id`` already holds a currently-``ACTIVE`` session
        for ``device_id`` on ``router_id`` -- checked by every guest
        self-service login method (``login_via_otp``/``_voucher``/
        ``_password``/``_pin``/``_mac_whitelist``, via
        ``_reuse_or_create_session`` below) immediately before it would
        otherwise insert a new row. Mirrors the exact "an already-connected
        identity re-authenticating is a no-op, not a new row" precedent
        this module already establishes in two other places:
        ``RadiusService._find_active_session_for_identifier`` (which every
        RADIUS Authorize reauth is checked against) and
        ``GuestService.reconnect``'s own "idempotent -- already connected,
        no duplicate session" early return.

        Real production gap this closes: unlike those two call sites, none
        of the five login methods ever checked this before -- confirmed
        live against a real guest+router (18 ``GuestSession`` rows for one
        guest across ~6.5 hours, several only 7-13 minutes long). A
        duplicate/near-simultaneous login submission -- a captive-portal
        tab remounting and re-POSTing before its own client-side cooldown
        window, two open tabs, a guest double-tapping "Verify", RouterOS
        reissuing a fresh hotspot redirect while the prior one is still
        mid-flight -- always inserted a second, fully redundant ``ACTIVE``
        row for a guest who, by every measure this platform already
        tracks (``GuestSession.status``), never actually disconnected.

        **Requires a real ``device_id`` match, deliberately not just
        ``guest_id``+``router_id``.** A guest legitimately holds more than
        one concurrent device on the very same router at once (a phone
        *and* a laptop both connected right now -- exactly what
        ``DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST`` exists to bound, not
        forbid); collapsing every login for that guest+router down to
        whichever single session happened to be "latest" would wrongly
        merge two genuinely distinct devices' histories into one row, or
        silently reattach an existing session to the wrong device. No
        ``device_id`` at all (a login that never presented a MAC) always
        creates a new row, exactly as before this change -- there is no
        safe way to disambiguate concurrent devices without one.

        Deliberately narrow in one more way: only ever returns an
        already-``ACTIVE`` session, never one that has already moved to a
        terminal status (``DISCONNECTED``/``TERMINATED``/``EXPIRED``) --
        this does **not** touch this module's append-only design (see
        ``models.py``'s "Sessions are append-only" write-up). A
        genuinely-ended session, even one that ended moments ago, still
        gets a new row on the next login -- exactly as today -- because
        collapsing *that* case would mean silently resurrecting or
        backdating a closed accounting interval, which is a real
        correctness (not just a noise) problem for anything downstream
        that trusts a session's own started_at/ended_at/bytes_* as one
        true, closed connection interval (FUP accrual, Bandwidth & Cost
        reporting, voucher redemption history). That class of
        fragmentation -- many short but genuinely sequential,
        non-overlapping disconnect/reconnect cycles -- is a display
        concern, handled by the Connected Guests table grouping sessions
        with a short gap between them, not by this method."""
        if device_id is None:
            return None
        now = datetime.now(UTC)
        active_sessions = await self.repository.list_active_sessions_for_guest(guest_id)
        for candidate in active_sessions:
            if candidate.router_id == router_id and candidate.device_id == device_id:
                # An ACTIVE row that has already outlived its own
                # `session_timeout_minutes` must not be reused, and this
                # guard is what stops the rest of this change locking
                # guests out. Reuse refreshes `last_activity_at` and
                # `session_timeout_minutes` but never `started_at` -- by
                # design, since backdating a closed accounting interval is
                # the very thing this method's docstring refuses to do. So
                # a guest signing in again after their 30 minutes ran out
                # would land back on the same overrun row, be measured
                # from the same old `started_at`, and be refused by
                # Authorize again, for ever: the sign-in would appear to
                # succeed and the internet would never come back.
                #
                # A fresh sign-in after the limit is a genuinely new
                # connection interval and gets a genuinely new row, which
                # is exactly what the append-only design already says
                # should happen for a session that has ended -- this one
                # has ended in every sense a guest can observe, whatever
                # its status column still says.
                if has_session_reached_time_limit(candidate, now=now):
                    return None
                return candidate
        return None

    async def _reuse_or_create_session(
        self,
        *,
        guest: Guest,
        device: GuestDevice | None,
        router: Router,
        location_id: uuid.UUID,
        auth_method: GuestAuthMethod,
        voucher_id: uuid.UUID | None,
        ip_address: str | None,
        user_agent: str | None,
        accept_language: str | None,
        data_limit_mb: int | None,
        session_timeout_minutes: int | None,
        idle_timeout_minutes: int | None = None,
    ) -> tuple[GuestSession, bool]:
        """Shared by every guest self-service login method: returns
        ``(session, created)``, where ``created`` is ``False`` when an
        already-``ACTIVE`` session for this exact ``guest``+``router``+
        ``device`` (see ``_find_reusable_active_session``) was reused in
        place of inserting a duplicate row. A reused session's
        ``last_activity_at`` is bumped to now (the same freshness signal a
        real RADIUS Interim-Update would give it), its ``ip_address`` is
        refreshed when this login presented a different one (e.g. a new
        DHCP lease on the same physical device), and its ``auth_method``/
        ``data_limit_mb``/``session_timeout_minutes``/``voucher_id`` are
        refreshed to whatever *this* login just granted -- e.g. a guest
        who sets up Portal PIN login and later re-authenticates via PIN
        while their original OTP session is still technically active
        should see that session's own auth_method reflect the login they
        actually just did, and a guest who redeems a fresh, more generous
        voucher while an old session from an earlier OTP login is still
        active should get that voucher's real entitlement applied, not
        have it silently discarded because a row already existed. Callers
        must skip their own "new session"
        side effects (real-time broadcast, queue assignment, visit-count
        bump) when ``created`` is ``False`` -- those already ran for this
        same still-open session.

        **Why this method locks the ``Guest`` row before its reuse read.**
        The find-then-insert above has no uniqueness backstop of its own:
        two near-simultaneous logins for the same guest+router+device (a
        captive-portal tab remounting and re-POSTing before its own
        client-side cooldown window, two open tabs, a guest double-tapping
        "Verify", RouterOS reissuing a fresh hotspot redirect while the
        prior login is still mid-flight) can both run
        ``_find_reusable_active_session``, both observe "no reusable
        ACTIVE session", and both insert a second, fully redundant
        ``ACTIVE`` row -- the *concurrent* half of the production incident
        ``_find_reusable_active_session``'s own docstring documents (18
        rows for one guest across ~6.5 hours, several only 7-13 minutes
        long), which that sequential fix does not close. So this method
        acquires a real row lock on the ``Guest`` row
        (``GuestRepository.get_guest_for_update``, ``SELECT ... FOR
        UPDATE`` -- the same pattern ``IspRepository.get_link_for_update``
        established for its own read-then-write race) *before* running the
        reuse read, whenever a real ``device_id`` makes reuse possible at
        all. The loser's lock waits on the winner's open request
        transaction; by the time it proceeds the winner's ``ACTIVE`` row
        is committed and visible, the loser's reuse read finds it, and it
        takes the reuse branch above -- the exact outcome the sequential
        case already produces, with no duplicate row and no error surfaced
        to either guest. Deliberately skipped when ``device`` is ``None``:
        a login that never presented a MAC can never reuse (see
        ``_find_reusable_active_session``), so there is no race to
        serialize."""
        # Acquired before -- never after -- the reuse read. A database
        # unique index cannot express "at most one *reusable* ACTIVE
        # session" (a row ACTIVE but past its own wall-clock limit is
        # deliberately not reused, and can legitimately coexist with the
        # fresh row this method then inserts -- see
        # ``_find_reusable_active_session``), so the serialization has to
        # happen on the guest row itself. Skipped for ``device is None``:
        # nothing is ever reused there, so there is nothing to serialize.
        if device is not None:
            await self.repository.get_guest_for_update(guest.id)
        reusable = await self._find_reusable_active_session(
            guest_id=guest.id,
            router_id=router.id,
            device_id=device.id if device is not None else None,
        )
        if reusable is not None:
            update_data: dict[str, object] = {
                "last_activity_at": datetime.now(UTC),
                "data_limit_mb": data_limit_mb,
                "session_timeout_minutes": session_timeout_minutes,
                # Refreshed with the rest of this login's entitlement, for
                # the same reason session_timeout_minutes is: the reused row
                # represents the login that just happened, and the NAS is
                # about to be told this session's idle allowance on the very
                # next Access-Accept. Leaving a stale value here would send
                # the previous login's number.
                "idle_timeout_minutes": idle_timeout_minutes,
            }
            if reusable.auth_method != auth_method.value:
                update_data["auth_method"] = auth_method.value
            if ip_address is not None and reusable.ip_address != ip_address:
                update_data["ip_address"] = ip_address
            if voucher_id is not None and reusable.voucher_id != voucher_id:
                update_data["voucher_id"] = voucher_id
            reused = await self.repository.update_session(reusable, update_data)
            return reused, False
        session = await self._create_session(
            guest=guest,
            device=device,
            router=router,
            location_id=location_id,
            auth_method=auth_method,
            voucher_id=voucher_id,
            ip_address=ip_address,
            user_agent=user_agent,
            accept_language=accept_language,
            data_limit_mb=data_limit_mb,
            session_timeout_minutes=session_timeout_minutes,
            idle_timeout_minutes=idle_timeout_minutes,
        )
        return session, True

    async def _bump_guest_visit(self, guest: Guest) -> Guest:
        now = datetime.now(UTC)
        return await self.repository.update_guest(
            guest,
            {"last_seen_at": now, "total_visit_count": guest.total_visit_count + 1},
        )

    async def _record_login_success(
        self,
        *,
        guest: Guest,
        identifier: str,
        auth_method: GuestAuthMethod,
        location_id: uuid.UUID,
        ip_address: str | None,
    ) -> None:
        await self.repository.create_login_history(
            guest_id=guest.id,
            organization_id=guest.organization_id,
            location_id=location_id,
            identifier=identifier,
            auth_method=auth_method.value,
            success=True,
            failure_reason=None,
            attempted_at=datetime.now(UTC),
            ip_address=ip_address,
        )

    async def _record_login_failure(
        self,
        *,
        guest: Guest | None,
        identifier: str,
        auth_method: GuestAuthMethod,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        reason: str,
        ip_address: str | None,
    ) -> None:
        await self.repository.create_login_history(
            guest_id=guest.id if guest else None,
            organization_id=organization_id,
            location_id=location_id,
            identifier=identifier,
            auth_method=auth_method.value,
            success=False,
            failure_reason=reason,
            attempted_at=datetime.now(UTC),
            ip_address=ip_address,
        )
        event = GuestLoginFailed(
            guest_id=guest.id if guest else None,
            identifier=identifier,
            auth_method=auth_method.value,
            reason=reason,
        )
        logger.warning("guest_login_failed", extra=_event_extra(event))

    async def _require_guest(
        self,
        guest_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Guest:
        guest = await self.repository.get_guest_by_id(guest_id)
        if guest is None:
            raise GuestNotFoundError(guest_id)
        self._enforce_tenant_scope(guest.organization_id, requesting_organization_id)
        # The chokepoint for all nine guest-by-id operations. Login does not
        # come through here -- it uses `get_or_create_guest` -- so a guest
        # signing in is unaffected.
        enforce_entity_location(
            entity_location_id=getattr(guest, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationGuestAccessError(),
        )
        return guest

    def _enforce_tenant_scope(
        self,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        if (
            requesting_organization_id is not None
            and organization_id != requesting_organization_id
        ):
            raise CrossOrganizationGuestAccessError()

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID,
        description: str,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        entity_type: str = "guest",
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            event_metadata={},
            organization_id=organization_id,
            location_id=location_id,
        )


# ============================================================================
# RadiusService: FreeRADIUS ``rlm_rest``-style HTTP integration
# ============================================================================


@dataclass(frozen=True, slots=True)
class RadiusNasRegistrationResult:
    """``register_nas``'s return value -- carries the plaintext shared
    secret back to the caller exactly once (whether admin-supplied or
    server-generated), the same "show it once at issuance, never again"
    posture any real secret/API-key issuance flow needs. Never persisted or
    logged anywhere in plaintext -- only ``nas_client.shared_secret_encrypted``
    is stored."""

    nas_client: RadiusNasClient
    shared_secret: str


@dataclass(frozen=True, slots=True)
class RadiusNasSecretRegenerationResult:
    """``regenerate_secret``'s return value -- see
    ``RadiusNasRegistrationResult``'s identical one-time-plaintext
    reasoning."""

    nas_client: RadiusNasClient
    shared_secret: str


class NasSecretPushProtocol(Protocol):
    """ "Put this secret into the real FreeRADIUS server's ``client{}``
    stanza, or raise."

    A *required* collaborator of ``RadiusService.regenerate_secret`` -- the
    whole point of it existing is that there is no way to call that method
    without one. See that method's own docstring for the fault this shape
    is written against (2026-09-02: a rotate wrote the new secret to the
    database, never told the hub, reported success, and every guest login
    at the venue Access-Rejected from that moment on).

    Narrow by construction, like ``router_lookup``/``location_lookup``/
    ``queue_lookup`` above: the caller already knows the NAS identifier and
    the tunnel address to bind the stanza to, and this domain deliberately
    does not -- ``RadiusService`` has no WireGuard collaborator and should
    not grow one. All it needs to know is that somebody else's push either
    returned or raised.
    """

    async def __call__(self, secret: str) -> None: ...


class QueueRateLimitLookupProtocol(Protocol):
    """The single method ``RadiusService.authorize``'s optional
    ``queue_lookup`` hook needs from the real
    ``app.domains.queue_management.service.QueueManagementService`` --
    reused directly, never reimplemented, the identical narrow-protocol
    composition style ``router_lookup``/``location_lookup`` already use.
    ``None``-by-default (see ``RadiusService.__init__``'s own docstring):
    a deployment with no Queue Management Engine configured simply never
    gets a ``Mikrotik-Rate-Limit`` reply attribute, exactly today's
    behavior."""

    async def get_rate_limit_reply_for_session(
        self, session_id: uuid.UUID
    ) -> str | None: ...


class RadiusService:
    """FreeRADIUS ``rlm_rest`` HTTP integration -- see module docstring for
    the full architectural write-up -- extended with real NAS lifecycle
    management (list/get/update/activate/disable/regenerate-secret/delete).
    See ``docs/guest/NAS_EXTENSION.md`` for the full design write-up behind
    every method added below the original four
    (``authenticate_nas``/``register_nas``/``authorize``/accounting).
    """

    def __init__(
        self,
        repository: GuestRepositoryProtocol,
        guest_service: GuestService,
        router_lookup: RouterLookupProtocol,
        location_lookup: LocationLookupProtocol,
        nas_code_counter_repository: NasCodeCounterRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        queue_lookup: QueueRateLimitLookupProtocol | None = None,
        caller_location_scope: LocationScope = None,
    ) -> None:
        self.repository = repository
        self.guest_service = guest_service
        self.router_lookup = router_lookup
        self.location_lookup = location_lookup
        self.nas_code_counter_repository = nas_code_counter_repository
        self.audit_writer = audit_writer
        self.queue_lookup = queue_lookup
        # Constructor-injected -- see `app.domains.rbac.location_scope`.
        self.caller_location_scope = caller_location_scope

    async def authenticate_nas(
        self, *, nas_identifier: str, shared_secret: str
    ) -> RadiusNasClient:
        nas_client = await self.repository.get_nas_client_by_identifier(nas_identifier)
        if nas_client is None or NasStatus(nas_client.status) != NasStatus.ACTIVE:
            raise RadiusNasAuthenticationError()
        try:
            decrypted = decrypt_secret(nas_client.shared_secret_encrypted)
        except RouterCredentialDecryptionError as exc:
            raise RadiusNasAuthenticationError() from exc
        if not secrets.compare_digest(decrypted, shared_secret):
            raise RadiusNasAuthenticationError()
        return nas_client

    async def register_nas(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        nas_identifier: str,
        shared_secret: str | None = None,
        shared_secret_length_bytes: int = NAS_SHARED_SECRET_DEFAULT_LENGTH_BYTES,
        name: str | None = None,
        description: str | None = None,
        ip_address: str | None = None,
        initial_status: NasStatus = NasStatus.ACTIVE,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> RadiusNasRegistrationResult:
        """Registers ``router_id`` as a RADIUS NAS. ``shared_secret`` is
        optional -- if omitted, a cryptographically-random one is generated
        (see ``nas_number_generator.generate_shared_secret``); either way
        the plaintext is returned exactly once via
        ``RadiusNasRegistrationResult.shared_secret``, never persisted.
        ``initial_status`` defaults to ``ACTIVE`` (immediately usable,
        preserving this method's original behavior) rather than ``PENDING``
        -- see ``constants.NasStatus.PENDING``'s own docstring for why a NAS
        registration has no genuine provisioning gate to default-stage
        behind, unlike ``Router``'s own ``PENDING_PROVISIONING``.
        ``organization_id``/``location_id`` are denormalized from the
        resolved ``Router`` at this exact moment (see ``models
        .RadiusNasClient``'s own docstring)."""
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        existing = await self.repository.get_nas_client_by_router(router.id)
        if existing is not None:
            raise RadiusNasAlreadyRegisteredError(router.id)

        location = await self.location_lookup.get_location(
            router.location_id, requesting_organization_id=router.organization_id
        )
        nas_code = await generate_nas_code(
            self.nas_code_counter_repository,
            location_id=router.location_id,
            location_code=location.location_code,
        )
        plaintext_secret = shared_secret or generate_shared_secret(
            shared_secret_length_bytes
        )
        # ``ip_address`` is now the router's WireGuard TUNNEL address and
        # nothing else -- see ``models.RadiusNasClient.ip_address``'s own
        # comment for the full write-up.
        #
        # The removed fallback (``router.public_ip_address or
        # router.management_ip_address``) was wrong twice over: every
        # router in this fleet is behind carrier-grade NAT, so it resolved
        # to NULL on the one production row that exists, and even when it
        # resolved it named an address FreeRADIUS never keys on. It is not
        # replaced with a tunnel-address lookup here because this method
        # deliberately does not know about the WireGuard domain: the
        # caller that HAS the peer (``register_external_radius_nas``, and
        # ``hub_reconciliation`` after it) passes it in, and
        # ``record_hub_client_sync`` keeps it current from then on. A NAS
        # registered with no address is honestly address-less rather than
        # confidently wrong.
        resolved_ip_address = ip_address

        nas_client = await self.repository.create_nas_client(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            nas_code=nas_code,
            nas_identifier=nas_identifier,
            shared_secret_encrypted=encrypt_secret(plaintext_secret),
            status=initial_status.value,
            is_active=initial_status == NasStatus.ACTIVE,
            name=name,
            description=description,
            ip_address=resolved_ip_address,
            created_by=actor_user_id,
        )
        event = RadiusNasRegistered(
            nas_client_id=nas_client.id,
            router_id=router.id,
            nas_identifier=nas_identifier,
        )
        logger.info("radius_nas_registered", extra=_event_extra(event))
        await self._audit_nas(
            actor_user_id,
            AuditAction.RADIUS_NAS_REGISTERED,
            nas_client=nas_client,
            description=(
                f"RADIUS NAS client '{nas_code}' registered for router {router.id}"
            ),
            event_metadata={"nas_identifier": nas_identifier, "nas_code": nas_code},
        )
        return RadiusNasRegistrationResult(
            nas_client=nas_client, shared_secret=plaintext_secret
        )

    # ========================================================================
    # NAS lifecycle: read/list/update/activate/disable/regenerate/delete
    # ========================================================================

    async def push_nas_client_to_device(
        self,
        *,
        nas_id: uuid.UUID,
        radius_server_host: str,
        actor_user_id: uuid.UUID | None = None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> RadiusNasClient:
        """Writes this NAS registration onto the router itself.

        The other half of ``record_hub_client_sync``. That one records that
        the hub's FreeRADIUS confirmed a ``client{}`` stanza; this one
        writes the router's own ``/radius`` row and its ``/radius incoming``
        CoA listener, over the RouterOS API on 8728 -- the only port that
        reaches a fleet router. Until this existed, the gateway method that
        does the writing had no caller anywhere in this application, so the
        router half could only ever land by somebody pasting the generated
        setup script by hand at provisioning.

        ``src-address`` is the NAS row's own ``ip_address``, which
        ``record_hub_client_sync`` keeps equal to the router's tunnel
        address. It is not optional and not cosmetic: the hub matches an
        incoming request to a ``client{}`` stanza by source address, so a
        registration pushed without it is one the hub will never answer.
        A row that has never been synced has no tunnel address to send, and
        this refuses rather than writing a registration that cannot work.

        **The failure record is committed before the re-raise.**
        ``GenericRepository.update`` only ``flush()``es and
        ``get_db_session`` rolls the session back on any exception, so a
        ``failed`` row written just before the raise would be discarded --
        leaving a record that still reads as though the push had reached the
        router. The exception then propagates as a real 502; it must not
        become a ``200 {"success": false}``, which the frontend's response
        interceptor cannot distinguish from success.
        """
        nas_client = await self.repository.get_nas_client_by_id(nas_id)
        if nas_client is None or nas_client.is_deleted:
            raise RadiusNasClientNotFoundError(str(nas_id))
        if (
            requesting_organization_id is not None
            and nas_client.organization_id != requesting_organization_id
        ):
            raise RadiusNasClientNotFoundError(str(nas_id))

        tunnel_ip = nas_client.ip_address
        if not tunnel_ip:
            raise RadiusNasNotSyncedError(nas_id)

        router = await self.router_lookup.get_router(
            nas_client.router_id,
            requesting_organization_id=requesting_organization_id,
        )
        credentials = self._resolve_nas_device_credentials(router)
        adapter = get_radius_nas_adapter(router.vendor)

        try:
            await adapter.push_nas_client(
                credentials,
                config=RadiusNasDeviceConfig(
                    radius_server_host=radius_server_host,
                    radius_secret=decrypt_secret(nas_client.shared_secret_encrypted),
                    src_address=tunnel_ip,
                ),
            )
        except Exception as exc:  # noqa: BLE001 -- committed, then re-raised
            await self.repository.update_nas_client(
                nas_client,
                {
                    "device_push_status": RadiusNasDevicePushStatus.FAILED.value,
                    "device_push_error": str(exc),
                },
            )
            await self.repository.commit()
            logger.warning(
                "radius_nas_device_push_failed",
                extra={
                    "event_nas_id": str(nas_id),
                    "event_router_id": str(nas_client.router_id),
                    "event_error": str(exc),
                },
            )
            raise

        updated = await self.repository.update_nas_client(
            nas_client,
            {
                "device_push_status": RadiusNasDevicePushStatus.ACTIVE.value,
                "device_push_error": None,
                "device_pushed_at": datetime.now(UTC),
            },
        )
        await self.repository.commit()
        logger.info(
            "radius_nas_device_push_succeeded",
            extra={
                "event_nas_id": str(nas_id),
                "event_router_id": str(nas_client.router_id),
            },
        )
        return updated

    def _resolve_nas_device_credentials(self, router: Router) -> RadiusNasCredentials:
        """Raise rather than guess -- mirrors ``vlan``/``qos``."""
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise RadiusNasMissingCredentialsError(router.id)
        return RadiusNasCredentials(
            host=host, username=router.api_username, password=secret
        )

    async def get_nas_client(
        self,
        nas_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> RadiusNasClient:
        nas_client = await self.repository.get_nas_client_by_id(nas_id)
        if nas_client is None:
            raise RadiusNasNotFoundError(nas_id)
        self._enforce_nas_tenant_scope(
            nas_client.organization_id, requesting_organization_id
        )
        enforce_entity_location(
            entity_location_id=getattr(nas_client, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationGuestAccessError(),
        )
        return nas_client

    async def list_nas_clients(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        status: NasStatus | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[RadiusNasClient], object]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        if router_id is not None:
            filters["router_id"] = router_id
        if status is not None:
            filters["status"] = status.value
        return await self.repository.list_nas_clients(
            page=page, page_size=page_size, filters=filters or None
        )

    async def update_nas_client(
        self,
        *,
        nas_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
        name: str | None = None,
        description: str | None = None,
        ip_address: str | None = None,
    ) -> RadiusNasClient:
        """Cosmetic-only update -- ``name``/``description``/``ip_address``.
        Status transitions go through ``activate_nas``/``disable_nas``/
        ``delete_nas`` instead, never through this method, so every status
        change is independently validated against
        ``constants.NAS_STATUS_TRANSITIONS``."""
        nas_client = await self.get_nas_client(
            nas_id, requesting_organization_id=requesting_organization_id
        )
        data: dict[str, object] = {"updated_by": actor_user_id}
        if name is not None:
            data["name"] = name
        if description is not None:
            data["description"] = description
        if ip_address is not None:
            data["ip_address"] = ip_address
        updated = await self.repository.update_nas_client(nas_client, data)
        event = RadiusNasUpdated(nas_client_id=updated.id)
        logger.info("radius_nas_updated", extra=_event_extra(event))
        await self._audit_nas(
            actor_user_id,
            AuditAction.RADIUS_NAS_UPDATED,
            nas_client=updated,
            description=f"RADIUS NAS client '{self._nas_display(updated)}' updated",
        )
        return updated

    async def record_hub_client_sync(
        self,
        *,
        nas_id: uuid.UUID,
        tunnel_ip_address: str,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> RadiusNasClient:
        """Records that the hub has CONFIRMED a ``client{}`` stanza for this
        NAS at ``tunnel_ip_address``.

        Called only after a 2xx from ``radius_bridge.push_nas_client`` --
        never optimistically, never on the way in. That ordering is the
        whole value of the column: ``hub_client_synced_ip`` is meant to
        answer "what is in clients.conf right now", and a value written
        before the write succeeded answers "what we hoped", which is the
        question that already had an answer.

        ``ip_address`` is set to the same value because for this
        deployment they are one fact -- see
        ``models.RadiusNasClient.ip_address``. Writing both here rather
        than leaving ``ip_address`` to drift separately is what keeps the
        CoA destination and the RADIUS client identity from becoming two
        independently-wrong records of the same address.

        No audit entry: this is the platform reconciling its own record of
        an external system, not an operator decision, and one audit row per
        reconciliation pass per NAS would bury the rows that are decisions.
        The ``radius_nas_hub_client_synced`` log line plus the timestamp
        column are the trail.
        """
        nas_client = await self.get_nas_client(
            nas_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_nas_client(
            nas_client,
            {
                "ip_address": tunnel_ip_address,
                "hub_client_synced_ip": tunnel_ip_address,
                "hub_client_synced_at": datetime.now(UTC),
            },
        )
        logger.info(
            "radius_nas_hub_client_synced",
            extra={
                "nas_identifier": updated.nas_identifier,
                "tunnel_ip_address": tunnel_ip_address,
            },
        )
        return updated

    async def activate_nas(
        self,
        *,
        nas_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> RadiusNasClient:
        nas_client = await self.get_nas_client(
            nas_id, requesting_organization_id=requesting_organization_id
        )
        current = NasStatus(nas_client.status)
        validate_nas_status_transition(current=current, target=NasStatus.ACTIVE)
        updated = await self.repository.update_nas_client(
            nas_client,
            {
                "status": NasStatus.ACTIVE.value,
                "is_active": True,
                "updated_by": actor_user_id,
            },
        )
        event = RadiusNasActivated(nas_client_id=updated.id)
        logger.info("radius_nas_activated", extra=_event_extra(event))
        await self._audit_nas(
            actor_user_id,
            AuditAction.RADIUS_NAS_ACTIVATED,
            nas_client=updated,
            description=f"RADIUS NAS client '{self._nas_display(updated)}' activated",
        )
        return updated

    async def disable_nas(
        self,
        *,
        nas_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
        reason: str | None = None,
    ) -> RadiusNasClient:
        nas_client = await self.get_nas_client(
            nas_id, requesting_organization_id=requesting_organization_id
        )
        current = NasStatus(nas_client.status)
        validate_nas_status_transition(current=current, target=NasStatus.DISABLED)
        updated = await self.repository.update_nas_client(
            nas_client,
            {
                "status": NasStatus.DISABLED.value,
                "is_active": False,
                "updated_by": actor_user_id,
            },
        )
        event = RadiusNasDisabled(nas_client_id=updated.id, reason=reason)
        logger.info("radius_nas_disabled", extra=_event_extra(event))
        description = f"RADIUS NAS client '{self._nas_display(updated)}' disabled"
        if reason:
            description += f": {reason}"
        await self._audit_nas(
            actor_user_id,
            AuditAction.RADIUS_NAS_DISABLED,
            nas_client=updated,
            description=description,
        )
        return updated

    async def regenerate_secret(
        self,
        *,
        nas_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
        push_secret: NasSecretPushProtocol,
        length_bytes: int = NAS_SHARED_SECRET_DEFAULT_LENGTH_BYTES,
    ) -> RadiusNasSecretRegenerationResult:
        """Generates a brand-new shared secret, **hands it to the hub
        first**, and only then overwrites ``shared_secret_encrypted`` -- the
        old secret is never recoverable again after that write
        (Fernet-encrypted, not hashed, but the plaintext itself is never
        retained anywhere once this method returns). Does not require any
        particular current ``status`` -- an operator may want to rotate a
        compromised secret on a currently-``DISABLED``/``SUSPENDED`` NAS
        too, and this action never changes ``status`` itself.

        PUSH BEFORE WRITE, AND ``push_secret`` IS NOT OPTIONAL. Until
        2026-09-02 this method took no such argument and did the database
        write alone, which meant a rotate left three places disagreeing:
        the row held the new secret, the hub's ``client{}`` stanza held the
        old one, and the router held the old one. FreeRADIUS answers an
        Access-Request whose authenticator was computed with a secret that
        is not the one in ``clients.conf`` with a bare Access-Reject, so
        every guest login at the venue failed from that instant, and
        nothing anywhere named the cause. The 5-minute reconciliation
        sweep did not repair it either: ``rebind_nas_for_router`` fires on
        *address* drift and deliberately re-pushes the stored secret, so a
        secret-only divergence is invisible to it.

        The ordering is what makes that unreachable, and it is the same one
        ``record_hub_client_sync``/``rebind_nas_for_router`` already
        established for the address half. If ``push_secret`` raises, this
        method raises the same exception and has written nothing: the row,
        the hub and the device all still hold the old secret, which is a
        *working* venue. Rotation now fails loudly where it used to
        half-succeed silently, and that is the intended behaviour change.

        The reverse ordering was considered and rejected. Writing first and
        rolling back on a failed push cannot be made safe: the old
        plaintext would have to be re-encrypted and re-written by a second
        database call that can itself fail, and the window in between is
        precisely the broken state. The residual risk here is the mirror
        image -- push succeeds, the database write then fails, and the hub
        is briefly *ahead* of the row -- and that one is recoverable
        without a site visit, because re-running the push with the stored
        (old) secret restores service, which is exactly what
        ``register-external`` and the reconciliation sweep both already do.
        Ahead-hub is a bad minute; ahead-database was a dead venue.

        WHAT THIS STILL CANNOT DO is write the new secret onto the router.
        Nothing in this codebase can -- the RADIUS chunk is pasted into
        RouterOS by hand. So a rotate that returns successfully has still
        taken the venue's guest WiFi down until somebody does that, and the
        caller is responsible for saying so; see
        ``schemas.RadiusNasSecretRotatedResponse``.
        """
        nas_client = await self.get_nas_client(
            nas_id, requesting_organization_id=requesting_organization_id
        )
        plaintext_secret = generate_shared_secret(length_bytes)
        # Raises straight through on failure -- deliberately not caught and
        # not translated. Nothing below this line has run, so there is
        # nothing to undo.
        await push_secret(plaintext_secret)
        updated = await self.repository.update_nas_client(
            nas_client,
            {
                "shared_secret_encrypted": encrypt_secret(plaintext_secret),
                "updated_by": actor_user_id,
            },
        )
        event = RadiusNasSecretRegenerated(nas_client_id=updated.id)
        logger.info("radius_nas_secret_regenerated", extra=_event_extra(event))
        await self._audit_nas(
            actor_user_id,
            AuditAction.RADIUS_NAS_SECRET_REGENERATED,
            nas_client=updated,
            description=(
                f"RADIUS NAS client '{self._nas_display(updated)}' shared "
                "secret regenerated"
            ),
        )
        return RadiusNasSecretRegenerationResult(
            nas_client=updated, shared_secret=plaintext_secret
        )

    async def delete_nas(
        self,
        *,
        nas_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
    ) -> RadiusNasClient:
        """Transitions to the terminal ``DELETED`` status *and* sets the
        row's ordinary ``BaseModel`` soft-delete fields
        (``is_deleted``/``deleted_at``), so it disappears from every normal
        listing the same way every other domain's soft-deleted rows already
        do -- ``status`` alone is not what hides it (see
        ``constants.NasStatus.DELETED``'s own docstring)."""
        nas_client = await self.get_nas_client(
            nas_id, requesting_organization_id=requesting_organization_id
        )
        current = NasStatus(nas_client.status)
        validate_nas_status_transition(current=current, target=NasStatus.DELETED)
        await self.repository.update_nas_client(
            nas_client,
            {
                "status": NasStatus.DELETED.value,
                "is_active": False,
                "updated_by": actor_user_id,
            },
        )
        # update_nas_client() -> GenericRepository.update() deliberately
        # refuses to set is_deleted/deleted_at (protected fields) -- without
        # this, the row's status became DELETED but it never actually left
        # get_nas_client_by_router()'s (correctly is_deleted-scoped) lookup,
        # permanently blocking the router from ever registering a new NAS.
        updated = await self.repository.soft_delete_nas_client(nas_client)
        event = RadiusNasDeleted(nas_client_id=updated.id)
        logger.info("radius_nas_deleted", extra=_event_extra(event))
        await self._audit_nas(
            actor_user_id,
            AuditAction.RADIUS_NAS_DELETED,
            nas_client=updated,
            description=f"RADIUS NAS client '{self._nas_display(updated)}' deleted",
        )
        return updated

    # ========================================================================
    # Internal helpers
    # ========================================================================

    @staticmethod
    def _nas_display(nas_client: RadiusNasClient) -> str:
        """``nas_code`` if this row has one, else the guaranteed-non-null
        ``nas_identifier`` -- see ``models.RadiusNasClient.nas_code``'s own
        docstring for why a pre-existing row can have ``nas_code is None``."""
        return nas_client.nas_code or nas_client.nas_identifier

    def _enforce_nas_tenant_scope(
        self,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        if (
            requesting_organization_id is not None
            and organization_id != requesting_organization_id
        ):
            raise CrossOrganizationNasAccessError()

    async def _audit_nas(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        nas_client: RadiusNasClient,
        description: str,
        event_metadata: dict[str, object] | None = None,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="radius_nas_client",
            entity_id=nas_client.id,
            description=description,
            event_metadata=event_metadata or {},
            organization_id=nas_client.organization_id,
            location_id=nas_client.location_id,
        )

    async def authorize(
        self,
        *,
        nas_client: RadiusNasClient,
        username: str,
        calling_station_id: str | None = None,
    ) -> RadiusAuthorizeResult:
        """Authorize phase: is ``username`` (the guest's identifier) a
        currently-``ACTIVE`` guest session on a router bound to this NAS?
        Returns the reply attributes a real deployment would forward
        (session timeout, bandwidth policy, and -- when a ``queue_lookup``
        hook is wired -- a real ``Mikrotik-Rate-Limit`` attribute) --
        composes entirely with this module's own already-recorded
        ``GuestSession``, never re-derives auth logic here. ``nas_client``
        is the already-authenticated NAS identity resolved by
        ``dependencies.CurrentNas`` -- this method (and every other
        RADIUS-facing method below) never re-authenticates the shared
        secret itself, that happens exactly once, at the FastAPI
        dependency layer.

        **MAC-whitelist auto-connect lives here, not a separate public
        endpoint.** A previous pass added ``POST /guest/login/mac``, a
        public, unauthenticated endpoint that issued a full guest session
        from nothing more than a client-supplied ``mac_address`` string in
        an HTTP body -- anyone who knew or guessed a whitelisted MAC could
        impersonate that device from anywhere on the internet, with no
        server-side verification the caller was ever near the real
        network. That endpoint has been removed entirely. The genuinely
        correct binding for "a pre-whitelisted device connects without
        OTP/voucher/password" is exactly the one every real captive-portal
        vendor (Cisco Meraki, Aruba, Ubiquiti) uses: bind the check to a
        value the NAS/router itself asserts, never a browser's claim. RFC
        2865 Section 5.31's ``Calling-Station-Id`` is that value -- it
        only ever reaches this method as ``calling_station_id``, alongside
        an already shared-secret-authenticated ``nas_client``, so it can
        never be forged by an unauthenticated caller the way a JSON body
        field could.

        When ``username`` has no existing active session on this NAS's
        router (the ordinary case for a device that has never been
        through the captive portal at all -- exactly what a whitelisted
        device skips), and a ``calling_station_id`` was supplied, this
        next checks for an existing active session under that MAC's own
        derived identity (``f"mac:{normalized_mac}"``, the same identity
        ``login_via_mac_whitelist`` always creates/reuses) before ever
        originating a new one -- a real NAS re-sends Authorize on every
        periodic reauthentication for an already-connected device, and
        without this check each one would call
        ``GuestService.login_via_mac_whitelist`` again, piling up a new
        concurrent ``GuestSession`` per reauth until
        ``ConcurrentSessionLimitExceededError`` started rejecting the
        device's *own* legitimate reauths. Only when neither lookup finds
        a live session does this fall through to
        ``GuestService.login_via_mac_whitelist`` -- composing with, not
        reimplementing, the same whitelist check/session-origination logic
        that method already owns -- to originate a real session right
        here, at authorize time. Any ``CloudGuestError`` that comes back
        (MAC not whitelisted, no MAC Authorization integration wired,
        guest blocked, router not eligible, device/session limits
        exceeded, FUP quota exhausted, malformed MAC, ...) is treated
        exactly like every other authorize-phase rejection below: a plain
        ``authorized=False``, never a raised exception -- RADIUS has no
        notion of "why", only accept/reject."""
        router = await self.router_lookup.get_router(
            nas_client.router_id, include_deleted=True
        )

        session = await self._find_active_session_for_identifier(router, username)

        if session is None and calling_station_id:
            try:
                normalized_mac = normalize_whitelist_mac_address(calling_station_id)
            except MacAuthorizationError:
                normalized_mac = None
            if normalized_mac is not None:
                session = await self._find_active_session_for_identifier(
                    router, f"mac:{normalized_mac}"
                )
            if session is None:
                try:
                    result = await self.guest_service.login_via_mac_whitelist(
                        mac_address=calling_station_id,
                        organization_id=router.organization_id,
                        location_id=router.location_id,
                        router_id=router.id,
                    )
                except CloudGuestError:
                    session = None
                else:
                    session = result.session

        if session is not None and session.device_id is None and calling_station_id:
            # A session created by a login that carried no ``device_mac``
            # (a supported case -- see ``GuestService
            # .adopt_nas_asserted_device``) is invisible to the captive
            # portal's own "already connected?" check, to login dedup, and
            # to /agent/authorized-macs, all three of which key on
            # ``device_id``. This is the first and only moment the platform
            # is told that session's real MAC by something entitled to
            # assert it, so it is where the row gets healed.
            #
            # Never allowed to change the verdict, exactly like
            # ``_resolve_rate_limit_reply`` below: this is a repair, and a
            # repair that failed must still leave an authorized guest
            # authorized. A broad catch is deliberate for the same reason
            # that method gives -- the alternative is a guest with a
            # verified OTP and no internet because a device write raced.
            try:
                session = await self.guest_service.adopt_nas_asserted_device(
                    session=session, mac_address=calling_station_id
                )
            except Exception as exc:  # noqa: BLE001 -- see comment above
                logger.warning(
                    "radius_authorize_device_adoption_failed",
                    extra={
                        "event_session_id": str(session.id),
                        "event_calling_station_id": calling_station_id,
                        "error": str(exc),
                    },
                )

        # The Authorize decision is otherwise invisible server-side: this
        # endpoint answers HTTP 200 for both Accept and Reject (the verdict
        # rides in ``control:Auth-Type``), so without this line an
        # operator cannot tell "the NAS never asked" from "the NAS asked
        # and we said no" without device-side RADIUS debugging. Field
        # names follow this module's ``event_``-prefixed convention;
        # ``event_identifier`` is the same raw value ``guest_logged_in``
        # already logs, which is what makes the two lines correlatable.
        decision_extra: dict[str, object] = {
            "event_identifier": username,
            "event_nas_identifier": nas_client.nas_identifier,
            "event_router_id": str(router.id),
            "event_calling_station_id": calling_station_id,
        }
        # A session that has already spent its wall-clock allowance is not
        # an authorization, however ACTIVE its row still says it is. This
        # is the hop that makes a venue's "30 min" actually mean the guest
        # signs in again: without it, a guest dropped by the router at 30
        # minutes hits the portal, the portal re-POSTs to the hotspot, the
        # NAS re-asks RADIUS, and this method -- looking only at status --
        # said yes and issued a fresh full timeout. The guest was silently
        # let back on without signing in, for ever, and the setting could
        # never be observed to work.
        #
        # Treated exactly like every other Authorize rejection: a plain
        # `authorized=False`, never an exception. RADIUS has no notion of
        # "why", and the guest's next stop is the portal, where
        # `/guest/session/last-ended` gives them the real explanation.
        if session is not None and has_session_reached_time_limit(
            session, now=datetime.now(UTC)
        ):
            logger.info(
                "radius_authorize_session_past_time_limit",
                extra={**decision_extra, "event_session_id": str(session.id)},
            )
            session = None
        if session is None:
            logger.info(
                "radius_authorize_decision",
                extra={
                    **decision_extra,
                    "event_authorized": False,
                    "event_session_id": None,
                },
            )
            return RadiusAuthorizeResult(
                authorized=False,
                session_timeout_seconds=None,
                idle_timeout_seconds=None,
                data_limit_mb=None,
            )
        logger.info(
            "radius_authorize_decision",
            extra={
                **decision_extra,
                "event_authorized": True,
                "event_session_id": str(session.id),
            },
        )
        return RadiusAuthorizeResult(
            authorized=True,
            # REMAINING time, not the full allowance again.
            #
            # This used to send `session_timeout_minutes * 60` on every
            # Authorize. A NAS re-authorizes an already-connected device
            # periodically, and the captive portal's own hotspot-login
            # POST triggers one too -- so each of those handed the guest a
            # brand-new full clock. A venue setting 30 minutes did not get
            # a guest who must sign in again after 30 minutes; it got a
            # guest whose 30 minutes restarted every time anything spoke
            # to RADIUS. The limit was unreachable by construction, which
            # is why "it just doesn't work" and not "it works late".
            #
            # A session at or past its limit is refused outright above, so
            # this is always positive; `max(..., 1)` guards only the
            # sub-second race between that check and this line, since a
            # NAS given `Session-Timeout: 0` may treat it as unlimited --
            # failing open on exactly the session we mean to end.
            session_timeout_seconds=self._remaining_session_seconds(session),
            # The FULL configured idle allowance, every time -- see the
            # field's own comment for why this is deliberately not the
            # "remaining" treatment its neighbour above gets.
            idle_timeout_seconds=(
                session.idle_timeout_minutes * 60
                if session.idle_timeout_minutes
                else None
            ),
            data_limit_mb=session.data_limit_mb,
            rate_limit=await self._resolve_rate_limit_reply(session.id),
        )

    @staticmethod
    def _remaining_session_seconds(session: GuestSession) -> int | None:
        """Seconds left of ``session``'s own wall-clock allowance, or
        ``None`` for an unbounded session (which stays unbounded -- absent
        is how RADIUS says "no limit", and sending a number there would
        impose one no venue asked for)."""
        if not session.session_timeout_minutes:
            return None
        ends_at = session.started_at + timedelta(
            minutes=session.session_timeout_minutes
        )
        remaining = (ends_at - datetime.now(UTC)).total_seconds()
        # Rounded UP, not truncated: a session authorized microseconds
        # after it was created has 14399.9997s left of a 240-minute
        # allowance, and truncation would quietly shave a second off every
        # venue's stated limit. Ceiling keeps a fresh session's reply
        # exactly `session_timeout_minutes * 60`, which is both what the
        # venue configured and what the existing wire-format tests pin.
        return max(math.ceil(remaining), 1)

    async def _find_active_session_for_identifier(
        self, router: Router, identifier: str
    ) -> GuestSession | None:
        """Shared by ``authorize``'s two lookups (``username``, and --
        MAC-whitelist bypass -- the MAC's own derived identity): is
        ``identifier`` a currently-``ACTIVE`` guest session on
        ``router``? Returns ``None`` for an unknown, blocked, or
        session-less guest, or a session that exists but is inactive or
        bound to a different router -- never raises, mirroring
        ``authorize``'s own "no notion of why, only accept/reject"
        contract.

        Normalizes ``identifier`` the same way every guest-creation path
        already does before writing it (``login_via_otp``/``_password``/
        ``_voucher``, all via ``normalize_identifier``) -- this is an
        exact-string DB lookup, so a caller (the NAS, forwarding whatever
        the guest's browser POSTed) sending un-normalized whitespace would
        otherwise silently never match a real, active session, reopening
        the exact "logged in, zero internet" class of bug this method's
        own username-matching design was built to fix."""
        guest = await self.repository.get_guest_by_identifier(
            router.organization_id, normalize_identifier(identifier)
        )
        if guest is None or guest.is_blocked:
            return None
        candidate = await self.repository.get_latest_session_for_guest(guest.id)
        if (
            candidate is not None
            and candidate.is_active()
            and candidate.router_id == router.id
        ):
            return candidate
        return None

    async def _resolve_rate_limit_reply(self, session_id: uuid.UUID) -> str | None:
        """Best-effort, additive ``Mikrotik-Rate-Limit`` resolution -- see
        ``QueueRateLimitLookupProtocol``'s own docstring. A no-op when no
        ``queue_lookup`` hook was wired (the default); never raises, since
        a queue-lookup failure must never turn an otherwise-valid
        authorize into a reject."""
        if self.queue_lookup is None:
            return None
        try:
            return await self.queue_lookup.get_rate_limit_reply_for_session(session_id)
        except Exception as exc:  # noqa: BLE001 -- see docstring: never raises
            logger.warning(
                "radius_authorize_rate_limit_lookup_failed",
                extra={"session_id": str(session_id), "error": str(exc)},
            )
            return None

    async def accounting_start(
        self, *, nas_client: RadiusNasClient, username: str
    ) -> GuestSession:
        """See module docstring for why this confirms an existing session
        rather than fabricating one."""
        session = await self._get_session_for_nas(nas_client, username)
        return session

    async def accounting_interim_update(
        self,
        *,
        nas_client: RadiusNasClient,
        username: str,
        bytes_uploaded_delta: int,
        bytes_downloaded_delta: int,
        bytes_uploaded_total: int | None = None,
        bytes_downloaded_total: int | None = None,
    ) -> GuestSession:
        """Prefers the NAS's cumulative counters over caller-supplied
        deltas, converting them to a delta against what this session has
        already recorded.

        RADIUS has no delta attribute. ``Acct-Input-Octets``/
        ``Acct-Output-Octets`` are running totals for the NAS's session
        (RFC 2866 §5.3-5.4), so the wire can only ever report totals --
        which is why ``ops/freeradius`` sends
        ``bytes_uploaded_total``/``bytes_downloaded_total``, reassembled
        from the 32-bit octet counter plus its ``Acct-*-Gigawords`` high
        word. Feeding those totals into the delta parameters (the shape
        the ``rest`` module was previously configured to send) makes every
        interim update re-add the whole session to date: a session that
        has moved 1 GB reports 1 GB on its first interim, 2 GB after two,
        3 GB after three. Data caps and FUP quotas would then fire against
        a number that grows quadratically with uptime.

        ``max(0, total - recorded)`` is also what makes this idempotent.
        RADIUS accounting retransmits are routine -- the NAS repeats an
        unacknowledged packet, and the hub's own config deliberately
        withholds the Accounting-Response while the backend is unreachable
        so that it does. A repeated total yields a zero delta and changes
        nothing; a delta-based protocol would double-count every one.

        A total *below* what is already recorded means the NAS's counter
        restarted (reboot, or a new NAS-side session mapped onto the same
        ``GuestSession``). Clamping at 0 keeps usage monotonic rather than
        crediting a guest back their quota, which is the safer direction
        to be wrong in for a cap that exists to be enforced.
        """
        session = await self._get_session_for_nas(nas_client, username)
        if bytes_uploaded_total is not None:
            bytes_uploaded_delta = max(0, bytes_uploaded_total - session.bytes_uploaded)
        if bytes_downloaded_total is not None:
            bytes_downloaded_delta = max(
                0, bytes_downloaded_total - session.bytes_downloaded
            )
        return await self.guest_service.record_usage(
            session_id=session.id,
            bytes_uploaded_delta=bytes_uploaded_delta,
            bytes_downloaded_delta=bytes_downloaded_delta,
        )

    async def accounting_stop(
        self,
        *,
        nas_client: RadiusNasClient,
        username: str,
        bytes_uploaded_total: int | None = None,
        bytes_downloaded_total: int | None = None,
        disconnect_reason: str | None = None,
    ) -> GuestSession:
        session = await self._get_session_for_nas(nas_client, username)

        if bytes_uploaded_total is not None or bytes_downloaded_total is not None:
            update_data: dict[str, object] = {}
            if bytes_uploaded_total is not None:
                update_data["bytes_uploaded"] = bytes_uploaded_total
            if bytes_downloaded_total is not None:
                update_data["bytes_downloaded"] = bytes_downloaded_total
            session = await self.repository.update_session(session, update_data)

        if not session.is_active():
            return session  # already terminal -- Stop is a no-op, not an error

        return await self.guest_service.disconnect_session(
            session_id=session.id,
            reason=disconnect_reason or "radius_accounting_stop",
        )

    async def accounting_on(self, *, nas_client: RadiusNasClient) -> list[GuestSession]:
        """RADIUS Accounting-On (RFC 2866 §5.13): the NAS sends this once,
        right after it boots -- a NAS-level event, carrying no
        Acct-Session-Id at all (unlike Start/Interim-Update/Stop above).
        Closes every ``GuestSession`` this platform still has ``ACTIVE``
        against ``nas_client.router_id``; see
        ``close_sessions_for_nas_restart``'s own docstring for why no live
        CoA-Disconnect is sent."""
        return await close_sessions_for_nas_restart(
            self.repository,
            router_id=nas_client.router_id,
            reason="radius_accounting_on",
        )

    async def accounting_off(
        self, *, nas_client: RadiusNasClient
    ) -> list[GuestSession]:
        """RADIUS Accounting-Off (RFC 2866 §5.13): the NAS sends this once,
        right before a controlled shutdown -- the same "NAS-level event,
        no Acct-Session-Id" shape as ``accounting_on`` above, and the
        identical close-not-disconnect handling; see
        ``close_sessions_for_nas_restart``'s own docstring."""
        return await close_sessions_for_nas_restart(
            self.repository,
            router_id=nas_client.router_id,
            reason="radius_accounting_off",
        )

    async def _get_session_for_nas(
        self, nas_client: RadiusNasClient, username: str
    ) -> GuestSession:
        """Resolves accounting's target session by ``username`` against
        this NAS's own router -- never by treating the NAS's own
        Acct-Session-Id as this platform's ``GuestSession.id``. See
        ``RadiusAccountingRequest``'s own docstring for why: a real
        MikroTik hotspot originates its Acct-Session-Id locally and has
        no way to echo back a caller-supplied UUID.

        Deliberately not ``_find_active_session_for_identifier`` (which
        ``authorize`` uses) -- that only ever returns an ACTIVE session,
        but Accounting-Stop for an already-disconnected session (e.g. a
        RADIUS retransmit, or this platform closing the session first via
        a different path) must still resolve it and no-op, not 404. This
        matches the latest session for the identifier on this router
        regardless of status, same as ``_find_active_session_for_identifier``
        minus its ``is_active()`` filter."""
        router = await self.router_lookup.get_router(
            nas_client.router_id, include_deleted=True
        )
        guest = await self.repository.get_guest_by_identifier(
            router.organization_id, normalize_identifier(username)
        )
        if guest is not None and not guest.is_blocked:
            candidate = await self.repository.get_latest_session_for_guest(guest.id)
            if candidate is not None and candidate.router_id == router.id:
                return candidate
        raise GuestSessionNotFoundError(username)


# ============================================================================
# GuestAnalyticsService: read-only, tenant-scoped aggregate queries
# ============================================================================


class GuestAnalyticsService:
    """Read-only aggregate analytics -- every query is tenant-scoped
    (``organization_id``, optional ``location_id``) and date-ranged, and
    implemented as real SQL aggregates (see ``repository.py``), never a
    Python-side loop over fetched rows."""

    def __init__(self, repository: GuestRepositoryProtocol) -> None:
        self.repository = repository

    async def get_summary(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> GuestAnalyticsSummary:
        validate_date_range(start, end)
        aggregate = await self.repository.get_session_aggregate(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        returning = await self.repository.get_returning_guest_count(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        return GuestAnalyticsSummary(
            visitors=aggregate.visitors,
            unique_guests=aggregate.unique_guests,
            returning_guests=returning,
            average_session_duration_seconds=aggregate.avg_duration_seconds,
            total_bandwidth_bytes=aggregate.total_bandwidth_bytes,
        )

    async def get_top_locations(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int = 10,
    ) -> list[LocationSessionCount]:
        validate_date_range(start, end)
        return await self.repository.get_top_locations(
            organization_id=organization_id, start=start, end=end, limit=limit
        )

    async def get_top_devices(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int = 10,
    ) -> list[DeviceSessionCount]:
        validate_date_range(start, end)
        return await self.repository.get_top_devices(
            organization_id=organization_id, start=start, end=end, limit=limit
        )

    async def get_otp_success_rate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> OtpSuccessRateResult:
        """Derived entirely from this module's own ``GuestLoginHistory`` --
        see module docstring's "Composing analytics without touching
        otp/voucher tables" write-up for why."""
        validate_date_range(start, end)
        counts = await self.repository.get_login_history_outcome_counts(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
            auth_methods=[
                GuestAuthMethod.OTP_SMS.value,
                GuestAuthMethod.OTP_EMAIL.value,
                GuestAuthMethod.OTP_WHATSAPP.value,
            ],
        )
        rate = (
            counts.successful_attempts / counts.total_attempts
            if counts.total_attempts
            else 0.0
        )
        return OtpSuccessRateResult(
            total_attempts=counts.total_attempts,
            successful_attempts=counts.successful_attempts,
            success_rate=rate,
        )

    async def get_voucher_usage(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> VoucherUsageResult:
        """Derived entirely from this module's own ``GuestSession`` rows
        (``auth_method == "voucher"``) -- see module docstring."""
        validate_date_range(start, end)
        aggregate = await self.repository.get_session_auth_method_aggregate(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
            auth_method=GuestAuthMethod.VOUCHER.value,
        )
        return VoucherUsageResult(
            sessions=aggregate.visitors,
            unique_guests=aggregate.unique_guests,
            total_bandwidth_bytes=aggregate.total_bandwidth_bytes,
        )


__all__ = [
    "GuestService",
    "RadiusService",
    "GuestAnalyticsService",
    "OtpVerifyProtocol",
    "VoucherRedeemProtocol",
    "CaptivePortalLookupProtocol",
    "RouterLookupProtocol",
    "AuditLogWriter",
    "GuestLoginResult",
    "RadiusAuthorizeResult",
    "GuestAnalyticsSummary",
    "OtpSuccessRateResult",
    "VoucherUsageResult",
]
