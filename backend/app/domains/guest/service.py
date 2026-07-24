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
(``login_via_otp``/``login_via_voucher``) -- a NAS never authenticates a
guest independently of CloudGuest's own OTP/voucher flow, unlike a generic
enterprise RADIUS deployment where a NAS might originate sessions for
usernames/passwords it has no other record of. The session id handed back
to the guest's device (and, in a real deployment, echoed into the router's
RADIUS accounting attributes as ``Acct-Session-Id``) is exactly the
``GuestSession.id`` this module already created -- ``accounting_start``'s
job is to confirm that id exists and belongs to a router this NAS is
registered for, not to fabricate a session with no known auth method.

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
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from app.common.exceptions import CloudGuestError
from app.domains.captive_portal.service import ResolvedPortalConfig
from app.domains.guest_access.exceptions import GuestAccessDeniedError
from app.domains.guest_access.service import AccessDecision
from app.domains.location.models import Location
from app.domains.monitoring.constants import RealtimeMessageType
from app.domains.otp.constants import OtpPurpose
from app.domains.otp.models import OtpRequest
from app.domains.policy.constants import PolicyType
from app.domains.queue_management.constants import QueueTargetType
from app.domains.rbac.enums import AuditAction
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
    DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST,
    DEFAULT_MAX_DEVICES_PER_GUEST,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    NAS_SHARED_SECRET_DEFAULT_LENGTH_BYTES,
    RECONNECT_GRACE_MINUTES,
    TERMINATION_RECONNECT_COOLDOWN_MINUTES,
    GuestAuthMethod,
    GuestSessionStatus,
    NasStatus,
    QuotaPeriodType,
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
)
from .exceptions import (
    ConcurrentSessionLimitExceededError,
    CrossOrganizationGuestAccessError,
    CrossOrganizationNasAccessError,
    FairUsagePolicyExceededError,
    GuestAuthMethodNotEnabledError,
    GuestBlockedError,
    GuestDeviceLimitExceededError,
    GuestNotFoundError,
    GuestSessionNotFoundError,
    InvalidSessionStatusTransitionError,
    NoReconnectableSessionError,
    RadiusNasAlreadyRegisteredError,
    RadiusNasAuthenticationError,
    RadiusNasNotFoundError,
    RouterNotEligibleForGuestSessionError,
    SessionTerminationCooldownError,
)
from .models import (
    Guest,
    GuestConsent,
    GuestDevice,
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
)
from .validators import (
    compute_period_start,
    is_concurrent_session_limit_reached,
    is_device_limit_reached,
    is_fup_usage_exceeded,
    is_quota_exceeded,
    is_session_timed_out,
    normalize_identifier,
    normalize_mac_address,
    validate_date_range,
    validate_extension_minutes,
    validate_nas_status_transition,
    validate_session_status_transition,
)

logger = logging.getLogger(__name__)


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


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...


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
    (``None``-by-default) rather than a required dependency."""

    async def check_access(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        identifier: str | None,
        mac_address: str | None,
    ) -> AccessDecision: ...


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

    For every distinct ``(guest_id, organization_id)`` pair with at least
    one currently ``ACTIVE`` session, resolves that organization's own
    ``PolicyType.FUP`` time limits; if none are configured at all, the
    guest is skipped entirely (no accrual round trip is worth paying for a
    guest whose organization never opted into time-based quotas -- unlike
    byte usage, which is tracked unconditionally in
    ``GuestService.record_usage`` because it rides for free on a call
    that already happens regardless). Otherwise, for each configured
    period, adds the wall-clock minutes elapsed since the row's own
    ``last_accrued_at`` (or ``period_start``) into ``minutes_used`` --
    guest-level connected time, not summed across concurrent sessions (see
    ``models.GuestQuotaUsage``'s own docstring for why). A guest whose
    accrued usage now meets or exceeds a configured limit has every one of
    their currently ``ACTIVE`` sessions expired. Returns a summary dict
    (rows accrued into, sessions expired)."""
    pairs = await repository.list_active_guest_org_pairs()
    accrued_rows = 0
    expired_sessions = 0
    for pair in pairs:
        tz_name = await repository.get_organization_timezone(pair.organization_id)
        resolved = await policy_lookup.resolve_effective_policy(
            policy_type=PolicyType.FUP,
            organization_id=pair.organization_id,
            location_id=None,
        )
        time_limits = {
            QuotaPeriodType.DAILY: resolved.rules.get("daily_time_limit_minutes"),
            QuotaPeriodType.WEEKLY: resolved.rules.get("weekly_time_limit_minutes"),
            QuotaPeriodType.MONTHLY: resolved.rules.get("monthly_time_limit_minutes"),
        }
        if not any(time_limits.values()):
            continue
        violated_period: str | None = None
        for period_type, limit_minutes in time_limits.items():
            usage = await get_or_reset_quota_usage(
                repository,
                guest_id=pair.guest_id,
                organization_id=pair.organization_id,
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
            active_sessions = await repository.list_active_sessions_for_guest(
                pair.guest_id
            )
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


@dataclass(frozen=True, slots=True)
class RadiusAuthorizeResult:
    authorized: bool
    session_timeout_seconds: int | None
    data_limit_mb: int | None
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
        policy_lookup: PolicyLookupProtocol | None = None,
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
        self.policy_lookup = policy_lookup

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
        never raises. Targets the newly-created ``session`` itself (not
        the guest) -- a real RouterOS ``/queue simple`` entry is tied to
        one concrete IP address, and ``session.ip_address`` is the only
        one that is actually correct *right now*; a guest-level
        assignment would go stale the moment they reconnect with a new
        DHCP lease."""
        if self.queue_assignment_hook is None or not session.ip_address:
            return
        try:
            await self.queue_assignment_hook.resolve_and_assign_queue(
                requesting_organization_id=organization_id,
                location_id=location_id,
                router_id=router.id,
                target_type=QueueTargetType.SESSION,
                target_id=session.id,
                device_target=session.ip_address,
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
        if auth_method not in (GuestAuthMethod.OTP_SMS, GuestAuthMethod.OTP_EMAIL):
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
        )
        if existing_guest is not None:
            # A brand-new guest (``existing_guest is None``) trivially holds
            # zero active sessions -- skip the query entirely rather than
            # counting against a guest_id that doesn't exist yet. Checked
            # before OTP verification below, not after, so a guest already
            # at the limit never spends a real (rate-limited, one-time) OTP
            # attempt on a login that was always going to be rejected.
            await self._enforce_concurrent_session_limit(existing_guest.id)
            # Same "brand-new guest trivially holds zero devices" skip --
            # see _enforce_device_limit's own docstring.
            await self._enforce_device_limit(
                guest_id=existing_guest.id,
                mac_address=device_mac,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            # Same skip -- see _enforce_fup_quota's own docstring.
            await self._enforce_fup_quota(
                guest_id=existing_guest.id, organization_id=resolved_org_id
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
            guest_id=guest.id, mac_address=device_mac, device_name=device_name
        )
        session = await self._create_session(
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
            session_timeout_minutes=DEFAULT_SESSION_TIMEOUT_MINUTES,
        )
        # BE-011 Part 3: additive, best-effort real-time broadcast -- see
        # GuestService's own docstring. Fires only after the real session
        # row above already exists.
        await self._broadcast_guest_session_started(
            session=session,
            guest=guest,
            router=router,
            location_id=location_id,
            organization_id=resolved_org_id,
            auth_method=auth_method.value,
            is_new_guest=is_new,
        )
        await self._assign_guest_queue(
            session=session,
            router=router,
            location_id=location_id,
            organization_id=resolved_org_id,
        )
        await self._bump_guest_visit(guest)
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
        )
        if existing_guest is not None:
            # See the identical comment in login_via_otp: skip the query for
            # a brand-new guest, and check before the voucher is redeemed
            # below, not after, so a guest already at the limit never
            # spends a real (single-use) voucher on a login that was always
            # going to be rejected.
            await self._enforce_concurrent_session_limit(existing_guest.id)
            await self._enforce_device_limit(
                guest_id=existing_guest.id,
                mac_address=device_mac,
                organization_id=resolved_org_id,
                location_id=location_id,
            )
            await self._enforce_fup_quota(
                guest_id=existing_guest.id, organization_id=resolved_org_id
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
            guest_id=guest.id, mac_address=device_mac, device_name=device_name
        )
        # Copied, not referenced -- see module docstring.
        session = await self._create_session(
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
        )
        # BE-011 Part 3: additive, best-effort real-time broadcast -- see
        # GuestService's own docstring. Fires only after the real session
        # row above already exists.
        await self._broadcast_guest_session_started(
            session=session,
            guest=guest,
            router=router,
            location_id=location_id,
            organization_id=resolved_org_id,
            auth_method=GuestAuthMethod.VOUCHER.value,
            is_new_guest=is_new,
        )
        await self._assign_guest_queue(
            session=session,
            router=router,
            location_id=location_id,
            organization_id=resolved_org_id,
        )
        # Phase 1 BhaiFi-parity: additive, best-effort speed-linked voucher
        # assignment -- see _assign_voucher_queue's own docstring.
        await self._assign_voucher_queue(
            voucher=voucher,
            session=session,
            router=router,
            location_id=location_id,
            organization_id=resolved_org_id,
        )
        await self._bump_guest_visit(guest)
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

    async def record_consent(
        self,
        *,
        guest_id: uuid.UUID,
        captive_portal_config_id: uuid.UUID | None,
        terms_version: str | None,
        ip_address: str | None,
    ) -> GuestConsent:
        guest = await self._require_guest(guest_id)
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

    async def get_or_create_device(
        self,
        *,
        guest_id: uuid.UUID,
        mac_address: str,
        device_name: str | None = None,
    ) -> GuestDevice:
        """Get-or-create a :class:`~.models.GuestDevice` by MAC address --
        see ``models.py``'s module docstring for why ``mac_address`` is
        globally unique with ``guest_id`` reassignable, not scoped per
        guest."""
        mac = normalize_mac_address(mac_address)
        now = datetime.now(UTC)
        device = await self.repository.get_device_by_mac(mac)
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
            GuestAuthMethod.VOUCHER: config.voucher_enabled,
            GuestAuthMethod.USERNAME_PASSWORD: config.username_password_enabled,
        }
        if not enabled_map[auth_method]:
            raise GuestAuthMethodNotEnabledError(auth_method.value)
        return resolved

    async def _get_eligible_router(self, router_id: uuid.UUID) -> Router:
        router = await self.router_lookup.get_router(router_id)
        ineligible = {RouterStatus.DECOMMISSIONED.value, RouterStatus.SUSPENDED.value}
        if router.status in ineligible:
            raise RouterNotEligibleForGuestSessionError(router.id, router.status)
        return router

    def _reject_if_blocked(self, guest: Guest | None) -> None:
        if guest is not None and guest.is_blocked:
            raise GuestBlockedError(guest.blocked_reason)

    async def _enforce_access_control(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        identifier: str,
        device_mac: str | None,
    ) -> None:
        """Guest Access Control (Phase 1): a no-op when no
        ``access_control_hook`` was wired (the default -- see
        ``GuestService``'s own docstring). When wired, calls
        ``AccessDecisionResolver`` (via ``GuestAccessService.check_access``)
        and raises ``GuestAccessDeniedError`` on a resolved ``BLOCKLIST``
        decision.

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
        there is no separate "requesting" identity to distinguish."""
        if self.access_control_hook is None:
            return
        decision: AccessDecision = await self.access_control_hook.check_access(
            organization_id=organization_id,
            requesting_organization_id=organization_id,
            location_id=location_id,
            identifier=identifier,
            mac_address=device_mac,
        )
        if not decision.allowed:
            raise GuestAccessDeniedError(decision.reason)

    async def _enforce_concurrent_session_limit(self, guest_id: uuid.UUID) -> None:
        """Guest Session Engine (Phase 1): raises
        ``ConcurrentSessionLimitExceededError`` if ``guest_id`` already holds
        ``constants.DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST`` (or more)
        ``ACTIVE`` sessions. Called from ``login_via_otp``/
        ``login_via_voucher`` after the guest identity is resolved but
        before a new ``GuestSession`` row is created -- mirrors
        ``_reject_if_blocked``'s placement (reject before any further
        side effect). Deliberately **not** called from ``reconnect``: that
        method is already idempotent against the guest's own existing
        ``ACTIVE`` session (see its docstring) and only ever derives a new
        row when the guest currently holds zero active sessions, so it can
        never itself push a guest over the limit."""
        active_count = await self.repository.count_active_sessions_for_guest(guest_id)
        if is_concurrent_session_limit_reached(
            active_count=active_count,
            limit=DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST,
        ):
            raise ConcurrentSessionLimitExceededError(
                guest_id=guest_id, limit=DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST
            )

    async def _resolve_device_limit(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> int:
        """Resolves the real per-guest device limit via
        ``PolicyType.DEVICE`` when a ``policy_lookup`` hook is wired,
        falling back to ``constants.DEFAULT_MAX_DEVICES_PER_GUEST``
        otherwise (or if the resolved rules omit the field, e.g. a
        ``GenericPolicyRules``-shaped override)."""
        if self.policy_lookup is None:
            return DEFAULT_MAX_DEVICES_PER_GUEST
        resolved = await self.policy_lookup.resolve_effective_policy(
            policy_type=PolicyType.DEVICE,
            organization_id=organization_id,
            location_id=location_id,
        )
        return resolved.rules.get(
            "max_devices_per_guest", DEFAULT_MAX_DEVICES_PER_GUEST
        )

    async def _enforce_device_limit(
        self,
        *,
        guest_id: uuid.UUID,
        mac_address: str | None,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> None:
        """Guest Session Engine (Phase 1): raises
        ``GuestDeviceLimitExceededError`` if registering ``mac_address``
        against ``guest_id`` would push the guest over their own resolved
        device limit. A no-op when ``mac_address`` is absent (no device to
        register at all) or when the device already belongs to this exact
        guest (a returning device, not a new one -- mirrors
        ``get_or_create_device``'s own "reassignment" logic, checked here
        without mutating anything). Called from ``login_via_otp``/
        ``login_via_voucher`` after ``_enforce_concurrent_session_limit``,
        before ``_maybe_get_or_create_device`` ever creates or reassigns a
        row -- the identical "reject before touching anything with a side
        effect" ordering that method's own docstring establishes."""
        if not mac_address:
            return
        existing_device = await self.repository.get_device_by_mac(
            normalize_mac_address(mac_address)
        )
        if existing_device is not None and existing_device.guest_id == guest_id:
            return
        device_count = await self.repository.count_devices_for_guest(guest_id)
        limit = await self._resolve_device_limit(
            organization_id=organization_id, location_id=location_id
        )
        if is_device_limit_reached(device_count=device_count, limit=limit):
            raise GuestDeviceLimitExceededError(guest_id=guest_id, limit=limit)

    async def _enforce_fup_quota(
        self, *, guest_id: uuid.UUID, organization_id: uuid.UUID
    ) -> None:
        """Guest Session Engine (Phase 1): raises
        ``FairUsagePolicyExceededError`` if ``guest_id`` already meets or
        exceeds a ``PolicyType.FUP`` daily/weekly/monthly data or time cap
        resolved for ``organization_id``. Unlike
        ``_enforce_device_limit``/``_enforce_concurrent_session_limit``,
        there is no platform-wide fallback: a no-op entirely when no
        ``policy_lookup`` hook is wired, and (once resolved) a no-op for
        any period with no configured limit at all -- see
        ``exceptions.FairUsagePolicyExceededError``'s own docstring for why
        ``app.domains.policy`` seeds no default here. Called from
        ``login_via_otp``/``login_via_voucher`` alongside
        ``_enforce_device_limit``, the identical "reject before touching
        OTP/voucher verification" placement."""
        if self.policy_lookup is None:
            return
        resolved = await self.policy_lookup.resolve_effective_policy(
            policy_type=PolicyType.FUP,
            organization_id=organization_id,
            location_id=None,
        )
        rules = resolved.rules
        data_limits = {
            QuotaPeriodType.DAILY: rules.get("daily_data_limit_mb"),
            QuotaPeriodType.WEEKLY: rules.get("weekly_data_limit_mb"),
            QuotaPeriodType.MONTHLY: rules.get("monthly_data_limit_mb"),
        }
        time_limits = {
            QuotaPeriodType.DAILY: rules.get("daily_time_limit_minutes"),
            QuotaPeriodType.WEEKLY: rules.get("weekly_time_limit_minutes"),
            QuotaPeriodType.MONTHLY: rules.get("monthly_time_limit_minutes"),
        }
        if not any(data_limits.values()) and not any(time_limits.values()):
            return
        tz_name = await self.repository.get_organization_timezone(organization_id)
        now = datetime.now(UTC)
        for period_type in QuotaPeriodType:
            limit_mb = data_limits[period_type]
            limit_minutes = time_limits[period_type]
            if limit_mb is None and limit_minutes is None:
                continue
            usage = await get_or_reset_quota_usage(
                self.repository,
                guest_id=guest_id,
                organization_id=organization_id,
                period_type=period_type,
                tz_name=tz_name,
                now=now,
            )
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
            )
            data_limits = {
                QuotaPeriodType.DAILY: resolved.rules.get("daily_data_limit_mb"),
                QuotaPeriodType.WEEKLY: resolved.rules.get("weekly_data_limit_mb"),
                QuotaPeriodType.MONTHLY: resolved.rules.get("monthly_data_limit_mb"),
            }
            violated_period: str | None = None
            for period_type, limit_mb in data_limits.items():
                usage = await get_or_reset_quota_usage(
                    self.repository,
                    guest_id=guest_id,
                    organization_id=organization_id,
                    period_type=period_type,
                    tz_name=tz_name,
                    now=now,
                )
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
    ) -> GuestDevice | None:
        if not mac_address:
            return None
        return await self.get_or_create_device(
            guest_id=guest_id, mac_address=mac_address, device_name=device_name
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
    ) -> None:
        self.repository = repository
        self.guest_service = guest_service
        self.router_lookup = router_lookup
        self.location_lookup = location_lookup
        self.nas_code_counter_repository = nas_code_counter_repository
        self.audit_writer = audit_writer
        self.queue_lookup = queue_lookup

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
        resolved_ip_address = (
            ip_address or router.public_ip_address or router.management_ip_address
        )

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
        length_bytes: int = NAS_SHARED_SECRET_DEFAULT_LENGTH_BYTES,
    ) -> RadiusNasSecretRegenerationResult:
        """Generates a brand-new shared secret and immediately overwrites
        ``shared_secret_encrypted`` -- the old secret is never recoverable
        again after this call (Fernet-encrypted, not hashed, but the
        plaintext itself is never retained anywhere once this method
        returns). Does not require any particular current ``status`` -- an
        operator may want to rotate a compromised secret on a
        currently-``DISABLED``/``SUSPENDED`` NAS too, and this action never
        changes ``status`` itself."""
        nas_client = await self.get_nas_client(
            nas_id, requesting_organization_id=requesting_organization_id
        )
        plaintext_secret = generate_shared_secret(length_bytes)
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
        self, *, nas_client: RadiusNasClient, username: str
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
        dependency layer."""
        router = await self.router_lookup.get_router(
            nas_client.router_id, include_deleted=True
        )
        guest = await self.repository.get_guest_by_identifier(
            router.organization_id, username
        )
        if guest is None or guest.is_blocked:
            return RadiusAuthorizeResult(
                authorized=False, session_timeout_seconds=None, data_limit_mb=None
            )
        session = await self.repository.get_latest_session_for_guest(guest.id)
        if session is None or not session.is_active() or session.router_id != router.id:
            return RadiusAuthorizeResult(
                authorized=False, session_timeout_seconds=None, data_limit_mb=None
            )
        return RadiusAuthorizeResult(
            authorized=True,
            session_timeout_seconds=(
                session.session_timeout_minutes * 60
                if session.session_timeout_minutes
                else None
            ),
            data_limit_mb=session.data_limit_mb,
            rate_limit=await self._resolve_rate_limit_reply(session.id),
        )

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
        self, *, nas_client: RadiusNasClient, session_id: uuid.UUID
    ) -> GuestSession:
        """See module docstring for why this confirms an existing session
        rather than fabricating one."""
        session = await self._get_session_for_nas(nas_client, session_id)
        return session

    async def accounting_interim_update(
        self,
        *,
        nas_client: RadiusNasClient,
        session_id: uuid.UUID,
        bytes_uploaded_delta: int,
        bytes_downloaded_delta: int,
    ) -> GuestSession:
        await self._get_session_for_nas(nas_client, session_id)
        return await self.guest_service.record_usage(
            session_id=session_id,
            bytes_uploaded_delta=bytes_uploaded_delta,
            bytes_downloaded_delta=bytes_downloaded_delta,
        )

    async def accounting_stop(
        self,
        *,
        nas_client: RadiusNasClient,
        session_id: uuid.UUID,
        bytes_uploaded_total: int | None = None,
        bytes_downloaded_total: int | None = None,
        disconnect_reason: str | None = None,
    ) -> GuestSession:
        session = await self._get_session_for_nas(nas_client, session_id)

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

    async def _get_session_for_nas(
        self, nas_client: RadiusNasClient, session_id: uuid.UUID
    ) -> GuestSession:
        session = await self.repository.get_session_by_id(session_id)
        if session is None:
            raise GuestSessionNotFoundError(session_id)
        if session.router_id != nas_client.router_id:
            raise RadiusNasAuthenticationError()
        return session


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
