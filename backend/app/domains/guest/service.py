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

## Timeout/quota: a reporting mechanism, not live enforcement

There is no live RADIUS daemon in this sandbox actually disconnecting
devices -- ``GuestService.enforce_timeouts`` is a status-transition/
reporting mechanism (flips ``ACTIVE`` sessions whose inactivity has
exceeded their own ``session_timeout_minutes`` to ``EXPIRED``), the same
honest "simulated, DB-tracked signal" posture
``app.domains.wireguard``'s tunnel-health computation and
``app.domains.router``'s heartbeat-derived online/offline status already
document. A real deployment would pair this with FreeRADIUS's own
Session-Timeout reply attribute (already returned by
``RadiusService.authorize``) and/or a scheduled sweep calling
``enforce_timeouts``; nothing in this module ever issues a live
CoA-Disconnect packet to a real NAS.

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
"""

from __future__ import annotations

import dataclasses
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from app.common.exceptions import CloudGuestError
from app.domains.captive_portal.service import ResolvedPortalConfig
from app.domains.guest_access.exceptions import GuestAccessDeniedError
from app.domains.guest_access.service import AccessDecision
from app.domains.monitoring.constants import RealtimeMessageType
from app.domains.otp.constants import OtpPurpose
from app.domains.otp.models import OtpRequest
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
    DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    RECONNECT_GRACE_MINUTES,
    TERMINATION_RECONNECT_COOLDOWN_MINUTES,
    GuestAuthMethod,
    GuestSessionStatus,
)
from .events import (
    GuestBlocked,
    GuestConsentRecorded,
    GuestLoggedIn,
    GuestLoginFailed,
    GuestSessionCreated,
    GuestSessionDisconnected,
    GuestSessionExpired,
    GuestSessionTerminated,
    GuestUnblocked,
    RadiusNasRegistered,
)
from .exceptions import (
    ConcurrentSessionLimitExceededError,
    CrossOrganizationGuestAccessError,
    GuestAuthMethodNotEnabledError,
    GuestBlockedError,
    GuestNotFoundError,
    GuestSessionNotFoundError,
    NoReconnectableSessionError,
    RadiusNasAlreadyRegisteredError,
    RadiusNasAuthenticationError,
    RouterNotEligibleForGuestSessionError,
    SessionTerminationCooldownError,
)
from .models import Guest, GuestConsent, GuestDevice, GuestSession, RadiusNasClient
from .repository import (
    DeviceSessionCount,
    GuestRepositoryProtocol,
    LocationSessionCount,
)
from .validators import (
    is_concurrent_session_limit_reached,
    is_quota_exceeded,
    is_session_timed_out,
    normalize_identifier,
    normalize_mac_address,
    validate_date_range,
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
        expired.append(updated)
    return expired


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
    ) -> None:
        self.repository = repository
        self.otp_service = otp_service
        self.voucher_service = voucher_service
        self.captive_portal_service = captive_portal_service
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        self.monitoring_hook = monitoring_hook
        self.access_control_hook = access_control_hook

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
        interim update arriving after the session already ended)."""
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


class RadiusService:
    """FreeRADIUS ``rlm_rest`` HTTP integration -- see module docstring for
    the full architectural write-up."""

    def __init__(
        self,
        repository: GuestRepositoryProtocol,
        guest_service: GuestService,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.guest_service = guest_service
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer

    async def authenticate_nas(
        self, *, nas_identifier: str, shared_secret: str
    ) -> RadiusNasClient:
        nas_client = await self.repository.get_nas_client_by_identifier(nas_identifier)
        if nas_client is None or not nas_client.is_active:
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
        shared_secret: str,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> RadiusNasClient:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        existing = await self.repository.get_nas_client_by_router(router.id)
        if existing is not None:
            raise RadiusNasAlreadyRegisteredError(router.id)

        nas_client = await self.repository.create_nas_client(
            router_id=router.id,
            nas_identifier=nas_identifier,
            shared_secret_encrypted=encrypt_secret(shared_secret),
            is_active=True,
            created_by=actor_user_id,
        )
        event = RadiusNasRegistered(
            nas_client_id=nas_client.id,
            router_id=router.id,
            nas_identifier=nas_identifier,
        )
        logger.info("radius_nas_registered", extra=_event_extra(event))
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=AuditAction.RADIUS_NAS_REGISTERED.value,
                entity_type="radius_nas_client",
                entity_id=nas_client.id,
                description=f"RADIUS NAS client registered for router {router.id}",
                event_metadata={"nas_identifier": nas_identifier},
                organization_id=router.organization_id,
                location_id=router.location_id,
            )
        return nas_client

    async def authorize(
        self, *, nas_client: RadiusNasClient, username: str
    ) -> RadiusAuthorizeResult:
        """Authorize phase: is ``username`` (the guest's identifier) a
        currently-``ACTIVE`` guest session on a router bound to this NAS?
        Returns the reply attributes a real deployment would forward
        (session timeout, bandwidth policy) -- composes entirely with this
        module's own already-recorded ``GuestSession``, never re-derives
        auth logic here. ``nas_client`` is the already-authenticated NAS
        identity resolved by ``dependencies.CurrentNas`` -- this method
        (and every other RADIUS-facing method below) never re-authenticates
        the shared secret itself, that happens exactly once, at the FastAPI
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
        )

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
