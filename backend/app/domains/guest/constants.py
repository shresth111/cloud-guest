"""Enumerations and small constants for the Guest domain (BE-010 Part 4).

Stored as plain ``String`` columns on the ORM models, never native
PostgreSQL enum types -- the same reason every other domain in this
codebase documents (``app.domains.otp.constants``,
``app.domains.voucher.constants``, ``app.domains.rbac.enums``): adding a
new value never requires an ``ALTER TYPE`` migration, only a new additive
``StrEnum`` member.

**No new ``Settings`` fields.** Like ``app.domains.voucher``/
``app.domains.captive_portal``, this module adds no fields to
``app.core.config.Settings`` -- every tunable default (session timeout,
termination cooldown) lives here instead, as plain module-level constants.
"""

from __future__ import annotations

from enum import StrEnum


class GuestAuthMethod(StrEnum):
    """How a guest authenticated for a given login/session.

    Deliberately mirrors ``app.domains.captive_portal.models
    .CaptivePortalConfig``'s four enabled-method flags
    (``otp_sms_enabled``/``otp_email_enabled``/``voucher_enabled``/
    ``username_password_enabled``) one-for-one, so
    ``GuestService._require_method_enabled`` can check a resolved portal
    config's boolean flag against exactly this enum without any translation
    table. ``USERNAME_PASSWORD`` is carried here for schema completeness
    (matching captive portal's own placeholder flag) but no login method in
    this module implements it -- see ``service.py``'s module docstring.
    """

    OTP_SMS = "otp_sms"
    OTP_EMAIL = "otp_email"
    VOUCHER = "voucher"
    USERNAME_PASSWORD = "username_password"


class GuestSessionStatus(StrEnum):
    """Lifecycle status of a :class:`~.models.GuestSession`.

    * ``ACTIVE`` -- the only status a session is ever created in. A guest
      is currently (as far as this platform's records show) connected.
    * ``DISCONNECTED`` -- a normal, non-punitive end of use: the guest
      finished browsing, RADIUS reported an Accounting-Stop, or an admin
      ended the session with no disciplinary intent. Reconnecting
      immediately is allowed (subject to the guest's underlying grant --
      voucher validity, a fresh OTP -- still being valid).
    * ``EXPIRED`` -- reached lazily, by ``GuestService.enforce_timeouts``,
      once ``last_activity_at`` is further in the past than
      ``session_timeout_minutes``. See that method's docstring for why this
      is a reporting/status-transition mechanism, not a live network
      disconnect.
    * ``TERMINATED`` -- an admin-driven, punitive, immediate kill (abuse,
      policy violation) -- see ``exceptions.SessionTerminationCooldownError``
      and ``service.GuestService.terminate_session``'s docstring for the
      distinction from ``DISCONNECTED`` and the reconnect cooldown it
      imposes.

    All three are terminal: once reached, a ``GuestSession`` row is never
    transitioned again. See ``service.py``'s module docstring for why
    "reconnect" always creates a **new** row rather than resurrecting an
    old one (sessions are append-only history, mirroring
    ``app.domains.voucher.models.Voucher``'s own append-only-per-code
    convention and ``OtpRequest.is_consumed``'s one-way state).
    """

    ACTIVE = "active"
    DISCONNECTED = "disconnected"
    EXPIRED = "expired"
    TERMINATED = "terminated"


# The explicit, exhaustive legal-transition graph for GuestSession.status --
# any transition not listed here is rejected by
# ``validators.validate_session_status_transition`` with
# ``InvalidSessionStatusTransitionError``. Mirrors
# ``app.domains.router.enums.ROUTER_STATUS_TRANSITIONS``'s identical
# dict-of-frozenset shape. Every non-ACTIVE status is terminal (no outgoing
# edges at all, including to itself) -- see GuestSessionStatus's docstring.
GUEST_SESSION_STATUS_TRANSITIONS: dict[
    GuestSessionStatus, frozenset[GuestSessionStatus]
] = {
    GuestSessionStatus.ACTIVE: frozenset(
        {
            GuestSessionStatus.DISCONNECTED,
            GuestSessionStatus.EXPIRED,
            GuestSessionStatus.TERMINATED,
        }
    ),
    GuestSessionStatus.DISCONNECTED: frozenset(),
    GuestSessionStatus.EXPIRED: frozenset(),
    GuestSessionStatus.TERMINATED: frozenset(),
}


# ============================================================================
# Session defaults -- used when no more-specific source (a redeemed
# voucher's own batch settings) supplies a value. See
# ``service.py``'s module docstring for the "copied, not referenced" write-up
# this mirrors from ``app.domains.voucher.models.Voucher.expires_at``.
# ============================================================================

# Fallback session inactivity timeout (minutes) for sessions not started via
# a voucher (e.g. OTP-authenticated sessions), or a voucher batch that left
# no explicit signal of its own. Deliberately generous (four hours) -- guest
# WiFi sessions are typically long-lived compared to e.g. OTP's own
# short-lived (minutes) verification codes.
DEFAULT_SESSION_TIMEOUT_MINUTES = 240

# How long, after an admin-driven ``terminate_session`` (punitive, not a
# normal disconnect), the same guest is blocked from reconnecting at all --
# see ``exceptions.SessionTerminationCooldownError``.
TERMINATION_RECONNECT_COOLDOWN_MINUTES = 60

# How long after a (non-terminated) prior session ended a guest may still
# ``reconnect`` onto a brand-new session derived from it, without presenting
# a fresh OTP code/voucher -- see ``service.GuestService.reconnect``'s
# docstring for the full "still-valid grant, bounded grace window" write-up
# and its honest scope limitation around voucher re-validation.
RECONNECT_GRACE_MINUTES = 30

BYTES_PER_MB = 1024 * 1024

# ============================================================================
# Concurrent session limit -- Guest Session Engine (Phase 1).
# ============================================================================

# The maximum number of simultaneously ``ACTIVE`` GuestSession rows one
# guest (one ``Guest.id``) may hold at once, enforced by
# ``service._enforce_concurrent_session_limit`` at the start of both
# ``login_via_otp``/``login_via_voucher`` (never at ``reconnect``, which is
# already idempotent against the guest's own existing ACTIVE session -- see
# ``GuestService.reconnect``'s docstring). Deliberately a plain module
# constant, not a new ``Organization.settings``/``Settings`` field: full
# per-organization/location configurability is the Policy Engine's job
# (Phase 2 ``policy`` module, ``PolicyType.SESSION`` -- see
# ``docs/ARCHITECTURE_DESIGN.md`` §13), so this stays a single, honest,
# platform-wide default until that seam exists, exactly the same "additive
# default now, resolver-driven override later" posture
# ``DEFAULT_SESSION_TIMEOUT_MINUTES`` above already establishes.
DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST = 3

# ============================================================================
# Session timeout sweep -- Celery Beat task wiring (Guest Session Engine,
# Phase 1). See ``tasks.py``'s module docstring: ``GuestService
# .enforce_timeouts`` already existed as a callable status-transition sweep
# but, before this, was never actually scheduled anywhere -- these two
# constants are what let ``app.core.celery_app`` register and periodically
# fire it, mirroring ``app.domains.analytics.constants
# .TASK_RUN_DAILY_AGGREGATION_FOR_ALL_ORGANIZATIONS``'s identical
# task-name-as-constant convention.
# ============================================================================

TASK_RUN_SESSION_TIMEOUT_SWEEP = "app.domains.guest.tasks.run_session_timeout_sweep"

# Every 5 minutes -- shorter than analytics' 15-minute rolling aggregation
# cadence (``SCHEDULED_REPORTS_CHECK_INTERVAL_SECONDS``-adjacent), because an
# expired-but-not-yet-flipped session is guest-facing/operationally visible
# (an admin's "live sessions" view showing a session that is, in practice,
# long idle) rather than merely a reporting staleness window.
SESSION_TIMEOUT_SWEEP_INTERVAL_SECONDS = 300.0

# ============================================================================
# FreeRADIUS ``rlm_rest``-style integration -- see ``service.py``'s module
# docstring for the full architectural write-up on why HTTP (rlm_rest), not
# raw RADIUS-UDP.
# ============================================================================

# Header a NAS (FreeRADIUS, configured with ``rlm_rest``) presents its
# registered nas_identifier + shared secret through -- mirrors
# ``app.domains.router_agent.constants.AGENT_CREDENTIAL_HEADER``'s identical
# "device/service credential via a custom header, not a platform-user JWT"
# posture, adapted to RADIUS's own two-part identity (an identifier plus a
# shared secret, the same shape RADIUS's own protocol already uses).
RADIUS_NAS_IDENTIFIER_HEADER = "X-RADIUS-NAS-Identifier"
RADIUS_SHARED_SECRET_HEADER = "X-RADIUS-Shared-Secret"

# RADIUS accounting status types this module's ``/radius/accounting``
# endpoint accepts, mirroring the real RADIUS protocol's own
# Acct-Status-Type values (rlm_rest maps these into the POST body verbatim).
RADIUS_ACCT_STATUS_START = "start"
RADIUS_ACCT_STATUS_INTERIM_UPDATE = "interim-update"
RADIUS_ACCT_STATUS_STOP = "stop"

__all__ = [
    "GuestAuthMethod",
    "GuestSessionStatus",
    "GUEST_SESSION_STATUS_TRANSITIONS",
    "DEFAULT_SESSION_TIMEOUT_MINUTES",
    "TERMINATION_RECONNECT_COOLDOWN_MINUTES",
    "RECONNECT_GRACE_MINUTES",
    "BYTES_PER_MB",
    "DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST",
    "TASK_RUN_SESSION_TIMEOUT_SWEEP",
    "SESSION_TIMEOUT_SWEEP_INTERVAL_SECONDS",
    "RADIUS_NAS_IDENTIFIER_HEADER",
    "RADIUS_SHARED_SECRET_HEADER",
    "RADIUS_ACCT_STATUS_START",
    "RADIUS_ACCT_STATUS_INTERIM_UPDATE",
    "RADIUS_ACCT_STATUS_STOP",
]
