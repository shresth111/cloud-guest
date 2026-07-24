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
    * ``PAUSED`` -- Phase 1 BhaiFi-parity: an admin-driven, *reversible*
      temporary suspension (``service.GuestService.pause_session``),
      distinct from every status above in being the only one with an
      outgoing edge back to ``ACTIVE`` (``resume_session``). A live RADIUS
      Disconnect-Request is issued the same way ``DISCONNECTED``/
      ``TERMINATED``/``EXPIRED`` already trigger one (see
      ``service.issue_live_disconnect``) -- pausing immediately cuts the
      guest's live network access, but (unlike ``TERMINATED``) the
      ``GuestSession`` row itself survives so ``resume_session`` can flip
      it back to ``ACTIVE`` rather than requiring a brand-new session.

    ``DISCONNECTED``/``EXPIRED``/``TERMINATED`` are terminal: once reached,
    a ``GuestSession`` row is never transitioned again. See ``service.py``'s
    module docstring for why "reconnect" always creates a **new** row
    rather than resurrecting an old one (sessions are append-only history,
    mirroring ``app.domains.voucher.models.Voucher``'s own
    append-only-per-code convention and ``OtpRequest.is_consumed``'s
    one-way state) -- ``PAUSED`` is the sole, deliberate exception to that
    append-only posture, since a pause is explicitly meant to be undone in
    place, not replaced by a new row.
    """

    ACTIVE = "active"
    DISCONNECTED = "disconnected"
    EXPIRED = "expired"
    TERMINATED = "terminated"
    PAUSED = "paused"


# The explicit, exhaustive legal-transition graph for GuestSession.status --
# any transition not listed here is rejected by
# ``validators.validate_session_status_transition`` with
# ``InvalidSessionStatusTransitionError``. Mirrors
# ``app.domains.router.enums.ROUTER_STATUS_TRANSITIONS``'s identical
# dict-of-frozenset shape. Every status except ACTIVE/PAUSED is terminal (no
# outgoing edges at all, including to itself) -- see GuestSessionStatus's
# docstring for why PAUSED alone has an edge back to ACTIVE.
GUEST_SESSION_STATUS_TRANSITIONS: dict[
    GuestSessionStatus, frozenset[GuestSessionStatus]
] = {
    GuestSessionStatus.ACTIVE: frozenset(
        {
            GuestSessionStatus.DISCONNECTED,
            GuestSessionStatus.EXPIRED,
            GuestSessionStatus.TERMINATED,
            GuestSessionStatus.PAUSED,
        }
    ),
    GuestSessionStatus.PAUSED: frozenset(
        {
            GuestSessionStatus.ACTIVE,
            GuestSessionStatus.DISCONNECTED,
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
# Device limit -- Guest Session Engine (Phase 1).
# ============================================================================

# The maximum number of distinct ``GuestDevice`` rows (by MAC address) one
# guest may have registered at once, enforced by
# ``service._enforce_device_limit`` at the start of both
# ``login_via_otp``/``login_via_voucher``. Unlike
# ``DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST`` above (which predates
# ``app.domains.policy`` and was only ever a plain constant), this value is
# resolved through the real ``PolicyType.DEVICE`` seam
# (``schemas.DevicePolicyRules.max_devices_per_guest``) via
# ``PolicyService.resolve_effective_policy`` -- this constant is what
# ``constants.PLATFORM_DEFAULT_RULES[PolicyType.DEVICE]`` mirrors as its own
# platform-wide fallback (see that module's own docstring on why the value
# is duplicated as a literal there, not imported), and what
# ``_enforce_device_limit`` falls back to if no ``queue_lookup``-style
# policy composition is wired at all. Same 3-device magnitude as the
# concurrent-session limit above -- a reasonable, real default for the
# hotel/hotspot use case this platform targets, not an arbitrary number.
DEFAULT_MAX_DEVICES_PER_GUEST = 3

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
# Fair Usage Policy (FUP) quota tracking -- Phase 1 BhaiFi-parity.
# See ``models.GuestQuotaUsage``'s own docstring and ``service.py``'s "FUP
# quota tracking" section for the full read/bump/rollover write-up.
# ============================================================================


class QuotaPeriodType(StrEnum):
    """Which recurring calendar period a :class:`~.models.GuestQuotaUsage`
    row tracks -- one row per ``(guest_id, period_type)``, each with its own
    independent rollover cadence. Mirrors ``schemas.FUPPolicyRules``'s own
    ``daily_*``/``weekly_*``/``monthly_*`` field naming one-for-one."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


# ============================================================================
# FUP time-accrual + enforcement sweep -- Celery Beat task wiring.
# Guest-level wall-clock connected time (not summed across concurrent
# sessions -- see ``tasks.run_fup_time_accrual_sweep``'s own docstring) can
# only be measured by periodically walking every currently ``ACTIVE``
# session, unlike byte usage (which rides along for free on every RADIUS
# Interim-Update -- see ``service.GuestService.record_usage``). Same 5-minute
# cadence as ``SESSION_TIMEOUT_SWEEP_INTERVAL_SECONDS`` -- a guest who has
# just crossed a configured daily/weekly/monthly time cap is exactly as
# operationally visible (should be disconnected promptly) as a timed-out
# session.
# ============================================================================

TASK_RUN_FUP_TIME_ACCRUAL_SWEEP = "app.domains.guest.tasks.run_fup_time_accrual_sweep"

FUP_TIME_ACCRUAL_SWEEP_INTERVAL_SECONDS = 300.0

# ============================================================================
# Quota-reset sweep -- Celery Beat task wiring. Proactively rolls every
# ``GuestQuotaUsage`` row over to a fresh period the moment its own
# organization's local calendar day/week/month boundary passes, so e.g. an
# admin's "quota remaining" view reflects a guest's fresh allowance even
# before that guest's next login/accounting call opportunistically triggers
# the identical rollover (see ``service._get_or_reset_quota_usage``, the one
# shared function both this sweep and every lazy, request-triggered call
# site delegate to). Hourly, not every 5 minutes like the two sweeps above --
# a day/week/month boundary never needs finer-than-hourly reset latency, the
# same "cadence matches the underlying data's own granularity" reasoning
# ``app.domains.billing.constants.SUBSCRIPTION_RENEWAL_SWEEP_INTERVAL_SECONDS``'s
# own docstring already establishes for billing's day/month/year periods.
# ============================================================================

TASK_RUN_QUOTA_RESET_SWEEP = "app.domains.guest.tasks.run_quota_reset_sweep"

QUOTA_RESET_SWEEP_INTERVAL_SECONDS = 3600.0

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
# RFC 2866 §5.13: a NAS sends Accounting-On once, right after it boots, and
# Accounting-Off once, right before a controlled shutdown -- both are
# NAS-level events (no Acct-Session-Id at all; RadiusAccountingRequest
# .session_id is therefore optional and ignored for these two status
# types), signalling that every session this platform still has ``ACTIVE``
# against that NAS is now stale (the NAS's own local accounting state was
# just lost/reset). See ``service.close_sessions_for_nas_restart``'s own
# docstring.
RADIUS_ACCT_STATUS_ACCOUNTING_ON = "accounting-on"
RADIUS_ACCT_STATUS_ACCOUNTING_OFF = "accounting-off"

# ============================================================================
# NAS lifecycle -- extends RadiusNasClient (originally a bare
# router_id/nas_identifier/shared_secret_encrypted/is_active row) with a
# real status graph, a human-readable ``nas_code``, and the fields a
# dashboard/admin API needs without joining through ``Router`` for every
# read. See ``models.py``'s own ``RadiusNasClient`` docstring and
# ``docs/guest/NAS_EXTENSION.md`` for the full design write-up.
# ============================================================================


class NasStatus(StrEnum):
    """Lifecycle status of a :class:`~.models.RadiusNasClient`.

    * ``PENDING`` -- registered but not yet confirmed ready to serve
      RADIUS traffic. Not the default for ``RadiusService.register_nas``
      (see that method's own docstring for why -- unlike ``Router``'s own
      ``PENDING_PROVISIONING``, a NAS registration has no genuine
      multi-step hardware provisioning gate; its only prerequisite,
      correct credentials, already exists at creation time), but a real,
      reachable status for a future caller (e.g. an automated
      router-provisioning flow) that wants to stage a NAS before its
      router finishes its own provisioning.
    * ``ACTIVE`` -- the default status a NAS is registered in.
      ``RadiusService.authenticate_nas`` only accepts a NAS in this
      status.
    * ``DISABLED`` -- an explicit, reversible administrative pause
      (``RadiusService.disable_nas`` / ``.activate_nas``).
    * ``SUSPENDED`` -- a stronger restriction than ``DISABLED`` (e.g. a
      security incident or billing hold) -- modeled here as a real,
      validated status with its own legal transitions for structural
      completeness, but this build exposes no dedicated
      ``POST /radius/nas/{id}/suspend`` endpoint of its own (only
      ``activate``/``disable``/``regenerate-secret`` were in this
      extension's own scope) -- see ``docs/guest/NAS_EXTENSION.md``.
    * ``DELETED`` -- terminal. Reached only via
      ``RadiusService.delete_nas``, which also sets the row's ordinary
      ``BaseModel`` soft-delete fields (``is_deleted``/``deleted_at``) so
      it disappears from every normal listing the same way every other
      domain's soft-deleted rows already do -- ``status`` alone is not
      what hides it.
    """

    PENDING = "pending"
    ACTIVE = "active"
    DISABLED = "disabled"
    SUSPENDED = "suspended"
    DELETED = "deleted"


# The explicit, exhaustive legal-transition graph for
# ``RadiusNasClient.status`` -- mirrors
# ``GUEST_SESSION_STATUS_TRANSITIONS``'s/``app.domains.voucher.constants
# .VOUCHER_BATCH_STATUS_TRANSITIONS``'s identical dict-of-frozenset shape.
# ``DELETED`` is terminal (no outgoing edges, not even to itself).
NAS_STATUS_TRANSITIONS: dict[NasStatus, frozenset[NasStatus]] = {
    NasStatus.PENDING: frozenset(
        {NasStatus.ACTIVE, NasStatus.DISABLED, NasStatus.DELETED}
    ),
    NasStatus.ACTIVE: frozenset(
        {NasStatus.DISABLED, NasStatus.SUSPENDED, NasStatus.DELETED}
    ),
    NasStatus.DISABLED: frozenset({NasStatus.ACTIVE, NasStatus.DELETED}),
    NasStatus.SUSPENDED: frozenset({NasStatus.ACTIVE, NasStatus.DELETED}),
    NasStatus.DELETED: frozenset(),
}

# Human-readable NAS code prefix/digit-width -- see
# ``nas_number_generator.py``'s own module docstring for the full
# "why this format, not the module brief's imagined one" write-up.
# ``"NAS-<location_code>-<sequence>"``.
NAS_CODE_PREFIX = "NAS"
NAS_CODE_SEQUENCE_DIGITS = 4

# Bound on how many (in-memory-generate, then DB-existence-check) rounds a
# fallback identifier attempt would need -- unlike the voucher/guest-team
# join-code generators, ``nas_code`` generation is not a random-retry
# scheme (it is a real, atomic, collision-free Postgres sequence via
# ``NAS_CODE_PREFIX``/``RadiusNasCodeCounter``), so no retry-round constant
# is needed here at all -- noted for readers expecting one by analogy with
# ``voucher.constants.CODE_GENERATION_MAX_ROUNDS``.

# Default length (bytes of entropy before base64url-encoding, via
# ``secrets.token_urlsafe``) for an auto-generated RADIUS shared secret when
# an admin does not supply one explicitly. 32 bytes -> a 43-character
# URL-safe string, comfortably exceeding
# ``schemas.RadiusNasRegisterRequest.shared_secret``'s existing
# ``min_length=8`` floor by a wide margin, and matching this codebase's own
# existing precedent for cryptographically-random secret material (e.g.
# ``app.domains.wireguard``'s key generation) of preferring the OS CSPRNG
# over a shorter, human-typed value whenever a human does not need to
# transcribe it (a RADIUS shared secret is configured once into
# FreeRADIUS's own config and never manually retyped afterward).
NAS_SHARED_SECRET_DEFAULT_LENGTH_BYTES = 32

__all__ = [
    "GuestAuthMethod",
    "GuestSessionStatus",
    "GUEST_SESSION_STATUS_TRANSITIONS",
    "DEFAULT_SESSION_TIMEOUT_MINUTES",
    "TERMINATION_RECONNECT_COOLDOWN_MINUTES",
    "RECONNECT_GRACE_MINUTES",
    "BYTES_PER_MB",
    "DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST",
    "DEFAULT_MAX_DEVICES_PER_GUEST",
    "QuotaPeriodType",
    "TASK_RUN_SESSION_TIMEOUT_SWEEP",
    "SESSION_TIMEOUT_SWEEP_INTERVAL_SECONDS",
    "TASK_RUN_FUP_TIME_ACCRUAL_SWEEP",
    "FUP_TIME_ACCRUAL_SWEEP_INTERVAL_SECONDS",
    "TASK_RUN_QUOTA_RESET_SWEEP",
    "QUOTA_RESET_SWEEP_INTERVAL_SECONDS",
    "RADIUS_NAS_IDENTIFIER_HEADER",
    "RADIUS_SHARED_SECRET_HEADER",
    "RADIUS_ACCT_STATUS_START",
    "RADIUS_ACCT_STATUS_INTERIM_UPDATE",
    "RADIUS_ACCT_STATUS_STOP",
    "RADIUS_ACCT_STATUS_ACCOUNTING_ON",
    "RADIUS_ACCT_STATUS_ACCOUNTING_OFF",
    "NasStatus",
    "NAS_STATUS_TRANSITIONS",
    "NAS_CODE_PREFIX",
    "NAS_CODE_SEQUENCE_DIGITS",
    "NAS_SHARED_SECRET_DEFAULT_LENGTH_BYTES",
]
