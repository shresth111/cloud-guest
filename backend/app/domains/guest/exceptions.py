"""Guest domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.

This module never re-raises ``app.domains.otp``'s or
``app.domains.voucher``'s own exceptions under a different name -- a caller
of ``login_via_otp``/``login_via_voucher`` sees exactly the same
``OtpCodeMismatchError``/``VoucherExpiredError``/etc. those services already
raise (composition, not translation). The exceptions defined here cover only
what is genuinely new at this module's own layer: guest/session lifecycle,
tenant isolation, and the RADIUS/NAS authentication boundary.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "GuestError",
    "GuestNotFoundError",
    "CrossOrganizationGuestAccessError",
    "GuestBlockedError",
    "GuestSessionNotFoundError",
    "GuestAuthMethodNotEnabledError",
    "VenueClosedError",
    "GuestTeamSharedQuotaExceededError",
    "RouterNotEligibleForGuestSessionError",
    "InvalidSessionStatusTransitionError",
    "SessionTerminationCooldownError",
    "NoReconnectableSessionError",
    "RadiusNasClientNotFoundError",
    "RadiusNasAuthenticationError",
    "RadiusNasAlreadyRegisteredError",
    "RadiusNasNotFoundError",
    "RadiusNasBridgeDeregistrationError",
    "CrossOrganizationNasAccessError",
    "InvalidNasStatusTransitionError",
    "InvalidAnalyticsDateRangeError",
    "TooManyDeviceIdsError",
    "ConcurrentSessionLimitExceededError",
    "GuestDeviceLimitExceededError",
    "FairUsagePolicyExceededError",
    "InvalidExtensionMinutesError",
    "GuestPasswordLoginFailedError",
    "GuestPasswordSetupNotAuthorizedError",
    "GuestPasswordTooWeakError",
    "GuestSelfDisconnectNotAuthorizedError",
    "MacAddressNotAuthorizedError",
    "GuestPinLoginFailedError",
    "GuestPinSetupNotAuthorizedError",
    "GuestPinTooWeakError",
    "GuestPinLockedError",
]


class GuestError(CloudGuestError):
    """Base exception for Guest domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class GuestNotFoundError(GuestError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Guest not found: {identifier}", status_code=status.HTTP_404_NOT_FOUND
        )


class CrossOrganizationGuestAccessError(GuestError):
    """A caller acting within organization A attempted to read/mutate a
    guest (or guest session) belonging to organization B -- mirrors
    ``app.domains.voucher.exceptions.CrossOrganizationVoucherBatchAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a guest belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class GuestBlockedError(GuestError):
    """The guest identified by this identifier has ``is_blocked=True`` --
    an admin-set ban. Raised before any OTP/voucher verification is even
    attempted, so a blocked guest never learns whether their code/voucher
    would otherwise have been valid."""

    def __init__(self, reason: str | None = None) -> None:
        message = "This guest has been blocked from guest WiFi access"
        if reason:
            message += f": {reason}"
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class GuestSessionNotFoundError(GuestError):
    def __init__(self, session_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Guest session not found: {session_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class GuestAuthMethodNotEnabledError(GuestError):
    """The resolved captive portal config for this location does not have
    the requested auth method enabled -- composes with
    ``CaptivePortalService.resolve_portal_config``, never re-implements
    that lookup."""

    def __init__(self, auth_method: str) -> None:
        super().__init__(
            f"Auth method '{auth_method}' is not enabled for this location's "
            "captive portal",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class VenueClosedError(GuestError):
    """The venue's Open Hours schedule says it is closed right now.

    ``captive_portal.validators.is_open_now`` shipped, was validated, and was
    evaluated on exactly one line in the whole backend --
    ``captive_portal/router.py``'s config-resolve response, as an advisory
    boolean for the portal UI. No login path consulted it, so a guest (or a
    script) hitting the login endpoint directly outside opening hours was
    authenticated normally. /how-it-works sells the opposite: "Outside those
    hours, guests see a 'we're closed' message instead of a working login
    screen. Nobody has to remember to switch anything off at close."

    Carries the venue's own ``business_hours_closed_message`` when one is set,
    so the guest sees the words the operator wrote rather than a generic
    refusal.
    """

    def __init__(self, closed_message: str | None = None) -> None:
        super().__init__(
            closed_message or "This WiFi network is closed right now.",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class GuestTeamSharedQuotaExceededError(GuestError):
    """The guest belongs to a team that has used up its shared data limit.

    Distinct from ``FairUsagePolicyExceededError``, which is a cap on one
    guest: this is the *pooled* cap across a whole team, the thing
    /features calls "one shared data limit" and /how-it-works shows as a
    usage bar on each group.

    ``GuestTeamService.check_shared_quota`` computed this correctly from the
    day it shipped and had no caller anywhere in the application, so a team
    with a 5 GB limit could use 50 GB unimpeded. See
    ``guest_teams.quota.SharedQuotaResolver`` for the gate.
    """

    def __init__(self) -> None:
        super().__init__(
            "Your group has used up its shared data allowance",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class RouterNotEligibleForGuestSessionError(GuestError):
    """The requested router is not in a status that may host a guest
    session (e.g. ``decommissioned``/``suspended``) -- composes with
    ``app.domains.router.enums.RouterStatus``, never re-implements it."""

    def __init__(self, router_id: uuid.UUID | str, router_status: str) -> None:
        super().__init__(
            f"Router {router_id} is not eligible to host a guest session "
            f"(status={router_status})",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidSessionStatusTransitionError(GuestError):
    """Raised when a requested status change is not a legal edge in
    ``app.domains.guest.constants.GUEST_SESSION_STATUS_TRANSITIONS``."""

    def __init__(self, current_status: str, requested_status: str) -> None:
        super().__init__(
            f"Cannot transition guest session from '{current_status}' to "
            f"'{requested_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class SessionTerminationCooldownError(GuestError):
    """The guest's most recent session was ``terminate_session``'d (a
    punitive, admin-driven kill) within
    ``constants.TERMINATION_RECONNECT_COOLDOWN_MINUTES`` -- see
    ``service.GuestService.terminate_session``'s docstring for why this is
    distinct from an ordinary ``disconnect_session``, which imposes no such
    cooldown."""

    def __init__(self, retry_after_minutes: int) -> None:
        self.retry_after_minutes = retry_after_minutes
        super().__init__(
            "This guest's access was terminated and cannot reconnect for "
            f"{retry_after_minutes} more minute(s)",
            status_code=status.HTTP_403_FORBIDDEN,
            data={"retry_after_minutes": retry_after_minutes},
        )


class NoReconnectableSessionError(GuestError):
    """``reconnect`` found no eligible prior session to derive a new session
    from -- either this guest has never logged in before, or their most
    recent session ended further in the past than
    ``constants.RECONNECT_GRACE_MINUTES`` ago. Either way, the guest must
    use ``login_via_otp``/``login_via_voucher`` instead."""

    def __init__(self, guest_id: uuid.UUID | str) -> None:
        super().__init__(
            f"No reconnectable session found for guest {guest_id} (none "
            "exists, or the prior session is outside the reconnect grace "
            "window)",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class RadiusNasDeviceOperationError(GuestError):
    """A router-side RADIUS write failed.

    502, not 200-with-an-error-body: the frontend's response interceptor
    unwraps ``data`` and never reads ``success``, so a ``200 {"success":
    false}`` is indistinguishable from a working push to every caller in
    the app -- which is the exact failure mode a device-push path exists to
    remove.
    """

    def __init__(self, operation: str, detail: str) -> None:
        super().__init__(
            f"RADIUS NAS device operation '{operation}' failed: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class RadiusNasMissingCredentialsError(GuestError):
    """The router has no reachable API credentials, so no push is possible.

    Refuses rather than reporting a push that never happened -- mirrors
    ``VlanMissingCredentialsError``.
    """

    def __init__(self, router_id: object) -> None:
        super().__init__(
            f"Router {router_id} has no management address or API credentials, "
            "so its RADIUS registration cannot be pushed",
            status_code=status.HTTP_409_CONFLICT,
        )


class RadiusNasNotSyncedError(GuestError):
    """The NAS row has no tunnel address, so there is nothing to send as
    ``src-address``.

    Refuses rather than pushing a registration without it: the hub matches
    an incoming request to a ``client{}`` stanza by source address, so such
    a registration would sit on the router looking correct and never
    authenticate anybody.
    """

    def __init__(self, nas_id: object) -> None:
        super().__init__(
            f"RADIUS NAS client {nas_id} has no tunnel address yet "
            "(the hub has not confirmed it), so it cannot be pushed to the router",
            status_code=status.HTTP_409_CONFLICT,
        )


class RadiusNasClientNotFoundError(GuestError):
    def __init__(self, nas_identifier: str) -> None:
        super().__init__(
            f"No RADIUS NAS client registered for nas_identifier "
            f"'{nas_identifier}'",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class RadiusNasAuthenticationError(GuestError):
    """The presented shared secret did not match the registered NAS
    client's decrypted ``shared_secret_encrypted``, or the NAS client is
    inactive -- see ``service.py``'s module docstring for why this is a
    shared-secret comparison, not RBAC's ``RequirePermission`` (FreeRADIUS
    has no platform-user identity)."""

    def __init__(self) -> None:
        super().__init__(
            "RADIUS NAS authentication failed", status_code=status.HTTP_401_UNAUTHORIZED
        )


class RadiusNasAlreadyRegisteredError(GuestError):
    """A router may only have one ``RadiusNasClient`` (one-to-one) -- see
    ``models.RadiusNasClient``'s module docstring."""

    def __init__(self, router_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Router {router_id} already has a registered RADIUS NAS client",
            status_code=status.HTTP_409_CONFLICT,
        )


class RadiusNasNotFoundError(GuestError):
    """No ``RadiusNasClient`` exists with this primary-key id -- the
    admin-facing CRUD 404, distinct from ``RadiusNasClientNotFoundError``
    (used along the RADIUS wire-protocol path, keyed by
    ``nas_identifier`` instead)."""

    def __init__(self, nas_id: uuid.UUID | str) -> None:
        super().__init__(
            f"RADIUS NAS client not found: {nas_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class RadiusNasBridgeDeregistrationError(GuestError):
    """The hub's FreeRADIUS agent did not confirm removal of this NAS's
    live ``clients.conf`` stanza, so its shared secret may still be
    accepted by the real RADIUS server.

    Raised instead of logged-and-swallowed, which is what this path used
    to do. Deleting a NAS is a credential revocation: until the hub has
    confirmed the stanza is gone, the router can still authenticate
    guests, and telling an operator the delete succeeded is a lie with
    security consequences. Observed live on 2026-08-22 -- the agent had no
    ``DELETE`` handler at all and answered every request ``501 Unsupported
    method``, leaving 21 stanzas on the hub against 0 active NAS rows in
    the database, all five of the freshly "deleted" ones included.

    502 rather than 500: the failure is in a downstream dependency this
    service called, exactly as ``register_external_radius_nas`` already
    reports its own bridge failures.
    """

    def __init__(self, nas_identifier: str, reason: str) -> None:
        super().__init__(
            f"RADIUS NAS client '{nas_identifier}' was NOT removed from the "
            f"RADIUS server and has not been deleted: {reason}. Its shared "
            f"secret may still be live -- retry once the hub is reachable.",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class CrossOrganizationNasAccessError(GuestError):
    """A caller acting within organization A attempted to read/mutate a
    NAS belonging to organization B -- mirrors
    ``app.domains.guest_teams.exceptions.CrossOrganizationGuestTeamAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a RADIUS NAS client belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidNasStatusTransitionError(GuestError):
    """Raised when a requested status change is not a legal edge in
    ``constants.NAS_STATUS_TRANSITIONS``."""

    def __init__(self, current_status: str, requested_status: str) -> None:
        super().__init__(
            f"Cannot transition NAS from '{current_status}' to "
            f"'{requested_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidAnalyticsDateRangeError(GuestError):
    def __init__(self) -> None:
        super().__init__(
            "start_date must be before or equal to end_date",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class TooManyDeviceIdsError(GuestError):
    """Raised by ``GET /guest-devices`` (bulk MAC-address resolution, see
    ``constants.MAX_BULK_DEVICE_LOOKUP_IDS``'s own docstring) when a caller
    passes more ``device_ids`` than this endpoint accepts in one request --
    a real, documented bound rather than a silent truncation to the first
    ``limit`` ids, which would otherwise leave a report's later rows
    resolved to no MAC address at all with no indication why."""

    def __init__(self, *, requested: int, limit: int) -> None:
        self.limit = limit
        super().__init__(
            f"Requested {requested} device_ids, which exceeds the maximum "
            f"of {limit} allowed per request",
            status_code=status.HTTP_400_BAD_REQUEST,
            data={"max_device_ids": limit},
        )


class RadiusAccountingUnsupportedStatusTypeError(GuestError):
    """Raised by ``POST /radius/accounting`` for an
    ``Acct-Status-Type`` this module does not (yet) handle -- e.g. RFC
    2866's ``modem-start``/``modem-stop``/``cyclic-guest-oth``. Deliberately
    explicit rather than silently falling through to the ``stop`` handling
    path (the previous shape of this endpoint's status-type dispatch, before
    ``accounting-on``/``accounting-off`` were added) -- an unrecognized
    status type is not the same event as a real Accounting-Stop, and must
    never be treated as one."""

    def __init__(self, status_type: str) -> None:
        super().__init__(
            f"Unsupported RADIUS Acct-Status-Type '{status_type}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class ConcurrentSessionLimitExceededError(GuestError):
    """The guest already holds
    ``constants.DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST`` (or more)
    ``ACTIVE`` sessions -- raised by
    ``service._enforce_concurrent_session_limit`` before a new session is
    created via ``login_via_otp``/``login_via_voucher``. Mirrors
    ``GuestBlockedError``'s "reject before touching OTP/voucher
    verification" placement in the caller, and ``SessionTerminationCooldownError``'s
    shape of surfacing the limit back to the caller as structured ``data``
    rather than only in the message string. An admin can free a slot with
    the existing ``terminate_session``/``disconnect_session`` endpoints --
    this module deliberately does not auto-evict the oldest session on the
    guest's behalf, so a guest never loses an active connection they didn't
    ask to end."""

    def __init__(self, *, guest_id: uuid.UUID | str, limit: int) -> None:
        self.limit = limit
        super().__init__(
            f"Guest {guest_id} already has {limit} active session(s), which "
            "is the maximum allowed at once",
            status_code=status.HTTP_409_CONFLICT,
            data={"max_concurrent_sessions": limit},
        )


class GuestDeviceLimitExceededError(GuestError):
    """The guest already has ``limit`` (or more) distinct
    :class:`~.models.GuestDevice` rows registered -- raised by
    ``service._enforce_device_limit`` before a *new* device would be
    registered (or an existing device reassigned to this guest) via
    ``login_via_otp``/``login_via_voucher``. ``limit`` is resolved through
    the real ``PolicyType.DEVICE`` seam when a ``policy_lookup`` hook is
    wired (``app.domains.policy.schemas.DevicePolicyRules
    .max_devices_per_guest``), falling back to
    ``constants.DEFAULT_MAX_DEVICES_PER_GUEST`` otherwise -- mirrors
    ``ConcurrentSessionLimitExceededError``'s identical shape and "surface
    the limit back to the caller as structured ``data``" convention. MAC
    uniqueness itself is unchanged by this check -- it only gates *how
    many* devices one guest may hold, never which physical device a MAC
    address belongs to."""

    def __init__(self, *, guest_id: uuid.UUID | str, limit: int) -> None:
        self.limit = limit
        super().__init__(
            f"Guest {guest_id} already has {limit} device(s) registered, "
            "which is the maximum allowed",
            status_code=status.HTTP_409_CONFLICT,
            data={"max_devices_per_guest": limit},
        )


class FairUsagePolicyExceededError(GuestError):
    """The guest already meets or exceeds a configured ``PolicyType.FUP``
    (Fair Usage Policy) ``daily``/``weekly``/``monthly`` data or time cap --
    raised by ``service.GuestService._enforce_fup_quota`` before a new
    session is created via ``login_via_otp``/``login_via_voucher``, exactly
    mirroring ``GuestDeviceLimitExceededError``'s/
    ``ConcurrentSessionLimitExceededError``'s "reject before touching
    OTP/voucher verification" placement and structured-``data`` shape.
    Unlike those two, there is no platform-wide fallback limit here at
    all -- this is only ever raised when a real ``PolicyType.FUP`` rule
    resolved a concrete cap for the guest's own organization (see
    ``app.domains.policy.constants``'s "no seeded default" write-up for
    ``FUP``); a deployment with no Policy Engine configured, or one with
    no FUP policy assigned, never raises this at all. ``metric``
    distinguishes a data cap (``"data"``, ``limit``/``used`` in MB) from a
    time cap (``"time"``, ``limit``/``used`` in minutes)."""

    def __init__(
        self,
        *,
        guest_id: uuid.UUID | str,
        period_type: str,
        metric: str,
        limit: int,
        used: int,
    ) -> None:
        self.period_type = period_type
        self.metric = metric
        self.limit = limit
        self.used = used
        unit = "MB" if metric == "data" else "minute(s)"
        super().__init__(
            f"Guest {guest_id} has used {used} {unit} of their {period_type} "
            f"{metric} allowance ({limit} {unit}), which is the maximum "
            "allowed for this period",
            status_code=status.HTTP_409_CONFLICT,
            data={
                "period_type": period_type,
                "metric": metric,
                "limit": limit,
                "used": used,
            },
        )


class InvalidExtensionMinutesError(GuestError):
    """``GuestService.extend_session`` was called with a non-positive
    ``additional_minutes`` -- mirrors ``InvalidAnalyticsDateRangeError``'s
    identical minimal input-validation shape. Extending by zero or a
    negative amount would either be a no-op or silently shorten the
    session, neither of which is what an admin calling "extend" means."""

    def __init__(self, additional_minutes: int) -> None:
        super().__init__(
            f"additional_minutes must be positive, got {additional_minutes}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class GuestPasswordLoginFailedError(GuestError):
    """Raised by ``GuestService.login_via_password`` for *every* way a
    password login can fail: no ``Guest`` row exists for this identifier at
    all, one exists but has never called ``set_guest_password``
    (``hashed_password IS NULL``), or one exists with a password that
    simply didn't match. All three collapse to this one, deliberately
    generic message -- distinguishing them in the response would let an
    attacker enumerate which phone numbers/emails are registered guests
    (and, separately, which of those have a password set) purely from this
    endpoint's error text, the same "don't leak identifier existence via a
    login failure" posture ``app.domains.auth.router``'s own ``/auth/login``
    already establishes for platform user accounts."""

    def __init__(self) -> None:
        super().__init__(
            "Invalid phone number/email or password. If you haven't set a "
            "password yet, please sign in with a one-time code instead.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class GuestPasswordSetupNotAuthorizedError(GuestError):
    """``GuestService.set_guest_password`` requires proof of a
    just-completed, still-``ACTIVE`` OTP-authenticated ``GuestSession``
    (see that method's docstring) -- raised when the presented
    ``session_id`` doesn't satisfy every leg of that proof: it doesn't
    exist, belongs to a different guest, wasn't created via
    ``otp_sms``/``otp_email``, is no longer ``ACTIVE``, or was started
    further in the past than
    ``constants.SET_PASSWORD_SESSION_WINDOW_MINUTES`` ago. Deliberately one
    generic message across every one of those distinct reasons -- the
    caller's only correct remedy is the same regardless of which leg
    failed: log in again via OTP, then retry immediately."""

    def __init__(self) -> None:
        super().__init__(
            "This session isn't eligible to set a password -- please sign "
            "in again with a one-time code and try again right after.",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class GuestProfileUpdateNotAuthorizedError(GuestError):
    """``GuestService.update_guest_profile`` requires the exact same proof
    of a just-completed, still-``ACTIVE`` OTP-authenticated ``GuestSession``
    that ``GuestPasswordSetupNotAuthorizedError`` documents for
    ``set_guest_password`` -- same eligibility check, same one generic
    message across every distinct reason it can fail (session doesn't
    exist / wrong guest / not an OTP session / no longer active / too old),
    same remedy: log in again via a one-time code and try again right
    after."""

    def __init__(self) -> None:
        super().__init__(
            "This session isn't eligible to update your details -- please "
            "sign in again with a one-time code and try again right after.",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class GuestPasswordTooWeakError(GuestError):
    """Wraps ``app.domains.auth.password.PasswordStrengthError`` from
    ``PasswordManager.validate_strength`` (composed, not reimplemented --
    the exact same strength policy platform ``AuthUser`` passwords are held
    to) in this domain's own exception hierarchy, so
    ``GuestService.set_guest_password`` callers only ever need to catch
    ``GuestError`` subclasses, not reach into ``app.domains.auth`` too."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason, status_code=status.HTTP_400_BAD_REQUEST)


class GuestSelfDisconnectNotAuthorizedError(GuestError):
    """``GuestService.disconnect_own_session`` requires the presented
    ``session_id`` to actually belong to the presented ``guest_id`` -- the
    same "no platform-user JWT a guest could ever present" situation
    ``GuestPasswordSetupNotAuthorizedError`` documents, applied to a guest
    ending their own connection instead of setting a password. Raised when
    the session doesn't exist or belongs to a different guest; a session
    that exists but is already non-``ACTIVE`` instead surfaces the ordinary
    ``InvalidSessionStatusTransitionError`` (a guest is allowed to learn
    that -- it isn't proof of anything the way ownership is)."""

    def __init__(self) -> None:
        super().__init__(
            "This session isn't yours to disconnect.",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class MacAddressNotAuthorizedError(GuestError):
    """``GuestService.login_via_mac_whitelist`` rejects this device --
    either no ``mac_authorization_hook`` is wired in at all (the feature
    is simply not turned on for this deployment), or a real
    ``MacAuthorizationService.is_mac_authorized`` lookup came back
    ``False`` for this ``mac_address``/``organization_id`` pair (never
    whitelisted, disabled, or expired -- see that method's own docstring;
    it never distinguishes those reasons, and neither does this). Meant
    to be handled silently by the guest-facing frontend: unlike a wrong
    OTP/password, this isn't a guest-visible mistake to show an error for
    -- it just means "fall back to the normal sign-in card", which every
    real enabled method (OTP/voucher/password) stays available on
    regardless."""

    def __init__(self, mac_address: str) -> None:
        super().__init__(
            f"MAC address not authorized: {mac_address}",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class GuestPinLoginFailedError(GuestError):
    """Raised by ``GuestService.login_via_pin`` for *every* way a PIN
    login can fail: no ``Guest`` row exists for this identifier at all,
    one exists but has never called ``set_guest_pin``
    (``hashed_pin IS NULL``), one exists with a PIN that simply didn't
    match, the presented ``device_mac`` is missing or doesn't belong to
    this guest's own ``GuestDevice`` history, or a real PIN match came
    back against a PIN that is now stale (older than
    ``constants.PIN_STALE_AFTER_DAYS`` -- see that constant's own
    docstring). All five collapse to this one, deliberately generic
    message -- the exact same "don't leak identifier existence, or which
    of these five reasons applies, via a login failure" posture
    ``GuestPasswordLoginFailedError`` already establishes for password
    login, extended here to also cover device recognition and staleness."""

    def __init__(self) -> None:
        super().__init__(
            "Invalid PIN, or this device isn't recognized. Please sign in "
            "with a one-time code instead.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class GuestPinSetupNotAuthorizedError(GuestError):
    """``GuestService.set_guest_pin`` requires the exact same proof of a
    just-completed, still-``ACTIVE`` OTP-authenticated ``GuestSession``
    that ``GuestPasswordSetupNotAuthorizedError`` documents for
    ``set_guest_password`` (reusing that same
    ``constants.SET_PASSWORD_SESSION_WINDOW_MINUTES`` window) -- raised
    when the presented ``session_id`` doesn't satisfy every leg of that
    proof. One generic message across every distinct reason it can fail,
    for the identical reason ``GuestPasswordSetupNotAuthorizedError``
    gives: the caller's only correct remedy is the same regardless of
    which leg failed."""

    def __init__(self) -> None:
        super().__init__(
            "This session isn't eligible to set a PIN -- please sign in "
            "again with a one-time code and try again right after.",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class GuestPinTooWeakError(GuestError):
    """``GuestService.set_guest_pin`` rejects a PIN that isn't exactly
    ``constants.PIN_LENGTH`` all-digit characters, or that is (see
    ``validators.is_weak_pin``'s own docstring for exactly which two
    shapes) trivially guessable -- this domain's own PIN-appropriate
    equivalent of ``GuestPasswordTooWeakError``/
    ``PasswordManager.validate_strength``, which a fixed-length numeric
    PIN could never satisfy in the first place (see
    ``app.domains.auth.password.PasswordManager.hash_raw``'s own
    docstring)."""

    def __init__(
        self,
        reason: str = (
            "This PIN is too easy to guess -- please choose a different one."
        ),
    ) -> None:
        super().__init__(reason, status_code=status.HTTP_400_BAD_REQUEST)


class GuestPinLockedError(GuestError):
    """``GuestService.login_via_pin``'s brute-force lockout -- raised by
    ``GuestPinSecurity.check_lockout`` (see that class's own docstring)
    once a ``(organization_id, identifier)`` pair has accumulated
    ``constants.PIN_MAX_ATTEMPTS`` (or more) failed PIN attempts within
    the current ``constants.PIN_LOCKOUT_MINUTES`` window. Mirrors
    ``app.domains.auth.security.AccountLockedError``'s identical shape
    and status code (423 Locked, ``locked_until`` carried on the
    exception instance) -- reused as a *pattern*, not literally
    subclassed or imported, since this domain's exception hierarchy is
    entirely rooted in ``GuestError`` (see ``GuestPasswordTooWeakError``'s
    docstring for why every guest-facing exception lives here, not in
    ``app.domains.auth``). Deliberately a distinct exception from
    ``GuestPinLoginFailedError`` -- unlike a routine wrong PIN, a lockout
    is not itself proof of anything about ``identifier`` (the caller was
    already told they hold the identifier, however wrongly, by the mere
    fact that this many attempts were made against it), so the
    guest-facing frontend is meant to render this differently: "try again
    in N minutes" rather than a plain "wrong PIN"."""

    def __init__(self, locked_until: datetime) -> None:
        self.locked_until = locked_until
        super().__init__(
            "Too many incorrect PIN attempts. Please try again later, or "
            "sign in with a one-time code instead.",
            status_code=status.HTTP_423_LOCKED,
        )
