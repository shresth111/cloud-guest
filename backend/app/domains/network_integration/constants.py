"""Enums, error codes and tunable defaults for the Network Integration domain.

Every value a caller may send or receive on this domain's API is named here
once, so ``schemas.py`` validates against the same set ``service.py``
branches on and ``router.py`` renders -- the convention every other domain
in this codebase follows (see ``app.domains.isp.constants``).

## Why ``NetworkProviderKind`` and not ``ControllerVendor``

The gateway package has its own ``ControllerVendor`` enum (see the shared
contract §2). It is deliberately *not* imported here. ``constants.py`` is
reachable from ``service.py``, ``router.py``, ``schemas.py`` and the
migration's own comments, and the whole point of the provider seam is that
none of those four ever learn that TP-Link exists: only
``providers/omada.py`` imports anything from ``wyfy_device_gateway``. So
this enum is this domain's *own* vocabulary, and
``providers/omada.py::OmadaProvider`` is the single place the two spellings
are mapped onto each other. Adding a second vendor is a new member here, a
new module under ``providers/``, and one line in that package's registry --
no edit to ``service.py``, ``router.py`` or ``models.py``.

## Why the status enum has seven members and not three

``IntegrationStatus`` distinguishes *four* different unhappy states, and
the distinction is the operational point rather than decoration:

* ``AUTH_FAILED`` -- we reached the controller and it rejected our stored
  credentials. Somebody rotated the operator password or deleted the Open
  API client. A human must re-enter credentials; retrying will never help.
* ``CONNECTION_FAILED`` -- we never got a usable answer at all: DNS,
  routing, TLS, a closed port, a box that is off. Retrying may well help,
  and nothing about the credentials is known to be wrong.
* ``SYNC_ERROR`` -- authentication and connectivity both worked, but a
  specific read (sites, devices, clients) failed. The integration is
  *live*; a subset of its data is stale.
* ``UNCONFIGURED`` -- the row exists but is not yet usable: no credentials
  stored, or no site selected. Nothing has failed; nothing has been
  finished either.

Collapsing these into one ``error`` state is what makes a status badge
useless: three of them need three different actions from three different
people, and one of them is not an error.

## Redaction is a write-time constant, not a logging filter

``REDACTED_CONTEXT_KEYS`` is applied by ``service.py`` before a
``network_integration_events`` row or an audit entry is written -- not by a
log formatter. A log filter protects the log; it does nothing about a
secret that has already been persisted into a JSONB column that the
customer dashboard then renders. The table is the thing that has to be
clean, so the redaction happens on the way into it.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "AuthorizationStatus",
    "ControllerAuthMode",
    "ControllerTlsMode",
    "DEFAULT_CONTROLLER_PORTS",
    "DEFAULT_CONTROLLER_TLS_MODE",
    "DEFAULT_SESSION_DURATION_SECONDS",
    "DEFAULT_SYNC_INTERVAL_SECONDS",
    "ErrorCode",
    "IntegrationEventStatus",
    "IntegrationEventType",
    "IntegrationStatus",
    "NetworkIntegrationAuditAction",
    "AUDIT_ENTITY_TYPE",
    "MAX_SESSION_DURATION_SECONDS",
    "MAX_SYNC_INTERVAL_SECONDS",
    "MIN_SESSION_DURATION_SECONDS",
    "MIN_SYNC_INTERVAL_SECONDS",
    "NETWORK_INTEGRATION_SYNC_SWEEP_INTERVAL_SECONDS",
    "NetworkProviderKind",
    "PORTAL_READINESS_GAP_LABELS",
    "PortalReadinessGap",
    "ROUTER_VENDOR_BY_PROVIDER",
    "PORTAL_AUTHORIZE_RATE_LIMIT_KEY_TEMPLATE",
    "PORTAL_AUTHORIZE_MAX_ATTEMPTS_PER_WINDOW",
    "PORTAL_AUTHORIZE_WINDOW_SECONDS",
    "REDACTED_CONTEXT_KEYS",
    "REDACTION_PLACEHOLDER",
    "SYNC_BACKOFF_CAP_MULTIPLIER",
    "SYNC_SWEEP_MAX_INTEGRATIONS_PER_RUN",
    "SyncStatus",
    "TASK_RUN_NETWORK_INTEGRATION_SYNC_SWEEP",
]


class NetworkProviderKind(StrEnum):
    """Which third-party network controller an integration row talks to.

    One member today. See the module docstring for why this is this
    domain's own enum rather than a re-export of the gateway's
    ``ControllerVendor``.
    """

    OMADA = "omada"


# ============================================================================
# The three spellings of "Omada", and why this table exists
# ============================================================================
#
# The same physical box is named three different ways across this system,
# and none of the three can simply be renamed to match the others:
#
#   1. ``NetworkProviderKind.OMADA == "omada"`` -- THIS domain's vocabulary.
#      Appears in `network_integrations.provider`, in the API contract
#      (§3 pins `"provider": "omada"`), and in the frontend's types.
#   2. ``Router.vendor == "tplink_omada"`` -- the FLEET's vocabulary. The
#      `routers.vendor` column is a free `String(50)` (no enum, no CHECK --
#      verified) whose 15 per-domain adapter registries are keyed on it.
#   3. ``wyfy_device_gateway.controller_contract.ControllerVendor
#      .TPLINK_OMADA == "tplink_omada"`` -- the GATEWAY's vocabulary, and
#      deliberately distinct from that package's own
#      ``DeviceVendor.TPLINK_OMADA`` despite the identical string (that
#      module documents them as "not interchangeable": one means a
#      router-shaped device, the other a controller).
#
# Translating between 1 and 2 is unavoidable and belongs in exactly one
# place, which is this table. Aligning them by fiat was considered and
# rejected: changing (1) breaks a published API contract and the
# frontend; changing (2) means a data migration of a column that 15
# registries dispatch on. A two-entry dict is cheaper than either, and it
# makes the seam greppable.
#
# Translating between 1 and 3 happens in ``providers/omada.py`` and
# nowhere else -- see that module.
ROUTER_VENDOR_BY_PROVIDER: dict[str, str] = {
    NetworkProviderKind.OMADA.value: "tplink_omada",
}


class ControllerAuthMode(StrEnum):
    """How this platform authenticates to the controller.

    Both modes are real and both are supported per-integration, because
    they are not alternatives that do the same job:

    * ``OPENAPI`` -- ``client_id``/``client_secret`` issued by the
      controller's own *Platform Integration > Open API* screen. Available
      on controller v5.13+. This is the inventory/telemetry path (sites,
      devices, clients).
    * ``LEGACY`` -- an operator ``name``/``password``. Available from
      v5.0.15. This is the path the *external captive portal* client
      authorization actually uses.

    A venue on a controller older than v5.13 has only ``LEGACY``. A venue
    on a newer controller may still need ``LEGACY`` for the portal step.
    Which is why this is a per-integration field and not a platform
    setting.
    """

    OPENAPI = "openapi"
    LEGACY = "legacy"


class ControllerTlsMode(StrEnum):
    """How much this platform trusts the certificate a controller presents.

    ## Why three modes and not a ``verify_tls`` boolean

    There was a boolean. It lived on the provider config dataclass, defaulted
    to ``True``, and **nothing in ``app/`` ever set it** -- no column, no
    schema field, no service parameter -- so in practice it was the constant
    ``True``. Which meant a self-hosted Omada controller could not be
    integrated at all, because those ship a self-signed certificate: the one
    this was first tested against answers with ``CN=localhost`` issued by
    itself.

    Making the boolean reachable would have fixed that by handing operators a
    switch whose only two positions are "cannot connect" and "no certificate
    check whatsoever". Everybody picks the second, once, on the day they are
    trying to get a venue online, and nothing records what they accepted.

    So the middle answer gets to exist:

    * ``STRICT`` -- ordinary public-CA verification. The default, because a
      default weaker than the rest of this platform's HTTPS posture is a
      decision nobody consciously made.
    * ``PINNED`` -- the controller's certificate must match the SHA-256
      fingerprint recorded on the integration row. This is the right answer
      for a self-signed controller and it is *stronger* than what a public CA
      buys: an interceptor has to hold that exact certificate, not merely one
      some CA will issue. The fingerprint is captured and shown to the
      operator by Test Connection, so pinning is a thing they confirm rather
      than a thing they have to go and find.
    * ``INSECURE`` -- no check. Reachable on purpose, because a controller
      behind something that reissues certificates constantly is a real
      configuration and refusing to model it pushes people to worse places.
      Never a default; the row records when it was chosen and the audit log
      records who.

    The mode is per-integration, not a platform setting, for the same reason
    ``ControllerAuthMode`` is: one tenant's controller has a real certificate
    and the next one's does not.
    """

    STRICT = "strict"
    PINNED = "pinned"
    INSECURE = "insecure"


#: What an integration created without saying anything about TLS gets, and
#: what every row that predates the column is backfilled to. Strict, so the
#: migration changes no existing integration's behaviour.
DEFAULT_CONTROLLER_TLS_MODE = ControllerTlsMode.STRICT


class IntegrationStatus(StrEnum):
    """Current state of one integration row. See the module docstring for
    why the four unhappy states are kept apart."""

    CONNECTED = "connected"
    CONNECTING = "connecting"
    AUTH_FAILED = "auth_failed"
    CONNECTION_FAILED = "connection_failed"
    DISABLED = "disabled"
    SYNC_ERROR = "sync_error"
    UNCONFIGURED = "unconfigured"


class SyncStatus(StrEnum):
    """Outcome of the most recent background sync attempt.

    ``NEVER`` is a real, distinct third value rather than a ``NULL``
    ``last_sync_status``: "has never been polled" and "was polled and it
    went fine" are different facts, and a dashboard that renders a blank
    for the first one invites the reader to assume the second.
    """

    OK = "ok"
    ERROR = "error"
    NEVER = "never"


class PortalReadinessGap(StrEnum):
    """What is missing before this integration can authorize a single guest.

    ## Why this exists as its own vocabulary

    An operator can complete the onboarding wizard, see a green
    ``CONNECTED`` badge, and have a venue where nobody gets online. That is
    not hypothetical: ``_sync`` used to set ``CONNECTED`` on the strength
    of the controller conversation alone -- credentials worked,
    ``GET /api/info`` answered, sites listed -- while
    ``authorize_portal_client`` refused every guest because no site had
    been picked. Two different questions ("can we reach the controller"
    and "do we know what to ask it") wearing one status.

    ## Each member is a real branch in the authorize path, verified

    Not a wish list of fields that look important. Each one is a place
    ``authorize_portal_client`` actually stops:

    * ``CREDENTIALS_MISSING`` -- ``_credentials_for`` raises.
    * ``LOCATION_NOT_MAPPED`` -- the portal path resolves an integration by
      ``(organization_id, location_id, provider)``, so a NULL
      ``location_id`` means this row is never selected for any venue.
    * ``SITE_NOT_SELECTED`` -- an explicit
      ``NetworkIntegrationSiteNotSelectedError``.

    ``guest_ssid_id`` is deliberately **not** here. The wizard asks for it
    and the list view shows it, but nothing on the authorize path reads it
    -- the SSID name arrives in the controller's own redirect. Listing it
    as blocking would send an operator to fix something that was never
    stopping anyone, which is the same class of misdirection this enum
    exists to end.

    ``is_enabled = False`` is not here either: that is an operator's
    deliberate choice and ``IntegrationStatus.DISABLED`` already says so.
    A gap means unfinished, not switched off.
    """

    CREDENTIALS_MISSING = "credentials_missing"
    LOCATION_NOT_MAPPED = "location_not_mapped"
    SITE_NOT_SELECTED = "site_not_selected"


# One human sentence per gap, written for the operator who has to fix it
# -- so it names the step in the setup flow, not the column.
PORTAL_READINESS_GAP_LABELS: dict[PortalReadinessGap, str] = {
    PortalReadinessGap.CREDENTIALS_MISSING: (
        "no controller credentials have been saved"
    ),
    PortalReadinessGap.LOCATION_NOT_MAPPED: (
        "it is not mapped to a location, so no venue's guests resolve to it"
    ),
    PortalReadinessGap.SITE_NOT_SELECTED: (
        "no controller site has been selected"
    ),
}


class IntegrationEventType(StrEnum):
    """What happened, for the operational feed
    (``network_integration_events``).

    Every member here is also written to ``audit_log_entries`` through the
    existing audit domain when a *human* caused it -- the two are not
    redundant. The audit table answers "which user did this, platform
    wide, for compliance"; this feed answers "what has this one
    integration been doing", including the things no user did (a
    background sync failing at 03:00). A machine-caused event has no
    ``actor_user_id`` to put in an audit row, and a customer looking at
    one integration's timeline should not be handed the tenant's whole
    audit log.
    """

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ENABLED = "enabled"
    DISABLED = "disabled"
    CONFIG_CHANGED = "config_changed"
    CREDENTIALS_ROTATED = "credentials_rotated"
    TEST_CONNECTION = "test_connection"
    SYNC = "sync"
    PORTAL_AUTHORIZE = "portal_authorize"
    PORTAL_DEAUTHORIZE = "portal_deauthorize"


class IntegrationEventStatus(StrEnum):
    OK = "ok"
    ERROR = "error"


class AuthorizationStatus(StrEnum):
    """Lifecycle of one ``network_integration_authorizations`` row.

    ``EXPIRED`` is never reached by a background job in this build: it is
    derived at read time from ``expires_at``. There is no sweep that walks
    the table flipping rows, because the controller is the authority on
    whether a client is still authorized and this table is a *record of
    what we asked for*, not a mirror of controller state. Saying so here
    rather than leaving a status that silently never occurs.
    """

    AUTHORIZED = "authorized"
    EXPIRED = "expired"
    DEAUTHORIZED = "deauthorized"
    FAILED = "failed"


class ErrorCode(StrEnum):
    """Normalized, stable machine codes returned in the ``ApiResponse``
    ``data.code`` field on failure.

    The frontend owns the human copy and maps code -> string; the
    ``message`` this backend returns is already human-safe, but it is not
    the contract. The ten ``OMADA_*`` codes are the gateway's own
    normalized set (shared contract §2) passed through unchanged -- the
    provider layer translates the gateway's exception classes into this
    domain's exceptions, and the *code* survives that translation so the
    frontend has one vocabulary regardless of which layer failed.
    """

    NOT_FOUND = "NETWORK_INTEGRATION_NOT_FOUND"
    DISABLED = "NETWORK_INTEGRATION_DISABLED"
    URL_REJECTED = "NETWORK_INTEGRATION_URL_REJECTED"
    PROVIDER_UNSUPPORTED = "NETWORK_INTEGRATION_PROVIDER_UNSUPPORTED"
    ALREADY_EXISTS = "NETWORK_INTEGRATION_ALREADY_EXISTS"
    CREDENTIALS_REQUIRED = "NETWORK_INTEGRATION_CREDENTIALS_REQUIRED"
    ORGANIZATION_REQUIRED = "NETWORK_INTEGRATION_ORGANIZATION_REQUIRED"
    CROSS_ORGANIZATION = "NETWORK_INTEGRATION_CROSS_ORGANIZATION"
    CROSS_LOCATION = "NETWORK_INTEGRATION_CROSS_LOCATION"
    SITE_NOT_SELECTED = "NETWORK_INTEGRATION_SITE_NOT_SELECTED"
    GUEST_SESSION_NOT_ACTIVE = "GUEST_SESSION_NOT_ACTIVE"
    RATE_LIMITED = "NETWORK_INTEGRATION_RATE_LIMITED"
    # The Master onboarding path could not reach the fleet (router) domain
    # to register the controller as a device. A deployment error rather
    # than a user error -- see the exception of the same name for why this
    # refuses instead of falling back to a plain integration create.
    FLEET_DEVICE_UNAVAILABLE = "NETWORK_INTEGRATION_FLEET_DEVICE_UNAVAILABLE"
    # The controller answered, and the integration still authorizes nobody
    # because the operator has not finished mapping it. Distinct from
    # CREDENTIALS_REQUIRED (which is one specific half of the same story)
    # so a caller can tell "we could not talk to the box" from "we talked
    # to the box and there is nothing to talk to it about".
    SETUP_INCOMPLETE = "NETWORK_INTEGRATION_SETUP_INCOMPLETE"

    AUTH_FAILED = "OMADA_AUTH_FAILED"
    CONNECTION_FAILED = "OMADA_CONNECTION_FAILED"
    TIMEOUT = "OMADA_TIMEOUT"
    PROVIDER_RATE_LIMITED = "OMADA_RATE_LIMITED"
    INVALID_CONTROLLER = "OMADA_INVALID_CONTROLLER"
    SITE_NOT_FOUND = "OMADA_SITE_NOT_FOUND"
    CLIENT_NOT_FOUND = "OMADA_CLIENT_NOT_FOUND"
    AUTHORIZATION_FAILED = "OMADA_AUTHORIZATION_FAILED"
    API_UNSUPPORTED = "OMADA_API_UNSUPPORTED"
    SESSION_EXPIRED = "OMADA_SESSION_EXPIRED"
    # Two codes, not one, and neither is CONNECTION_FAILED. A rejected
    # certificate and an unreachable address send an operator to opposite
    # ends of the problem, and "the certificate changed" is a third thing
    # again -- it is the only one of the three that might mean somebody is
    # in the middle. Collapsing them is how the original defect happened:
    # a self-signed controller reported as "check the URL and port" when
    # the URL and the port were both correct.
    TLS_UNTRUSTED = "OMADA_TLS_UNTRUSTED"
    TLS_PIN_MISMATCH = "OMADA_TLS_PIN_MISMATCH"
    # The request asked for pinning without supplying a fingerprint (or
    # supplied one that is not a SHA-256). A 400 from this platform, not a
    # 502 from the controller -- the controller was never contacted.
    TLS_PIN_REQUIRED = "NETWORK_INTEGRATION_TLS_PIN_REQUIRED"


# ============================================================================
# Defaults and bounds
# ============================================================================

# How long a portal authorization lasts on the controller, when the
# integration row does not say otherwise. One hour matches the platform's
# own default guest session length rather than being a number invented
# here.
DEFAULT_SESSION_DURATION_SECONDS = 3600
MIN_SESSION_DURATION_SECONDS = 60
# 24 hours, and this ceiling is a security control rather than a sanity
# bound.
#
# CR-001 (see /Users/shresth/wyfy-omada/CHANGE-REQUESTS.md).
# TP-Link publishes **no client-deauthorization endpoint** in any
# generation of the Omada API, so this platform cannot revoke a portal
# authorization it has already granted. The duration is therefore not a
# convenience default -- it is the *only* mechanism by which a guest's
# network access ever ends.
#
# That inverts how the number should be chosen. A generous ceiling would
# normally be harmless; here a 30-day authorization is 30 days during
# which an abusive guest cannot be removed from the venue's network by
# any action this platform can take. Ending the WyfyGuest ``GuestSession``
# row still works and is still required, but it does not touch the
# controller -- claiming otherwise is precisely the class of falsehood
# ``app.domains.guest_access.device_adapters`` was written to fix (read
# its "mechanism 4" note).
#
# 24 hours is the longest window in which "wait for it to expire" is a
# usable answer to "this guest is abusing the WiFi". Venues wanting
# longer sessions should re-authorize on the next portal hit, which costs
# the guest nothing and keeps the revocation window bounded.
MAX_SESSION_DURATION_SECONDS = 24 * 3600

DEFAULT_SYNC_INTERVAL_SECONDS = 300
# A floor, and a real one. Every sync tick is a live HTTP round trip to a
# customer's controller, which may be a small hardware box on a hotel's
# own uplink. Letting a tenant configure a 5-second interval would let
# them point this platform at their own hardware as a load generator.
MIN_SYNC_INTERVAL_SECONDS = 60
MAX_SYNC_INTERVAL_SECONDS = 86_400

# Controller ports this platform will connect to. Software controller
# HTTPS is 8043; OC-series hardware controllers answer on 443; 8843/8088
# appear in TP-Link's own documentation for older/alternate layouts. An
# allowlist rather than "any port" because the controller URL is
# user-supplied and reaches a server-side HTTP client -- an unrestricted
# port turns this field into a port scanner against whatever the platform
# can route to. Extendable per-deployment via
# ``Settings.omada_extra_allowed_controller_ports``.
DEFAULT_CONTROLLER_PORTS: frozenset[int] = frozenset({443, 8043, 8088, 8843})

# Keys whose values are stripped before an event/audit row is written.
# Matched case-insensitively against dictionary keys anywhere in a nested
# context payload. See the module docstring for why this is a write-time
# constant.
REDACTED_CONTEXT_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "client_secret",
        "client_id",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "csrf_token",
        "csrf-token",
        "cookie",
        "set-cookie",
        "authorization",
        "credentials",
        "credentials_encrypted",
        "session_cookie",
        "tpomada_sessionid",
        "tpeap_sessionid",
    }
)
REDACTION_PLACEHOLDER = "[redacted]"

# ============================================================================
# Background sync
# ============================================================================

TASK_RUN_NETWORK_INTEGRATION_SYNC_SWEEP = (
    "app.domains.network_integration.tasks.run_network_integration_sync_sweep"
)

# The Beat cadence, which is *not* the per-integration interval. Beat
# wakes this sweep every 60s; the sweep then polls only the integrations
# whose own ``sync_interval_seconds`` has actually elapsed. A single Beat
# entry cannot express "each row has its own period", so the tick is the
# greatest common divisor of the allowed intervals (== the floor) and the
# per-row decision is made in SQL. Mirrors
# ``app.domains.notification.tasks``'s identical arrangement.
NETWORK_INTEGRATION_SYNC_SWEEP_INTERVAL_SECONDS = 60.0

# A bound on one sweep run, so a tenant with a hundred integrations cannot
# make one tick run for an unbounded time and overlap the next. The rest
# are picked up on the following tick -- ordered by ``last_sync_at``
# ascending, so the most stale go first and nothing starves.
SYNC_SWEEP_MAX_INTEGRATIONS_PER_RUN = 50

# Consecutive-failure backoff cap, as a multiplier of the integration's
# own ``sync_interval_seconds``. A controller that has been unreachable
# for a day is polled every ``interval * 32`` rather than every
# ``interval`` -- which for the 300s default is once every ~2.7 hours, not
# 288 pointless HTTP timeouts a day. Capped rather than unbounded so a box
# that comes back is noticed within hours, not never.
SYNC_BACKOFF_CAP_MULTIPLIER = 32

# ============================================================================
# Portal authorize rate limiting
# ============================================================================

# In-domain, identifier-scoped limiter for POST /portal/authorize, keyed on
# the guest session -- the same INCR+EXPIRE+TTL Redis pattern
# ``app.domains.otp.service.OtpRateLimiter`` and
# ``app.domains.voucher.service.VoucherRedemptionRateLimiter`` already use.
#
# This is the *second* of two layers, not the only one:
# ``app.middleware.rate_limit.RateLimitMiddleware`` also covers this path
# per client IP. The two protect different things and both are needed --
# the middleware bounds one source hammering the endpoint while rotating
# session ids; this bounds one session being replayed from many sources.
PORTAL_AUTHORIZE_RATE_LIMIT_KEY_TEMPLATE = (
    "rate_limit:network_integration_portal_authorize:{source}"
)
# Sized for retries, not for use. A guest's device authorizes once per
# join; a captive-portal page that races or a user who taps twice makes
# two or three. Ten in five minutes is generous for every legitimate
# pattern and still bounds replay.
PORTAL_AUTHORIZE_MAX_ATTEMPTS_PER_WINDOW = 10
PORTAL_AUTHORIZE_WINDOW_SECONDS = 300


# ============================================================================
# Audit actions
# ============================================================================


class NetworkIntegrationAuditAction(StrEnum):
    """The actions this domain writes to ``audit_log_entries``.

    ## Why these live here and not in ``app.domains.rbac.enums.AuditAction``

    Most domains add their own members to that shared enum, and that is the
    better convention -- one place to read "every auditable action on the
    platform". Two existing domains do not:
    ``app.domains.provisioning_engine.planner.plan_service`` and
    ``app.domains.live_sessions.service`` both pass plain action strings.
    So a local vocabulary is precedented, and it is what this domain uses.

    The honest reason is coordination, not design: ``rbac/enums.py`` is
    being edited concurrently by another engineer on this same feature (the
    ``PermissionModule.NETWORK_INTEGRATIONS`` entry), and two writers on one
    enum is how one of the two sets of members quietly disappears in a
    merge. A ``StrEnum`` here produces byte-identical column values to
    members there, so folding these into ``AuditAction`` later is a
    mechanical change with no data migration -- the ``action`` column is a
    ``String(50)`` and does not care which Python enum produced the string.

    Every value is prefixed ``network_integration_`` so it cannot collide
    with an existing member of the shared enum, and so an auditor filtering
    the table by action prefix gets this domain's whole trail.
    """

    CONNECTED = "network_integration_connected"
    DISCONNECTED = "network_integration_disconnected"
    ENABLED = "network_integration_enabled"
    DISABLED = "network_integration_disabled"
    CONFIG_CHANGED = "network_integration_config_changed"
    CREDENTIALS_ROTATED = "network_integration_credentials_rotated"
    TEST_CONNECTION = "network_integration_test_connection"
    SYNCED = "network_integration_synced"
    # Its own action rather than a second CONNECTED entry. This one records
    # that the platform wrote a row into another domain's table -- the fleet
    # inventory -- on the operator's behalf, which is a materially different
    # act from a tenant registering a controller they already own, and an
    # auditor asking "where did this Router row come from" must be able to
    # find it by action alone. Contract §11.6.
    FLEET_DEVICE_ONBOARDED = "network_integration_fleet_device_onboarded"

# Audit entity_type for every entry this domain writes -- one value, so an
# auditor can retrieve the whole trail for one integration by
# (entity_type, entity_id) using the existing indexes on that table.
AUDIT_ENTITY_TYPE = "network_integration"
