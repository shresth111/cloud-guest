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
    "DEFAULT_PORTAL_AUTH_MODE",
    "DisconnectMechanism",
    "PortalAuthMode",
    "CONTROLLER_SETUP_GAP_LABELS",
    "CONTROLLER_SETUP_OPERATOR_PREFIX",
    "CONTROLLER_SETUP_PORTAL_NAME_MAX_LENGTH",
    "CONTROLLER_SETUP_PORTAL_NAME_PREFIX",
    "ControllerAuthMode",
    "ControllerSetupGap",
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
    "FLEET_DEVICE_DEFAULT_MODEL_BY_PROVIDER",
    "GUEST_OPERATOR_CREDENTIAL_FIELDS",
    "PORTAL_AUTHORIZE_RATE_LIMIT_KEY_TEMPLATE",
    "PORTAL_AUTHORIZE_MAX_ATTEMPTS_PER_WINDOW",
    "PORTAL_AUTHORIZE_DIAGNOSTICS_KEY",
    "PORTAL_AUTHORIZE_DIAGNOSTICS_ON_SUCCESS",
    "PORTAL_REDIRECT_STALE_AFTER_SECONDS",
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

# What lands in ``routers.model`` (NOT NULL) when a fleet row is registered
# for a controller whose operator was never asked for a model -- the
# customer self-service path and the "Register controller" repair action.
# The Master onboarding wizard asks, and what it is told wins. Keyed by
# provider for the same reason the table above is: ``service.py`` does not
# name vendors.
FLEET_DEVICE_DEFAULT_MODEL_BY_PROVIDER: dict[str, str] = {
    NetworkProviderKind.OMADA.value: "Omada Controller",
}

# The credential pair that authorizes a guest. Omada's only external-portal
# authorization endpoint takes a hotspot *operator* login, in either auth
# mode -- an Open API app can read inventory but cannot let anybody online.
# So an Open API integration needs this pair stored alongside its client
# id/secret before it can serve a venue; see
# ``PortalReadinessGap.GUEST_OPERATOR_MISSING``.
GUEST_OPERATOR_CREDENTIAL_FIELDS: frozenset[str] = frozenset({"username", "password"})


class PortalAuthMode(StrEnum):
    """Which of the controller's two captive-portal contracts this venue is
    on. **Stored, never inferred.**

    An Omada controller can put a guest online by two completely different
    routes, and they are not variants of one flow -- they invert the
    direction of trust:

    * ``EXTERNAL_PORTAL`` -- TP-Link ``authType 4``, *External Portal
      Server*. The guest's browser posts its identity to **us**; this
      platform then calls the controller's ``hotspot/extPortal/auth`` with
      a stored operator session and the controller opens the gate. Every
      call is **outbound** from this platform, so it works through a
      venue's NAT with nothing exposed on our side. This is what the whole
      integration was built and proven on (a real guest, real hardware,
      2026-09-11) and it is the default for every integration, existing
      and new.
    * ``RADIUS`` -- TP-Link ``authType 2`` + *External Web Portal*. The
      guest's browser posts its identity to **the controller**
      (``POST /portal/radius/browserauth``), the controller becomes the
      RADIUS client and sends an **inbound** Access-Request to this
      platform's FreeRADIUS, and the controller opens the gate on the
      Access-Accept. This platform is not in the authorization path at
      all.

    ## Why this is a column and not a derivation

    The two modes send *different redirect parameters* (``authType 2``
    carries ``target``/``targetPort``/``scheme`` and carries **no**
    ``site`` and no ``t``; ``authType 4`` is the mirror image of that), so
    it is tempting to let each surface sniff the query string and decide
    for itself. Three surfaces would then be guessing independently -- the
    guest portal, ``authorize_portal_client`` and the disconnect path --
    and a venue mid-migration, a stale pasted URL or a controller firmware
    that adds a parameter would make them disagree. A guest's internet
    access is the thing that disagreement breaks.

    So the row holds the answer, ``build_external_portal_url`` stamps it
    into the URL the operator pastes, and each surface dispatches on that
    one answer. Where a surface can *also* see the redirect's own shape it
    uses it as a **cross-check** that refuses loudly, never as a second
    opinion that quietly wins.

    ## RADIUS is opt-in and must stay opt-in

    ``EXTERNAL_PORTAL`` is the column default and the server default, so
    every existing row and every new row is on the proven path. Moving a
    venue to ``RADIUS`` requires, today, all of: an inbound UDP path to
    this platform's FreeRADIUS that does not exist yet, a NAS client
    keyed on the controller's public address, and a certificate the
    guest's browser will accept on the controller itself. None of those
    can be arranged by flipping a field, which is why the field alone
    never turns anything on -- see ``ops/runbooks/omada-radius-mode.md``.
    """

    EXTERNAL_PORTAL = "external_portal"
    RADIUS = "radius"


# The mode every integration is in unless somebody deliberately moved it.
# Named once, here, so the column default, the server default, the
# migration's backfill and the "is this venue on the proven path" checks
# cannot drift apart.
DEFAULT_PORTAL_AUTH_MODE: PortalAuthMode = PortalAuthMode.EXTERNAL_PORTAL


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
    * ``GUEST_OPERATOR_MISSING`` -- an Open API integration whose stored
      credential set has no hotspot operator login. The provider refuses
      every guest with ``OMADA_API_UNSUPPORTED``, because the controller's
      only external-portal authorization endpoint takes an operator login
      whatever mode the integration reads inventory with. Before this gap
      existed such a row synced green -- the Open API app works -- and
      authorized nobody.
    * ``LOCATION_NOT_MAPPED`` -- the portal path resolves an integration by
      ``(organization_id, location_id, provider)``, so a NULL
      ``location_id`` means this row is never selected for any venue.
    * ``SITE_NOT_SELECTED`` -- an explicit
      ``NetworkIntegrationSiteNotSelectedError``.
    * ``FLEET_DEVICE_MISSING`` -- there is no ``router_id`` to put in the
      venue's portal URL, and none to put in ``guest_sessions.router_id``
      (NOT NULL) if a guest somehow reached a sign-in screen anyway.

      This one is not a branch inside ``authorize_portal_client``; it is
      *earlier* than the whole flow, and it is here because
      ``network_integrations.router_id`` is nullable and must stay nullable
      -- a customer self-service integration legitimately has no fleet row
      (see that column's own docstring). So an integration can be
      credentialled, mapped, site-selected and CONNECTED, and still be
      unable to issue a single guest session, because there is no value to
      put in that NOT NULL column and no router id to hand the portal.

      Nothing consumed that fact until the Omada guest flow existed, which
      is exactly why it was invisible; now it decides whether the dashboard
      can give a venue a portal URL at all. The customer path now registers
      the fleet row itself once the integration is mapped to a venue, and
      ``POST /{id}/fleet-device`` repairs a row created before it did.

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
    GUEST_OPERATOR_MISSING = "guest_operator_missing"
    LOCATION_NOT_MAPPED = "location_not_mapped"
    SITE_NOT_SELECTED = "site_not_selected"
    FLEET_DEVICE_MISSING = "fleet_device_missing"


# One human sentence per gap, written for the operator who has to fix it
# -- so it names the step in the setup flow, not the column.
PORTAL_READINESS_GAP_LABELS: dict[PortalReadinessGap, str] = {
    PortalReadinessGap.CREDENTIALS_MISSING: (
        "no controller credentials have been saved"
    ),
    PortalReadinessGap.GUEST_OPERATOR_MISSING: (
        "it has an Open API app but no hotspot operator account, and guest "
        "sign-in needs the operator account"
    ),
    PortalReadinessGap.LOCATION_NOT_MAPPED: (
        "it is not mapped to a location, so no venue's guests resolve to it"
    ),
    PortalReadinessGap.SITE_NOT_SELECTED: (
        "no controller site has been selected"
    ),
    PortalReadinessGap.FLEET_DEVICE_MISSING: (
        "it has no fleet device, so no guest session can be created for it"
    ),
}


class ControllerSetupGap(StrEnum):
    """Why "Configure controller automatically" cannot run for a row.

    Checked all at once, before any controller is contacted, so an operator
    sees every missing piece in one answer instead of fixing them one refusal
    at a time. Four members share their value -- and their wording, via
    ``CONTROLLER_SETUP_GAP_LABELS`` -- with ``PortalReadinessGap``, because
    they are the same fact. ``guest_operator_missing`` is deliberately absent:
    creating that account is one of the things the run does.
    """

    INTEGRATION_DISABLED = "integration_disabled"
    PROVIDER_UNSUPPORTED = "provider_unsupported"
    OPENAPI_REQUIRED = "openapi_required"
    CREDENTIALS_MISSING = PortalReadinessGap.CREDENTIALS_MISSING.value
    LOCATION_NOT_MAPPED = PortalReadinessGap.LOCATION_NOT_MAPPED.value
    SITE_NOT_SELECTED = PortalReadinessGap.SITE_NOT_SELECTED.value
    FLEET_DEVICE_MISSING = PortalReadinessGap.FLEET_DEVICE_MISSING.value
    GUEST_SSID_MISSING = "guest_ssid_missing"


CONTROLLER_SETUP_GAP_LABELS: dict[ControllerSetupGap, str] = {
    ControllerSetupGap.INTEGRATION_DISABLED: "the integration is disabled",
    ControllerSetupGap.PROVIDER_UNSUPPORTED: (
        "this controller type cannot be configured automatically"
    ),
    ControllerSetupGap.OPENAPI_REQUIRED: (
        "it signs in with a hotspot operator login, and automatic setup needs "
        "an Open API app (controller Settings > Platform Integration > Open "
        "API, controller v5.13 or newer)"
    ),
    ControllerSetupGap.CREDENTIALS_MISSING: (
        "no Open API app credentials (client ID and secret) have been saved"
    ),
    ControllerSetupGap.LOCATION_NOT_MAPPED: PORTAL_READINESS_GAP_LABELS[
        PortalReadinessGap.LOCATION_NOT_MAPPED
    ],
    ControllerSetupGap.SITE_NOT_SELECTED: PORTAL_READINESS_GAP_LABELS[
        PortalReadinessGap.SITE_NOT_SELECTED
    ],
    ControllerSetupGap.FLEET_DEVICE_MISSING: PORTAL_READINESS_GAP_LABELS[
        PortalReadinessGap.FLEET_DEVICE_MISSING
    ],
    ControllerSetupGap.GUEST_SSID_MISSING: "no guest SSID has been chosen",
}

#: The display name given to the portal automatic setup creates, before the
#: integration's short id is appended -- see
#: ``service._controller_setup_portal_name``.
CONTROLLER_SETUP_PORTAL_NAME_PREFIX = "Wyfy Guest"
#: ``PortalSetting.name`` is 1 to 128 characters in TP-Link's spec.
CONTROLLER_SETUP_PORTAL_NAME_MAX_LENGTH = 128
#: The hotspot operator account automatic setup creates is named this plus
#: the first 12 hex digits of the integration id.
CONTROLLER_SETUP_OPERATOR_PREFIX = "wyfy-"


class DisconnectMechanism(StrEnum):
    """*How* a staff disconnect actually took a guest off the network, which
    differs by portal mode and does not mean the same thing in both.

    * ``CONTROLLER_AUTHORIZATION`` -- External Portal Server mode. This
      platform issued the authorization, holds a
      ``network_integration_authorizations`` row for it, and revokes that
      authorization on the controller. The row is flipped to
      ``DEAUTHORIZED`` and the guest's ``GuestSession`` is ended from it, so
      re-admission is closed as well.
    * ``CONTROLLER_CLIENT_ONLY`` -- RADIUS mode. This platform never issued
      the authorization (the controller did, on an Access-Accept), so there
      is no authorization row to revoke and none to find the guest's
      session from. All this call can do is ask the controller to drop the
      client. **Re-admission is not closed by it**: what closes that is
      ending the guest's ``GuestSession``, because the RADIUS authorize
      path is a session lookup -- see ``app.domains.guest.service
      .RadiusService.authorize``. That is a separate action on the guest
      domain, and this value is how a caller knows it is still outstanding.

    Named rather than inferred from the other booleans for the usual reason
    in this domain: "disconnected: true" already means one narrow thing, and
    a second narrow thing wearing the same word is how an operator ends up
    believing a guest was removed when they were merely dropped.
    """

    CONTROLLER_AUTHORIZATION = "controller_authorization"
    CONTROLLER_CLIENT_ONLY = "controller_client_only"


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
    # One row per real (non-dry) "Configure controller automatically" run,
    # carrying the per-step report. A dry run writes nothing, this included.
    CONTROLLER_CONFIGURED = "controller_configured"


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
    # A fleet row was asked for (the "Register controller" repair action) on
    # an integration that is not mapped to a venue. A device must be
    # somewhere; the fix is to pick the location first.
    LOCATION_REQUIRED = "NETWORK_INTEGRATION_LOCATION_REQUIRED"
    # The controller answered, and the integration still authorizes nobody
    # because the operator has not finished mapping it. Distinct from
    # CREDENTIALS_REQUIRED (which is one specific half of the same story)
    # so a caller can tell "we could not talk to the box" from "we talked
    # to the box and there is nothing to talk to it about".
    SETUP_INCOMPLETE = "NETWORK_INTEGRATION_SETUP_INCOMPLETE"
    # A guest portal called `POST /portal/authorize` for an integration
    # whose stored `portal_mode` is RADIUS. In that mode this platform is
    # not in the authorization path -- the guest's browser submits to the
    # controller and the controller asks our FreeRADIUS -- so the call is
    # a stale pasted URL or a mode change that has not reached the
    # controller yet. Refused with its own code rather than a generic
    # failure, because "this venue is configured for the other contract"
    # is the single most likely explanation and nothing else says it.
    # Never returned to the guest: this endpoint answers one
    # indistinguishable 403. It is what the integration's own event feed
    # records, which is where an operator looks.
    PORTAL_MODE_MISMATCH = "NETWORK_INTEGRATION_PORTAL_MODE_MISMATCH"
    # A caller asked for a RADIUS-mode operation on an integration that is
    # on the External Portal Server contract, or asked to move an
    # integration into RADIUS mode without the authority to do so.
    PORTAL_MODE_NOT_PERMITTED = "NETWORK_INTEGRATION_PORTAL_MODE_NOT_PERMITTED"
    # "Forget the stored hotspot operator login" was asked of a legacy-mode
    # integration, where that pair is the *only* credential -- clearing it
    # would leave the row unable to authenticate at all, which is what
    # deleting the integration is for. Its own code because the caller is
    # not wrong about the operation, only about which integration to run it
    # on, and the frontend hides the control rather than explaining it.
    GUEST_OPERATOR_REQUIRED = "NETWORK_INTEGRATION_GUEST_OPERATOR_REQUIRED"

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
    # The controller answered and refused: the Open API app's role or site
    # privileges do not cover the call (Omada -1005 / -1505). Not an auth
    # failure -- the credential is valid -- and not a connection failure.
    PERMISSION_DENIED = "OMADA_PERMISSION_DENIED"
    # The request asked for pinning without supplying a fingerprint (or
    # supplied one that is not a SHA-256). A 400 from this platform, not a
    # 502 from the controller -- the controller was never contacted.
    TLS_PIN_REQUIRED = "NETWORK_INTEGRATION_TLS_PIN_REQUIRED"
    # This deployment would encrypt controller credentials under the key
    # committed to the public repository. A 503 from this platform: nothing
    # the operator typed is wrong, and nothing was stored.
    ENCRYPTION_KEY_NOT_CONFIGURED = "NETWORK_INTEGRATION_ENCRYPTION_KEY_NOT_CONFIGURED"
    # "Configure controller automatically" refused before contacting the
    # controller: the integration is missing something the run needs. The
    # response's ``data.missing`` lists ``ControllerSetupGap`` values.
    AUTOCONFIG_PRECONDITIONS = "NETWORK_INTEGRATION_AUTOCONFIG_PRECONDITIONS"
    # Another organization's integration manages the same controller site.
    # Two tenants writing one site's portal and pre-auth settings would undo
    # each other, so neither may automate it. The other tenant is not named.
    CONTROLLER_SITE_SHARED = "NETWORK_INTEGRATION_CONTROLLER_SITE_SHARED"
    # Another integration in the same organization already uses this guest
    # SSID on this controller site. Two portals cannot both own one SSID.
    GUEST_SSID_IN_USE = "NETWORK_INTEGRATION_GUEST_SSID_IN_USE"
    # The guest SSID is bound to a portal this integration did not create.
    # Nothing was changed; ``take_over_ssid_portal`` releases it.
    PORTAL_CONFLICT = "NETWORK_INTEGRATION_PORTAL_CONFLICT"
    # The stored guest SSID does not exist on the site, or its name matches
    # more than one SSID there.
    GUEST_SSID_NOT_FOUND = "NETWORK_INTEGRATION_GUEST_SSID_NOT_FOUND"
    GUEST_SSID_AMBIGUOUS = "NETWORK_INTEGRATION_GUEST_SSID_AMBIGUOUS"


# ============================================================================
# Defaults and bounds
# ============================================================================

# How long a portal authorization lasts on the controller, when the
# integration row does not say otherwise. One hour matches the platform's
# own default guest session length rather than being a number invented
# here.
DEFAULT_SESSION_DURATION_SECONDS = 3600
MIN_SESSION_DURATION_SECONDS = 60
# 7 days. **The reason this number was originally chosen no longer holds.**
# It used to be a safety backstop; it is now a policy choice. Read both
# halves before touching it.
#
# ## The old reason, which was false
#
# This ceiling used to be justified entirely on CR-001's claim that
# TP-Link publishes no client-deauthorization endpoint, and therefore that
# this platform could never revoke an authorization it had granted. On
# that premise the duration was not a convenience default but the *only*
# mechanism by which a guest's access ever ended, which inverted how the
# number had to be chosen: a 30-day authorization would have been 30 days
# during which an abusive guest could not be removed from the venue's
# network by any action available to us.
#
# **That premise is false.** CR-001 was overturned (2026-09-10) and then
# found to be narrower still than its overturn said. A per-guest
# disconnect exists on the controller and is implemented:
# ``service.disconnect_guest`` -> the provider seam ->
# ``omada.deauth``, which lists the Hotspot Manager's Authorized Clients
# table and ends every live authorization the MAC holds. It needs only the
# hotspot-operator credentials the portal authorization itself already
# uses -- observed working against a live controller (5.15.24.19), not
# inferred. So revocation is available in exactly the configurations that
# can grant an authorization in the first place: there is no state in
# which this platform can let a guest on and then not remove them.
#
# ## Why the value is a week, and not longer
#
# The owner raised it from 24 hours to 7 days on 2026-09-11, once the
# disconnect above was verified on hardware. A week is the usual ask for a
# hotel stay, which is the case that drove it. What the ceiling still
# protects is narrower and weaker than what it protected before, and those
# reasons are why it is a week rather than a month:
#
#   * Revocation is *operator-initiated*. Nobody watches the dashboard at
#     03:00, so a long authorization is still a long unattended grant --
#     it is now recoverable rather than irrevocable, which is a different
#     thing from harmless.
#   * The controller, not this database, is the authority on whether a
#     client is still authorized (see ``AuthorizationStatus``). A longer
#     window is a longer period over which the two can drift with nobody
#     reconciling them.
#   * A shorter authorization means the guest re-hits the portal, which is
#     the only moment the platform re-checks consent, quota and blocklist
#     state. That check is worth keeping frequent on its own merits, and
#     it costs the guest nothing.
#
# What the ceiling no longer protects against is "an abusive guest cannot
# be removed". So this is now a *policy* number, chosen for the length of
# a stay, and not a safety backstop. Moving it again is the same kind of
# decision and needs the same kind of reason -- not a code review.
MAX_SESSION_DURATION_SECONDS = 7 * 24 * 3600

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
# Portal authorization diagnostics
# ============================================================================
#
# ## The problem this exists for
#
# Probed against a live Omada 6.3.0.100 cloud controller on 2026-09-11, one
# body field varied at a time:
#
#     authType omitted        -> -41500  "Invalid authentication type."
#     clientIp omitted        -> -41501  "Failed to authenticate."
#     clientMac omitted       -> -41501  "Failed to authenticate."
#     apMac/ssidName/radioId  -> -41501  "Failed to authenticate."
#     time omitted            -> -41501  "Failed to authenticate."
#     clientMac malformed     -> -41501  "Failed to authenticate."
#
# The endpoint validates its parameters -- `authType` has a code of its own --
# and then collapses every other fault into one opaque code, including a
# missing `clientMac`, which is beyond argument required. So when a guest in a
# real venue cannot get online, the controller hands this platform a single
# code covering a wrong MAC, a stale timestamp, the wrong site, an AP that
# never saw the client, a missing field, and a `clientIp` it disliked.
#
# **No operator-facing error can be more specific than that.** The mitigation
# therefore cannot be a better message; it has to be a better *record*. What
# is stored on a failure is the exact body that went on the wire, the redirect
# parameters that produced it, the raw vendor code, and the handful of checks
# this platform could have made from its own state before calling -- so a
# support engineer can diff the two sides afterwards, without asking a guest
# who has long since left the building to reproduce it.
#
# ## Why this is a key in the existing event context and not a new table
#
# `network_integration_events.context` is already a JSONB column, already
# written through `redact_context` on the way in, already scoped per
# organization, and already rendered by `GET /{id}/events`. A new log sink
# would need a migration, a retention policy, an endpoint and a permission of
# its own to reach parity with a column that has all four today. Nesting under
# one key keeps the bundle identifiable in a query
# (`context ? 'authorize_diagnostics'`) without colonising the top level of a
# context other event types share.
PORTAL_AUTHORIZE_DIAGNOSTICS_KEY = "authorize_diagnostics"

# Written on failure only.
#
# This is the retention control, and it is deliberately the *only* one. The
# bundle names a guest's device, so recording it for every successful
# authorization would put a MAC per guest per join into a table that has never
# held a per-guest identifier, forever, to answer a question nobody asks about
# a call that worked. Failures are the small minority and the only population
# anybody diffs. A successful authorization still records what it always did.
#
# The MAC itself is not a new disclosure: the identical address for the
# identical attempt is already persisted unmasked and indefinitely in
# `network_integration_authorizations.client_mac`, in the same organization's
# scope, and `app.common.masking.mask_mac` is a documented no-op because
# venues need the real address to identify a device for support. What changes
# is only which table it is in. No client IP is recorded because none is sent:
# the authorize body this platform builds has no `clientIp` field at all.
PORTAL_AUTHORIZE_DIAGNOSTICS_ON_SUCCESS = False

# How old a redirect's `t` has to be before the record calls it stale.
#
# Not a validation threshold -- nothing refuses a redirect for exceeding it,
# and a request that does is still authorized. It exists so that a human
# reading a failure is not left to eyeball an epoch. Fifteen minutes is longer
# than any guest spends between the redirect landing and finishing sign-in,
# and short enough that a page reopened from a browser's history -- one of the
# few `-41501` causes that is decidable from our side -- is visibly flagged.
PORTAL_REDIRECT_STALE_AFTER_SECONDS = 900


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
    # One guest's access ended early by a human. Its own action rather
    # than reusing DISCONNECTED, which means "the *integration* was
    # disconnected from the controller" -- an integration-scoped
    # administrative act, not a guest-scoped one. An auditor answering
    # "who kicked this guest off the WiFi" must not have to disambiguate
    # the two by reading the description.
    GUEST_DISCONNECTED = "network_integration_guest_disconnected"
    # "Configure controller automatically": this platform wrote portal,
    # pre-auth and operator settings onto a customer's controller. Recorded
    # on real runs only; a dry run reads and writes nothing.
    CONTROLLER_CONFIGURED = "network_integration_controller_configured"

# Audit entity_type for every entry this domain writes -- one value, so an
# auditor can retrieve the whole trail for one integration by
# (entity_type, entity_id) using the existing indexes on that table.
AUDIT_ENTITY_TYPE = "network_integration"
