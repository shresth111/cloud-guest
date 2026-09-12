"""Core Network Integration business logic.

**This module is provider-agnostic and must stay that way.** It imports
``providers.base``'s Protocol and dataclasses and the registry lookup, and
nothing else provider-shaped. There is no ``wyfy_device_gateway`` import,
no ``Omada`` identifier, and no vendor string other than the value that
arrives from a request and is handed straight to
``providers.get_network_provider``. A test
(``TestProviderSeamIsolation``) asserts it, because a seam nobody checks
is a seam that closes.

## The three security decisions this module exists to make

### 1. Tenant isolation happens here, on the loaded row

``RequirePermission`` resolves the scope it checks from the
``X-Organization-Id`` header (with a path-parameter fallback for routes
that *name* an organization -- see ``app.domains.rbac.dependencies
._current_scope_context``). This domain's by-id routes name an
``integration_id``, which tells RBAC nothing about tenancy until the row
is loaded, and the row loads *after* the permission check has run. That
gap is the defect class this codebase found live in fourteen endpoints.

It is worse here than in the domains where it was found. ``base_url`` is
the address this platform sends a tenant's decrypted controller
credentials to. A cross-tenant *write* is therefore not a data leak, it is
a credential exfiltration primitive: repoint victim's ``base_url`` at a
host you control, wait for the sync sweep, receive their controller
credentials. So :meth:`_load_owned_integration` is the single chokepoint
every by-id operation funnels through, it compares
``row.organization_id`` against the caller's, and it additionally applies
``app.domains.rbac.location_scope.enforce_entity_location`` for the
within-tenant, cross-site case that the organization comparison cannot
see.

### 2. ``organization_id is None`` is refused on customer paths

``CurrentOrganization`` returns ``None`` for a caller holding an active
GLOBAL-scoped role, and ``None`` means "apply no filter" everywhere
downstream in this codebase. On a customer route that reading silently
widens one tenant's list to every tenant. :meth:`_require_organization`
raises instead. The platform reads that genuinely want the unscoped query
ask for it by name -- :meth:`list_platform_integrations`,
:meth:`get_platform_summary` -- and those methods say in their own
docstrings that they are unscoped and what gates them.

### 3. Credentials are write-only, and the rotation path never reads back

``_credentials_for`` decrypts on the stack, hands the plaintext to a
provider call, and returns nothing to any caller. :meth:`rotate_credentials`
encrypts the *new* set and overwrites the column; it never decrypts the old
one, because there is no operation that needs to and a decrypt is a chance
to leak. No method on this class returns a credential, and no response
schema has a field for one.

## Errors: what changes the row's status and what does not

A ``ProviderError`` from a *background sync* or a *saved-integration
action* updates ``status``/``last_error_*`` and writes an event row -- that
is the venue's own diagnostic trail. A ``ProviderError`` from the
*pre-save* ``test_connection_unsaved`` updates nothing, because there is no
row to update; it writes an audit entry only. And a ``ProviderError`` from a
*live read* (``/sites``, ``/devices``) sets ``SYNC_ERROR`` rather than
``CONNECTION_FAILED``: authentication demonstrably worked recently enough
for the row to be ``CONNECTED``, so reporting "cannot connect" would be
telling the operator to check something that is not wrong.

## What this module does not do, and will not pretend to

* It does not know whether a guest is currently online. The
  authorizations table records what this platform *asked* a controller
  for; the controller can expire or revoke silently and Omada's controller
  API offers no webhook. See
  ``models.NetworkIntegrationAuthorization``'s own docstring.
* It has never run against a physical Omada controller. Every provider
  interaction in this module is exercised against mocks.
"""

from __future__ import annotations

import dataclasses
import logging
import secrets
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from redis.asyncio import Redis

from app.common.exceptions import CloudGuestError
from app.core.config import Settings, get_settings
from app.domains.rbac.location_scope import LocationScope, enforce_entity_location

from .constants import (
    AUDIT_ENTITY_TYPE,
    CONTROLLER_SETUP_OPERATOR_PREFIX,
    CONTROLLER_SETUP_PORTAL_NAME_MAX_LENGTH,
    CONTROLLER_SETUP_PORTAL_NAME_PREFIX,
    DEFAULT_CONTROLLER_TLS_MODE,
    DEFAULT_PORTAL_AUTH_MODE,
    FLEET_DEVICE_DEFAULT_MODEL_BY_PROVIDER,
    GUEST_OPERATOR_CREDENTIAL_FIELDS,
    PORTAL_AUTHORIZE_DIAGNOSTICS_KEY,
    PORTAL_AUTHORIZE_DIAGNOSTICS_ON_SUCCESS,
    PORTAL_AUTHORIZE_MAX_ATTEMPTS_PER_WINDOW,
    PORTAL_AUTHORIZE_RATE_LIMIT_KEY_TEMPLATE,
    PORTAL_AUTHORIZE_WINDOW_SECONDS,
    PORTAL_REDIRECT_STALE_AFTER_SECONDS,
    REDACTED_CONTEXT_KEYS,
    REDACTION_PLACEHOLDER,
    SYNC_BACKOFF_CAP_MULTIPLIER,
    AuthorizationStatus,
    ControllerAuthMode,
    ControllerSetupGap,
    ControllerTlsMode,
    DisconnectMechanism,
    ErrorCode,
    IntegrationEventStatus,
    IntegrationEventType,
    IntegrationStatus,
    NetworkIntegrationAuditAction,
    NetworkProviderKind,
    PortalAuthMode,
    SyncStatus,
)
from .crypto import (
    NetworkIntegrationCredentialDecryptionError,
    encrypt_credentials,
    stored_credential_fields,
)
from .crypto import decrypt_credentials as _decrypt_credentials
from .exceptions import (
    ControllerSetupPreconditionsError,
    ControllerSiteSharedError,
    CrossLocationNetworkIntegrationAccessError,
    CrossOrganizationNetworkIntegrationAccessError,
    GuestSessionNotActiveError,
    GuestSsidAmbiguousError,
    GuestSsidInUseError,
    GuestSsidNotFoundError,
    NetworkIntegrationAlreadyExistsError,
    NetworkIntegrationCredentialsRequiredError,
    NetworkIntegrationDeauthorizationUnsupportedError,
    NetworkIntegrationDisabledError,
    NetworkIntegrationFleetDeviceUnavailableError,
    NetworkIntegrationInventoryRequiresOpenApiError,
    NetworkIntegrationLocationRequiredError,
    NetworkIntegrationNotFoundError,
    NetworkIntegrationOrganizationRequiredError,
    NetworkIntegrationPortalModeNotPermittedError,
    NetworkIntegrationRateLimitedError,
    NetworkIntegrationSiteNotSelectedError,
    NetworkIntegrationTlsPinRequiredError,
    NetworkIntegrationUrlRejectedError,
    PortalConflictError,
    ProviderAuthFailedError,
    ProviderError,
    ProviderSiteNotFoundError,
    UnsupportedNetworkProviderError,
)
from .models import NetworkIntegration
from .providers import get_network_provider
from .providers.base import (
    NetworkProvider,
    ProviderAuthorizationResult,
    ProviderClient,
    ProviderConnectionConfig,
    ProviderControllerInfo,
    ProviderControllerSetupBlock,
    ProviderControllerSetupRequest,
    ProviderControllerSetupStep,
    ProviderDevice,
    ProviderPortalContext,
    ProviderSite,
    ProviderSsid,
    ProviderTlsObservation,
)
from .repository import NetworkIntegrationRepositoryProtocol
from .validators import (
    EXTERNAL_PORTAL_OWNERSHIP_PARAM,
    build_external_portal_url,
    describe_mac_wire_format,
    describe_portal_readiness_gaps,
    describe_redirect_shape,
    normalize_client_mac,
    portal_readiness_gaps,
    portal_redirect_timestamp_age_seconds,
    summarize_redirect_url,
    synthesize_fleet_identity,
    validate_auth_mode_credentials,
    validate_controller_url,
    validate_tls_trust,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AuditLogWriter",
    "ControllerDraftProbeOutcome",
    "ControllerSetupOutcome",
    "FleetDeviceProvisionerProtocol",
    "GuestDisconnectOutcome",
    "GuestSessionLookupProtocol",
    "GuestSessionTerminatorProtocol",
    "NetworkIntegrationService",
    "PortalAuthorizationOutcome",
    "SyncOutcome",
    "SyncSweepSummary",
    "redact_context",
    "run_network_integration_sync_sweep",
]

# The one guest-session status this domain will act on. A literal rather
# than an import of ``app.domains.guest.constants.GuestSessionStatus``:
# see ``GuestSessionLookupProtocol`` for why this domain composes the guest
# domain through a two-line Protocol instead of importing it.
_GUEST_SESSION_ACTIVE = "active"


class AuditLogWriter(Protocol):
    """The same narrow, duck-typed protocol every other domain's service
    uses to reach ``audit_log_entries`` (see
    ``app.domains.organization.service.AuditLogWriter``) -- satisfied by
    ``app.domains.rbac.repository.RBACRepository``. Optional at the type
    level so unit tests can construct this service without one."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


class FleetDeviceProvisionerProtocol(Protocol):
    """How this domain registers a controller in the fleet inventory.

    One method, satisfied as-is by
    ``app.domains.router.service.RouterService.create_router`` -- so the
    Master onboarding path composes the router domain rather than reaching
    into ``routers`` itself, and every invariant that domain enforces
    (location belongs to the organization, serial and MAC are unique, the
    location is not archived) keeps applying to rows this path creates.

    ## Why a Protocol rather than importing RouterService

    The same reason ``GuestSessionLookupProtocol`` above is one: it keeps
    the import graph one-directional and it lets the onboarding tests run
    without constructing a ``RouterService`` and the location lookup,
    repository and session it needs. The narrowness is the point -- this
    domain can create a fleet device and can do nothing else to the fleet.

    ## The organization id is passed, not assumed

    ``requesting_organization_id`` is forwarded to the router domain
    deliberately. On this route the organization arrives in the request
    body, because a GLOBAL-scoped platform operator has no organization of
    their own to infer it from. What makes that safe is that the pair is
    re-checked downstream: ``create_router`` resolves the location *with*
    this organization id and rejects a location belonging to anyone else.
    A caller who lies about the pairing gets a 404 from the router domain
    rather than a cross-tenant row.
    """

    async def create_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        name: str,
        serial_number: str,
        mac_address: str,
        model: str,
        vendor: str = ...,
        settings: dict[str, Any] | None = None,
    ) -> Any: ...


class GuestSessionLookupProtocol(Protocol):
    """How this domain reads a ``GuestSession``.

    Two lines, satisfied as-is by
    ``app.domains.guest.repository.GuestRepository`` -- which is
    constructed from an ``AsyncSession`` and nothing else, so wiring it
    costs no service graph.

    ## Why not ``GuestService.get_session``

    Because that method is *correctly* tenant-scoped and
    location-confined for a staff caller, and this call site is a guest
    with no roles at all. Passing ``requesting_organization_id=None``
    through it to get past its own guard would be using a security control
    backwards. This domain does the check it actually needs -- the session
    must be ACTIVE and its organization *and* location must match the
    request body -- in :meth:`authorize_portal_client`, which is a
    different check with a different failure mode.

    ## Why not import ``GuestService`` at all

    ``GuestService`` is composed into eleven domains and drags a large
    graph with it. More importantly, this domain must not become a
    dependency of the guest login path or vice versa: the portal authorize
    endpoint runs *after* login and must be able to fail without touching
    it. A Protocol keeps that direction one-way.
    """

    async def get_session_by_id(
        self, session_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Any: ...

    # Needed to bind the MAC being authorized to the device that actually
    # authenticated -- see `authorize_portal_client`. Satisfied as-is by
    # `GuestRepository.get_device_by_id`, so widening this Protocol by one
    # method costs no new wiring.
    async def get_device_by_id(self, device_id: uuid.UUID) -> Any: ...


class GuestSessionTerminatorProtocol(Protocol):
    """How this domain *ends* a ``GuestSession``. One method.

    Deliberately a second Protocol rather than two more lines on
    ``GuestSessionLookupProtocol``, because the two have different
    callers and different risks. The lookup is read-only and is used by
    the anonymous portal route; this one writes, and is used only by the
    RBAC-gated staff disconnect. Keeping them apart means the portal path
    cannot acquire the ability to end sessions by accident.

    ## Why a service here, where the lookup is a repository

    Ending a session is not a row update. ``GuestService.disconnect_session``
    validates the status transition, stamps ``ended_at`` and the reason,
    writes the audit entry, and issues the live RFC 5176 disconnect for
    the venue's *other* enforcement path. Writing to ``guest_sessions``
    from this domain would reimplement four of those and silently skip
    the fifth. So this composes the real service, exactly as
    ``FleetDeviceProvisionerProtocol`` composes ``RouterService`` rather
    than writing ``routers`` rows itself.

    The dependency direction is one-way and stays that way: this domain
    may reach into ``app.domains.guest``; nothing in ``app.domains.guest``
    may reach back, or the portal authorize endpoint stops being able to
    fail without taking guest login down with it.

    Satisfied as-is by ``GuestService`` -- the signature below is that
    method's, unchanged.
    """

    async def disconnect_session(
        self,
        *,
        session_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
        reason: str | None = None,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class SyncOutcome:
    integration_id: uuid.UUID
    synced: bool
    status: str
    site_count: int = 0
    device_count: int = 0
    client_count: int = 0
    error_code: str | None = None
    message: str | None = None


@dataclass(frozen=True, slots=True)
class SyncSweepSummary:
    considered: int = 0
    synced: int = 0
    skipped_backoff: int = 0
    errors: int = 0


@dataclass(frozen=True, slots=True)
class PortalAuthorizationOutcome:
    authorized: bool
    provider: str
    expires_at: datetime | None = None
    redirect_url: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class GuestDisconnectOutcome:
    """What one staff-initiated disconnect actually achieved.

    Three separate booleans rather than one, because they are three
    separate facts and the whole history of this feature is people
    collapsing them:

    * ``disconnected`` -- the controller ended the authorization. This is
      the only one that means the device stopped forwarding traffic.
    * ``had_active_authorization`` -- whether this platform held a live
      authorization row for the MAC before the call. ``False`` with
      ``disconnected`` ``True`` is normal and not an error: the guest's
      grant had already lapsed, or was made outside this platform.
    * ``guest_session_ended`` -- the WyfyGuest session row was ended, so
      the guest cannot silently re-authorize. ``False`` here means the
      session was already over, not that anything failed.

    A caller rendering "Disconnected" must read the first. A caller
    explaining what happened should read all three.
    """

    disconnected: bool
    provider: str
    client_mac: str
    had_active_authorization: bool
    deauthorized_at: datetime | None = None
    guest_session_id: uuid.UUID | None = None
    guest_session_ended: bool = False
    # WHICH OF THE TWO REVOCATIONS THIS WAS -- see
    # `constants.DisconnectMechanism`. In RADIUS mode the three booleans
    # above are all still true statements and they add up to something
    # weaker than they do in External Portal Server mode, because this
    # platform never issued the authorization being revoked. A caller that
    # renders "Disconnected" without reading this will overstate what
    # happened at exactly one kind of venue.
    mechanism: str = DisconnectMechanism.CONTROLLER_AUTHORIZATION.value


@dataclass(frozen=True, slots=True)
class ControllerDraftProbeOutcome:
    """What :meth:`NetworkIntegrationService.probe_controller_draft` found.

    ``error`` is the connection/credential verdict; ``inventory_error`` is a
    separate, lesser one about reading sites and SSIDs afterwards. They are
    kept apart because a controller that signed in fine and then refused a
    site listing is *connected*, and the wizard must not tell the operator
    otherwise.
    """

    info: ProviderControllerInfo | None
    error: ProviderError | None
    tls: ProviderTlsObservation | None
    suggested_tls_mode: str | None = None
    credentials_checked: bool = False
    inventory_requires_openapi: bool = False
    inventory_available: bool = False
    inventory_error: ProviderError | None = None
    sites: tuple[ProviderSite, ...] = ()
    ssids_site_id: str | None = None
    ssids: tuple[ProviderSsid, ...] = ()


# ============================================================================
# Redaction
# ============================================================================


@dataclass(frozen=True, slots=True)
class ControllerSetupOutcome:
    """What one "Configure controller automatically" run did (or, on a dry
    run, would do). ``ok`` is false when any step failed; ``changed`` is true
    when any step created or updated something."""

    integration_id: uuid.UUID
    dry_run: bool
    ok: bool
    changed: bool
    steps: tuple[ProviderControllerSetupStep, ...]
    portal_id: str | None
    guest_ssid_id: str | None
    portal_url_scheme: str
    portal_url_host_and_query: str
    pre_auth_host: str


#: Step outcomes, as the provider seam reports them.
_SETUP_FAILED = "failed"
_SETUP_CHANGING = frozenset({"created", "updated"})


def redact_context(value: Any, *, _depth: int = 0) -> Any:
    """Strip anything that looks like a secret out of an event/audit payload.

    Applied at **write time**, before the value reaches
    ``network_integration_events.context`` or an audit entry's
    ``metadata`` -- not by a log filter. A log filter protects the log; it
    does nothing about a secret already persisted into a JSONB column that
    the customer dashboard then renders. See ``constants``'s own
    "Redaction is a write-time constant" note.

    Key matching is case-insensitive and recursive, and bounded at ten
    levels: a deeply nested or self-referential structure must not turn a
    redaction pass into a stack overflow on the write path.
    """
    if _depth > 10:
        return REDACTION_PLACEHOLDER
    if isinstance(value, Mapping):
        return {
            key: (
                REDACTION_PLACEHOLDER
                if str(key).lower() in REDACTED_CONTEXT_KEYS
                else redact_context(item, _depth=_depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact_context(item, _depth=_depth + 1) for item in value]
    return value


# ============================================================================
# Portal authorization diagnostics
# ============================================================================


def build_portal_authorize_diagnostics(
    *,
    context: ProviderPortalContext,
    normalized_client_mac: str,
    integration: NetworkIntegration,
    request_snapshot: dict[str, Any] | None = None,
    provider_code: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Everything a support engineer needs to diff a failed authorization.

    Two halves, deliberately kept apart in the output:

    * ``request`` -- the exact body that went to the controller, field by
      field, in the vendor's own spelling, produced by the same builder the
      gateway uses to make the request (see
      ``providers/omada.py::_authorize_snapshot``). ``None`` when the call
      never got that far.
    * ``redirect`` -- the parameters the controller put on the redirect that
      sent the guest here in the first place.

    Diffing those two is the entire feature. Today neither is recoverable
    after the fact, so a venue reporting "the WiFi did not work at 19:40"
    leaves nothing to look at but a timestamp and a code that means "no".

    ``precall`` is the third part and the one that does not come from either
    side: the checks this platform could have made from its own state before
    calling. They exist because the controller's ``-41501`` is a catch-all
    (see ``constants``'s own write-up) and every candidate cause that can be
    decided here is one an engineer does not have to chase. They describe;
    they never refuse -- see ``validators``'s note on why a guard built on
    this would be a guess that costs real guests their internet.

    ## What is not in here

    No credential, cookie, token or controller response body -- none of those
    is an input to any value above. No client IP: this platform's authorize
    body has no ``clientIp`` field, so there is nothing to record, and this
    function does not invent one. The redirect URL is reduced to its origin,
    path and query-parameter *names* (``validators.summarize_redirect_url``
    explains why the values are dropped).

    The raw ``provider_code`` is passed through as an integer and is not
    interpreted here. Which codes are specific and which are catch-alls is
    vendor knowledge, and this module does not hold vendor knowledge -- the
    gateway classifies, this records. Keeping the number is what preserves
    the one discrimination the controller makes.
    """
    stored_site_id = integration.external_site_id or None
    stored_site_name = integration.external_site_name or None
    if stored_site_id is not None and context.site == stored_site_id:
        site_matched_by = "id"
    elif stored_site_name is not None and context.site == stored_site_name:
        # The redirect named the site's *display name* and the check passed on
        # that. Worth recording rather than flattening into "matched": the
        # body then carries a name where the controller may want a key, which
        # is one of the causes the catch-all covers.
        site_matched_by = "name"
    else:
        site_matched_by = "none"

    age_seconds = portal_redirect_timestamp_age_seconds(context.t, now=now)
    wire_format = describe_mac_wire_format(context.client_mac)

    return {
        "request": {
            # The vendor's spelling, on purpose. A "friendlier" rename here
            # would mean an engineer comparing this against TP-Link's own
            # documentation has to translate it back, which is the one job
            # this record exists to remove.
            "body": request_snapshot,
            "fields": sorted(request_snapshot) if request_snapshot else [],
        },
        "redirect": {
            "client_mac": context.client_mac,
            "site": context.site,
            "ap_mac": context.ap_mac,
            "ssid_name": context.ssid_name,
            "radio_id": context.radio_id,
            "gateway_mac": context.gateway_mac,
            "vid": context.vid,
            "t": context.t,
            "redirect_url": summarize_redirect_url(context.redirect_url),
        },
        "precall": {
            "site_matched_by": site_matched_by,
            "stored_site_id": stored_site_id,
            "redirect_shape": describe_redirect_shape(
                ap_mac=context.ap_mac,
                ssid_name=context.ssid_name,
                radio_id=context.radio_id,
                gateway_mac=context.gateway_mac,
                vid=context.vid,
            ),
            "client_mac_wire_format": wire_format,
            "client_mac_normalized": normalized_client_mac,
            # True means the controller was sent a different spelling from the
            # one this platform stored and compares on. Harmless on every
            # firmware anyone has tested, and exactly the kind of thing that
            # stops being harmless without warning.
            "client_mac_rewritten_for_wire": (
                (context.client_mac or "").strip() != normalized_client_mac
            ),
            "t_age_seconds": age_seconds,
            "t_stale": (
                None
                if age_seconds is None
                else age_seconds > PORTAL_REDIRECT_STALE_AFTER_SECONDS
            ),
            "requested_duration_seconds": integration.session_duration_seconds,
        },
        "controller": {"provider_code": provider_code},
    }


# ============================================================================
# Service
# ============================================================================


class NetworkIntegrationService:
    """Core Network Integration business logic."""

    def __init__(
        self,
        repository: NetworkIntegrationRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        guest_session_lookup: GuestSessionLookupProtocol | None = None,
        guest_session_terminator: GuestSessionTerminatorProtocol | None = None,
        fleet_device_provisioner: FleetDeviceProvisionerProtocol | None = None,
        provider_resolver=get_network_provider,
        url_resolver=None,
        redis: Redis | None = None,
        settings: Settings | None = None,
        caller_location_scope: LocationScope = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer
        self.guest_session_lookup = guest_session_lookup
        # Optional in the same way, and for the same reason: a unit test
        # constructs this service directly. Its absence is *not* a silent
        # degradation -- ``disconnect_guest`` refuses rather than
        # reporting a guest session ended that it never ended.
        self.guest_session_terminator = guest_session_terminator
        # Optional, and its absence is an error rather than a degradation:
        # only the Master onboarding path uses it, and that path refuses
        # outright when it is missing. See
        # ``create_integration_with_fleet_device``.
        self.fleet_device_provisioner = fleet_device_provisioner
        # Injectable so tests substitute a fake provider without the
        # gateway package installed, and so a second provider needs no
        # change here. Production always passes the real registry.
        self._get_provider = provider_resolver
        # Injectable for the identical reason ``provider_resolver`` above is:
        # a unit test must be able to exercise the real SSRF address rules
        # without depending on live DNS or on the machine's own network
        # (which makes the suite fail offline, and worse, makes it *pass or
        # fail differently* depending on what a captive resolver returns).
        # ``None`` means "use validators.py's own real resolver" -- which is
        # what production always does, since nothing but tests passes this.
        self._url_resolver = url_resolver
        # Optional at the type level for the same reason ``IspService``'s
        # and ``NetworkDiagnosticsService``'s are: unit tests construct
        # this service directly with no Redis, and the portal limiter
        # degrades to a no-op rather than failing the request. The real
        # FastAPI wiring always supplies the shared
        # ``app.database.redis.redis_client`` singleton.
        self._redis = redis
        self._settings = settings
        # Constructor injection, not a per-method argument. A method that
        # accepts a security control can forget to use it; on the instance
        # there is nothing per-method to forget. See
        # ``tests/unit/test_location_scope_coverage.py``'s own docstring
        # for the incident that established this.
        self.caller_location_scope = caller_location_scope

    @property
    def settings(self) -> Settings:
        return self._settings or get_settings()

    # -- guards ------------------------------------------------------------

    async def _validate_url(self, raw: str):
        """Every SSRF check in this service goes through here, so the
        injected resolver cannot be forgotten at one call site -- which is
        exactly how a URL allowlist quietly stops covering one code path."""
        if self._url_resolver is None:
            return await validate_controller_url(raw, settings=self.settings)
        return await validate_controller_url(
            raw, settings=self.settings, resolver=self._url_resolver
        )

    @staticmethod
    def _require_organization(
        requesting_organization_id: uuid.UUID | None,
    ) -> uuid.UUID:
        """The customer-path guard against ``None`` meaning "every tenant".

        See this module's docstring, decision 2. Every customer-facing
        method calls this before touching the repository.
        """
        if requesting_organization_id is None:
            raise NetworkIntegrationOrganizationRequiredError()
        return requesting_organization_id

    def _enforce_tenant_scope(
        self,
        integration: NetworkIntegration,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        """Compare the *loaded row* against the caller.

        Two checks, and the second is not redundant:

        1. ``organization_id`` -- refuses tenant B's row to tenant A.
        2. ``enforce_entity_location`` -- refuses site B's row to a caller
           whose grants confine them to site A *within the same tenant*.
           The organization comparison cannot see this, and a
           location-scoped account is exactly the population that reaches
           these routes (seven seeded roles are LOCATION-scoped).

        ``requesting_organization_id is None`` reaching here means a
        deliberate platform read, and is allowed -- every caller that got
        here through a customer route has already been through
        ``_require_organization``.
        """
        if (
            requesting_organization_id is not None
            and integration.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationNetworkIntegrationAccessError()
        enforce_entity_location(
            entity_location_id=getattr(integration, "location_id", None),
            caller_location_scope=self.caller_location_scope,
            error=CrossLocationNetworkIntegrationAccessError(),
        )

    async def _load_owned_integration(
        self,
        integration_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        scope_read_to_organization: bool = False,
    ) -> NetworkIntegration:
        """The chokepoint every by-id operation funnels through.

        Load, then verify, then return. Nothing in this domain reaches an
        integration by id any other way -- which is what makes the tenant
        check impossible to forget on a new endpoint, rather than
        something a reviewer has to notice.

        ``scope_read_to_organization`` puts the caller's organization into
        the *query*, so another tenant's id is not found at all (404) rather
        than read and then refused (403). It is opt-in so the existing
        routes keep the 403 their clients already handle; the verification
        below still runs either way, which is what keeps location
        confinement in force.
        """
        if scope_read_to_organization and requesting_organization_id is not None:
            integration = await self.repository.get_integration_for_organization(
                integration_id, organization_id=requesting_organization_id
            )
        else:
            integration = await self.repository.get_integration_by_id(integration_id)
        if integration is None:
            raise NetworkIntegrationNotFoundError(integration_id)
        self._enforce_tenant_scope(integration, requesting_organization_id)
        return integration

    def _provider(self, kind: str) -> NetworkProvider:
        try:
            return self._get_provider(kind)
        except UnsupportedNetworkProviderError:
            raise
        except Exception as exc:  # noqa: BLE001 -- registry/import failure
            raise UnsupportedNetworkProviderError(kind) from exc

    # -- credentials -------------------------------------------------------

    def _credentials_for(self, integration: NetworkIntegration) -> dict[str, str]:
        """Decrypt on the stack. Never returned to a caller.

        A decryption failure is surfaced as ``ProviderAuthFailedError``,
        not as the underlying key error. The practical consequence is
        identical -- this integration cannot authenticate until somebody
        re-enters credentials -- and "your stored secret cannot be
        decrypted" is a statement about this platform's key management
        that has no business in a customer's API response. The real cause
        is logged, without the ciphertext.
        """
        if not integration.credentials_encrypted:
            raise NetworkIntegrationCredentialsRequiredError()
        try:
            return _decrypt_credentials(
                integration.credentials_encrypted, settings=self.settings
            )
        except NetworkIntegrationCredentialDecryptionError:
            logger.exception(
                "network_integration_credential_decryption_failed",
                extra={"integration_id": str(integration.id)},
            )
            raise ProviderAuthFailedError(
                "This integration's stored credentials could not be read. "
                "Re-enter them to reconnect."
            ) from None

    @staticmethod
    def _resolve_tls_trust(
        tls_mode: str | None, tls_pinned_sha256: str | None
    ) -> tuple[ControllerTlsMode, str | None]:
        """Validate a requested trust decision, or refuse it.

        One place, called by create, onboard, update, rotate and the
        pre-save probe, so that "pinned with no fingerprint" cannot be
        accepted on whichever path somebody forgets. Refusing is a 422 from
        this platform: nothing has been dialled, and the request describes a
        row that would claim to pin and pin nothing.
        """
        try:
            mode = ControllerTlsMode(tls_mode or DEFAULT_CONTROLLER_TLS_MODE.value)
        except ValueError as exc:
            raise NetworkIntegrationTlsPinRequiredError(
                f"'{tls_mode}' is not a recognised certificate trust mode"
            ) from exc
        try:
            return validate_tls_trust(
                tls_mode=mode, tls_pinned_sha256=tls_pinned_sha256
            )
        except ValueError as exc:
            raise NetworkIntegrationTlsPinRequiredError(str(exc)) from exc

    async def _observe_tls(
        self, provider_impl: NetworkProvider, config: ProviderConnectionConfig
    ) -> ProviderTlsObservation | None:
        """Best-effort certificate observation for an operator-facing probe.

        Never raises. This runs alongside a connection test whose own result
        is the answer; an observation that fails must not turn a successful
        test into a failure, and must not replace a *useful* connection
        error with a TLS one. ``None`` means "we could not look", which the
        response reports as absent rather than as anything.
        """
        try:
            return await provider_impl.inspect_tls(config)
        except Exception:  # noqa: BLE001 -- decoration around the real answer
            logger.warning(
                "network_integration_tls_observation_failed",
                extra={"base_url": config.base_url},
            )
            return None

    def _connection_config(
        self, integration: NetworkIntegration, credentials: dict[str, str]
    ) -> ProviderConnectionConfig:
        return ProviderConnectionConfig(
            provider=integration.provider,
            base_url=integration.base_url,
            auth_mode=integration.auth_mode,
            credentials=credentials,
            controller_id=integration.controller_id,
            # The row's own trust decision, not a platform-wide constant.
            # `tls_mode` is NOT NULL with a server default of 'strict', so
            # the `or` is for an object built in a test without touching the
            # database rather than for a real row.
            tls_mode=integration.tls_mode or DEFAULT_CONTROLLER_TLS_MODE.value,
            tls_pinned_sha256=integration.tls_pinned_sha256,
            timeout_seconds=self.settings.omada_api_timeout_seconds,
        )

    # -- event / audit writing --------------------------------------------

    async def _record_event(
        self,
        integration: NetworkIntegration,
        *,
        event_type: IntegrationEventType,
        status: IntegrationEventStatus,
        error_code: str | None = None,
        message: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Append one row to the integration's operational feed.

        ``message`` and ``context`` go through :func:`redact_context`
        first, unconditionally. The message is redacted too, not only the
        structured context: a provider message is produced by the gateway,
        whose contract obliges it to be secret-free (§2) -- but this is the
        line that would carry a secret into a customer-visible column if
        that obligation were ever broken, and a promise from another
        repository is not a control this one can rely on.
        """
        await self.repository.create_event(
            integration_id=integration.id,
            organization_id=integration.organization_id,
            event_type=event_type.value,
            status=status.value,
            error_code=error_code,
            message=self._redact_message(message),
            context=redact_context(context or {}),
        )

    @staticmethod
    def _redact_message(message: str | None) -> str | None:
        """Blunt substring pass over a free-text message.

        ``redact_context`` works on dictionary *keys*; a message is one
        string with no keys. So this looks for a redacted key name
        appearing as ``key=value`` or ``key: value`` and cuts the value.
        Deliberately crude: it can over-redact a message that merely
        mentions the word "password", which is a cosmetic loss, and it
        cannot catch a secret that appears with no label at all, which is
        an honest limitation rather than one this docstring hides.
        """
        if not message:
            return message
        redacted = message
        lowered = message.lower()
        for key in REDACTED_CONTEXT_KEYS:
            index = lowered.find(key)
            while index != -1:
                tail = redacted[index + len(key) :]
                stripped = tail.lstrip()
                if stripped[:1] in ("=", ":"):
                    offset = len(tail) - len(stripped)
                    redacted = (
                        redacted[: index + len(key) + offset + 1]
                        + f" {REDACTION_PLACEHOLDER}"
                    )
                    lowered = redacted.lower()
                    break
                index = lowered.find(key, index + 1)
        return redacted

    async def _write_audit(
        self,
        *,
        action: NetworkIntegrationAuditAction,
        actor_user_id: uuid.UUID | None,
        integration: NetworkIntegration | None,
        description: str,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """One audit entry, through the existing audit domain.

        No second audit table, per the shared contract's ground rules --
        this writes ``audit_log_entries`` via the same narrow
        ``AuditLogWriter`` protocol every other domain's service uses.
        A ``None`` writer is a no-op, which is the established convention
        for a service a test constructs directly.
        """
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type=AUDIT_ENTITY_TYPE,
            entity_id=integration.id if integration is not None else None,
            description=description,
            organization_id=(
                organization_id
                if organization_id is not None
                else (integration.organization_id if integration else None)
            ),
            location_id=(
                location_id
                if location_id is not None
                else (integration.location_id if integration else None)
            ),
            event_metadata=redact_context(metadata or {}),
        )

    # -- status bookkeeping ------------------------------------------------

    @staticmethod
    def _status_for_provider_error(
        error: ProviderError, *, during_sync: bool
    ) -> IntegrationStatus:
        """Map a controller failure onto the state to show the venue.

        The distinction is the operational point (see
        ``constants.IntegrationStatus``'s own docstring): an auth failure
        needs a human with the controller's password, a connection failure
        needs someone to look at the network, and a failed read on an
        otherwise-live integration is neither.
        """
        if error.code in (ErrorCode.AUTH_FAILED, ErrorCode.SESSION_EXPIRED):
            return IntegrationStatus.AUTH_FAILED
        if error.code in (
            ErrorCode.CONNECTION_FAILED,
            ErrorCode.TIMEOUT,
            ErrorCode.INVALID_CONTROLLER,
            # A rejected or changed certificate sits under CONNECTION_FAILED
            # in the *status* ladder because the operational consequence is
            # identical -- this integration is not talking to its controller
            # and somebody has to go and look. The distinction that matters
            # is in `last_error_code` and in the message, which is where an
            # operator reads *what* to look at; the status vocabulary is
            # four coarse buckets and inventing a fifth would change every
            # consumer of it for no new decision. See ErrorCode.TLS_*.
            ErrorCode.TLS_UNTRUSTED,
            ErrorCode.TLS_PIN_MISMATCH,
        ):
            return IntegrationStatus.CONNECTION_FAILED
        if during_sync:
            return IntegrationStatus.SYNC_ERROR
        return IntegrationStatus.SYNC_ERROR

    @staticmethod
    def _consecutive_failures(integration: NetworkIntegration) -> int:
        metadata = integration.provider_metadata or {}
        try:
            return int(metadata.get("consecutive_failure_count", 0) or 0)
        except (TypeError, ValueError):
            return 0

    async def _record_failure(
        self,
        integration: NetworkIntegration,
        error: ProviderError,
        *,
        event_type: IntegrationEventType,
        during_sync: bool,
    ) -> NetworkIntegration:
        now = datetime.now(UTC)
        status = self._status_for_provider_error(error, during_sync=during_sync)
        metadata = dict(integration.provider_metadata or {})
        metadata["consecutive_failure_count"] = self._consecutive_failures(
            integration
        ) + 1
        updates: dict[str, object] = {
            "status": status.value,
            "last_error_code": error.code.value,
            "last_error_message": self._redact_message(error.message),
            "last_error_at": now,
            "provider_metadata": metadata,
        }
        if during_sync:
            updates["last_sync_at"] = now
            updates["last_sync_status"] = SyncStatus.ERROR.value
        updated = await self.repository.update_integration(integration, updates)
        await self._record_event(
            updated,
            event_type=event_type,
            status=IntegrationEventStatus.ERROR,
            error_code=error.code.value,
            message=error.message,
            context={"consecutive_failure_count": metadata[
                "consecutive_failure_count"
            ]},
        )
        return updated

    # -- CRUD --------------------------------------------------------------

    async def create_integration(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        provider: str,
        name: str,
        base_url: str,
        auth_mode: str,
        controller_id: str | None = None,
        location_id: uuid.UUID | None = None,
        external_site_id: str | None = None,
        external_site_name: str | None = None,
        guest_ssid_id: str | None = None,
        guest_ssid_name: str | None = None,
        session_duration_seconds: int,
        sync_interval_seconds: int,
        is_enabled: bool = True,
        tls_mode: str | None = None,
        tls_pinned_sha256: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> NetworkIntegration:
        """Register a controller for this tenant.

        The URL is SSRF-validated *and normalized* before anything is
        written -- normalized because the partial unique index is on the
        stored string, so ``https://Host:8043/`` and
        ``https://host:8043`` must not be able to produce two rows for one
        controller.

        Credentials are optional at create time: the connect wizard saves a
        row so the operator can come back to it, and an integration with no
        credentials is ``UNCONFIGURED`` rather than broken. The status
        ladder here is deliberate and reflects only what is known --
        nothing claims ``CONNECTED`` until a real authenticated call has
        succeeded.
        """
        organization_id = self._require_organization(requesting_organization_id)
        if provider not in {kind.value for kind in NetworkProviderKind}:
            raise UnsupportedNetworkProviderError(provider)

        mode = ControllerAuthMode(auth_mode)
        trust_mode, pinned = self._resolve_tls_trust(tls_mode, tls_pinned_sha256)
        validated = await self._validate_url(base_url)

        credentials_encrypted: str | None = None
        if any((client_id, client_secret, username, password)):
            try:
                credentials = validate_auth_mode_credentials(
                    auth_mode=mode,
                    client_id=client_id,
                    client_secret=client_secret,
                    username=username,
                    password=password,
                )
            except ValueError as exc:
                raise NetworkIntegrationUrlRejectedError(str(exc)) from exc
            credentials_encrypted = encrypt_credentials(
                credentials, settings=self.settings
            )

        existing = await self.repository.find_live_integration(
            organization_id=organization_id,
            provider=provider,
            base_url=validated.base_url,
            external_site_id=external_site_id,
        )
        if existing is not None:
            raise NetworkIntegrationAlreadyExistsError(
                validated.base_url, external_site_id
            )

        if not is_enabled:
            status = IntegrationStatus.DISABLED
        elif credentials_encrypted is None or external_site_id is None:
            status = IntegrationStatus.UNCONFIGURED
        else:
            # Credentials and a site are stored, but nothing has been
            # proven yet. CONNECTING, not CONNECTED -- claiming a working
            # connection this platform has not made is the kind of
            # invented fact the sync sweep would then quietly contradict.
            status = IntegrationStatus.CONNECTING

        integration = await self.repository.create_integration(
            organization_id=organization_id,
            location_id=location_id,
            provider=provider,
            name=name,
            status=status.value,
            is_enabled=is_enabled,
            base_url=validated.base_url,
            auth_mode=mode.value,
            # Stored as given when supplied, and left None otherwise so the
            # first successful identity call still discovers and persists it
            # (`test_integration_connection` writes both identity columns).
            # Required only for a cloud-managed controller, where there is
            # nothing to discover.
            controller_id=(controller_id or None),
            # Written explicitly rather than left to the column default, for
            # the reason `tls_mode` below is: the Python-side default is only
            # applied at flush, so a caller reading the returned object back
            # before then would see None -- a state the database cannot hold
            # and the response schema will not serialise. Every integration
            # starts on the proven External Portal Server contract; nothing
            # here can create one in RADIUS mode.
            portal_mode=DEFAULT_PORTAL_AUTH_MODE.value,
            tls_mode=trust_mode.value,
            tls_pinned_sha256=pinned,
            # Only a decision that departs from the default is a decision
            # worth timestamping. A row left on strict has had nothing
            # accepted about it, and stamping it would make every row look
            # like somebody reviewed a certificate.
            tls_trust_decided_at=(
                None
                if trust_mode is DEFAULT_CONTROLLER_TLS_MODE
                else datetime.now(UTC)
            ),
            external_site_id=external_site_id,
            external_site_name=external_site_name,
            guest_ssid_id=guest_ssid_id,
            guest_ssid_name=guest_ssid_name,
            credentials_encrypted=credentials_encrypted,
            session_duration_seconds=session_duration_seconds,
            sync_interval_seconds=sync_interval_seconds,
            provider_metadata={},
            last_sync_status=SyncStatus.NEVER.value,
            created_by=actor_user_id,
        )
        await self._record_event(
            integration,
            event_type=IntegrationEventType.CONNECTED,
            status=IntegrationEventStatus.OK,
            message="Integration created",
            context={
                "base_url": validated.base_url,
                "auth_mode": mode.value,
                "has_credentials": credentials_encrypted is not None,
                "tls_mode": trust_mode.value,
            },
        )
        await self._write_audit(
            action=NetworkIntegrationAuditAction.CONNECTED,
            actor_user_id=actor_user_id,
            integration=integration,
            description=f"Network integration '{name}' created ({provider})",
            # The fingerprint goes in the audit metadata on purpose: it is
            # public, and "which certificate did they accept, and when" is
            # exactly the question an audit trail exists to answer. The
            # redaction pass leaves it alone -- it matches no secret-shaped
            # key name, and there is nothing in a certificate hash to
            # protect.
            metadata={
                "base_url": validated.base_url,
                "auth_mode": mode.value,
                "tls_mode": trust_mode.value,
                "tls_pinned_sha256": pinned,
            },
        )
        return integration

    async def create_integration_with_fleet_device(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        provider: str,
        name: str,
        base_url: str,
        auth_mode: str,
        controller_model: str,
        session_duration_seconds: int,
        sync_interval_seconds: int,
        controller_id: str | None = None,
        serial_number: str | None = None,
        mac_address: str | None = None,
        external_site_id: str | None = None,
        external_site_name: str | None = None,
        guest_ssid_id: str | None = None,
        guest_ssid_name: str | None = None,
        is_enabled: bool = True,
        tls_mode: str | None = None,
        tls_pinned_sha256: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> tuple[NetworkIntegration, Any]:
        """Register a controller *and* the fleet device row it needs.

        Returns ``(integration, fleet_device)``.

        The Master-driven onboarding path (contract §11.6). The customer
        self-service path writes the same pair through
        :meth:`ensure_fleet_device` once the integration names a venue --
        it used to create no fleet row at all, which left every
        customer-created integration unable to sign a single guest in.

        ## Why a venue needs the second row at all

        ``guest_sessions.router_id`` is NOT NULL and
        ``GuestOtpLoginRequest.router_id`` is required, so at a venue whose
        only network equipment is an Omada controller a guest cannot be
        issued a session -- and therefore cannot be authorized onto the
        WiFi -- unless something in the fleet table represents that
        controller. Contract §11.4 records why making the column nullable
        was rejected instead.

        ## The two writes are one unit of work

        Both go through the ``AsyncSession`` this service's repository and
        the provisioner share, and neither is committed here. A failure
        registering the device therefore propagates rather than being
        caught: swallowing it would return ``201`` for an integration whose
        venue still cannot log a guest in, and the row pair would be
        half-written. The route's session dependency rolls both back
        together.

        ## What is deliberately *not* done here

        No connection test. Onboarding stores what the operator entered and
        leaves the integration ``CONNECTING`` (or ``UNCONFIGURED`` when they
        have not finished the wizard); the Test Connection action is its own
        endpoint and its own explicit act. Claiming ``CONNECTED`` because a
        form was submitted is the failure mode this domain's status ladder
        exists to prevent.
        """
        if self.fleet_device_provisioner is None:
            raise NetworkIntegrationFleetDeviceUnavailableError()

        # Reused wholesale rather than reimplemented: SSRF validation and
        # URL normalization, the duplicate-controller check, credential
        # encryption, the status ladder, the domain event and the
        # `CONNECTED` audit entry all belong to that method, and a second
        # create path that reimplemented any of them is a second create path
        # that would drift out of agreement with the first. It runs first,
        # so a rejected URL never reaches another domain's table.
        integration = await self.create_integration(
            actor_user_id=actor_user_id,
            requesting_organization_id=organization_id,
            provider=provider,
            name=name,
            base_url=base_url,
            auth_mode=auth_mode,
            controller_id=controller_id,
            location_id=location_id,
            external_site_id=external_site_id,
            external_site_name=external_site_name,
            guest_ssid_id=guest_ssid_id,
            guest_ssid_name=guest_ssid_name,
            session_duration_seconds=session_duration_seconds,
            sync_interval_seconds=sync_interval_seconds,
            is_enabled=is_enabled,
            tls_mode=tls_mode,
            tls_pinned_sha256=tls_pinned_sha256,
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            password=password,
        )

        return await self._register_fleet_device(
            integration,
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            location_id=location_id,
            controller_model=controller_model,
            serial_number=serial_number,
            mac_address=mac_address,
        )

    async def _register_fleet_device(
        self,
        integration: NetworkIntegration,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        controller_model: str | None = None,
        serial_number: str | None = None,
        mac_address: str | None = None,
    ) -> tuple[NetworkIntegration, Any]:
        """Write the fleet row for ``integration`` and link it. One place.

        Shared by Master onboarding, the customer path once a venue is
        mapped, and the "Register controller" repair action, so the three
        cannot drift into registering controllers three different ways.
        Nothing here commits: the caller's request-scoped session holds this
        write and whatever wrote the integration, and a failure rolls both
        back together.

        ``controller_model`` falls back to the provider's generic model name
        when nobody was asked for one -- only the Master wizard asks.
        """
        if self.fleet_device_provisioner is None:
            raise NetworkIntegrationFleetDeviceUnavailableError()
        name = integration.name
        model = controller_model or FLEET_DEVICE_DEFAULT_MODEL_BY_PROVIDER.get(
            integration.provider, "Network controller"
        )
        # A hardware controller (an OC200/OC300) has a serial plate and a
        # real MAC, and using them means the fleet row matches the sticker
        # on the box an engineer is holding. A software controller has
        # neither, and gets an identity that is deterministic and visibly
        # synthetic -- see `synthesize_fleet_identity` for why it must never
        # be a plausible-looking vendor MAC.
        supplied = serial_number is not None and mac_address is not None
        if supplied:
            fleet_serial, fleet_mac = serial_number, mac_address
        else:
            fleet_serial, fleet_mac = synthesize_fleet_identity(integration.id)

        fleet_device = await self.fleet_device_provisioner.create_router(
            actor_user_id=actor_user_id,
            location_id=location_id,
            requesting_organization_id=organization_id,
            name=name,
            serial_number=fleet_serial,
            mac_address=fleet_mac,
            model=model,
            # From the provider, never from a branch here. `service.py` does
            # not know any vendor's name, and the column this lands in
            # defaults to a different vendor entirely -- so a provider that
            # failed to declare one would produce a fleet row that every
            # RouterOS-assuming sweep in the product would then report as a
            # broken MikroTik.
            vendor=self._provider(integration.provider).fleet_device_vendor,
            # Nothing here enables an agent path: no API credentials, no
            # SNMP, and the router domain's own default status is
            # PENDING_PROVISIONING rather than ONLINE. Those omissions are
            # the mitigation described in `models.py` -- the RouterOS
            # sweeps find nothing to talk to instead of relying on each of
            # them to remember to check the vendor. The vendor gating in
            # `app.domains.router.vendor_capabilities` is what makes them
            # report it honestly.
            settings={
                "synthetic_identity": not supplied,
                # The back-reference an operator needs when they find this
                # row in the fleet table and ask what it is.
                "network_integration_id": str(integration.id),
            },
        )

        integration = await self.repository.update_integration(
            integration, {"router_id": fleet_device.id}
        )

        await self._write_audit(
            action=NetworkIntegrationAuditAction.FLEET_DEVICE_ONBOARDED,
            actor_user_id=actor_user_id,
            integration=integration,
            description=(
                f"Controller '{name}' onboarded and registered as a fleet "
                f"device ({model})"
            ),
            organization_id=organization_id,
            location_id=location_id,
            metadata={
                "router_id": str(fleet_device.id),
                "model": model,
                "synthetic_identity": not supplied,
            },
        )
        return integration, fleet_device

    async def ensure_fleet_device(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> NetworkIntegration:
        """Give a mapped integration the fleet row its guests need. Idempotent.

        ## Why the customer path needs this at all

        ``guest_sessions.router_id`` is NOT NULL, so a venue whose only
        equipment is a controller cannot issue a guest session until
        something in the fleet represents the controller. Only Master
        onboarding used to write that row, so an integration added from the
        customer page could be credentialled, mapped and CONNECTED and still
        show ``fleet_device_missing`` forever, with no portal link and no
        way for its operator to fix it.

        It is called in three places: after the customer create when a
        location was given, after an update that maps a location, and by
        ``POST /{id}/fleet-device`` -- the explicit repair for rows created
        before this existed. That last one is deliberately an action a
        person takes rather than a sweep that rewrites production rows on
        its own.

        ## Idempotent, and never moves anything

        A row that already has a fleet device is returned untouched. That
        includes a row whose location was changed after its device was
        registered: moving a fleet row between venues is a decision about
        inventory, not something a repair button should do silently.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )
        if integration.router_id is not None:
            return integration
        if integration.location_id is None:
            raise NetworkIntegrationLocationRequiredError()
        integration, _ = await self._register_fleet_device(
            integration,
            actor_user_id=actor_user_id,
            organization_id=integration.organization_id,
            location_id=integration.location_id,
        )
        return integration

    async def get_integration(
        self,
        integration_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> NetworkIntegration:
        return await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )

    async def find_integration_for_router(
        self, router_id: uuid.UUID
    ) -> NetworkIntegration | None:
        """The integration a controller-managed fleet row belongs to, or
        ``None``.

        Satisfies ``readiness.NetworkIntegrationLookupProtocol`` -- the
        "smallest interface the sibling already implements" convention this
        codebase uses everywhere, rather than letting `readiness` query
        `network_integrations` itself.

        No ``requesting_organization_id``, and that omission is the
        deliberate part: see the repository method's own docstring. The
        caller resolves the router org-scoped before it gets here, and this
        row's `router_id` was written alongside that router in one
        transaction. A parameter compared against the *caller's* header
        instead of the router's owner would be the path-id scoping defect
        rather than a fix for it.

        Reads only. Nothing here decrypts a credential, so no reveal is
        audit-logged for a checklist page refresh.
        """
        return await self.repository.find_integration_for_router(router_id)

    async def list_integrations(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        provider: str | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[NetworkIntegration], Any]:
        """This tenant's integrations. Never every tenant's.

        ``_require_organization`` first, so a GLOBAL caller hitting the
        *customer* list route gets a 400 telling them to send
        ``X-Organization-Id`` rather than silently receiving the whole
        platform. The Master console's own cross-tenant list is
        :meth:`list_platform_integrations`, and it is a different method
        behind a different permission scope.
        """
        organization_id = self._require_organization(requesting_organization_id)
        return await self.repository.list_integrations(
            requesting_organization_id=organization_id,
            location_id=location_id,
            provider=provider,
            status=status,
            page=page,
            page_size=page_size,
        )

    async def update_integration(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        fields: dict[str, Any],
    ) -> NetworkIntegration:
        """Partial update of a row this caller is proven to own.

        ``base_url`` gets the full SSRF validation again on every change,
        not only at create -- this is the field that decides where a
        tenant's credentials get sent, and an update path that skipped the
        check would make the create-time check decorative.

        Changing ``base_url`` or ``external_site_id`` also resets the
        status ladder: what was ``CONNECTED`` was connected *to the old
        controller*, and carrying that badge over to a new address would
        assert a working connection to something nobody has tried.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )
        updates: dict[str, object] = {}
        changed: list[str] = []

        if "portal_mode" in fields and fields["portal_mode"] is not None:
            # PLATFORM CALLERS ONLY, re-checked here rather than trusted to
            # the schema split. `PlatformNetworkIntegrationUpdateRequest` is
            # the only body with this field, but this method is the one
            # entry point both the customer PATCH and the Master PATCH go
            # through, and "the other route's schema does not have it" is
            # not a check -- it is an assumption about a file somebody else
            # may edit. `requesting_organization_id is None` is exactly the
            # "platform caller, no tenant filter" argument every other
            # platform method in this class already makes.
            if requesting_organization_id is not None:
                raise NetworkIntegrationPortalModeNotPermittedError()
            mode = PortalAuthMode(str(fields["portal_mode"]))
            if mode.value != integration.portal_mode:
                updates["portal_mode"] = mode.value
                changed.append("portal_mode")

        if "auth_mode" in fields and fields["auth_mode"] is not None:
            mode = ControllerAuthMode(str(fields["auth_mode"]))
            if mode.value != integration.auth_mode:
                updates["auth_mode"] = mode.value
                changed.append("auth_mode")
                # The stored credential set belongs to the *old* mode and
                # cannot satisfy the new one. Cleared rather than kept:
                # keeping it would leave the row claiming
                # `has_credentials: true` while every call fails with
                # AUTH_FAILED and nothing explains why.
                updates["credentials_encrypted"] = None

        target_base_url = integration.base_url
        if "base_url" in fields and fields["base_url"] is not None:
            validated = await self._validate_url(str(fields["base_url"]))
            target_base_url = validated.base_url
            if target_base_url != integration.base_url:
                updates["base_url"] = target_base_url
                changed.append("base_url")
                # The controller id was discovered from the old address.
                updates["controller_id"] = None
                updates["controller_version"] = None

        # Applied AFTER the base_url reset above, so an operator who changes
        # the address and supplies the new controller's id in one request gets
        # the id they typed rather than the reset to None. This is the only
        # way to repair a cloud-managed row whose id is wrong or missing:
        # nothing can rediscover it, because the cloud edge's address fronts
        # every controller in the region.
        if "controller_id" in fields and fields["controller_id"] is not None:
            supplied_id = str(fields["controller_id"]).strip()
            if supplied_id and supplied_id != integration.controller_id:
                updates["controller_id"] = supplied_id
                changed.append("controller_id")
                # The version was read from whatever the old id identified.
                updates["controller_version"] = None

        target_site = integration.external_site_id
        if "external_site_id" in fields:
            target_site = (
                None
                if fields["external_site_id"] is None
                else str(fields["external_site_id"])
            )
            if target_site != integration.external_site_id:
                updates["external_site_id"] = target_site
                changed.append("external_site_id")

        if "base_url" in changed or "external_site_id" in changed:
            collision = await self.repository.find_live_integration(
                organization_id=integration.organization_id,
                provider=integration.provider,
                base_url=target_base_url,
                external_site_id=target_site,
                exclude_id=integration.id,
            )
            if collision is not None:
                raise NetworkIntegrationAlreadyExistsError(
                    target_base_url, target_site
                )

        for field_name in (
            "name",
            "location_id",
            "external_site_name",
            "guest_ssid_id",
            "guest_ssid_name",
            "session_duration_seconds",
            "sync_interval_seconds",
        ):
            if (
                field_name in fields
                and fields[field_name] is not None
                and getattr(integration, field_name) != fields[field_name]
            ):
                updates[field_name] = fields[field_name]
                changed.append(field_name)

        if ("tls_mode" in fields and fields["tls_mode"] is not None) or (
            # A fingerprint on its own is a re-pin, and it has to work. It is
            # the literal instruction OMADA_TLS_PIN_MISMATCH gives the
            # operator -- "review the new fingerprint and pin it" -- after a
            # venue replaces a certificate. Requiring them to restate the
            # mode they are already in would make that a silent no-op, which
            # is the worst possible outcome for this particular field: the
            # row keeps the *old* pin and every call keeps failing.
            fields.get("tls_pinned_sha256") is not None
        ):
            # Mode and fingerprint are resolved together even when only one
            # of them was sent, because the pair has to be coherent: moving
            # to 'pinned' needs a fingerprint from *somewhere*, and moving
            # away from it must clear the one already stored.
            #
            # The stored fingerprint is the fallback only for a request that
            # did not send one. That is not a way to skip re-confirming a
            # certificate on the way back into pinned mode -- leaving pinned
            # clears the column, so there is nothing to fall back to.
            requested_mode = fields.get("tls_mode")
            requested_pin = fields.get("tls_pinned_sha256")
            trust_mode, pinned = self._resolve_tls_trust(
                (
                    integration.tls_mode
                    if requested_mode is None
                    else str(requested_mode)
                ),
                (
                    integration.tls_pinned_sha256
                    if requested_pin is None
                    else str(requested_pin)
                ),
            )
            if (
                trust_mode.value != integration.tls_mode
                or pinned != integration.tls_pinned_sha256
            ):
                updates["tls_mode"] = trust_mode.value
                updates["tls_pinned_sha256"] = pinned
                updates["tls_trust_decided_at"] = (
                    None
                    if trust_mode is DEFAULT_CONTROLLER_TLS_MODE
                    else datetime.now(UTC)
                )
                changed.append("tls_mode")

        if "is_enabled" in fields and fields["is_enabled"] is not None:
            is_enabled = bool(fields["is_enabled"])
            if is_enabled != integration.is_enabled:
                updates["is_enabled"] = is_enabled
                changed.append("is_enabled")

        if changed:
            updates["updated_by"] = actor_user_id
            # `controller_id` joins this set for the same reason `base_url`
            # is in it: a row whose Omada ID changed is pointed at a
            # different controller, and a CONNECTED badge earned against the
            # old one asserts a working connection nobody has tried.
            # `tls_mode` is here for the same reason, from the other
            # direction: a row whose trust decision changed has not proven
            # anything under the new one.
            if {
                "base_url",
                "controller_id",
                "external_site_id",
                "auth_mode",
                "tls_mode",
            } & set(changed):
                has_credentials = (
                    updates.get(
                        "credentials_encrypted", integration.credentials_encrypted
                    )
                    is not None
                )
                updates["status"] = (
                    IntegrationStatus.CONNECTING.value
                    if has_credentials and target_site is not None
                    else IntegrationStatus.UNCONFIGURED.value
                )
                updates["last_error_code"] = None
                updates["last_error_message"] = None
                updates["last_error_at"] = None
            elif "is_enabled" in changed:
                updates["status"] = (
                    IntegrationStatus.DISABLED.value
                    if not updates["is_enabled"]
                    else IntegrationStatus.CONNECTING.value
                )

        updated = (
            await self.repository.update_integration(integration, updates)
            if updates
            else integration
        )
        if changed:
            event_type = (
                IntegrationEventType.ENABLED
                if updates.get("is_enabled") is True
                else IntegrationEventType.DISABLED
                if updates.get("is_enabled") is False
                else IntegrationEventType.CONFIG_CHANGED
            )
            await self._record_event(
                updated,
                event_type=event_type,
                status=IntegrationEventStatus.OK,
                message="Configuration updated",
                # Field *names* only, never values: a "before/after" diff
                # of this row would put the old and new base_url in a
                # customer-visible column, and `changed` is what an
                # operator actually needs to see.
                context={"changed_fields": sorted(set(changed))},
            )
            await self._write_audit(
                action=(
                    NetworkIntegrationAuditAction.ENABLED
                    if updates.get("is_enabled") is True
                    else NetworkIntegrationAuditAction.DISABLED
                    if updates.get("is_enabled") is False
                    else NetworkIntegrationAuditAction.CONFIG_CHANGED
                ),
                actor_user_id=actor_user_id,
                integration=updated,
                description=(
                    f"Network integration '{updated.name}' updated: "
                    f"{', '.join(sorted(set(changed)))}"
                ),
                metadata=(
                    {"changed_fields": sorted(set(changed))}
                    | (
                        # A trust change is the one config change whose
                        # *value* belongs in the audit trail. "Somebody
                        # changed tls_mode" is not an answer to "what are we
                        # trusting now"; the mode and the fingerprint are,
                        # and both are public.
                        {
                            "tls_mode": updates["tls_mode"],
                            "tls_pinned_sha256": updates.get("tls_pinned_sha256"),
                        }
                        if "tls_mode" in changed
                        else {}
                    )
                    | (
                        # The other config change whose *value* belongs in
                        # the audit trail, for the same reason: "somebody
                        # changed portal_mode" does not answer "which
                        # contract are this venue's guests on now", and
                        # that answer decides whether the gate is opened
                        # by this platform or by an inbound RADIUS
                        # exchange. Neither value is a secret.
                        {"portal_mode": updates["portal_mode"]}
                        if "portal_mode" in changed
                        else {}
                    )
                ),
            )
        if (
            "location_id" in changed
            and updated.location_id is not None
            and updated.router_id is None
            and self.fleet_device_provisioner is not None
        ):
            # Mapping a venue is the moment an integration can have a fleet
            # row, so it gets one here, in the same transaction as the
            # mapping -- otherwise "Finish setup" would end on a
            # `fleet_device_missing` gap its operator cannot clear. Skipped
            # (not refused) when no provisioner is wired, which only happens
            # outside the real dependency graph; the gap then says so.
            updated, _ = await self._register_fleet_device(
                updated,
                actor_user_id=actor_user_id,
                organization_id=updated.organization_id,
                location_id=updated.location_id,
            )
        return updated

    async def delete_integration(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> NetworkIntegration:
        """Soft-delete. The credential column is cleared in the same write.

        A soft-deleted row keeps its history for the audit trail, which is
        the whole reason soft delete exists here -- but there is no reason
        for it to keep holding a decryptable controller secret. A deleted
        integration is never polled and never authorizes anyone, so the
        ciphertext has no remaining use and every day it stays is a day it
        can leak.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )
        await self.repository.update_integration(
            integration,
            {
                "credentials_encrypted": None,
                "is_enabled": False,
                "status": IntegrationStatus.DISABLED.value,
                "updated_by": actor_user_id,
            },
        )
        await self._record_event(
            integration,
            event_type=IntegrationEventType.DISCONNECTED,
            status=IntegrationEventStatus.OK,
            message="Integration deleted; stored credentials destroyed",
        )
        await self._write_audit(
            action=NetworkIntegrationAuditAction.DISCONNECTED,
            actor_user_id=actor_user_id,
            integration=integration,
            description=f"Network integration '{integration.name}' deleted",
        )
        return await self.repository.soft_delete_integration(integration)

    async def rotate_credentials(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        auth_mode: str,
        tls_mode: str | None = None,
        tls_pinned_sha256: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> NetworkIntegration:
        """Replace the stored credential set. Write-only.

        **The old value is never decrypted.** Not returned, not compared,
        not logged, not read at all -- there is no operation here that
        needs it, and a decrypt is an opportunity to leak. Rotation is
        therefore an overwrite: validate the new set against the declared
        mode, encrypt, write.

        The status resets to ``CONNECTING`` rather than staying
        ``CONNECTED``: the previous status was earned by the previous
        credentials. If the new ones are wrong, the next real call sets
        ``AUTH_FAILED`` -- and in the meantime the row honestly says "not
        proven yet" instead of claiming a connection that may already be
        broken.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )
        mode = ControllerAuthMode(auth_mode)
        try:
            credentials = validate_auth_mode_credentials(
                auth_mode=mode,
                client_id=client_id,
                client_secret=client_secret,
                username=username,
                password=password,
            )
        except ValueError as exc:
            raise NetworkIntegrationUrlRejectedError(str(exc)) from exc

        # Trust is optional here and unchanged when omitted. Re-entering a
        # password is the moment an operator is most likely to be sitting in
        # front of a controller whose certificate has just been replaced --
        # which is exactly when forcing them through a separate PATCH to
        # re-pin it would send them to 'insecure' instead.
        trust_updates: dict[str, object] = {}
        if tls_mode is not None:
            trust_mode, pinned = self._resolve_tls_trust(
                tls_mode,
                (
                    integration.tls_pinned_sha256
                    if tls_pinned_sha256 is None
                    else tls_pinned_sha256
                ),
            )
            trust_updates = {
                "tls_mode": trust_mode.value,
                "tls_pinned_sha256": pinned,
                "tls_trust_decided_at": (
                    None
                    if trust_mode is DEFAULT_CONTROLLER_TLS_MODE
                    else datetime.now(UTC)
                ),
            }

        updated = await self.repository.update_integration(
            integration,
            {
                "auth_mode": mode.value,
                **trust_updates,
                "credentials_encrypted": encrypt_credentials(
                    credentials, settings=self.settings
                ),
                "status": (
                    IntegrationStatus.CONNECTING.value
                    if integration.is_enabled
                    else IntegrationStatus.DISABLED.value
                ),
                "last_error_code": None,
                "last_error_message": None,
                "last_error_at": None,
                "updated_by": actor_user_id,
            },
        )
        await self._record_event(
            updated,
            event_type=IntegrationEventType.CREDENTIALS_ROTATED,
            status=IntegrationEventStatus.OK,
            message="Controller credentials replaced",
            # `auth_mode` and the *names* of the fields supplied. Never a
            # value, never a length, never a prefix -- a "first four
            # characters" breadcrumb is a real attack aid and buys nothing.
            context={
                "auth_mode": mode.value,
                "credential_fields": sorted(credentials),
            },
        )
        await self._write_audit(
            action=NetworkIntegrationAuditAction.CREDENTIALS_ROTATED,
            actor_user_id=actor_user_id,
            integration=updated,
            description=(
                f"Controller credentials rotated for network integration "
                f"'{updated.name}'"
            ),
            metadata={"auth_mode": mode.value},
        )
        return updated

    # -- connection testing ------------------------------------------------

    async def test_connection_unsaved(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        provider: str,
        base_url: str,
        auth_mode: str,
        controller_id: str | None = None,
        tls_mode: str | None = None,
        tls_pinned_sha256: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> tuple[
        ProviderControllerInfo | None,
        ProviderError | None,
        ProviderTlsObservation | None,
    ]:
        """The connect wizard's pre-save probe. Persists nothing.

        No row exists yet, so there is nothing to set a status on and no
        integration to hang an event row from. An **audit entry is still
        written**, on success and on failure: a caller making this platform
        open an authenticated connection from its own network to an
        arbitrary address is exactly the action worth having a record of,
        and it is the one action in this domain with no row to trace it
        back to later.

        Returns ``(info, None, tls)`` or ``(None, error, tls)`` rather than
        raising, because the wizard renders a failure inline next to the
        form -- a 502 would make the browser's own error handling swallow
        the specific reason, which is the only useful part.

        The certificate observation is returned **on failure as well as on
        success**, and that is the whole point of it being here. The failing
        probe against a self-signed controller is the exact moment an
        operator needs to be shown a fingerprint and asked whether to pin
        it; making them succeed first in order to see it would require them
        to turn verification off in order to find out that they did not need
        to. It is ``None`` only when the observation itself could not be
        made.
        """
        organization_id = self._require_organization(requesting_organization_id)
        if provider not in {kind.value for kind in NetworkProviderKind}:
            raise UnsupportedNetworkProviderError(provider)
        mode = ControllerAuthMode(auth_mode)
        trust_mode, pinned = self._resolve_tls_trust(tls_mode, tls_pinned_sha256)
        validated = await self._validate_url(base_url)
        try:
            credentials = validate_auth_mode_credentials(
                auth_mode=mode,
                client_id=client_id,
                client_secret=client_secret,
                username=username,
                password=password,
            )
        except ValueError as exc:
            raise NetworkIntegrationUrlRejectedError(str(exc)) from exc

        config = ProviderConnectionConfig(
            provider=provider,
            base_url=validated.base_url,
            auth_mode=mode.value,
            credentials=credentials,
            # Forwarded because on a cloud-managed controller it is not
            # optional: the provider cannot discover an id from a host that
            # fronts every controller in a region. There is no row to read it
            # from on this path, so if the operator did not type it, the probe
            # fails with a message naming the field -- which is the honest
            # outcome and the one the wizard can act on.
            controller_id=(controller_id or None),
            tls_mode=trust_mode.value,
            tls_pinned_sha256=pinned,
            timeout_seconds=self.settings.omada_api_timeout_seconds,
        )
        provider_impl = self._provider(provider)
        observation = await self._observe_tls(provider_impl, config)
        try:
            info = await provider_impl.test_connection(config)
        except ProviderError as error:
            await self._write_audit(
                action=NetworkIntegrationAuditAction.TEST_CONNECTION,
                actor_user_id=actor_user_id,
                integration=None,
                organization_id=organization_id,
                description=(
                    f"Pre-save connection test to {validated.base_url} failed "
                    f"({error.code.value})"
                ),
                metadata={
                    "base_url": validated.base_url,
                    "auth_mode": mode.value,
                    "error_code": error.code.value,
                    "tls_mode": trust_mode.value,
                    "observed_tls_sha256": (
                        None if observation is None
                        else observation.fingerprint_sha256
                    ),
                },
            )
            return None, error, observation

        await self._write_audit(
            action=NetworkIntegrationAuditAction.TEST_CONNECTION,
            actor_user_id=actor_user_id,
            integration=None,
            organization_id=organization_id,
            description=f"Pre-save connection test to {validated.base_url} succeeded",
            metadata={
                "base_url": validated.base_url,
                "auth_mode": mode.value,
                "tls_mode": trust_mode.value,
                "observed_tls_sha256": (
                    None if observation is None else observation.fingerprint_sha256
                ),
            },
        )
        return info, None, observation

    async def test_integration_connection(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[
        ProviderControllerInfo | None,
        ProviderError | None,
        ProviderTlsObservation | None,
    ]:
        """Probe a saved integration and record the outcome on the row.

        Unlike the unsaved probe, this one *does* move the status -- it is
        the operator explicitly asking "is this working right now", and an
        answer that is not written down is one the dashboard immediately
        contradicts. Also persists the discovered ``controller_id`` /
        ``controller_version``. That is how those columns are normally
        populated -- read from the controller rather than typed in -- with one
        exception found on hardware: a cloud-managed controller cannot be
        identified at all until an ``omadacId`` is supplied, because its
        address fronts every controller in the region. So ``controller_id``
        is also accepted at create/update time, and the write below keeps a
        stored id when the probe returns none rather than clearing it.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._credentials_for(integration)
        provider_impl = self._provider(integration.provider)
        config = self._connection_config(integration, credentials)
        # Observed before the test, so that a test which fails *because of*
        # the certificate still returns the fingerprint the operator needs
        # in order to fix it.
        observation = await self._observe_tls(provider_impl, config)
        try:
            info = await provider_impl.test_connection(config)
        except ProviderError as error:
            await self._record_failure(
                integration,
                error,
                event_type=IntegrationEventType.TEST_CONNECTION,
                during_sync=False,
            )
            return None, error, observation

        metadata = dict(integration.provider_metadata or {})
        metadata["consecutive_failure_count"] = 0
        updated = await self.repository.update_integration(
            integration,
            {
                "status": IntegrationStatus.CONNECTED.value,
                "controller_id": info.controller_id or integration.controller_id,
                "controller_version": info.controller_version,
                "last_error_code": None,
                "last_error_message": None,
                "last_error_at": None,
                "provider_metadata": metadata,
            },
        )
        await self._record_event(
            updated,
            event_type=IntegrationEventType.TEST_CONNECTION,
            status=IntegrationEventStatus.OK,
            message="Connection test succeeded",
            context={"controller_version": info.controller_version},
        )
        await self._write_audit(
            action=NetworkIntegrationAuditAction.TEST_CONNECTION,
            actor_user_id=actor_user_id,
            integration=updated,
            description=(
                f"Connection test succeeded for network integration "
                f"'{updated.name}'"
            ),
        )
        return info, None, observation

    # -- live controller reads --------------------------------------------

    async def _for_live_read(
        self,
        integration_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        capability: str,
        require_site: bool = True,
    ) -> tuple[NetworkIntegration, NetworkProvider, ProviderConnectionConfig]:
        """Shared preamble for every live controller read.

        Four gates, in this order, and the order matters: the tenant check
        comes first so a caller learns nothing about a row they do not own
        (not even whether it is enabled or which auth mode it uses).

        The auth-mode gate is contract change **CR-002**: an integration
        authenticating with a hotspot operator credential cannot read
        controller inventory at all, so the refusal happens here -- before
        a provider is resolved and before any request is issued -- rather
        than letting the controller answer with what looks like a wrong
        password. Refused loudly, never as an empty list; see
        ``exceptions.NetworkIntegrationInventoryRequiresOpenApiError`` for
        why an empty list would be a false statement about the venue's
        hardware.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )
        if not integration.is_enabled:
            raise NetworkIntegrationDisabledError()
        if integration.auth_mode == ControllerAuthMode.LEGACY.value:
            raise NetworkIntegrationInventoryRequiresOpenApiError(capability)
        if require_site and not integration.external_site_id:
            raise NetworkIntegrationSiteNotSelectedError()
        credentials = self._credentials_for(integration)
        return (
            integration,
            self._provider(integration.provider),
            self._connection_config(integration, credentials),
        )

    async def list_sites(
        self,
        integration_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[ProviderSite]:
        """Live from the controller.

        ``require_site=False``: this is the call the connect wizard makes
        *in order to choose* a site, so requiring one first would make the
        wizard unable to reach its own next step.
        """
        integration, provider_impl, config = await self._for_live_read(
            integration_id,
            requesting_organization_id=requesting_organization_id,
            capability="sites",
            require_site=False,
        )
        try:
            return await provider_impl.list_sites(config)
        except ProviderError as error:
            await self._record_failure(
                integration,
                error,
                event_type=IntegrationEventType.SYNC,
                during_sync=False,
            )
            raise

    async def list_ssids(
        self,
        integration_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[ProviderSsid]:
        integration, provider_impl, config = await self._for_live_read(
            integration_id,
            requesting_organization_id=requesting_organization_id,
            capability="SSIDs",
        )
        try:
            return await provider_impl.list_ssids(
                config, str(integration.external_site_id)
            )
        except ProviderError as error:
            await self._record_failure(
                integration,
                error,
                event_type=IntegrationEventType.SYNC,
                during_sync=False,
            )
            raise

    async def list_devices(
        self,
        integration_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[ProviderDevice]:
        integration, provider_impl, config = await self._for_live_read(
            integration_id,
            requesting_organization_id=requesting_organization_id,
            capability="devices",
        )
        try:
            return await provider_impl.list_devices(
                config, str(integration.external_site_id)
            )
        except ProviderError as error:
            await self._record_failure(
                integration,
                error,
                event_type=IntegrationEventType.SYNC,
                during_sync=False,
            )
            raise

    async def list_clients(
        self,
        integration_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> list[ProviderClient]:
        integration, provider_impl, config = await self._for_live_read(
            integration_id,
            requesting_organization_id=requesting_organization_id,
            capability="clients",
        )
        try:
            return await provider_impl.list_clients(
                config, str(integration.external_site_id)
            )
        except ProviderError as error:
            await self._record_failure(
                integration,
                error,
                event_type=IntegrationEventType.SYNC,
                during_sync=False,
            )
            raise

    async def list_events(
        self,
        integration_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[Any], Any]:
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_events(
            integration_id=integration.id,
            requesting_organization_id=integration.organization_id,
            page=page,
            page_size=page_size,
        )

    async def get_status(
        self,
        integration_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> dict[str, Any]:
        """Cached status, with the counts and the next-due time.

        Reads nothing from the controller: this is the endpoint a dashboard
        polls, and making it a live round trip would mean every open
        browser tab generating traffic against a venue's hardware. The
        numbers are as fresh as the last sync and ``last_sync_at`` is
        returned so the reader can tell.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )
        metadata = integration.provider_metadata or {}
        active = await self.repository.count_active_authorizations(
            integration_id=integration.id, now=datetime.now(UTC)
        )
        next_due: datetime | None = None
        if integration.last_sync_at is not None and integration.is_enabled:
            next_due = integration.last_sync_at + timedelta(
                seconds=self._effective_sync_interval(integration)
            )
        return {
            "id": str(integration.id),
            "status": integration.status,
            "is_enabled": integration.is_enabled,
            "last_sync_at": integration.last_sync_at,
            "last_sync_status": integration.last_sync_status,
            "last_error_code": integration.last_error_code,
            "last_error_message": integration.last_error_message,
            "last_error_at": integration.last_error_at,
            "device_count": int(metadata.get("device_count", 0) or 0),
            "client_count": int(metadata.get("client_count", 0) or 0),
            "active_authorization_count": active,
            "consecutive_failure_count": self._consecutive_failures(integration),
            "next_sync_due_at": next_due,
        }

    async def counts_for(self, integration: NetworkIntegration) -> dict[str, int]:
        """The three numbers the list/detail response carries.

        ``device_count``/``client_count`` come from the last sync's cached
        metadata, not from a live call: rendering a list of twenty-five
        integrations must not mean twenty-five HTTPS round trips to
        twenty-five customer controllers.
        """
        metadata = integration.provider_metadata or {}
        return {
            "device_count": int(metadata.get("device_count", 0) or 0),
            "client_count": int(metadata.get("client_count", 0) or 0),
            "active_authorization_count": (
                await self.repository.count_active_authorizations(
                    integration_id=integration.id, now=datetime.now(UTC)
                )
            ),
        }

    # -- sync --------------------------------------------------------------

    def _effective_sync_interval(self, integration: NetworkIntegration) -> int:
        """The row's own interval, multiplied by its consecutive-failure
        backoff and capped.

        Doubling per failure up to ``SYNC_BACKOFF_CAP_MULTIPLIER``. Capped
        rather than unbounded so a controller that comes back after a long
        outage is noticed within hours instead of never -- an exponential
        with no ceiling eventually means "we stopped checking", which is
        indistinguishable from a bug.
        """
        failures = self._consecutive_failures(integration)
        if failures <= 0:
            return integration.sync_interval_seconds
        multiplier = min(2**failures, SYNC_BACKOFF_CAP_MULTIPLIER)
        return integration.sync_interval_seconds * multiplier

    def is_sync_due(
        self, integration: NetworkIntegration, *, now: datetime | None = None
    ) -> bool:
        """Whether the backoff-adjusted interval has actually elapsed.

        The SQL in ``repository.list_due_for_sync`` selects on the *base*
        interval (a JSONB-derived multiplier cannot be indexed usefully),
        so the sweep re-checks each candidate here. See that method's own
        docstring for why the cheap over-selection was preferred to a
        denormalized ``next_sync_due_at`` column that can go stale.
        """
        if not integration.is_enabled or integration.is_deleted:
            return False
        if integration.last_sync_at is None:
            return True
        moment = now or datetime.now(UTC)
        due_at = integration.last_sync_at + timedelta(
            seconds=self._effective_sync_interval(integration)
        )
        return moment >= due_at

    async def sync_integration(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None = None,
        requesting_organization_id: uuid.UUID | None,
    ) -> SyncOutcome:
        """Operator-triggered sync of one integration.

        Goes through ``_load_owned_integration`` like every other by-id
        path -- a manual sync is a real outbound call to a controller, so
        letting tenant A trigger it against tenant B's box would be both a
        cross-tenant action and a way to make this platform generate
        traffic at a third party on demand.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )
        if not integration.is_enabled:
            raise NetworkIntegrationDisabledError()
        outcome = await self._sync(integration)
        if outcome.synced:
            await self._write_audit(
                action=NetworkIntegrationAuditAction.SYNCED,
                actor_user_id=actor_user_id,
                integration=integration,
                description=(
                    f"Manual sync of network integration '{integration.name}'"
                ),
            )
        return outcome

    async def _sync(self, integration: NetworkIntegration) -> SyncOutcome:
        """The provider-agnostic sync body, shared by the sweep and the
        manual endpoint.

        Does **not** re-check tenancy: both callers have already
        established their right to act (the manual path via
        ``_load_owned_integration``, the sweep because it runs as the
        platform with no caller at all). Kept private and marked so,
        rather than exposed as a convenient shortcut past the guard.
        """
        if not integration.credentials_encrypted:
            # Not an error and not a failure to record against the
            # controller: nobody has finished setting this up. Recording
            # a sync failure here would put a red badge on an integration
            # whose only problem is that a wizard was abandoned.
            return SyncOutcome(
                integration_id=integration.id,
                synced=False,
                status=integration.status,
                error_code=ErrorCode.CREDENTIALS_REQUIRED.value,
                message="No stored credentials",
            )
        try:
            credentials = self._credentials_for(integration)
            provider_impl = self._provider(integration.provider)
            config = self._connection_config(integration, credentials)
            info = await provider_impl.get_controller_info(config)
            sites = await provider_impl.list_sites(config)
            devices: Sequence[ProviderDevice] = []
            clients: Sequence[ProviderClient] = []
            if integration.external_site_id:
                site_id = str(integration.external_site_id)
                devices = await provider_impl.list_devices(config, site_id)
                clients = await provider_impl.list_clients(config, site_id)
        except ProviderError as error:
            await self._record_failure(
                integration,
                error,
                event_type=IntegrationEventType.SYNC,
                during_sync=True,
            )
            return SyncOutcome(
                integration_id=integration.id,
                synced=False,
                status=self._status_for_provider_error(
                    error, during_sync=True
                ).value,
                error_code=error.code.value,
                message=error.message,
            )

        now = datetime.now(UTC)
        metadata = dict(integration.provider_metadata or {})
        metadata["device_count"] = len(devices)
        metadata["client_count"] = len(clients)
        metadata["site_count"] = len(sites)
        metadata["consecutive_failure_count"] = 0
        # A successful controller conversation is not the same claim as a
        # working venue, and reporting it as one is how an operator ends up
        # with a green CONNECTED badge over a site where nobody gets
        # online. `portal_readiness_gaps` asks the narrower question --
        # would `authorize_portal_client` actually get as far as the
        # controller for a guest at this venue -- and every gap it can
        # return is a branch that method really takes.
        gaps = portal_readiness_gaps(integration, settings=self.settings)
        updates: dict[str, object] = {
            "status": (
                IntegrationStatus.UNCONFIGURED.value
                if gaps
                else IntegrationStatus.CONNECTED.value
            ),
            "controller_id": info.controller_id or integration.controller_id,
            "controller_version": info.controller_version,
            "last_sync_at": now,
            # The *sync* did succeed, and saying otherwise would put this
            # row into the failure backoff and stop it being polled -- so
            # the moment the operator finishes the mapping, nothing would
            # notice. Two different facts, two different columns.
            "last_sync_status": SyncStatus.OK.value,
            "last_error_code": ErrorCode.SETUP_INCOMPLETE.value if gaps else None,
            "last_error_message": (
                describe_portal_readiness_gaps(gaps) if gaps else None
            ),
            "last_error_at": now if gaps else None,
            "provider_metadata": metadata,
        }
        # Refresh the cached site name if the controller renamed it. The
        # *id* is never overwritten from a name match -- that would be
        # guessing at a mapping (see providers/omada.py).
        for site in sites:
            if site.site_id == integration.external_site_id:
                if site.name != integration.external_site_name:
                    updates["external_site_name"] = site.name
                break
        updated = await self.repository.update_integration(integration, updates)
        await self._record_event(
            updated,
            event_type=IntegrationEventType.SYNC,
            # Recorded as an ERROR rather than an OK-with-a-note. This feed
            # is what a human reads to answer "what has this integration
            # been doing", and "it has been talking to the controller
            # perfectly and authorizing nobody" is the single most
            # important thing it can say. No extra rows: one SYNC event per
            # sync either way.
            status=(
                IntegrationEventStatus.ERROR if gaps else IntegrationEventStatus.OK
            ),
            error_code=ErrorCode.SETUP_INCOMPLETE.value if gaps else None,
            message=(
                describe_portal_readiness_gaps(gaps) if gaps else "Sync completed"
            ),
            context={
                "site_count": len(sites),
                "device_count": len(devices),
                "client_count": len(clients),
                **({"readiness_gaps": [gap.value for gap in gaps]} if gaps else {}),
            },
        )
        return SyncOutcome(
            integration_id=updated.id,
            synced=True,
            status=updated.status,
            site_count=len(sites),
            device_count=len(devices),
            client_count=len(clients),
            error_code=ErrorCode.SETUP_INCOMPLETE.value if gaps else None,
            message=describe_portal_readiness_gaps(gaps) if gaps else None,
        )

    # -- platform (Master console) ----------------------------------------

    async def list_platform_integrations(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        provider: str | None = None,
        status: str | None = None,
        query: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[
        list[NetworkIntegration],
        Any,
        dict[uuid.UUID, tuple[str | None, str | None]],
    ]:
        """**Deliberately unscoped cross-tenant read.** Master console only.

        The method name and this docstring are the entire safety story, so
        both are explicit: when ``organization_id`` is ``None`` this
        returns integrations belonging to *every tenant on the platform*.
        That is the requirement -- the Master console's Network
        Integrations page exists to show exactly that -- and it is why this
        is a separate method from :meth:`list_integrations` rather than the
        same one called with ``None``.

        What stops a customer reaching it is the route:
        ``RequirePermission("network_integrations.read",
        scope=ScopeType.GLOBAL)``. An Organization Owner holds
        ``network_integrations.read`` at ORGANIZATION scope and cannot
        satisfy a GLOBAL check, so the bare permission key is not enough
        and the explicit scope is doing real work. ``organization_id``
        here is a *filter* a platform operator chose, never a tenant
        boundary derived from their identity.
        """
        integrations, meta = await self.repository.list_integrations(
            requesting_organization_id=organization_id,
            provider=provider,
            status=status,
            query=query,
            page=page,
            page_size=page_size,
        )
        names = await self.repository.resolve_display_names(integrations)
        return integrations, meta, names

    async def get_platform_integration(
        self, integration_id: uuid.UUID
    ) -> tuple[NetworkIntegration, tuple[str | None, str | None]]:
        """One integration, any tenant. Master console only.

        No organization comparison, by design -- ``requesting_organization_id
        =None`` is passed to the shared guard so the *location* confinement
        still applies (a platform operator is unconfined, so it is a
        no-op) while the tenant comparison is skipped. Gated at the route
        by GLOBAL scope, exactly as :meth:`list_platform_integrations`.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=None
        )
        names = await self.repository.resolve_display_names([integration])
        return integration, names.get(integration.id, (None, None))

    async def get_platform_summary(self) -> Any:
        """Platform-wide aggregates. Unscoped by definition -- it counts
        tenants. Gated at the route by GLOBAL scope; see
        ``repository.platform_summary``."""
        return await self.repository.platform_summary()

    async def set_platform_enabled(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        is_enabled: bool,
    ) -> NetworkIntegration:
        """Platform operator enable/disable of any tenant's integration.

        A real, deliberate cross-tenant *write*, and the only one in this
        domain. It exists because a platform operator must be able to stop
        this platform hammering a customer's controller during an incident
        without waiting for the customer to log in. Audited on every call,
        with the target organization recorded -- that trail is the control
        that makes this defensible.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=None
        )
        if integration.is_enabled == is_enabled:
            return integration
        updated = await self.repository.update_integration(
            integration,
            {
                "is_enabled": is_enabled,
                "status": (
                    IntegrationStatus.CONNECTING.value
                    if is_enabled
                    else IntegrationStatus.DISABLED.value
                ),
                "updated_by": actor_user_id,
            },
        )
        await self._record_event(
            updated,
            event_type=(
                IntegrationEventType.ENABLED
                if is_enabled
                else IntegrationEventType.DISABLED
            ),
            status=IntegrationEventStatus.OK,
            message=(
                "Enabled by a platform operator"
                if is_enabled
                else "Disabled by a platform operator"
            ),
        )
        await self._write_audit(
            action=(
                NetworkIntegrationAuditAction.ENABLED
                if is_enabled
                else NetworkIntegrationAuditAction.DISABLED
            ),
            actor_user_id=actor_user_id,
            integration=updated,
            description=(
                f"Network integration '{updated.name}' "
                f"{'enabled' if is_enabled else 'disabled'} by a platform operator"
            ),
            metadata={"platform_action": True},
        )
        return updated

    async def test_platform_connection(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
    ) -> tuple[
        ProviderControllerInfo | None,
        ProviderError | None,
        ProviderTlsObservation | None,
    ]:
        """Platform-operator connection test against any tenant's controller.

        Unscoped like the two reads above and gated the same way. Reuses
        the customer method with ``requesting_organization_id=None`` rather
        than duplicating the probe, so there is one implementation of "test
        a saved integration" and one place where its status bookkeeping
        lives.
        """
        return await self.test_integration_connection(
            integration_id,
            actor_user_id=actor_user_id,
            requesting_organization_id=None,
        )

    # -- configure controller automatically -------------------------------

    async def configure_controller(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        dry_run: bool,
        take_over_ssid_portal: bool = False,
    ) -> ControllerSetupOutcome:
        """Configure the venue's controller for guest sign-in -- customer path.

        Portal, Pre-Authentication Access entry and hotspot operator account,
        through the provider's automatic setup. See
        :meth:`_configure_controller` for the rules.

        The integration is read **with** the caller's organization in the
        query, so a path id from another tenant is a 404, never a read
        followed by a refusal. ``None`` is refused outright: on this route it
        would mean "no tenant filter", and the platform has its own route.
        """
        organization_id = self._require_organization(requesting_organization_id)
        integration = await self._load_owned_integration(
            integration_id,
            requesting_organization_id=organization_id,
            scope_read_to_organization=True,
        )
        return await self._configure_controller(
            integration,
            actor_user_id=actor_user_id,
            dry_run=dry_run,
            take_over_ssid_portal=take_over_ssid_portal,
            platform_action=False,
        )

    async def configure_platform_controller(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        dry_run: bool,
        take_over_ssid_portal: bool = False,
    ) -> ControllerSetupOutcome:
        """The same run for a platform operator, against any tenant's row.

        Unscoped like :meth:`test_platform_connection` and gated the same way
        -- GLOBAL scope at the route. Everything written is still derived
        from the loaded row's own organization, location and fleet device,
        exactly as on the customer path; a platform caller chooses *which*
        integration, never what it points at. Audited as a platform action.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=None
        )
        return await self._configure_controller(
            integration,
            actor_user_id=actor_user_id,
            dry_run=dry_run,
            take_over_ssid_portal=take_over_ssid_portal,
            platform_action=True,
        )

    async def update_platform_integration(
        self,
        integration_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        fields: dict[str, Any],
    ) -> NetworkIntegration:
        """Correct or complete any tenant's integration from the Master console.

        The site id, guest SSID, TLS mode and Omada ID a controller needs
        cannot all be known at ``POST /platform/onboard`` time -- listing
        sites requires an authenticated call, which requires stored
        credentials, which require the row the wizard is creating at that
        moment. Something has to be able to fill them in afterwards, and
        since ``PATCH /network-integrations/{id}`` is GLOBAL-scoped now
        (see that router's docstring), a platform operator would otherwise
        have had to complete a controller setup by sending organization
        headers at a route that no longer honours them.

        Deliberately a thin delegation to :meth:`update_integration` with
        ``requesting_organization_id=None`` rather than a second
        implementation: every rule that method enforces -- the SSRF
        re-validation of ``base_url``, the status ladder reset when the
        address/site/Omada id/trust changes, the duplicate-integration
        check, the TLS mode/fingerprint coherence -- is exactly as
        necessary for a platform operator, and a parallel copy would be a
        second place for them to drift. ``None`` is the same "platform
        caller, no filter" argument :meth:`configure_platform_controller`
        and :meth:`set_platform_enabled` already make, and the audit entry
        ``update_integration`` writes names the target organization.

        Credentials are **not** reachable here, exactly as on the customer
        body: ``NetworkIntegrationUpdateRequest`` carries no credential
        field, and rotation keeps its own endpoint and its own audit
        action.
        """
        return await self.update_integration(
            integration_id,
            actor_user_id=actor_user_id,
            requesting_organization_id=None,
            fields=fields,
        )

    def _controller_setup_gaps(
        self, integration: NetworkIntegration, provider_impl: NetworkProvider
    ) -> list[ControllerSetupGap]:
        """Everything automatic setup needs that this row lacks, in fix order.

        Stored credential *names* only -- ``stored_credential_fields`` never
        returns a value. An unreadable ciphertext adds no gap here:
        ``_credentials_for`` reports that on its own path, as re-enter the
        credentials, which is the true fix.
        """
        gaps: list[ControllerSetupGap] = []
        if not integration.is_enabled:
            gaps.append(ControllerSetupGap.INTEGRATION_DISABLED)
        if not callable(getattr(provider_impl, "configure_controller", None)):
            gaps.append(ControllerSetupGap.PROVIDER_UNSUPPORTED)
        if integration.auth_mode != ControllerAuthMode.OPENAPI.value:
            gaps.append(ControllerSetupGap.OPENAPI_REQUIRED)
        elif not integration.credentials_encrypted:
            gaps.append(ControllerSetupGap.CREDENTIALS_MISSING)
        else:
            fields = stored_credential_fields(
                integration.credentials_encrypted, settings=self.settings
            )
            if fields is not None and not {"client_id", "client_secret"} <= fields:
                gaps.append(ControllerSetupGap.CREDENTIALS_MISSING)
        if integration.location_id is None:
            gaps.append(ControllerSetupGap.LOCATION_NOT_MAPPED)
        if not integration.external_site_id:
            gaps.append(ControllerSetupGap.SITE_NOT_SELECTED)
        if integration.router_id is None:
            gaps.append(ControllerSetupGap.FLEET_DEVICE_MISSING)
        if not integration.guest_ssid_id and not integration.guest_ssid_name:
            gaps.append(ControllerSetupGap.GUEST_SSID_MISSING)
        return gaps

    async def _refuse_shared_controller_site(
        self, integration: NetworkIntegration
    ) -> None:
        """Refuse when anyone else already manages this controller site.

        Two rules, both about state that lives on the controller and is
        shared by every integration pointed at one site:

        * **Another organization** on the same site: refused for both. The
          other tenant is not named and nothing of theirs is returned.
        * **Another integration in this organization** with the same guest
          SSID: refused, because one SSID can be bound to one portal and two
          locations would take it from each other on every run. A second
          location on the same site with its *own* SSID is the supported
          multi-location layout and passes.

        "Same controller" is same normalized ``base_url`` and, when both rows
        know one, same ``controller_id``. A row that has not discovered its
        id yet is assumed to be the same controller: site ids are per-
        controller object ids, so a coincidental match across controllers
        behind one address is not a realistic case, and guessing "different"
        is the unsafe direction.
        """
        others = await self.repository.list_live_integrations_on_controller_site(
            provider=integration.provider,
            base_url=integration.base_url,
            external_site_id=str(integration.external_site_id),
            exclude_id=integration.id,
        )
        mine = (integration.controller_id or "").strip().lower()
        same_controller = [
            other
            for other in others
            if not mine
            or not (other.controller_id or "").strip()
            or (other.controller_id or "").strip().lower() == mine
        ]
        if any(
            other.organization_id != integration.organization_id
            for other in same_controller
        ):
            raise ControllerSiteSharedError()
        for other in same_controller:
            if (
                integration.guest_ssid_id
                and other.guest_ssid_id == integration.guest_ssid_id
            ) or (
                integration.guest_ssid_name
                and other.guest_ssid_name == integration.guest_ssid_name
            ):
                raise GuestSsidInUseError()

    @staticmethod
    def _controller_setup_portal_name(
        integration: NetworkIntegration, location_name: str | None
    ) -> str:
        """``Wyfy Guest - <venue> (<8 hex of the integration id>)``.

        The id suffix is what makes the name safe to match on: two locations
        of one customer on one site can share a display name, never a suffix.
        Truncated on the venue part to the controller's 128-character limit,
        and stripped of control characters and edge spaces its pattern
        refuses.
        """
        suffix = f" ({integration.id.hex[:8]})"
        label = " ".join((location_name or integration.name or "").split())
        label = "".join(ch for ch in label if ch.isprintable())
        base = (
            f"{CONTROLLER_SETUP_PORTAL_NAME_PREFIX} - {label}"
            if label
            else CONTROLLER_SETUP_PORTAL_NAME_PREFIX
        )
        room = CONTROLLER_SETUP_PORTAL_NAME_MAX_LENGTH - len(suffix)
        return base[:room].rstrip() + suffix

    @staticmethod
    def _setup_block_error(block: ProviderControllerSetupBlock) -> Exception:
        if block.kind == "ssid_portal_conflict":
            return PortalConflictError(
                block.message,
                portal_id=block.portal_id,
                portal_name=block.portal_name,
            )
        if block.kind == "guest_ssid_ambiguous":
            return GuestSsidAmbiguousError(block.message, match_count=block.match_count)
        return GuestSsidNotFoundError(block.message)

    async def _record_setup_event(
        self,
        integration: NetworkIntegration,
        *,
        dry_run: bool,
        ok: bool,
        message: str,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """The one event row a real run leaves behind. A dry run writes
        nothing to this database, this row included."""
        if dry_run:
            return
        await self._record_event(
            integration,
            event_type=IntegrationEventType.CONTROLLER_CONFIGURED,
            status=IntegrationEventStatus.OK if ok else IntegrationEventStatus.ERROR,
            error_code=error_code,
            message=message,
            context=context,
        )

    async def _configure_controller(
        self,
        integration: NetworkIntegration,
        *,
        actor_user_id: uuid.UUID | None,
        dry_run: bool,
        take_over_ssid_portal: bool,
        platform_action: bool,
    ) -> ControllerSetupOutcome:
        """The run itself. Tenancy has already been settled by the caller.

        ## Everything written derives from this row

        The portal URL is ``validators.build_external_portal_url`` over this
        row's own organization, location and fleet device -- the same URL the
        integration card shows; the site, SSID and operator name are this
        row's; nothing comes from the request except ``dry_run`` and
        ``take_over_ssid_portal``. That is what makes the platform variant
        safe to share this body.

        ## Order of refusals, all before any controller write

        preconditions (no controller contact) -> another tenant or another
        location on this site (no controller contact) -> credentials readable
        -> the provider's own read-only planning (SSID resolution, a foreign
        portal on the SSID). Each refusal on a real run records one event.

        ## The operator password

        Generated here with ``secrets`` and encrypted *before* the controller
        is asked to create the account, so a deployment that cannot store it
        (the public-key refusal) refuses before anything is created. It is
        stored only when the provider reports it was actually set on the
        controller. It is never logged, returned, or put in an event.

        Known edge, stated rather than hidden: two real runs racing on one
        integration each generate a password, and the last database write may
        not be the last controller write. The next run then reports the
        stored login as refused, and the documented recovery (save the Open
        API app alone and run again) resets this integration's own account.
        """
        provider_impl = self._provider(integration.provider)
        gaps = self._controller_setup_gaps(integration, provider_impl)
        if gaps:
            error = ControllerSetupPreconditionsError(gaps)
            await self._record_setup_event(
                integration,
                dry_run=dry_run,
                ok=False,
                message=error.message,
                error_code=error.code.value,
                context={"missing": [gap.value for gap in gaps]},
            )
            raise error

        try:
            await self._refuse_shared_controller_site(integration)
        except (ControllerSiteSharedError, GuestSsidInUseError) as error:
            await self._record_setup_event(
                integration,
                dry_run=dry_run,
                ok=False,
                message=error.message,
                error_code=error.code.value,
            )
            raise

        credentials = self._credentials_for(integration)
        portal_url = build_external_portal_url(
            organization_id=integration.organization_id,
            location_id=integration.location_id,
            router_id=integration.router_id,
            provider=integration.provider,
        )
        if portal_url is None:  # pragma: no cover - excluded by the gaps above
            raise ControllerSetupPreconditionsError(
                [ControllerSetupGap.FLEET_DEVICE_MISSING]
            )
        pre_auth_host = portal_url.host_and_query.split("/", 1)[0]
        _, location_name = (
            await self.repository.resolve_display_names([integration])
        ).get(integration.id, (None, None))
        operator_name = f"{CONTROLLER_SETUP_OPERATOR_PREFIX}{integration.id.hex[:12]}"

        has_operator = set(credentials) >= GUEST_OPERATOR_CREDENTIAL_FIELDS
        new_password: str | None = None
        pending_ciphertext: str | None = None
        if not has_operator and not dry_run:
            # ~190 bits, URL-safe alphabet: inside the operator password
            # pattern (printable ASCII, 1-128 characters) by construction.
            new_password = secrets.token_urlsafe(24)
            pending_ciphertext = encrypt_credentials(
                {**credentials, "username": operator_name, "password": new_password},
                settings=self.settings,
            )

        request = ProviderControllerSetupRequest(
            site_id=str(integration.external_site_id),
            portal_name=self._controller_setup_portal_name(integration, location_name),
            portal_url_scheme=portal_url.scheme,
            portal_url_host_and_query=portal_url.host_and_query,
            ownership_query=(
                EXTERNAL_PORTAL_OWNERSHIP_PARAM,
                str(integration.router_id),
            ),
            pre_auth_host=pre_auth_host,
            auth_timeout_minutes=max(
                1, -(-integration.session_duration_seconds // 60)
            ),
            operator_name=operator_name,
            operator_note=(
                f"Managed by Wyfy Guest for integration {integration.id}. "
                "Do not edit or delete."
            ),
            operator_marker=str(integration.id),
            guest_ssid_id=integration.guest_ssid_id,
            guest_ssid_name=integration.guest_ssid_name,
            create_operator_if_missing=not has_operator,
            new_operator_password=new_password,
            take_over_ssid_portal=take_over_ssid_portal,
            dry_run=dry_run,
        )
        config = self._connection_config(integration, credentials)
        try:
            report = await provider_impl.configure_controller(config, request)
        except ProviderError as error:
            await self._record_setup_event(
                integration,
                dry_run=dry_run,
                ok=False,
                message=error.message,
                error_code=error.code.value,
                context={"provider_code": error.provider_code},
            )
            raise

        if report.block is not None:
            error = self._setup_block_error(report.block)
            await self._record_setup_event(
                integration,
                dry_run=dry_run,
                ok=False,
                message=error.message,
                error_code=error.code.value,
                context={"block": report.block.kind},
            )
            raise error

        saved: list[str] = []
        if not dry_run:
            updates: dict[str, object] = {}
            resolved_ssid = report.guest_ssid_id
            if resolved_ssid and resolved_ssid != integration.guest_ssid_id:
                updates["guest_ssid_id"] = report.guest_ssid_id
                saved.append("guest_ssid_id")
            if report.operator_credentials_set and pending_ciphertext is not None:
                updates["credentials_encrypted"] = pending_ciphertext
                saved.append("hotspot_operator_login")
            if updates:
                updates["updated_by"] = actor_user_id
                integration = await self.repository.update_integration(
                    integration, updates
                )

        ok = all(step.outcome != _SETUP_FAILED for step in report.steps)
        changed = any(step.outcome in _SETUP_CHANGING for step in report.steps)
        summary = ", ".join(f"{step.step} {step.outcome}" for step in report.steps)
        await self._record_setup_event(
            integration,
            dry_run=dry_run,
            ok=ok,
            message=(
                f"Controller configured automatically: {summary}"
                if ok
                else f"Automatic controller configuration incomplete: {summary}"
            ),
            context={
                "take_over_ssid_portal": take_over_ssid_portal,
                "platform_action": platform_action,
                "portal_id": report.portal_id,
                "guest_ssid_id": report.guest_ssid_id,
                "saved": saved,
                "steps": [
                    {
                        "step": step.step,
                        "outcome": step.outcome,
                        "message": step.message,
                        "provider_code": step.provider_code,
                        "details": step.details,
                    }
                    for step in report.steps
                ],
            },
        )
        if not dry_run:
            await self._write_audit(
                action=NetworkIntegrationAuditAction.CONTROLLER_CONFIGURED,
                actor_user_id=actor_user_id,
                integration=integration,
                description=(
                    f"Controller for network integration '{integration.name}' "
                    f"configured automatically"
                    f"{' by a platform operator' if platform_action else ''}: "
                    f"{summary}"
                ),
                metadata={
                    "platform_action": platform_action,
                    "take_over_ssid_portal": take_over_ssid_portal,
                    "outcomes": {step.step: step.outcome for step in report.steps},
                },
            )
        return ControllerSetupOutcome(
            integration_id=integration.id,
            dry_run=dry_run,
            ok=ok,
            changed=changed,
            steps=report.steps,
            portal_id=report.portal_id,
            guest_ssid_id=report.guest_ssid_id,
            portal_url_scheme=portal_url.scheme,
            portal_url_host_and_query=portal_url.host_and_query,
            pre_auth_host=pre_auth_host,
        )

    async def probe_controller_draft(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        provider: str,
        base_url: str,
        auth_mode: str,
        controller_id: str | None = None,
        tls_mode: str | None = None,
        tls_pinned_sha256: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        username: str | None = None,
        password: str | None = None,
        site_id: str | None = None,
    ) -> ControllerDraftProbeOutcome:
        """The Master console's pre-save probe. No organization, persists nothing.

        The platform twin of :meth:`test_connection_unsaved`, for the "Add
        customer" wizard, which reaches its device step before the customer's
        organization exists. Same gates in the same order -- provider, trust
        decision, :meth:`_validate_url` (ports, private ranges; the provider
        re-validates before every request), credential shape -- and the same
        certificate observation made *before* the test, so a failure still
        carries the fingerprint. What it adds is what lets the wizard fill
        the form in for the operator: a suggested trust mode, and with Open
        API credentials the controller's sites and SSIDs.

        No integration row and no event row: there is nothing to hang either
        on. One **audit entry** is written, with no organization, exactly as
        the customer probe writes one -- this platform opening an
        authenticated connection to an address a caller typed is the action
        worth a record, and here there is no row to trace it back to later.

        Inventory reads are best-effort. They run only after the connection
        test passed, and a failure there is returned as ``inventory_error``
        rather than turning a working connection into a failed probe.

        **No credentials at all is a valid request**, and a deliberate one:
        the wizard probes as soon as the address is typed. It then gets the
        certificate and the controller's unauthenticated identity (version,
        Omada ID) from ``get_controller_info``, with ``credentials_checked``
        false so nobody reads ``ok`` as "the password works". Half a
        credential is still refused, exactly as on every other path.
        """
        if provider not in {kind.value for kind in NetworkProviderKind}:
            raise UnsupportedNetworkProviderError(provider)
        mode = ControllerAuthMode(auth_mode)
        trust_mode, pinned = self._resolve_tls_trust(tls_mode, tls_pinned_sha256)
        validated = await self._validate_url(base_url)
        credentials_checked = any((client_id, client_secret, username, password))
        credentials: dict[str, str] = {}
        if credentials_checked:
            try:
                credentials = validate_auth_mode_credentials(
                    auth_mode=mode,
                    client_id=client_id,
                    client_secret=client_secret,
                    username=username,
                    password=password,
                )
            except ValueError as exc:
                raise NetworkIntegrationUrlRejectedError(str(exc)) from exc

        config = ProviderConnectionConfig(
            provider=provider,
            base_url=validated.base_url,
            auth_mode=mode.value,
            credentials=credentials,
            controller_id=(controller_id or None),
            tls_mode=trust_mode.value,
            tls_pinned_sha256=pinned,
            timeout_seconds=self.settings.omada_api_timeout_seconds,
        )
        provider_impl = self._provider(provider)
        observation = await self._observe_tls(provider_impl, config)
        suggested = (
            None
            if observation is None
            else (
                ControllerTlsMode.STRICT.value
                if observation.chain_trusted
                else ControllerTlsMode.PINNED.value
            )
        )
        # A property of the credential, not of this attempt: a hotspot
        # operator login cannot read inventory whether or not it signed in.
        operator_only = mode is ControllerAuthMode.LEGACY
        audit_metadata: dict[str, Any] = {
            "base_url": validated.base_url,
            "auth_mode": mode.value,
            "tls_mode": trust_mode.value,
            "observed_tls_sha256": (
                None if observation is None else observation.fingerprint_sha256
            ),
            "platform_action": True,
            "credentials_checked": credentials_checked,
        }

        try:
            if credentials_checked:
                info = await provider_impl.test_connection(config)
            else:
                info = await provider_impl.get_controller_info(config)
        except ProviderError as error:
            await self._write_audit(
                action=NetworkIntegrationAuditAction.TEST_CONNECTION,
                actor_user_id=actor_user_id,
                integration=None,
                description=(
                    f"Platform pre-save connection test to {validated.base_url} "
                    f"failed ({error.code.value})"
                ),
                metadata={**audit_metadata, "error_code": error.code.value},
            )
            return ControllerDraftProbeOutcome(
                info=None,
                error=error,
                tls=observation,
                suggested_tls_mode=suggested,
                credentials_checked=credentials_checked,
                inventory_requires_openapi=operator_only,
            )

        sites: list[ProviderSite] = []
        ssids: list[ProviderSsid] = []
        ssids_site_id: str | None = None
        inventory_error: ProviderError | None = None
        inventory_available = False
        if credentials_checked and not operator_only:
            # Scoped with the id the test just discovered, so the reads below
            # do not each repeat the controller-identity round trip.
            inventory_config = dataclasses.replace(
                config, controller_id=info.controller_id or config.controller_id
            )
            try:
                sites = list(await provider_impl.list_sites(inventory_config))
                inventory_available = True
                known = {site.site_id for site in sites}
                if site_id:
                    if site_id not in known:
                        raise ProviderSiteNotFoundError(
                            "The controller has no site with that id. Choose "
                            "one of the sites listed."
                        )
                    ssids_site_id = site_id
                elif len(sites) == 1:
                    ssids_site_id = sites[0].site_id
                if ssids_site_id is not None:
                    ssids = list(
                        await provider_impl.list_ssids(inventory_config, ssids_site_id)
                    )
            except ProviderError as error:
                inventory_error = error
                ssids, ssids_site_id = [], None

        await self._write_audit(
            action=NetworkIntegrationAuditAction.TEST_CONNECTION,
            actor_user_id=actor_user_id,
            integration=None,
            description=(
                f"Platform pre-save connection test to {validated.base_url} "
                "succeeded"
            ),
            metadata={
                **audit_metadata,
                "inventory_error_code": (
                    None if inventory_error is None else inventory_error.code.value
                ),
            },
        )
        return ControllerDraftProbeOutcome(
            info=info,
            error=None,
            tls=observation,
            suggested_tls_mode=suggested,
            credentials_checked=credentials_checked,
            inventory_requires_openapi=operator_only,
            inventory_available=inventory_available,
            inventory_error=inventory_error,
            sites=tuple(sites),
            ssids_site_id=ssids_site_id,
            ssids=tuple(ssids),
        )

    # -- portal authorize (public) ----------------------------------------

    async def _check_portal_rate_limit(self, source: str) -> None:
        """Per-session limiter, mirroring ``OtpRateLimiter``'s INCR+EXPIRE+TTL.

        Fails **open** on a Redis error and when no Redis is configured,
        matching ``RateLimitMiddleware``'s own documented posture: this is
        the network-enforcement step of a guest getting online, and a Redis
        blip must not become a venue-wide WiFi outage. The per-IP
        middleware layer is still in front of this endpoint regardless.
        """
        if self._redis is None:
            return
        key = PORTAL_AUTHORIZE_RATE_LIMIT_KEY_TEMPLATE.format(source=source)
        try:
            current = await self._redis.incr(key)
            if current == 1:
                await self._redis.expire(key, PORTAL_AUTHORIZE_WINDOW_SECONDS)
            if current > PORTAL_AUTHORIZE_MAX_ATTEMPTS_PER_WINDOW:
                ttl = await self._redis.ttl(key)
                raise NetworkIntegrationRateLimitedError(
                    ttl if ttl and ttl > 0 else PORTAL_AUTHORIZE_WINDOW_SECONDS
                )
        except NetworkIntegrationRateLimitedError:
            raise
        except Exception:  # noqa: BLE001 -- Redis unavailable
            logger.warning(
                "network_integration_portal_rate_limit_unavailable", exc_info=True
            )

    async def authorize_portal_client(
        self,
        *,
        session_id: uuid.UUID,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        provider: str,
        client_mac: str,
        site: str,
        ap_mac: str | None = None,
        ssid_name: str | None = None,
        radio_id: int | None = None,
        gateway_mac: str | None = None,
        vid: int | None = None,
        t: str | None = None,
        redirect_url: str | None = None,
        client_ip: str | None = None,
    ) -> PortalAuthorizationOutcome:
        """Authorize one guest device on the venue's controller.

        **This authenticates nobody.** By the time it is called,
        ``app.domains.guest`` has already decided the guest may go online
        (OTP, voucher, consent) and has issued a ``GuestSession``. This is
        the network-enforcement step that follows -- the Omada equivalent
        of the existing MikroTik ``link-login-only`` POST.

        Every argument arrives from an unauthenticated request body, so
        every one of them is treated as a claim:

        1. **The session must exist and be ``ACTIVE``.** A
           ``DISCONNECTED``/``EXPIRED``/``TERMINATED`` session is refused
           -- particularly ``TERMINATED``, which is the punitive kill an
           admin used to throw an abusive guest off the network. Honouring
           it here would hand that guest a fresh controller authorization.
        2. **The session's own ``organization_id`` and ``location_id`` must
           match the body.** Both, not either. This is what stops a caller
           pairing a session id they somehow learned with a *different*
           venue's ids to get authorized on that venue's controller.
        3. **The integration is resolved by (organization, location,
           provider)** -- from the *session's* venue, not from the body's,
           so even a body that lied consistently cannot select a foreign
           integration.
        4. **The redirect's ``site`` must match the integration's stored
           site.** A mismatch means the redirect came from a controller
           this integration is not configured for.

        Failures are recorded server-side (an event row where an
        integration was resolved) but the response is a single
        indistinguishable 403 -- see
        ``exceptions.GuestSessionNotActiveError`` for why this endpoint
        must not be an oracle.
        """
        if provider not in {kind.value for kind in NetworkProviderKind}:
            raise UnsupportedNetworkProviderError(provider)
        await self._check_portal_rate_limit(str(session_id))

        try:
            normalized_mac = normalize_client_mac(client_mac)
        except ValueError as exc:
            raise NetworkIntegrationUrlRejectedError(str(exc)) from exc

        if self.guest_session_lookup is None:
            # Nothing can be proven, so nothing is authorized. Refusing is
            # the only safe branch: an unauthenticated endpoint whose one
            # check is unavailable must not fall through to "allow".
            logger.error("network_integration_portal_no_session_lookup")
            raise GuestSessionNotActiveError()

        session = await self.guest_session_lookup.get_session_by_id(session_id)
        if (
            session is None
            or getattr(session, "is_deleted", False)
            or str(getattr(session, "status", "")) != _GUEST_SESSION_ACTIVE
            or getattr(session, "organization_id", None) != organization_id
            or getattr(session, "location_id", None) != location_id
        ):
            logger.warning(
                "network_integration_portal_session_rejected",
                extra={
                    "session_present": session is not None,
                    "organization_id": str(organization_id),
                    "location_id": str(location_id),
                },
            )
            raise GuestSessionNotActiveError()

        # The MAC being authorized must be the device that authenticated.
        #
        # Without this, every check above is satisfied by a guest who did
        # everything honestly -- their own session, their own venue -- while
        # the body names SOMEONE ELSE'S device. That guest completes OTP once
        # and then puts a stranger's phone, or a neighbouring shop's laptop,
        # onto the venue's WiFi. The organization and location comparisons
        # above stop a foreign tenant's controller being reached; they say
        # nothing at all about *which device* is being let on.
        #
        # It is not a theoretical shape: this endpoint takes `client_mac`
        # straight from the request body, and the only other thing it does
        # with it is hand it to the controller.
        #
        # A session with no device is refused rather than waved through.
        # `GuestSession.device_id` is nullable -- a guest can log in without
        # presenting a MAC -- but on this path the MAC always arrives on
        # Omada's own redirect, so a missing device means the binding cannot
        # be established, and an authorization we cannot bind is exactly the
        # one worth refusing. Same `GuestSessionNotActiveError` as every
        # other failure of this check: the endpoint is unauthenticated, and
        # distinguishing "wrong device" from "no session" for a caller who
        # holds no credentials just tells a prober which half to vary.
        device_id = getattr(session, "device_id", None)
        device = (
            await self.guest_session_lookup.get_device_by_id(device_id)
            if device_id is not None
            else None
        )
        session_mac = getattr(device, "mac_address", None)
        if session_mac is None or normalize_client_mac(session_mac) != normalized_mac:
            logger.warning(
                "network_integration_portal_device_mismatch",
                extra={
                    "session_has_device": device is not None,
                    "organization_id": str(organization_id),
                    "location_id": str(location_id),
                },
            )
            raise GuestSessionNotActiveError()

        integration = await self.repository.find_enabled_integration_for_location(
            organization_id=session.organization_id,
            location_id=session.location_id,
            provider=provider,
        )
        if integration is None:
            raise NetworkIntegrationNotFoundError(
                f"no enabled {provider} integration for this location"
            )
        if integration.portal_mode == PortalAuthMode.RADIUS.value:
            # THIS PLATFORM IS NOT IN THE AUTHORIZATION PATH AT THIS VENUE.
            #
            # On the RADIUS contract the guest's browser submits to the
            # controller's own `POST /portal/radius/browserauth`, the
            # controller sends an Access-Request to this platform's
            # FreeRADIUS, and the controller opens the gate on the
            # Access-Accept. Nothing here can authorize anybody, and an
            # `extPortal/auth` call made anyway would either fail against a
            # portal configured for `authType 2` or -- worse -- succeed and
            # produce an authorization nobody asked for.
            #
            # A call arriving here therefore means one of two things, and
            # both are configuration rather than abuse: a guest is using a
            # portal URL captured before this venue moved contracts, or the
            # controller is still configured for the mode the row no longer
            # says. The event row names it; see `ErrorCode
            # .PORTAL_MODE_MISMATCH`.
            #
            # Refused with the SAME opaque 403 as every other failure of
            # this endpoint. It is unauthenticated and reachable by anyone
            # on a venue's WiFi (see `GuestSessionNotActiveError`), so it
            # does not become an oracle for which contract a venue is on
            # just because that answer happens to be operationally
            # interesting.
            await self._record_event(
                integration,
                event_type=IntegrationEventType.PORTAL_AUTHORIZE,
                status=IntegrationEventStatus.ERROR,
                error_code=ErrorCode.PORTAL_MODE_MISMATCH.value,
                message=(
                    "A guest portal called the authorize endpoint for a "
                    "venue configured for RADIUS mode, where this platform "
                    "is not in the authorization path"
                ),
                context={"portal_mode": integration.portal_mode},
            )
            raise GuestSessionNotActiveError()
        if not integration.external_site_id:
            raise NetworkIntegrationSiteNotSelectedError()
        context = ProviderPortalContext(
            client_mac=client_mac,
            site=site,
            ap_mac=ap_mac,
            ssid_name=ssid_name,
            radio_id=radio_id,
            gateway_mac=gateway_mac,
            vid=vid,
            t=t,
            redirect_url=redirect_url,
            # CR-004. Carried, not computed: this is the ``clientIp`` the
            # controller put on its own redirect. This method never
            # consults the HTTP request's source address -- it does not
            # have one, and the layer that does (``router.py``) is
            # forbidden from substituting it, because behind the venue's
            # NAT and this platform's proxy that address is not the
            # guest's. ``None`` means the redirect carried none, and the
            # provider then omits the field entirely.
            client_ip=client_ip,
        )
        if site != integration.external_site_id and site != (
            integration.external_site_name or ""
        ):
            # The controller that issued this redirect is not the one this
            # integration is configured against. Recorded, then refused --
            # authorizing against a site we were not configured for would
            # be acting on an attacker's choice of target.
            #
            # The full diagnostics go on this row too, even though no request
            # was ever built. This is the one failure the controller would
            # never have explained anyway -- it never saw the call -- and it
            # is a leading candidate whenever a venue's guests stop working
            # after somebody re-created a site on the controller. An operator
            # looking at a failed join should find the same shape of record
            # whichever side refused.
            await self._record_event(
                integration,
                event_type=IntegrationEventType.PORTAL_AUTHORIZE,
                status=IntegrationEventStatus.ERROR,
                error_code=ErrorCode.SITE_NOT_FOUND.value,
                message="Portal redirect named a site this integration is not "
                "configured for",
                context={
                    "requested_site": site,
                    PORTAL_AUTHORIZE_DIAGNOSTICS_KEY: (
                        build_portal_authorize_diagnostics(
                            context=context,
                            normalized_client_mac=normalized_mac,
                            integration=integration,
                        )
                    ),
                },
            )
            raise GuestSessionNotActiveError()

        credentials = self._credentials_for(integration)
        provider_impl = self._provider(integration.provider)
        config = self._connection_config(integration, credentials)
        try:
            result = await provider_impl.authorize_guest(
                config,
                context,
                duration_seconds=integration.session_duration_seconds,
            )
        except ProviderError as error:
            await self._record_authorization(
                integration,
                session_id=session_id,
                client_mac=normalized_mac,
                ap_mac=ap_mac,
                ssid_name=ssid_name,
                result=None,
                error_code=error.code.value,
            )
            await self._record_event(
                integration,
                event_type=IntegrationEventType.PORTAL_AUTHORIZE,
                status=IntegrationEventStatus.ERROR,
                error_code=error.code.value,
                message=error.message,
                context={
                    PORTAL_AUTHORIZE_DIAGNOSTICS_KEY: (
                        build_portal_authorize_diagnostics(
                            context=context,
                            normalized_client_mac=normalized_mac,
                            integration=integration,
                            request_snapshot=error.request_snapshot,
                            provider_code=error.provider_code,
                        )
                    )
                },
            )
            raise

        await self._record_authorization(
            integration,
            session_id=session_id,
            client_mac=normalized_mac,
            ap_mac=ap_mac,
            ssid_name=ssid_name,
            result=result,
            error_code=None,
        )
        await self._record_event(
            integration,
            event_type=IntegrationEventType.PORTAL_AUTHORIZE,
            status=(
                IntegrationEventStatus.OK
                if result.authorized
                else IntegrationEventStatus.ERROR
            ),
            error_code=None if result.authorized else result.provider_code,
            message=(
                "Guest authorized on controller"
                if result.authorized
                else "Controller declined the authorization"
            ),
            context=self._portal_authorize_event_context(
                context=context,
                normalized_client_mac=normalized_mac,
                integration=integration,
                result=result,
            ),
        )
        return PortalAuthorizationOutcome(
            authorized=result.authorized,
            provider=integration.provider,
            expires_at=result.expires_at,
            # Echoed back from the request. This platform never fetches it.
            redirect_url=redirect_url,
        )

    @staticmethod
    def _portal_authorize_event_context(
        *,
        context: ProviderPortalContext,
        normalized_client_mac: str,
        integration: NetworkIntegration,
        result: ProviderAuthorizationResult,
    ) -> dict[str, Any]:
        """The event context for a call the controller actually answered.

        A declined authorization gets the full diagnostics; a successful one
        gets what it always got and nothing more.

        That asymmetry is the retention decision, not an oversight. The
        bundle names a guest's device, and writing it on every success would
        put one MAC per guest per join into
        ``network_integration_events`` -- a table that holds no per-guest
        identifier today and has no retention sweep -- in order to answer a
        question nobody asks about a call that worked. Failures are the small
        population anybody ever diffs, and confining the record to them
        bounds the new data by the failure rate rather than by traffic. See
        ``constants.PORTAL_AUTHORIZE_DIAGNOSTICS_ON_SUCCESS``, which is the
        switch and is off.

        ``result.authorized`` is False here only defensively: the provider
        raises on every refusal the controller reports, so this branch is
        reached by a gateway that returned a negative result instead of
        raising. That is exactly the case where an engineer has least to go
        on, which is why it is treated as a failure for recording purposes.
        """
        event_context: dict[str, Any] = {"ssid_name": context.ssid_name}
        if result.authorized and not PORTAL_AUTHORIZE_DIAGNOSTICS_ON_SUCCESS:
            return event_context
        event_context[PORTAL_AUTHORIZE_DIAGNOSTICS_KEY] = (
            build_portal_authorize_diagnostics(
                context=context,
                normalized_client_mac=normalized_client_mac,
                integration=integration,
                request_snapshot=result.request_snapshot,
            )
        )
        return event_context

    async def disconnect_guest(
        self,
        integration_id: uuid.UUID,
        *,
        client_mac: str,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        reason: str | None = None,
    ) -> GuestDisconnectOutcome:
        """End one guest's network access now, on the controller and here.

        The staff-facing half of the portal authorize flow, and the one
        this domain spent its first release unable to perform. It does two
        distinct things in a deliberate order:

        1. **The controller.** The provider ends every live authorization
           the MAC holds on the integration's site. This is the part that
           actually takes the device off the network, and it is the part
           that used to be impossible.
        2. **This platform.** The authorization row is marked
           ``DEAUTHORIZED``/``deauthorized_at``, and the guest's
           ``GuestSession`` is ended through ``app.domains.guest`` so the
           next portal hit does not find an ``ACTIVE`` session and
           re-admit them.

        ## Why the controller goes first

        Because the failure modes are not symmetric. If the controller
        call fails we raise and nothing is written -- no row claiming a
        revocation that did not happen, no session marked ended while the
        guest is still streaming. The reverse order would produce exactly
        the falsehood this domain's docstrings keep pointing at: a record
        reading "ended" over a device still forwarding traffic.

        The consequence is that a controller failure leaves the guest
        session untouched and the operator with a real error. Ending the
        session *alone* remains available and remains meaningful -- it
        prevents re-authorization -- but it is a different action on a
        different route, and it is not silently substituted here.

        ## Idempotence, and what "success" claims

        Disconnecting a guest who is already disconnected succeeds. The
        provider contract treats "this MAC holds no live authorization" as
        the end state the caller asked for, so a second click, a guest
        whose hour ran out, and a guest an operator already removed in the
        controller's own UI all return ``disconnected=True`` with
        ``had_active_authorization=False``. That is the honest reading:
        the guest is not authorized. It is not a claim that this call is
        what ended it.

        ## What it means at a RADIUS-mode venue, which is less

        Dispatched on the integration's stored ``portal_mode``, and the two
        branches make genuinely different promises -- see
        ``constants.DisconnectMechanism``:

        * **External Portal Server.** This platform issued the
          authorization and holds the row for it. The controller call
          revokes that authorization, the row is flipped, and the guest's
          ``GuestSession`` is ended *from that row*, so re-admission is
          closed too.
        * **RADIUS.** This platform never issued the authorization -- the
          controller did, on an Access-Accept from our FreeRADIUS -- so
          there is no ``network_integration_authorizations`` row, nothing
          to flip, and nothing to find the guest's session from. The
          controller is still asked to drop the client, which is the only
          outbound revocation that exists on this contract; the
          Disconnect-Request the mode advertises (``receiverPort``) travels
          *inbound to the venue* and has never been received by anything.
          So this call drops the device and does **not** stop the guest
          from logging straight back in: the RADIUS authorize path is a
          session lookup, so what closes re-admission is ending the
          ``GuestSession`` on the guest domain.

        ``outcome.mechanism`` is how a caller tells the two apart. It is
        not inferred from the other booleans, because in RADIUS mode all of
        them are individually true and collectively weaker.

        ## Tenant authorization

        Through ``_load_owned_integration`` like every other by-id
        operation in this domain, so the organization and location checks
        cannot be forgotten here -- the caller's organization is never
        read from the request body. The guest-session end is additionally
        passed ``requesting_organization_id``, so the guest domain applies
        its own scoping rather than trusting ours.
        """
        integration = await self._load_owned_integration(
            integration_id, requesting_organization_id=requesting_organization_id
        )
        mechanism = (
            DisconnectMechanism.CONTROLLER_CLIENT_ONLY
            if integration.portal_mode == PortalAuthMode.RADIUS.value
            else DisconnectMechanism.CONTROLLER_AUTHORIZATION
        )
        if not integration.external_site_id:
            raise NetworkIntegrationSiteNotSelectedError()
        try:
            normalized_mac = normalize_client_mac(client_mac)
        except ValueError as exc:
            raise NetworkIntegrationUrlRejectedError(str(exc)) from exc

        # Read *before* the controller call, so the outcome can say whether
        # this platform believed the guest was authorized -- which is no
        # longer knowable once the row has been flipped.
        active = await self.repository.find_active_authorization(
            integration_id=integration.id, client_mac=normalized_mac
        )

        credentials = self._credentials_for(integration)
        provider_impl = self._provider(integration.provider)
        config = self._connection_config(integration, credentials)
        try:
            result = await provider_impl.deauthorize_guest(
                config, str(integration.external_site_id), normalized_mac
            )
        except ProviderError as error:
            await self._record_event(
                integration,
                event_type=IntegrationEventType.PORTAL_DEAUTHORIZE,
                status=IntegrationEventStatus.ERROR,
                error_code=error.code.value,
                message=error.message,
            )
            if error.code is ErrorCode.API_UNSUPPORTED:
                raise NetworkIntegrationDeauthorizationUnsupportedError() from error
            raise

        deauthorized_at: datetime | None = None
        if active is not None:
            deauthorized_at = datetime.now(UTC)
            await self.repository.update_authorization(
                active,
                {
                    "status": AuthorizationStatus.DEAUTHORIZED.value,
                    "deauthorized_at": deauthorized_at,
                },
            )

        guest_session_id = getattr(active, "guest_session_id", None)
        session_ended = await self._end_guest_session(
            guest_session_id,
            actor_user_id=actor_user_id,
            requesting_organization_id=requesting_organization_id,
            reason=reason,
        )

        await self._record_event(
            integration,
            event_type=IntegrationEventType.PORTAL_DEAUTHORIZE,
            status=IntegrationEventStatus.OK,
            message=(
                "Guest access ended on the controller"
                if mechanism is DisconnectMechanism.CONTROLLER_AUTHORIZATION
                else "Client dropped on the controller; the guest's session "
                "must be ended separately to stop re-admission"
            ),
            context={
                "had_active_authorization": active is not None,
                "guest_session_ended": session_ended,
                "mechanism": mechanism.value,
                "reason": reason,
            },
        )
        await self._write_audit(
            action=NetworkIntegrationAuditAction.GUEST_DISCONNECTED,
            actor_user_id=actor_user_id,
            integration=integration,
            description=(
                "Ended a guest's network access early"
                + (f": {reason}" if reason else "")
            ),
            metadata={
                "had_active_authorization": active is not None,
                "guest_session_ended": session_ended,
                "mechanism": mechanism.value,
                "guest_session_id": (
                    str(guest_session_id) if guest_session_id else None
                ),
            },
        )
        return GuestDisconnectOutcome(
            mechanism=mechanism.value,
            disconnected=bool(result),
            provider=integration.provider,
            client_mac=normalized_mac,
            had_active_authorization=active is not None,
            deauthorized_at=deauthorized_at,
            guest_session_id=guest_session_id,
            guest_session_ended=session_ended,
        )

    async def _end_guest_session(
        self,
        guest_session_id: uuid.UUID | None,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        reason: str | None,
    ) -> bool:
        """End the guest's session, and report honestly whether it ended.

        Returns ``False`` rather than raising when there is nothing to
        end. Three distinct cases land there and none of them is a failure
        of the disconnect the operator asked for:

        * no authorization row, so no session to point at;
        * the session is already ``DISCONNECTED``/``EXPIRED``/terminated,
          which ``app.domains.guest``'s transition graph rejects by design
          (it has no same-status no-op, deliberately);
        * no terminator wired -- which happens only in a unit test that
          constructed this service directly.

        The controller-side revocation has already happened by the time
        this runs and is the load-bearing half. Failing the whole request
        because a session row was already closed would turn a completed
        disconnect into a 4xx, and the operator would click again.

        The guest domain's own error is logged rather than swallowed
        silently, and the ``False`` is carried all the way out to the API
        response so nobody has to infer it.
        """
        if guest_session_id is None or self.guest_session_terminator is None:
            return False
        try:
            await self.guest_session_terminator.disconnect_session(
                session_id=guest_session_id,
                requesting_organization_id=requesting_organization_id,
                actor_user_id=actor_user_id,
                reason=reason or "Disconnected by venue staff",
            )
        except CloudGuestError:
            logger.info(
                "network_integration_guest_session_not_ended",
                extra={"guest_session_id": str(guest_session_id)},
                exc_info=True,
            )
            return False
        return True

    async def deauthorize_portal_client(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        provider: str,
        client_mac: str,
    ) -> bool:
        """End a guest's *controller* authorization, resolved by venue.

        The location-keyed sibling of :meth:`disconnect_guest`. Same
        provider call underneath; the difference is how the integration is
        found and who is allowed to ask.

        * :meth:`disconnect_guest` takes an integration id and runs it
          through ``_load_owned_integration``, so a staff caller's
          organization and location confinement are enforced from their
          token. That is the method a dashboard route uses.
        * This one takes ``organization_id``/``location_id`` as **trusted
          arguments** and resolves the venue's enabled integration from
          them. It is for internal callers that have already established
          whose venue this is -- an expiry sweep, or a guest-side flow
          acting on a session it has already validated. It must never be
          reached directly from a request body.

        ## What changed here

        This used to raise unconditionally. Its previous docstring
        explained, at length, that TP-Link publishes no
        client-deauthorization endpoint and that a guest's access
        therefore ended only when the duration expired. TP-Link does
        publish none; the controller has one anyway, in the Hotspot
        Manager API tree behind the operator session the portal
        authorization already opens, and it is implemented. So the success
        path below is now the ordinary path rather than dead code kept for
        a hypothetical second provider.

        ``OMADA_API_UNSUPPORTED`` still arrives here, and is still
        re-raised as
        :class:`~.exceptions.NetworkIntegrationDeauthorizationUnsupportedError`
        -- but it now means one specific, narrow thing: the integration
        stores no hotspot operator credentials, so there is no session to
        send the disconnect with. The same gap makes ``authorize_guest``
        refuse, so such an integration never put a guest on the network to
        begin with.

        ## What has not changed

        Nothing is written for an attempt that raised. Recording a
        deauthorization this platform did not achieve would move the
        falsehood out of the response and into the database, which is
        worse and not better.

        Ending the WyfyGuest ``GuestSession`` row is still required and is
        still ``app.domains.guest``'s job: it is what stops the next
        re-authorization finding an ``ACTIVE`` session and re-admitting
        the guest. This method does not do it -- :meth:`disconnect_guest`
        does, through the terminator seam, after the controller has
        confirmed.
        """
        if provider not in {kind.value for kind in NetworkProviderKind}:
            raise UnsupportedNetworkProviderError(provider)
        integration = await self.repository.find_enabled_integration_for_location(
            organization_id=organization_id,
            location_id=location_id,
            provider=provider,
        )
        if integration is None:
            raise NetworkIntegrationNotFoundError(
                f"no enabled {provider} integration for this location"
            )
        if not integration.external_site_id:
            raise NetworkIntegrationSiteNotSelectedError()
        try:
            normalized_mac = normalize_client_mac(client_mac)
        except ValueError as exc:
            raise NetworkIntegrationUrlRejectedError(str(exc)) from exc

        credentials = self._credentials_for(integration)
        provider_impl = self._provider(integration.provider)
        config = self._connection_config(integration, credentials)
        try:
            result = await provider_impl.deauthorize_guest(
                config, str(integration.external_site_id), normalized_mac
            )
        except ProviderError as error:
            await self._record_event(
                integration,
                event_type=IntegrationEventType.PORTAL_DEAUTHORIZE,
                status=IntegrationEventStatus.ERROR,
                error_code=error.code.value,
                message=error.message,
            )
            if error.code is ErrorCode.API_UNSUPPORTED:
                raise NetworkIntegrationDeauthorizationUnsupportedError() from error
            raise

        # This was unreachable against Omada when it was written, and was
        # kept correct anyway on the premise that a second provider which
        # genuinely supported deauthorization must not need the method
        # rewritten. Omada turned out to be that provider, and the branch
        # was already right when it became live -- which is the argument
        # for the provider seam, made by accident.
        active = await self.repository.find_active_authorization(
            integration_id=integration.id, client_mac=normalized_mac
        )
        if active is not None:
            await self.repository.update_authorization(
                active,
                {
                    "status": AuthorizationStatus.DEAUTHORIZED.value,
                    "deauthorized_at": datetime.now(UTC),
                },
            )
        await self._record_event(
            integration,
            event_type=IntegrationEventType.PORTAL_DEAUTHORIZE,
            status=IntegrationEventStatus.OK,
            message="Guest deauthorized on controller",
        )
        return bool(result)

    async def _record_authorization(
        self,
        integration: NetworkIntegration,
        *,
        session_id: uuid.UUID,
        client_mac: str,
        ap_mac: str | None,
        ssid_name: str | None,
        result: ProviderAuthorizationResult | None,
        error_code: str | None,
    ) -> None:
        """Insert the authorizations row, on success *and* on failure.

        A failed attempt is a row, not a silence. It is what lets a venue
        owner (and this platform's own support) answer "did anything even
        try to authorize this device", which is the first question asked
        every time a guest says the WiFi did not work.
        """
        authorized = bool(result and result.authorized)
        await self.repository.create_authorization(
            integration_id=integration.id,
            organization_id=integration.organization_id,
            location_id=integration.location_id,
            guest_session_id=session_id,
            client_mac=client_mac,
            ap_mac=ap_mac,
            ssid_name=ssid_name,
            external_site_id=integration.external_site_id,
            status=(
                AuthorizationStatus.AUTHORIZED.value
                if authorized
                else AuthorizationStatus.FAILED.value
            ),
            authorized_at=datetime.now(UTC) if authorized else None,
            expires_at=result.expires_at if result else None,
            error_code=error_code,
        )


# ============================================================================
# Sweep (module-level, as the other sweeps in this codebase are)
# ============================================================================


async def run_network_integration_sync_sweep(
    service: NetworkIntegrationService,
    *,
    now: datetime | None = None,
    limit: int,
) -> SyncSweepSummary:
    """Poll every integration whose own interval has elapsed.

    Module-level rather than a method, matching
    ``app.domains.network_diagnostics.service.purge_expired_runs`` and
    ``app.domains.isp.service.run_health_check_sweep``: the sweep needs a
    service and nothing a request would provide, and a Celery task body
    has no FastAPI dependency graph to build one from.

    **Runs as the platform, with no caller.** It therefore never goes
    through ``_load_owned_integration`` -- there is no organization to
    compare against -- and calls ``_sync`` directly. That is safe for
    exactly one reason: the only rows it can reach are the ones
    ``list_due_for_sync`` returns, which is enabled, non-deleted
    integrations, and it acts on each one strictly within its own tenant's
    controller. It never crosses a tenancy boundary because it never
    resolves anything from a caller-supplied id.

    Per-integration failure isolation: one tenant's unreachable controller
    must not abort the sweep for everyone else, so each is wrapped
    individually. The summary counts, and the event rows, are how a
    failure is surfaced -- not by the task raising.
    """
    moment = now or datetime.now(UTC)
    due = await service.repository.list_due_for_sync(now=moment, limit=limit)
    summary = SyncSweepSummary(considered=len(due))
    synced = skipped = errors = 0
    for integration in due:
        if not service.is_sync_due(integration, now=moment):
            skipped += 1
            continue
        try:
            outcome = await service._sync(integration)
        except Exception:  # noqa: BLE001 -- one tenant must not stop the sweep
            logger.exception(
                "network_integration_sync_failed",
                extra={"integration_id": str(integration.id)},
            )
            errors += 1
            continue
        if outcome.synced:
            synced += 1
        else:
            errors += 1
    return dataclasses.replace(
        summary, synced=synced, skipped_backoff=skipped, errors=errors
    )
