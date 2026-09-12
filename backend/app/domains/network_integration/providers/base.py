"""The provider seam: what ``service.py`` is allowed to know about a
network controller.

``service.py`` talks to :class:`NetworkProvider` and to the dataclasses in
this module, and to nothing else. It does not import
``wyfy_device_gateway``, it does not import ``providers.omada``, and it
contains no string that a vendor would recognise. Adding a second vendor
must not require touching ``service.py``, ``router.py`` or ``models.py`` --
that is the property this file exists to enforce, and it is checked by a
test (``tests/unit/test_network_integration.py``'s
``TestProviderSeamIsolation``) rather than left as an aspiration.

## Why these dataclasses instead of re-exporting the gateway's

The shared contract §2 already defines ``ControllerSite``,
``ControllerDevice``, ``ControllerClient`` and friends in
``wyfy_device_gateway.controller_contract``. Re-exporting them from here
would be less code and would be wrong:

* **It would put a vendor package in the import graph of the whole
  domain.** ``service.py`` importing a type from
  ``wyfy_device_gateway.controller_contract`` is a real import of a real
  third-party package. The moment that package is unavailable -- it is
  vendored, it is under active development by another engineer, it did not
  exist when this file was written -- the entire domain stops importing.
  These types exist so this domain's tests run against mocks with the
  gateway absent entirely.
* **The seam would be defined by the vendor.** If a future gateway release
  renames ``omadac_id``, this domain's models and API would follow it,
  which is precisely what "Omada is a pluggable provider, not a product"
  is meant to prevent. The mapping between the two vocabularies is one
  function in ``providers/omada.py``, and that is the only place a rename
  should be felt.

The cost is a translation layer of about forty lines of field copying. That
is a cheap price for the domain being independently importable and
testable, and it is where the second provider's field-shape differences
will be absorbed.

## Every method takes a ``ProviderConnectionConfig`` first

Stateless by construction: a provider instance holds no session, no
cached token and no per-tenant state, so one module-level instance is
shared by every request and there is nothing for two tenants to
accidentally share. Whatever token/cookie caching a controller needs
lives inside the gateway, keyed on the credential fingerprint (contract
§2), which is the correct place for it -- it is a property of the HTTP
conversation, not of this domain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "NetworkProvider",
    "ProviderAuthorizationResult",
    "ProviderClient",
    "ProviderConnectionConfig",
    "ProviderControllerInfo",
    "ProviderControllerSetupBlock",
    "ProviderControllerSetupReport",
    "ProviderControllerSetupRequest",
    "ProviderControllerSetupStep",
    "ProviderDevice",
    "ProviderPortalContext",
    "ProviderSite",
    "ProviderSsid",
    "ProviderTlsObservation",
]


@dataclass(frozen=True, slots=True)
class ProviderConnectionConfig:
    """Everything a provider needs to talk to one controller, once.

    ``base_url`` is **already SSRF-validated** by the caller -- and
    re-validated by the provider immediately before the request goes out,
    because DNS can change in between (see ``validators.py``). Both are
    true and the second is the one that matters; this docstring says so
    rather than letting the field name imply the check happened somewhere
    trustworthy.

    ``credentials`` is the decrypted plaintext set. It is constructed on
    the stack, passed down, and never stored on an object, never logged,
    and never put in an exception message.
    """

    provider: str
    base_url: str
    auth_mode: str
    credentials: dict[str, str] = field(default_factory=dict)
    controller_id: str | None = None
    #: One of ``constants.ControllerTlsMode``: ``"strict"``, ``"pinned"`` or
    #: ``"insecure"``. A ``str`` rather than the enum for the same reason
    #: ``auth_mode`` is one -- this dataclass is the seam, and a provider
    #: must be able to consume it without importing this domain's enums.
    #:
    #: This replaces a ``verify_tls: bool = True`` that no code in ``app/``
    #: ever set. Being unreachable, it was permanently ``True``, which made
    #: every self-signed controller -- i.e. almost every self-hosted Omada
    #: install -- impossible to integrate. Defaulting it to ``False``
    #: instead would have swapped that for "nothing is ever checked"; the
    #: third value is what makes the honest answer available. See
    #: ``constants.ControllerTlsMode``.
    tls_mode: str = "strict"
    #: Lowercase hex SHA-256 of the controller certificate's DER encoding.
    #: Required by the provider when ``tls_mode`` is ``"pinned"``; ignored
    #: otherwise. Public data -- a hash of a certificate the controller
    #: hands to any caller -- so unlike ``credentials`` it is safe to log,
    #: safe to store in plaintext and safe to return from an endpoint.
    tls_pinned_sha256: str | None = None
    timeout_seconds: float = 15.0


@dataclass(frozen=True, slots=True)
class ProviderTlsObservation:
    """What the controller's TLS endpoint presented, right now.

    Exists so the connect wizard can show an operator the fingerprint of the
    box in front of them and ask them to confirm it. Asking an operator to
    *produce* a fingerprint means asking them to run ``openssl`` against
    their own controller, and the reliable outcome of that is that they pick
    whichever option does not require it.

    ``chain_trusted`` answers "would strict mode have worked", separately
    from ``matches_pin``. Neither implies the other and a UI needs both: a
    controller with a real certificate should be told it does not need to
    pin at all.

    ``subject`` / ``issuer`` / ``not_valid_after`` are best-effort. They are
    parsed from the certificate for display and are ``None`` when parsing
    fails -- a fingerprint that renders without a subject is still a usable
    confirmation, and inventing a subject would not be.
    """

    fingerprint_sha256: str
    chain_trusted: bool
    matches_pin: bool | None = None
    subject: str | None = None
    issuer: str | None = None
    not_valid_after: datetime | None = None


@dataclass(frozen=True, slots=True)
class ProviderControllerInfo:
    controller_id: str
    controller_version: str | None = None
    model: str | None = None
    supports_openapi: bool = False


@dataclass(frozen=True, slots=True)
class ProviderSite:
    site_id: str
    name: str
    device_count: int | None = None
    client_count: int | None = None


@dataclass(frozen=True, slots=True)
class ProviderSsid:
    ssid_id: str | None
    name: str
    portal_enabled: bool | None = None


@dataclass(frozen=True, slots=True)
class ProviderDevice:
    mac: str
    name: str | None = None
    device_type: str = "unknown"
    model: str | None = None
    status: str = "unknown"
    ip_address: str | None = None
    firmware_version: str | None = None
    uptime_seconds: int | None = None
    client_count: int | None = None


@dataclass(frozen=True, slots=True)
class ProviderClient:
    """One client the controller currently reports.

    ``is_authorized`` is three-state on purpose. ``None`` means the
    controller did not tell us, and it must not be collapsed into
    ``False`` by any consumer: rendering "not authorized" for a guest who
    is happily online is the same class of invented fact as
    ``app.domains.connected_devices``'s ``is_wireless=None`` note, and for
    the same reason -- a missing reading is not a negative one.
    """

    mac: str
    name: str | None = None
    ip_address: str | None = None
    ssid: str | None = None
    ap_mac: str | None = None
    radio_id: int | None = None
    vlan_id: int | None = None
    is_guest: bool | None = None
    is_authorized: bool | None = None
    connected_since: datetime | None = None
    duration_seconds: int | None = None
    traffic_down_bytes: int | None = None
    traffic_up_bytes: int | None = None
    signal_dbm: int | None = None


@dataclass(frozen=True, slots=True)
class ProviderPortalContext:
    """The values the controller itself put on the captive-portal redirect.

    Field names deliberately mirror the vendor's query parameters 1:1 (see
    contract §2's ``PortalAuthContext``) so that nothing is invented
    between the guest's browser and the controller. This is the one place
    in the domain where a vendor's naming is allowed to show through, and
    it is allowed precisely because inventing a "nicer" name for
    ``radio_id`` or ``vid`` would mean guessing at a mapping -- the values
    are opaque to this platform and must be handed back exactly as
    received.

    ``site`` is the controller's site *name or id* as it appeared on the
    redirect. ``providers/omada.py`` reconciles it against the
    integration's stored ``external_site_id``; ``service.py`` does not
    interpret it.

    ``client_ip`` is **captured, never derived** (CR-004). It is the
    ``clientIp`` query parameter the controller itself put on the redirect,
    and it is required in the authorize body on controller v6.2.10+. It is
    *not* the source address of the HTTP request that carried this context
    here: the portal is reached through a proxy and a NAT, so that address
    belongs to the proxy, and a wrong client IP authorizes the wrong device
    or nobody -- which is strictly worse than an absent one. When the
    redirect carried no ``clientIp`` (any controller before v6.2.10 -- the
    parameter does not appear in TP-Link doc 13080 at all), this stays
    ``None`` and the field is omitted from the body, leaving those
    controllers exactly as they were.
    """

    client_mac: str
    site: str
    ap_mac: str | None = None
    ssid_name: str | None = None
    radio_id: int | None = None
    gateway_mac: str | None = None
    vid: int | None = None
    t: str | None = None
    redirect_url: str | None = None
    client_ip: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderAuthorizationResult:
    """What the controller did with one authorization request.

    ``request_snapshot`` is the exact body that went on the wire, field by
    field, in the vendor's own spelling. It is on the *result* as well as on
    ``exceptions.ProviderError`` because "the controller accepted a body we
    did not intend to send" is a real outcome -- a successful authorization
    against the wrong site still reads as success here -- and because a
    caller that records it only on failure can never show an operator a
    working request to compare a broken one against.

    Opaque above this layer: ``service.py`` persists it without reading it.
    """

    authorized: bool
    expires_at: datetime | None = None
    provider_code: str | None = None
    request_snapshot: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class ProviderControllerSetupRequest:
    """What "Configure controller automatically" should make true on one
    controller site, for one integration.

    Built by ``service.py`` from the integration row alone -- its own
    organization, location, fleet device and site -- and never from request
    input, so nothing a caller sends can point the run at another tenant's
    portal URL, site or SSID.

    ``ownership_query`` is the ``(key, value)`` pair that, found in a portal's
    server URL query, marks that portal as this integration's even after a
    venue renamed it. ``service.py`` uses the fleet ``routerId`` it already
    stamps into the URL: unique per integration, so two locations sharing a
    site cannot claim each other's portal.

    ``new_operator_password`` is set only on a real run for an integration
    that holds no operator login. ``repr=False`` keeps it out of tracebacks.
    """

    site_id: str
    portal_name: str
    portal_url_scheme: str
    portal_url_host_and_query: str
    ownership_query: tuple[str, str]
    pre_auth_host: str
    auth_timeout_minutes: int
    operator_name: str
    operator_note: str
    operator_marker: str
    guest_ssid_id: str | None = None
    guest_ssid_name: str | None = None
    create_operator_if_missing: bool = True
    new_operator_password: str | None = field(default=None, repr=False)
    take_over_ssid_portal: bool = False
    dry_run: bool = True


@dataclass(frozen=True, slots=True)
class ProviderControllerSetupStep:
    """One line of the report: ``outcome`` is one of ``created``,
    ``updated``, ``unchanged``, ``skipped`` or ``failed``. ``details`` holds
    identifiers and counts, never a credential."""

    step: str
    outcome: str
    message: str
    provider_code: int | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProviderControllerSetupBlock:
    """Why the run stopped before writing anything. ``kind`` is
    ``guest_ssid_not_found``, ``guest_ssid_ambiguous`` or
    ``ssid_portal_conflict``; ``service.py`` turns each into its own typed
    error."""

    kind: str
    message: str
    portal_id: str | None = None
    portal_name: str | None = None
    match_count: int | None = None


@dataclass(frozen=True, slots=True)
class ProviderControllerSetupReport:
    dry_run: bool
    steps: tuple[ProviderControllerSetupStep, ...] = ()
    guest_ssid_id: str | None = None
    portal_id: str | None = None
    #: True only when this run put ``new_operator_password`` on an operator
    #: account on the controller -- the caller's cue to store it.
    operator_credentials_set: bool = False
    block: ProviderControllerSetupBlock | None = None


@runtime_checkable
class NetworkProvider(Protocol):
    """What a vendor implements to become a supported network integration.

    A new provider is exactly: implement this Protocol in a new module
    under ``providers/``, register it in ``providers/__init__.py``, and add
    a member to ``constants.NetworkProviderKind``. Nothing else in the
    domain changes.

    Every method raises one of ``exceptions.ProviderError``'s subclasses on
    failure -- never a vendor exception, never a bare ``Exception``. That
    translation is each provider module's own job, because the vendor's
    error vocabulary is a vendor detail.
    """

    kind: str

    # The ``routers.vendor`` value a fleet row for this provider's hardware
    # must carry (contract §11.3).
    #
    # On the Protocol rather than in a table in ``service.py`` because
    # ``service.py`` is not allowed to name a vendor -- see this module's
    # docstring and ``TestProviderSeamIsolation``. A branch there mapping
    # provider kind to fleet vendor would be exactly the coupling this seam
    # exists to prevent, and it is the kind that goes unnoticed: the
    # ``routers.vendor`` column defaults to ``"mikrotik"``, so a second
    # provider whose vendor nobody remembered to add would silently write
    # fleet rows claiming to be MikroTiks and be reported as broken ones by
    # every RouterOS-assuming sweep in the product.
    #
    # Declared on every provider even though only the Master onboarding path
    # reads it: a provider is registered once and used from several call
    # sites, and an attribute that exists only on the providers that
    # happened to need it is an attribute the next call site cannot rely on.
    fleet_device_vendor: str

    async def test_connection(
        self, config: ProviderConnectionConfig
    ) -> ProviderControllerInfo:
        """Authenticate for real and return what the controller says it is.

        Must actually authenticate -- a reachability probe that skips the
        login is worse than no test at all, because it reports success for
        wrong credentials and the venue only finds out when a guest cannot
        get online.
        """
        ...

    async def get_controller_info(
        self, config: ProviderConnectionConfig
    ) -> ProviderControllerInfo: ...

    async def inspect_tls(
        self, config: ProviderConnectionConfig
    ) -> ProviderTlsObservation:
        """Observe the controller's certificate without sending credentials.

        Called by the pre-save probe and by Test Connection on a saved row,
        on success *and* on failure -- the failing case is the one where the
        operator most needs to see a fingerprint, because it is the case
        where they are about to decide whether to pin it.

        Must send no credential. It exists to be safe to call against an
        address whose certificate is not trusted yet, which is the only
        situation it is for.
        """
        ...

    async def list_sites(
        self, config: ProviderConnectionConfig
    ) -> list[ProviderSite]: ...

    async def list_ssids(
        self, config: ProviderConnectionConfig, site_id: str
    ) -> list[ProviderSsid]: ...

    async def list_devices(
        self, config: ProviderConnectionConfig, site_id: str
    ) -> list[ProviderDevice]: ...

    async def list_clients(
        self, config: ProviderConnectionConfig, site_id: str
    ) -> list[ProviderClient]: ...

    async def get_client(
        self, config: ProviderConnectionConfig, site_id: str, client_mac: str
    ) -> ProviderClient | None: ...

    async def authorize_guest(
        self,
        config: ProviderConnectionConfig,
        context: ProviderPortalContext,
        *,
        duration_seconds: int,
        down_kbps: int | None = None,
        up_kbps: int | None = None,
    ) -> ProviderAuthorizationResult:
        """Let one client onto the network for ``duration_seconds``.

        On a provider with no deauthorization (see
        :meth:`deauthorize_guest`), ``duration_seconds`` is not a default
        -- it is the *only* thing that ever ends this access, and callers
        must size it accordingly. Omada is no longer such a provider.
        ``constants.MAX_SESSION_DURATION_SECONDS`` bounds it at 7 days,
        which is a policy bound on an unattended grant rather than a
        technical limit or tidiness.
        """
        ...

    async def deauthorize_guest(
        self, config: ProviderConnectionConfig, site_id: str, client_mac: str
    ) -> bool:
        """End one client's authorization on the controller.

        **A provider that cannot do this must raise, not return
        ``False``.** ``False`` means "the controller was asked and
        declined"; a provider whose vendor offers no such endpoint must
        raise ``ProviderUnsupportedApiError``
        (``OMADA_API_UNSUPPORTED``), because the caller has to be able to
        tell "revocation failed" from "revocation is impossible here" --
        the second one changes what the caller may truthfully tell a user.

        The Omada provider is exactly that case (contract change CR-001):
        TP-Link publishes no client-deauthorization endpoint in any API
        generation, so it always raises. The method stays on this Protocol
        anyway -- it is a real capability that a second vendor will
        support, and defining the seam now is what stops that vendor's
        arrival from requiring a change to ``service.py``.
        """
        ...

    async def configure_controller(
        self,
        config: ProviderConnectionConfig,
        request: ProviderControllerSetupRequest,
    ) -> ProviderControllerSetupReport:
        """Make the controller match ``request``: portal, walled-garden entry
        and guest-authorization account. Idempotent, merge-only for shared
        settings, and read-only when ``request.dry_run`` is set.

        Raises a ``ProviderError`` only for failures before anything was
        written; once writing starts, every failure is reported on its step.
        """
        ...
