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
from typing import Protocol, runtime_checkable

__all__ = [
    "NetworkProvider",
    "ProviderAuthorizationResult",
    "ProviderClient",
    "ProviderConnectionConfig",
    "ProviderControllerInfo",
    "ProviderDevice",
    "ProviderPortalContext",
    "ProviderSite",
    "ProviderSsid",
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
    verify_tls: bool = True
    timeout_seconds: float = 15.0


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


@dataclass(frozen=True, slots=True)
class ProviderAuthorizationResult:
    authorized: bool
    expires_at: datetime | None = None
    provider_code: str | None = None


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
        -- it is the *only* thing that ever ends this access. Callers must
        size it accordingly; ``constants.MAX_SESSION_DURATION_SECONDS``
        bounds it at 24 hours for that reason and not for tidiness.
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
