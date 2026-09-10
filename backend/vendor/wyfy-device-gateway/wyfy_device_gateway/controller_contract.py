"""The controller-shaped contract -- deliberately NOT the router-shaped one.

``contract.py``'s ``DeviceGatewayAdapter`` is a ~30-method Protocol modelled
on a device this platform talks to *directly*: a MikroTik box on a
management IP, one socket, one set of credentials, commands issued straight
at the hardware (PRD section 2.1). That shape is correct for RouterOS and
wrong for every controller-mediated vendor.

## Why a second contract instead of extending the first

A controller is not a router, and forcing Omada through ``DeviceGatewayAdapter``
would have required either lying or breaking things:

* **The unit of addressing is different.** ``DeviceCredentials.host`` is *the
  device*. For Omada the host is the *controller*, which fronts an arbitrary
  number of APs, switches and gateways across an arbitrary number of *sites*.
  Nearly every Omada operation needs a ``site_id`` that has no analogue in the
  router contract, and the router contract's operations need a device identity
  that Omada's controller-level API does not take.
* **The operations barely overlap.** Of the router Protocol's methods, Omada's
  controller API has no equivalent for ``provision_device`` (no config-text
  push), ``configure_vlan`` / ``configure_dhcp_pool`` / ``configure_port_forward``
  (controller-managed, not per-device pushes of rendered RouterOS script), or
  ``execute_raw_command``. Implementing those as ``NotImplementedError`` would
  have made ``capabilities()`` almost entirely ``False`` -- a Protocol that a
  vendor satisfies only by declining it is not an abstraction, it is paperwork.
* **The router Protocol is load-bearing and in production.** Six cloud-guest-repo
  call sites depend on it (PRD section 7). Widening it to accommodate a
  controller would change a type that real, live MikroTik code depends on, for
  the benefit of a vendor that does not use it. PRD section 6 already flagged
  this exact question -- "does a controller credential become a new, separate
  concept" -- and deferred it. This module is the answer: yes, separately.

So ``get_adapter`` / ``DeviceGatewayAdapter`` / ``TpLinkAdapter`` are left
exactly as they are (``TpLinkAdapter`` remains an honest stub: there is no
per-device TP-Link adapter, and pretending otherwise would be worse than the
stub), and controller-mediated vendors get their own registry entry point,
``registry.get_controller_adapter``.

## What this contract promises the backend

Every method is ``async``, takes ``creds`` first, and returns frozen
dataclasses built only from stdlib types -- no ORM objects, no framework
types, nothing that cannot be trivially JSON-serialized. That is the same
property PRD section 5 relied on to keep the eventual "promote the gateway to
an HTTP service" migration a transport swap rather than a redesign, and it
holds here for the same reason.

Credentials arrive **already decrypted and already SSRF-validated**. This
package owns no Fernet key, opens no database connection, and imports neither
FastAPI nor SQLAlchemy; ``base_url`` is used as given. Validating that a
user-supplied controller URL is safe to dial is the caller's job (contract
section 6) and must be re-done immediately before each call, because DNS can
change between validation and connection -- a gateway-side check could not be
trusted anyway.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable


class ControllerVendor(StrEnum):
    """Controller-mediated vendors. Deliberately separate from
    ``contract.DeviceVendor``: that enum names *devices we dial directly*,
    this one names *controllers that front a fleet*. TP-Link appears in both
    (``DeviceVendor.TPLINK_OMADA`` is the per-device stub that has never been
    implemented; this is the real, controller-level integration) and the two
    are not interchangeable."""

    TPLINK_OMADA = "tplink_omada"


class ControllerAuthMode(StrEnum):
    """How we authenticate to the controller.

    These are two genuinely different APIs on the same box, not two ways into
    one API -- different base paths, different credential shapes, different
    response envelopes, different capabilities. See
    ``omada/__init__.py`` for exactly what each one can and cannot do.
    """

    OPENAPI = "openapi"  # client_id + client_secret, controller v5.13+
    LEGACY = "legacy"  # hotspot operator name + password, controller v5.0.15+


@dataclass(frozen=True, slots=True)
class ControllerCredentials:
    """Resolved, already-decrypted controller connection material.

    Built by the caller (cloud-guest-repo) from a decrypted
    ``network_integrations.credentials_encrypted`` row. Used for the duration
    of one call and discarded -- the same lifecycle every credentials
    dataclass in this package already has (PRD section 6).

    ``base_url`` is trusted as given: it is the caller's responsibility to
    have SSRF-validated it (contract section 6). ``verify_tls`` defaults to
    ``True`` and should stay there; Omada controllers ship a self-signed
    certificate by default, so operators will be tempted to turn it off, and
    the honest place to make that trade-off consciously is the integration
    row, not a silent default in here.
    """

    vendor: ControllerVendor
    base_url: str  # "https://host:8043" -- ALREADY SSRF-validated by the caller
    auth_mode: ControllerAuthMode
    client_id: str | None = None
    client_secret: str | None = None
    username: str | None = None
    password: str | None = None
    omadac_id: str | None = None  # None => discover via GET /api/info
    verify_tls: bool = True
    timeout_seconds: float = 15.0


@dataclass(frozen=True, slots=True)
class ControllerInfo:
    """Identity of the controller itself.

    ``supports_openapi`` is a *version-derived guess*, not a probe: it is true
    when the reported controller version is >= 5.13, the release where TP-Link
    introduced Open API. A controller can be new enough and still have Open
    API switched off (it is opt-in under Settings > Platform Integration), so
    treat this as "the firmware could do it", never as "credentials will work".
    The only real test is authenticating, which is what ``test_connection``
    does.
    """

    omadac_id: str
    controller_version: str | None
    model: str | None
    supports_openapi: bool


@dataclass(frozen=True, slots=True)
class ControllerSite:
    site_id: str
    name: str
    device_count: int | None = None
    client_count: int | None = None


@dataclass(frozen=True, slots=True)
class ControllerSsid:
    ssid_id: str | None
    name: str
    wlan_group_id: str | None = None
    portal_enabled: bool | None = None


@dataclass(frozen=True, slots=True)
class ControllerDevice:
    """One managed device (AP / switch / gateway) as the controller sees it.

    ``device_type`` and ``status`` are normalized to the small closed
    vocabularies below rather than passed through, because Omada reports both
    as integer enums whose meaning differs between API versions. Anything we
    do not recognise becomes ``"unknown"`` -- never a raw integer leaking into
    a database column the frontend then has to guess at.
    """

    mac: str
    name: str | None
    device_type: str  # "ap" | "switch" | "gateway" | "unknown"
    model: str | None
    status: str  # "connected" | "disconnected" | "pending" | "unknown"
    ip_address: str | None = None
    firmware_version: str | None = None
    uptime_seconds: int | None = None
    client_count: int | None = None


@dataclass(frozen=True, slots=True)
class ControllerClient:
    """One client device currently known to the controller.

    Every field past ``mac`` is optional on purpose. Which of these the
    controller actually returns varies by API version, by whether the client
    is wired or wireless, and by whether the controller is a hardware OC200 or
    the software controller. Modelling them as required would mean inventing
    values for fields a real controller simply did not send.
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
    connected_since: datetime | None = None  # tz-aware UTC
    duration_seconds: int | None = None
    traffic_down_bytes: int | None = None
    traffic_up_bytes: int | None = None
    signal_dbm: int | None = None


@dataclass(frozen=True, slots=True)
class PortalAuthContext:
    """Exactly the values Omada itself put on the portal redirect.

    Field names mirror the Omada query params 1:1 so nothing is invented
    downstream. Omada sends one of two shapes depending on which device is
    enforcing the portal: the EAP/AP shape (``ap_mac`` + ``ssid_name`` +
    ``radio_id``) or the gateway shape (``gateway_mac`` + ``vid``). Do not
    fill in the fields of the shape you did not receive -- the adapter picks
    the request body by inspecting which of these is populated, and guessing
    a ``gateway_mac`` onto an AP-originated redirect would send the controller
    a body it cannot match to a real session.
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
class AuthorizationResult:
    """Outcome of one portal authorization.

    ``expires_at`` is computed by this package from the duration we asked for,
    not read back from the controller: the external-portal authorize endpoint
    replies with ``{"errorCode": 0}`` and nothing else, so there is no
    controller-reported expiry to return. It is therefore an expectation, not
    an observation -- if the controller silently clamps the duration to a
    site-configured maximum, this value will be optimistic and we would have
    no way to know.
    """

    authorized: bool
    expires_at: datetime | None
    provider_code: str | None = None


@runtime_checkable
class ControllerAdapter(Protocol):
    """One adapter per controller vendor.

    Unlike ``DeviceGatewayAdapter`` there is no ``capabilities()`` here. That
    method exists on the router Protocol because five of its six vendors are
    stubs that implement nothing, so callers needed to branch before calling.
    Here the honest answer is finer-grained than a per-method boolean: what an
    Omada controller can do depends on its ``auth_mode`` and firmware version,
    both of which live in ``creds``, not in the adapter. So an operation that
    this controller cannot perform raises ``OmadaUnsupportedApiError``
    (normalized code ``OMADA_API_UNSUPPORTED``) with a message explaining
    which mode would be needed -- a real, catchable, actionable signal rather
    than a static capability table that would have to lie about half the
    matrix.
    """

    vendor: ControllerVendor

    async def get_controller_info(self, creds: ControllerCredentials) -> ControllerInfo:
        """Identify the controller. Unauthenticated: reads ``GET /api/info``."""
        ...

    async def test_connection(self, creds: ControllerCredentials) -> ControllerInfo:
        """Identify the controller *and* authenticate for real against it."""
        ...

    async def list_sites(self, creds: ControllerCredentials) -> list[ControllerSite]: ...

    async def get_site(
        self, creds: ControllerCredentials, site_id: str
    ) -> ControllerSite: ...

    async def list_ssids(
        self, creds: ControllerCredentials, site_id: str
    ) -> list[ControllerSsid]: ...

    async def list_devices(
        self, creds: ControllerCredentials, site_id: str
    ) -> list[ControllerDevice]: ...

    async def list_clients(
        self, creds: ControllerCredentials, site_id: str
    ) -> list[ControllerClient]: ...

    async def get_client(
        self, creds: ControllerCredentials, site_id: str, client_mac: str
    ) -> ControllerClient | None:
        """``None`` -- not an exception -- when the client is simply not
        connected. A guest whose phone dropped off the WiFi is an ordinary,
        expected state, not an error condition."""
        ...

    async def authorize_guest(
        self,
        creds: ControllerCredentials,
        ctx: PortalAuthContext,
        *,
        duration_seconds: int,
        down_kbps: int | None = None,
        up_kbps: int | None = None,
    ) -> AuthorizationResult: ...

    async def deauthorize_guest(
        self, creds: ControllerCredentials, site_id: str, client_mac: str
    ) -> bool: ...


__all__ = [
    "AuthorizationResult",
    "ControllerAdapter",
    "ControllerAuthMode",
    "ControllerClient",
    "ControllerCredentials",
    "ControllerDevice",
    "ControllerInfo",
    "ControllerSite",
    "ControllerSsid",
    "ControllerVendor",
    "PortalAuthContext",
]
