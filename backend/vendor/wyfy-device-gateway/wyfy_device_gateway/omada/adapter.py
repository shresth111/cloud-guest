"""``OmadaControllerAdapter`` -- the one class the backend actually holds.

Composes ``client`` (transport), ``auth`` (sessions), and the four resource
modules into the ``ControllerAdapter`` Protocol. Both ``auth_mode``s live
behind this one adapter, exactly as the contract requires: the backend never
branches on mode, never learns an Omada path, and never sees an ``httpx``
type.

## The capability matrix, stated plainly

This is the most important thing to understand about Omada, and it follows
directly from what each credential actually is (see ``auth.py``):

| operation            | ``legacy`` (hotspot operator) | ``openapi`` (client id/secret) |
|----------------------|-------------------------------|--------------------------------|
| ``get_controller_info`` | yes (unauthenticated)      | yes (unauthenticated)          |
| ``test_connection``  | yes                           | yes                            |
| ``list_sites``       | **no**                        | yes                            |
| ``get_site``         | **no**                        | yes                            |
| ``list_ssids``       | **no**                        | yes                            |
| ``list_devices``     | **no**                        | yes                            |
| ``list_clients``     | **no**                        | yes                            |
| ``get_client``       | **no**                        | yes                            |
| ``authorize_guest``  | yes                           | yes, *if* operator credentials are also stored |
| ``deauthorize_guest``| **no** (see below)            | **no** (see below)             |

The legacy "no"s are not laziness. A hotspot operator account exists to
authorize portal clients; the controller's inventory lives behind its admin
API, which that credential does not open. Sending those requests anyway
would produce an auth failure that looks like "your password is wrong" and
would send an operator off debugging a credential that is perfectly fine. So
they raise ``OmadaUnsupportedApiError`` with a message naming the actual fix.

## Why ``authorize_guest`` uses the legacy endpoint even in ``openapi`` mode

The only portal-authorization endpoint with primary TP-Link documentation is
``/{omadacId}/api/v2/hotspot/extPortal/auth``, and it takes a hotspot
operator login. ``PortalAuthContext`` is literally the shape of that
endpoint's redirect parameters.

There are references in circulation to an Open API equivalent at
``/openapi/v1/{omadacId}/sites/{siteId}/hotspot/clients/{clientMac}/auth``,
but we could not tie that path to any primary TP-Link source or to any
open-source client that calls it, so it is deliberately **not** implemented.
Contract section 1's rule -- do not invent Omada API endpoints -- binds
hardest on the one call that decides whether a paying guest gets internet.
Guessing here and being wrong means a guest sits at a spinner while the
controller 404s.

So: an integration in ``openapi`` mode that also stores operator credentials
authorizes through the legacy endpoint. One that does not gets
``OmadaUnsupportedApiError`` naming exactly what to add. ``ControllerCredentials``
carries both credential pairs precisely so a single integration row can do
inventory over Open API and portal auth over the operator account, which is
the configuration we expect real deployments to use.

## Statelessness, and the one thing that is not stateless

Every method takes ``creds`` and builds a fresh ``OmadaHttpClient``. The
adapter instance holds exactly one piece of state: the ``SessionCache``,
shared across calls so that a burst of portal authorizations against one
controller reuses a single operator login instead of re-authenticating per
guest. It is keyed on a credential *fingerprint*, never a credential, so
rotating a password cannot reuse a session issued to the old one.

The registry hands out a single shared adapter instance, which is what makes
that cache useful across calls. Anything wanting an isolated cache (tests,
mostly) can construct its own ``OmadaControllerAdapter``.

## Honest scope

No line of this has run against a physical Omada controller. Endpoint paths,
request bodies and response parsing are exercised against
``httpx.MockTransport`` in ``tests/test_omada_*.py`` and nowhere else. What
that proves is that this client does what we believe the API expects; it
cannot prove the API expects it. The docstrings mark every claim as VERIFIED
(primary TP-Link doc, with URL), CORROBORATED (open-source client or forum),
or INFERRED.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from datetime import datetime

import httpx

from ..controller_contract import (
    AuthorizationResult,
    ControllerAuthMode,
    ControllerClient,
    ControllerCredentials,
    ControllerDevice,
    ControllerInfo,
    ControllerSite,
    ControllerSsid,
    ControllerVendor,
    PortalAuthContext,
)
from . import clients as clients_module
from . import devices as devices_module
from . import portal as portal_module
from . import sites as sites_module
from .auth import SessionCache
from .client import OmadaHttpClient, SleepFn
from .errors import OmadaUnsupportedApiError
from .types import coerce_str

#: Open API arrived in controller v5.13. Below that, ``openapi`` mode cannot
#: work at all and we say so rather than failing at the token endpoint.
MIN_OPENAPI_VERSION = (5, 13)
#: The external portal API this package targets. Contract section 1's
#: version policy: below this, raise rather than half-work.
MIN_SUPPORTED_VERSION = (5, 0, 15)


def _parse_version(raw: str | None) -> tuple[int, ...] | None:
    """Parse a controller version like ``"5.13.30.8"`` into a tuple.

    Returns ``None`` for anything unparseable, and callers treat ``None`` as
    "do not enforce a version gate". Refusing to work because we could not
    parse a version string would be a worse failure than trying and getting
    a real error from the controller.
    """
    if not raw:
        return None
    parts: list[int] = []
    for chunk in raw.strip().split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) or None


class OmadaControllerAdapter:
    """TP-Link Omada, implementing ``ControllerAdapter``."""

    vendor = ControllerVendor.TPLINK_OMADA

    def __init__(
        self,
        *,
        cache: SessionCache | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: SleepFn | None = None,
        rng: random.Random | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._cache = cache if cache is not None else SessionCache()
        self._transport = transport
        self._sleep = sleep
        self._rng = rng
        # ``clock`` exists so a test can assert the exact ``expires_at`` this
        # adapter computes. The public method signatures stay exactly as
        # contract section 2 specifies -- the test seam is on the
        # constructor, not on the surface the backend calls.
        self._clock = clock

    # -- plumbing ---------------------------------------------------------

    def _client(self, creds: ControllerCredentials) -> OmadaHttpClient:
        return OmadaHttpClient(
            creds,
            cache=self._cache,
            transport=self._transport,
            sleep=self._sleep,
            rng=self._rng,
        )

    @property
    def session_cache(self) -> SessionCache:
        """Exposed so a caller can drop cached sessions after a credential
        rotation without waiting for the TTL. Rotation already changes the
        cache key, so this is belt-and-braces rather than load-bearing."""
        return self._cache

    @staticmethod
    def _require_openapi(creds: ControllerCredentials, operation: str) -> None:
        """Refuse an inventory operation that a hotspot operator cannot do."""
        if creds.auth_mode != ControllerAuthMode.OPENAPI:
            raise OmadaUnsupportedApiError(
                f"Listing {operation} needs Omada Open API access. This "
                "integration is configured with a hotspot operator login, "
                "which can authorize guests but cannot read the controller's "
                "inventory. Add Open API credentials (controller v5.13+, "
                "Settings > Platform Integration > Open API) to enable it."
            )

    # -- identity ---------------------------------------------------------

    async def get_controller_info(
        self, creds: ControllerCredentials
    ) -> ControllerInfo:
        """Identify the controller without authenticating.

        Uses ``GET /api/info``, which needs no credentials. That is what
        makes it useful in the connect wizard: an operator can confirm they
        have the right URL before they have finished entering secrets.
        """
        async with self._client(creds) as client:
            return await self._controller_info(client, creds)

    async def _controller_info(
        self, client: OmadaHttpClient, creds: ControllerCredentials
    ) -> ControllerInfo:
        info = await client.fetch_controller_info()
        version = coerce_str(
            info.get("controllerVer")
            if info.get("controllerVer") is not None
            else info.get("controllerVersion")
        )
        omadac_id = (
            coerce_str(info.get("omadacId"))
            or coerce_str(info.get("omadacid"))
            or creds.omadac_id
        )
        if not omadac_id:
            omadac_id = await client.resolve_omadac_id()

        parsed = _parse_version(version)
        if parsed is not None and parsed < MIN_SUPPORTED_VERSION:
            # Contract section 1's version policy, applied literally: below
            # v5.0.15 the external-portal API has a different shape (no
            # controller-id path segment, CSRF as a query parameter), and
            # half-supporting it would be worse than refusing.
            raise OmadaUnsupportedApiError(
                f"This Omada controller reports version {version}. Wyfy Guest "
                "supports Omada Controller 5.0.15 and newer."
            )

        return ControllerInfo(
            omadac_id=omadac_id,
            controller_version=version,
            model=coerce_str(info.get("type")) or coerce_str(info.get("model")),
            supports_openapi=parsed is not None and parsed >= MIN_OPENAPI_VERSION,
        )

    async def test_connection(self, creds: ControllerCredentials) -> ControllerInfo:
        """Identify the controller *and* prove the credentials work.

        The authentication is deliberately not optional and its result is
        deliberately discarded: the point is the side effect of having
        actually logged in. A "test connection" that only checked
        reachability would go green for a wrong password, which is precisely
        the moment an operator most needs it to go red.
        """
        async with self._client(creds) as client:
            info = await self._controller_info(client, creds)
            # Force a real login rather than reusing a cached session --
            # otherwise pressing "Test connection" twice would validate the
            # credentials once.
            await client.ensure_authenticated()
            return info

    # -- inventory (Open API only) ----------------------------------------

    async def list_sites(self, creds: ControllerCredentials) -> list[ControllerSite]:
        self._require_openapi(creds, "sites")
        async with self._client(creds) as client:
            omadac_id = await client.resolve_omadac_id()
            return await sites_module.list_sites(client, omadac_id)

    async def get_site(
        self, creds: ControllerCredentials, site_id: str
    ) -> ControllerSite:
        self._require_openapi(creds, "sites")
        async with self._client(creds) as client:
            omadac_id = await client.resolve_omadac_id()
            return await sites_module.get_site(client, omadac_id, site_id)

    async def list_ssids(
        self, creds: ControllerCredentials, site_id: str
    ) -> list[ControllerSsid]:
        self._require_openapi(creds, "SSIDs")
        async with self._client(creds) as client:
            omadac_id = await client.resolve_omadac_id()
            return await sites_module.list_ssids(client, omadac_id, site_id)

    async def list_devices(
        self, creds: ControllerCredentials, site_id: str
    ) -> list[ControllerDevice]:
        self._require_openapi(creds, "devices")
        async with self._client(creds) as client:
            omadac_id = await client.resolve_omadac_id()
            return await devices_module.list_devices(client, omadac_id, site_id)

    async def list_clients(
        self, creds: ControllerCredentials, site_id: str
    ) -> list[ControllerClient]:
        self._require_openapi(creds, "clients")
        async with self._client(creds) as client:
            omadac_id = await client.resolve_omadac_id()
            return await clients_module.list_clients(client, omadac_id, site_id)

    async def get_client(
        self, creds: ControllerCredentials, site_id: str, client_mac: str
    ) -> ControllerClient | None:
        self._require_openapi(creds, "clients")
        async with self._client(creds) as client:
            omadac_id = await client.resolve_omadac_id()
            return await clients_module.get_client(
                client, omadac_id, site_id, client_mac
            )

    # -- portal -----------------------------------------------------------

    async def authorize_guest(
        self,
        creds: ControllerCredentials,
        ctx: PortalAuthContext,
        *,
        duration_seconds: int,
        down_kbps: int | None = None,
        up_kbps: int | None = None,
    ) -> AuthorizationResult:
        """Grant one guest network access through the external portal.

        Requires hotspot operator credentials in *either* auth mode -- see
        this module's docstring for why the Open API path is not used here.
        """
        if not creds.username or not creds.password:
            raise OmadaUnsupportedApiError(
                "Authorizing a guest on Omada requires a hotspot operator "
                "username and password. Omada's only documented external-"
                "portal authorization endpoint uses an operator login, so "
                "Open API credentials alone are not enough. Add an operator "
                "account (controller: Hotspot Manager) to this integration."
            )

        # The operator login lives under the legacy hotspot API regardless of
        # which mode the integration uses for inventory, so the session is
        # established with a legacy-mode view of the same credentials. This
        # also keeps the two sessions in separate cache slots, because
        # ``session_key`` includes the auth mode.
        portal_creds = (
            creds
            if creds.auth_mode == ControllerAuthMode.LEGACY
            else _as_legacy(creds)
        )

        async with self._client(portal_creds) as client:
            omadac_id = await client.resolve_omadac_id()
            return await portal_module.authorize_client(
                client,
                omadac_id,
                ctx,
                duration_seconds=duration_seconds,
                down_kbps=down_kbps,
                up_kbps=up_kbps,
                now=self._clock() if self._clock else None,
            )

    async def deauthorize_guest(
        self, creds: ControllerCredentials, site_id: str, client_mac: str
    ) -> bool:
        """Always raises ``OmadaUnsupportedApiError``. This is not a stub.

        TP-Link documents no way to revoke an external-portal authorization.
        Every version of the *API and Code Sample for External Portal Server*
        document covers exactly two calls -- operator login and client
        authorization -- and neither the v4, v5 nor v6.2.10 revision mentions
        deauthorization, expiry-shortening, or session teardown.

        The options were: invent an endpoint (forbidden by contract section
        1, and a wrong guess on a write is how you knock a paying guest
        offline); repurpose the Open API's ``clients/{mac}/block`` route,
        which is a *blocklist* -- a materially more punitive and longer-lived
        action than ending a portal session, and one an operator would have
        to undo by hand; or say plainly that this cannot be done and let the
        caller handle it.

        We say plainly that it cannot be done. Access ends when the
        ``duration_seconds`` passed to ``authorize_guest`` elapses, which is
        the mechanism Omada actually provides, so the backend should size
        that duration to the session it wants rather than planning to revoke
        early. ``OMADA_API_UNSUPPORTED`` is a normalized, catchable code, so
        a caller can degrade gracefully.

        The signature keeps the contract's ``-> bool`` so the Protocol is
        satisfied and the shape stays correct if TP-Link ever publishes one.
        """
        raise OmadaUnsupportedApiError(
            "Omada does not provide a way to end a guest's network access "
            "early. Access ends automatically when the authorized duration "
            "expires."
        )


def _as_legacy(creds: ControllerCredentials) -> ControllerCredentials:
    """A copy of ``creds`` switched to legacy mode, for the portal call.

    ``ControllerCredentials`` is frozen, so this builds a new one rather than
    mutating. Only the mode changes; the operator username/password are
    already present on the original (the caller checked).
    """
    return ControllerCredentials(
        vendor=creds.vendor,
        base_url=creds.base_url,
        auth_mode=ControllerAuthMode.LEGACY,
        client_id=creds.client_id,
        client_secret=creds.client_secret,
        username=creds.username,
        password=creds.password,
        omadac_id=creds.omadac_id,
        verify_tls=creds.verify_tls,
        timeout_seconds=creds.timeout_seconds,
    )


__all__ = ["MIN_OPENAPI_VERSION", "MIN_SUPPORTED_VERSION", "OmadaControllerAdapter"]
