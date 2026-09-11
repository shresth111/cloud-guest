"""TP-Link Omada provider -- the ONLY backend module that imports
``wyfy_device_gateway.omada`` / ``wyfy_device_gateway.controller_contract``.

Everything vendor-specific in this domain lives here: the gateway import,
the two vocabularies' field mapping, and the translation of the gateway's
error classes into this domain's ``ProviderError`` hierarchy. If a grep for
``wyfy_device_gateway`` in ``app/domains/network_integration/`` ever
returns a second file, the provider seam has been broken -- there is a test
that asserts exactly that (``TestProviderSeamIsolation``).

## The gateway import is lazy, and that is not tidiness

At the time this module was written the gateway's
``wyfy_device_gateway/omada/`` package did not exist: it is being built in
parallel in another repository and mirrored into
``vendor/wyfy-device-gateway/`` when ready. A module-level
``from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter``
would therefore have made this entire domain unimportable -- which means
``app.main.create_app()`` fails, which means every one of the 131 test
modules in this repository fails to collect, on a change that touches none
of them.

So the concrete adapter is resolved inside :func:`_adapter`, on first real
use, and the result is cached per process. The consequences, stated plainly
rather than hidden:

* Importing this module, constructing ``OmadaProvider``, and running every
  test in ``tests/unit/test_network_integration.py`` all work with the
  gateway package entirely absent. Tests inject a fake adapter.
* The *first live call* against a real controller is where a missing
  gateway surfaces, as ``ProviderUnsupportedApiError`` with a message
  saying the adapter is not installed -- a 501, not a 500, and not a
  traceback.
* ``_adapter`` prefers the contract's registry entry
  (``wyfy_device_gateway.registry.get_controller_adapter``) and falls back
  to constructing ``OmadaControllerAdapter`` directly, because at the time
  of writing the registry entry was the part of §2 least likely to have
  landed. Both paths are specified in the contract; taking either is
  correct.

## The endpoint verdict (settled, and the docs contradict themselves)

TP-Link's own v5/v6 external-portal documentation disagrees with itself:
the prose and the bundled PHP sample give the two URLs the other way
round. The TP-Link engineer fetched the page and established which is
which; recorded here so nobody re-derives it from the sample:

* operator login -> ``POST /{omadacId}/api/v2/hotspot/login``
* client authorization -> ``POST /{omadacId}/api/v2/hotspot/extPortal/auth``

The **prose is right; the PHP sample has them swapped.** Source:
<https://support.omadanetworks.com/us/document/13080/> ("API and Code
Sample for External Portal Server", controller v5.0.15-v6.2.0).

Also settled: ``time`` in the authorize body is a **duration in
milliseconds**, not an absolute timestamp. The gateway owns that
conversion; this module passes ``duration_seconds`` and does not do
arithmetic on it.

## Two capabilities Omada does not have (CR-001, CR-002)

Both are contract changes accepted after this domain was designed, and
both are handled by refusing rather than by faking:

* **No client deauthorization, at all** (CR-001). See
  :meth:`OmadaProvider.deauthorize_guest`. Open API's
  ``clients/{mac}/block`` was deliberately not repurposed -- a blocklist
  is more punitive and longer-lived than ending a portal session, and it
  keys on a MAC that phones rotate per SSID.
* **Legacy (operator-credential) mode cannot read inventory** (CR-002).
  Sites, devices and clients need Open API credentials. The gateway
  refuses those calls in legacy mode rather than issuing them, because
  the controller's refusal reads as "wrong password" and sends operators
  debugging a credential that is in fact correct. ``service.py`` refuses
  one layer earlier still, before a provider is resolved.

## Field mapping: what is verified and what is not

The dataclass field names below mirror the shared contract §2 exactly, and
§2 is the coordinator's own transcription of TP-Link's published external
portal documentation. This module has been written against that contract
and **has never run against a physical Omada controller**. Specifically
unverified here:

* whether ``AuthorizationResult.expires_at`` is populated by the gateway or
  must be derived from ``duration_seconds`` -- so this module derives it
  when the gateway leaves it ``None``, which is safe either way;
* whether the gateway's ``ControllerSite.site_id`` is Omada's internal site
  key or its display name. The portal redirect's ``site`` parameter and the
  Open API's ``siteId`` are documented as different things in TP-Link's own
  material, which is why :meth:`authorize_guest` passes the *redirect's*
  ``site`` value straight through untouched instead of substituting the
  integration's stored ``external_site_id``. Substituting would be
  inventing a mapping nobody has confirmed.

Anything this module infers is marked ``# INFERRED, unverified`` inline.

## Timeouts, retries and redirects belong to the gateway

Contract §2 makes the gateway responsible for connect/read timeouts from
``creds.timeout_seconds``, bounded retry with jitter, one automatic
re-login on session expiry, and log redaction. This module supplies the
timeout and does not reimplement any of the rest -- a second retry loop
wrapped around one that already retries multiplies the attempt count
against a customer's hardware.

One §6 requirement is genuinely *not* enforced anywhere this repository can
reach: "no redirects followed to a different host". The HTTP client lives
in the gateway, so nothing here can see a redirect. Re-validating the URL
before each request (below) closes DNS rebinding; it does not close a
redirect to an internal host. That gap is real, is recorded in
``/Users/shresth/wyfy-omada/CHANGE-REQUESTS.md`` as a gateway obligation,
and is not papered over here.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from ..constants import (
    ROUTER_VENDOR_BY_PROVIDER,
    ControllerAuthMode,
    ControllerTlsMode,
    NetworkProviderKind,
)
from ..exceptions import (
    PROVIDER_ERRORS_BY_CODE,
    ProviderConnectionFailedError,
    ProviderError,
    ProviderTlsPinMismatchError,
    ProviderUnsupportedApiError,
)
from ..validators import validate_controller_url
from .base import (
    ProviderAuthorizationResult,
    ProviderClient,
    ProviderConnectionConfig,
    ProviderControllerInfo,
    ProviderDevice,
    ProviderPortalContext,
    ProviderSite,
    ProviderSsid,
    ProviderTlsObservation,
)

logger = logging.getLogger(__name__)

__all__ = ["OmadaProvider"]

_ADAPTER_CACHE: dict[str, Any] = {}


def _adapter() -> Any:
    """The gateway's ``OmadaControllerAdapter``, resolved on first use.

    See the module docstring for why this is not a module-level import.
    Raises :class:`ProviderUnsupportedApiError` -- a 501 with a message an
    operator can act on -- when the gateway package is not installed,
    rather than letting an ``ImportError`` become an unhandled 500.
    """
    cached = _ADAPTER_CACHE.get("adapter")
    if cached is not None:
        return cached

    adapter: Any = None
    try:
        # Preferred path, per contract §2: the gateway's own controller
        # registry, kept separate from the router-shaped `get_adapter`.
        from wyfy_device_gateway.controller_contract import (  # noqa: PLC0415
            ControllerVendor,
        )
        from wyfy_device_gateway.registry import (  # noqa: PLC0415
            get_controller_adapter,
        )

        adapter = get_controller_adapter(ControllerVendor.TPLINK_OMADA)
    except Exception:  # noqa: BLE001 -- ImportError or AttributeError
        try:
            from wyfy_device_gateway.omada.adapter import (  # noqa: PLC0415
                OmadaControllerAdapter,
            )

            adapter = OmadaControllerAdapter()
        except Exception as exc:  # noqa: BLE001
            raise ProviderUnsupportedApiError(
                "The TP-Link Omada controller adapter is not installed in this "
                "deployment, so this platform cannot talk to an Omada "
                "controller. Nothing is misconfigured on the controller side."
            ) from exc

    _ADAPTER_CACHE["adapter"] = adapter
    return adapter


def _gateway_credentials(config: ProviderConnectionConfig, base_url: str) -> Any:
    """Build the gateway's ``ControllerCredentials`` from this domain's config.

    The gateway's own dataclass is imported here (lazily, via
    :func:`_adapter`'s import having already succeeded) rather than in this
    domain's type signatures -- which is the whole point of the seam.
    """
    from wyfy_device_gateway.controller_contract import (  # noqa: PLC0415
        ControllerAuthMode as GatewayAuthMode,
    )
    from wyfy_device_gateway.controller_contract import (  # noqa: PLC0415
        ControllerCredentials,
        ControllerVendor,
    )
    from wyfy_device_gateway.controller_contract import (  # noqa: PLC0415
        ControllerTlsMode as GatewayTlsMode,
    )

    credentials = config.credentials or {}
    mode = (
        GatewayAuthMode.OPENAPI
        if config.auth_mode == ControllerAuthMode.OPENAPI.value
        else GatewayAuthMode.LEGACY
    )
    return ControllerCredentials(
        vendor=ControllerVendor.TPLINK_OMADA,
        base_url=base_url,
        auth_mode=mode,
        client_id=credentials.get("client_id"),
        client_secret=credentials.get("client_secret"),
        username=credentials.get("username"),
        password=credentials.get("password"),
        omadac_id=config.controller_id,
        tls_mode=GatewayTlsMode(config.tls_mode),
        tls_pinned_sha256=config.tls_pinned_sha256,
        timeout_seconds=config.timeout_seconds,
    )


def _translate(exc: Exception) -> ProviderError:
    """Gateway exception -> this domain's exception, by normalized code.

    Keyed on ``exc.code`` rather than on the exception *class*, because the
    class lives in a package this module must not import at type-check
    time and because the contract defines the code as the stable part of
    the surface. A code the gateway invents that is not in
    ``PROVIDER_ERRORS_BY_CODE`` becomes ``ProviderConnectionFailedError``
    rather than escaping as a 500 -- a wrong-but-safe classification beats
    an unhandled exception, and the real code is logged.

    ``str(exc)`` is passed through as the human message. Contract §2
    obliges the gateway to keep it free of secrets, cookies, tokens and raw
    response bodies. That is the gateway's promise, not something this
    module can verify -- so if it is ever broken, this is the line that
    would carry a secret into an API response and into an event row. Noted
    here deliberately; the mitigation is that ``service.py`` redacts every
    message it writes to an event row through
    ``constants.REDACTED_CONTEXT_KEYS`` before persisting it.
    """
    code = getattr(exc, "code", None)
    message = str(exc) or None
    if isinstance(code, str):
        error_class = PROVIDER_ERRORS_BY_CODE.get(code)
        if error_class is not None:
            return error_class(message)
        logger.warning(
            "network_integration_unmapped_provider_error_code",
            extra={"provider_error_code": code},
        )
    return ProviderConnectionFailedError(message)


def _describe_certificate(
    certificate_der: bytes | None,
) -> tuple[str | None, str | None, datetime | None]:
    """``(subject, issuer, expiry)`` for display, or three ``None``s.

    Best-effort on purpose. Everything this returns is decoration around the
    fingerprint, which is the value the operator is actually confirming, so
    an unparseable certificate must degrade rather than break the probe. The
    import is local for the same reason the gateway import is: nothing in
    this module should be able to stop the domain from importing.
    """
    if not certificate_der:
        return None, None, None
    try:
        from cryptography import x509  # noqa: PLC0415

        certificate = x509.load_der_x509_certificate(bytes(certificate_der))
        return (
            certificate.subject.rfc4514_string(),
            certificate.issuer.rfc4514_string(),
            certificate.not_valid_after_utc,
        )
    except Exception:  # noqa: BLE001 -- display-only, never fatal
        logger.warning("network_integration_certificate_parse_failed")
        return None, None, None


def _is_gateway_error(exc: Exception) -> bool:
    """Whether ``exc`` came from the gateway's own error hierarchy.

    Duck-typed on the presence of a string ``.code``, which is the shape
    contract §2 guarantees for every ``OmadaError`` subclass. An
    ``isinstance`` check against ``wyfy_device_gateway.omada.errors
    .OmadaError`` would need the import this module refuses to make
    eagerly -- and would silently stop matching if the gateway were absent,
    turning every controller failure into a 500.
    """
    return isinstance(getattr(exc, "code", None), str)


class OmadaProvider:
    """``NetworkProvider`` implementation for TP-Link Omada controllers.

    Stateless. One instance per process (see ``providers/__init__.py``).
    """

    kind = NetworkProviderKind.OMADA.value

    # Read from the one translation table rather than repeated as a literal.
    # ``constants.ROUTER_VENDOR_BY_PROVIDER`` documents at length why this
    # domain's ``"omada"`` and the fleet's ``"tplink_omada"`` are two
    # different strings that cannot be reconciled by renaming either one;
    # this is the second half of that translation, and it belongs here for
    # the same reason the gateway translation does -- inside the provider,
    # where a vendor's vocabulary is allowed to be known.
    fleet_device_vendor = ROUTER_VENDOR_BY_PROVIDER[NetworkProviderKind.OMADA.value]

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _assert_trust_is_coherent(config: ProviderConnectionConfig) -> None:
        """Refuse a config that says it pins and carries nothing to pin to.

        The gateway refuses this too, and this is not a duplicate of that
        check -- it is the one that runs before the URL is re-resolved and
        before a socket is opened, so a misconfigured row costs nothing and
        produces this domain's own 422 rather than a 502 describing a
        controller that was never contacted.
        """
        if config.tls_mode != ControllerTlsMode.PINNED.value:
            return
        if not config.tls_pinned_sha256:
            raise ProviderTlsPinMismatchError(
                "This integration is set to pin the controller's HTTPS "
                "certificate but has no fingerprint recorded. Run Test "
                "Connection to capture and confirm the certificate."
            )

    async def _creds(self, config: ProviderConnectionConfig) -> Any:
        """Re-validate the URL, then build gateway credentials.

        **The re-validation is the security control, not a formality.**
        ``config.base_url`` was validated when the row was written, which
        may have been weeks ago. Nothing prevents the DNS record it depends
        on from now pointing at ``169.254.169.254``, and this request is
        about to send a tenant's controller credentials to whatever answers.
        So the resolution and address checks run again, here, immediately
        before every outbound call. See ``validators.py``'s "Validated
        twice, deliberately".
        """
        self._assert_trust_is_coherent(config)
        validated = await validate_controller_url(config.base_url)
        return _gateway_credentials(config, validated.base_url)

    async def _call(
        self, config: ProviderConnectionConfig, method: str, *args, **kwargs
    ):
        """One place where every gateway call is made and every gateway
        exception is translated, so no individual method can forget to."""
        creds = await self._creds(config)
        adapter = _adapter()
        func = getattr(adapter, method, None)
        if func is None:
            raise ProviderUnsupportedApiError(
                f"The installed Omada controller adapter does not implement "
                f"'{method}'."
            )
        try:
            return await func(creds, *args, **kwargs)
        except ProviderError:
            raise
        except Exception as exc:
            if _is_gateway_error(exc):
                raise _translate(exc) from exc
            # Not a gateway error at all -- a bug in the adapter, a
            # transport-level exception it failed to wrap. Reported as a
            # connection failure with no detail: `str(exc)` on an
            # unclassified exception has no contractual promise of being
            # secret-free, and this string reaches an API response.
            logger.exception(
                "network_integration_provider_unexpected_error",
                extra={"provider": self.kind, "provider_method": method},
            )
            raise ProviderConnectionFailedError() from exc

    # -- NetworkProvider ---------------------------------------------------

    async def test_connection(
        self, config: ProviderConnectionConfig
    ) -> ProviderControllerInfo:
        info = await self._call(config, "test_connection")
        return self._controller_info(info)

    async def get_controller_info(
        self, config: ProviderConnectionConfig
    ) -> ProviderControllerInfo:
        info = await self._call(config, "get_controller_info")
        return self._controller_info(info)

    async def inspect_tls(
        self, config: ProviderConnectionConfig
    ) -> ProviderTlsObservation:
        """The certificate the controller is presenting, for the operator.

        Goes through :meth:`_call` like everything else, so the URL is
        re-validated against the SSRF rules immediately beforehand and the
        gateway's errors are translated the same way. That matters more here
        than elsewhere: this is the one call an operator makes at an address
        this platform has never successfully talked to.

        The certificate is parsed for a subject and an expiry *here* rather
        than in the gateway, because the gateway's dependency list is
        deliberately four packages long and does not include
        ``cryptography``, while this application already depends on it. A
        parse failure degrades to a bare fingerprint rather than failing the
        observation -- the fingerprint is the part the operator confirms.
        """
        observation = await self._call(config, "inspect_tls")
        subject, issuer, not_valid_after = _describe_certificate(
            getattr(observation, "certificate_der", None)
        )
        return ProviderTlsObservation(
            fingerprint_sha256=str(observation.fingerprint_sha256),
            chain_trusted=bool(observation.chain_trusted),
            matches_pin=getattr(observation, "matches_pin", None),
            subject=subject,
            issuer=issuer,
            not_valid_after=not_valid_after,
        )

    async def list_sites(
        self, config: ProviderConnectionConfig
    ) -> list[ProviderSite]:
        sites = await self._call(config, "list_sites")
        return [
            ProviderSite(
                site_id=str(site.site_id),
                name=str(site.name),
                device_count=getattr(site, "device_count", None),
                client_count=getattr(site, "client_count", None),
            )
            for site in sites or []
        ]

    async def list_ssids(
        self, config: ProviderConnectionConfig, site_id: str
    ) -> list[ProviderSsid]:
        ssids = await self._call(config, "list_ssids", site_id)
        return [
            ProviderSsid(
                ssid_id=(
                    None if getattr(ssid, "ssid_id", None) is None
                    else str(ssid.ssid_id)
                ),
                name=str(ssid.name),
                portal_enabled=getattr(ssid, "portal_enabled", None),
            )
            for ssid in ssids or []
        ]

    async def list_devices(
        self, config: ProviderConnectionConfig, site_id: str
    ) -> list[ProviderDevice]:
        devices = await self._call(config, "list_devices", site_id)
        return [self._device(device) for device in devices or []]

    async def list_clients(
        self, config: ProviderConnectionConfig, site_id: str
    ) -> list[ProviderClient]:
        clients = await self._call(config, "list_clients", site_id)
        return [self._client(client) for client in clients or []]

    async def get_client(
        self, config: ProviderConnectionConfig, site_id: str, client_mac: str
    ) -> ProviderClient | None:
        client = await self._call(config, "get_client", site_id, client_mac)
        return None if client is None else self._client(client)

    async def authorize_guest(
        self,
        config: ProviderConnectionConfig,
        context: ProviderPortalContext,
        *,
        duration_seconds: int,
        down_kbps: int | None = None,
        up_kbps: int | None = None,
    ) -> ProviderAuthorizationResult:
        """Authorize one client on the controller for ``duration_seconds``.

        ``context`` is passed through with the values the controller itself
        put on the portal redirect -- including ``site``, which is *not*
        replaced with the integration's stored ``external_site_id``. TP-Link
        documents the redirect's ``site`` parameter and the Open API's
        ``siteId`` as different identifiers, and this platform has verified
        neither against hardware; substituting one for the other would be
        inventing a mapping. ``service.py`` separately refuses a redirect
        whose ``site`` does not match what the integration expects, which is
        the check that can be made honestly.
        """
        from wyfy_device_gateway.controller_contract import (  # noqa: PLC0415
            PortalAuthContext,
        )

        gateway_context = PortalAuthContext(
            client_mac=context.client_mac,
            site=context.site,
            ap_mac=context.ap_mac,
            ssid_name=context.ssid_name,
            radio_id=context.radio_id,
            gateway_mac=context.gateway_mac,
            vid=context.vid,
            t=context.t,
            redirect_url=context.redirect_url,
        )
        result = await self._call(
            config,
            "authorize_guest",
            gateway_context,
            duration_seconds=duration_seconds,
            down_kbps=down_kbps,
            up_kbps=up_kbps,
        )
        expires_at = getattr(result, "expires_at", None)
        if expires_at is None and getattr(result, "authorized", False):
            # INFERRED, unverified: whether the gateway populates
            # `expires_at` from the controller's own reply or leaves it to
            # the caller. Deriving it from the duration we asked for is
            # correct in both cases -- it is what this platform requested,
            # which is exactly what `AuthorizationStatus`/the
            # authorizations table claims to record (see that model's "not
            # a mirror of controller state" docstring).
            expires_at = datetime.now(UTC) + timedelta(seconds=duration_seconds)
        return ProviderAuthorizationResult(
            authorized=bool(getattr(result, "authorized", False)),
            expires_at=expires_at,
            provider_code=getattr(result, "provider_code", None),
        )

    async def deauthorize_guest(
        self, config: ProviderConnectionConfig, site_id: str, client_mac: str
    ) -> bool:
        """Always raises ``ProviderUnsupportedApiError``. Omada cannot do it.

        Contract change CR-001. The call is still *made* -- it is not
        short-circuited here with a local raise -- so that the refusal
        comes from the one component that actually knows the vendor's API
        surface, and so that the day TP-Link ships a deauthorization
        endpoint this module needs no change at all. The gateway raises
        ``OmadaUnsupportedApiError`` (``OMADA_API_UNSUPPORTED``), which
        ``_call`` translates into ``ProviderUnsupportedApiError`` through
        the same code table as every other gateway error.

        Never returns ``False`` to mean "impossible" -- see
        ``providers/base.py::NetworkProvider.deauthorize_guest`` for why
        the caller must be able to tell the two apart.
        """
        result = await self._call(config, "deauthorize_guest", site_id, client_mac)
        return bool(result)

    # -- mapping -----------------------------------------------------------

    @staticmethod
    def _controller_info(info: Any) -> ProviderControllerInfo:
        return ProviderControllerInfo(
            controller_id=str(getattr(info, "omadac_id", "") or ""),
            controller_version=getattr(info, "controller_version", None),
            model=getattr(info, "model", None),
            supports_openapi=bool(getattr(info, "supports_openapi", False)),
        )

    @staticmethod
    def _device(device: Any) -> ProviderDevice:
        return ProviderDevice(
            mac=str(device.mac),
            name=getattr(device, "name", None),
            device_type=str(getattr(device, "device_type", "unknown") or "unknown"),
            model=getattr(device, "model", None),
            status=str(getattr(device, "status", "unknown") or "unknown"),
            ip_address=getattr(device, "ip_address", None),
            firmware_version=getattr(device, "firmware_version", None),
            uptime_seconds=getattr(device, "uptime_seconds", None),
            client_count=getattr(device, "client_count", None),
        )

    @staticmethod
    def _client(client: Any) -> ProviderClient:
        return ProviderClient(
            mac=str(client.mac),
            name=getattr(client, "name", None),
            ip_address=getattr(client, "ip_address", None),
            ssid=getattr(client, "ssid", None),
            ap_mac=getattr(client, "ap_mac", None),
            radio_id=getattr(client, "radio_id", None),
            vlan_id=getattr(client, "vlan_id", None),
            is_guest=getattr(client, "is_guest", None),
            # Never coerced to False when absent -- see ProviderClient's
            # own docstring for why a missing reading is not a negative one.
            is_authorized=getattr(client, "is_authorized", None),
            connected_since=getattr(client, "connected_since", None),
            duration_seconds=getattr(client, "duration_seconds", None),
            traffic_down_bytes=getattr(client, "traffic_down_bytes", None),
            traffic_up_bytes=getattr(client, "traffic_up_bytes", None),
            signal_dbm=getattr(client, "signal_dbm", None),
        )
