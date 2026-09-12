"""Network Integration domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.

## Every exception carries a machine code, and that is the point

``CloudGuestError.data`` is rendered into the response envelope's ``data``
field. Every exception here puts ``{"code": <ErrorCode>}`` there, so the
frontend maps one stable vocabulary to its own copy instead of pattern
matching on English prose that a later edit will change. See
``constants.ErrorCode``.

The ten ``Provider*Error`` classes at the bottom exist so that the
gateway's own normalized codes (shared contract §2) survive translation
into this domain. ``providers/omada.py`` is the only module that catches
``wyfy_device_gateway.omada.errors.OmadaError``; it re-raises as one of
these, and the code is preserved. That is what keeps ``service.py`` and
``router.py`` free of any Omada import while still letting a customer's
dashboard say "the controller rejected our credentials" rather than
"something went wrong".

## Status codes: whose fault was it

A failure to reach or satisfy a *third-party controller* is not the API
caller's fault, so it is a 5xx (502/504) rather than a 4xx -- with two
deliberate exceptions. ``OMADA_SITE_NOT_FOUND``/``OMADA_CLIENT_NOT_FOUND``
are 404: the caller named a site or a client that does not exist, which is
a request problem and is retried by fixing the request.
``OMADA_RATE_LIMITED`` is 429 so a client's own backoff logic (which
already understands 429) does the right thing without special-casing.
``OMADA_API_UNSUPPORTED`` is 501: the controller is too old for the API
this platform speaks, and no retry or credential change will help.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

from .constants import CONTROLLER_SETUP_GAP_LABELS, ControllerSetupGap, ErrorCode

__all__ = [
    "ControllerSetupPreconditionsError",
    "ControllerSiteSharedError",
    "CrossLocationNetworkIntegrationAccessError",
    "CrossOrganizationNetworkIntegrationAccessError",
    "GuestSessionNotActiveError",
    "GuestSsidAmbiguousError",
    "GuestSsidInUseError",
    "GuestSsidNotFoundError",
    "NetworkIntegrationAlreadyExistsError",
    "NetworkIntegrationCredentialsRequiredError",
    "NetworkIntegrationDeauthorizationUnsupportedError",
    "NetworkIntegrationDisabledError",
    "NetworkIntegrationEncryptionKeyNotConfiguredError",
    "NetworkIntegrationFleetDeviceUnavailableError",
    "NetworkIntegrationLocationRequiredError",
    "NetworkIntegrationInventoryRequiresOpenApiError",
    "NetworkIntegrationError",
    "NetworkIntegrationNotFoundError",
    "NetworkIntegrationOrganizationRequiredError",
    "NetworkIntegrationRateLimitedError",
    "NetworkIntegrationSiteNotSelectedError",
    "NetworkIntegrationTlsPinRequiredError",
    "NetworkIntegrationUrlRejectedError",
    "PROVIDER_ERRORS_BY_CODE",
    "PortalConflictError",
    "ProviderAuthFailedError",
    "ProviderAuthorizationFailedError",
    "ProviderClientNotFoundError",
    "ProviderConnectionFailedError",
    "ProviderError",
    "ProviderInvalidControllerError",
    "ProviderPermissionDeniedError",
    "ProviderRateLimitedError",
    "ProviderSessionExpiredError",
    "ProviderSiteNotFoundError",
    "ProviderTimeoutError",
    "ProviderTlsPinMismatchError",
    "ProviderTlsUntrustedError",
    "ProviderUnsupportedApiError",
    "UnsupportedNetworkProviderError",
]


class NetworkIntegrationError(CloudGuestError):
    """Base exception for Network Integration domain errors."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        code: ErrorCode,
        data: dict[str, object] | None = None,
    ) -> None:
        payload: dict[str, object] = {"code": code.value}
        if data:
            payload.update(data)
        self.code = code
        super().__init__(message, status_code=status_code, data=payload)


# ============================================================================
# Row lifecycle / tenancy
# ============================================================================


class NetworkIntegrationNotFoundError(NetworkIntegrationError):
    def __init__(self, integration_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Network integration not found: {integration_id}",
            status_code=status.HTTP_404_NOT_FOUND,
            code=ErrorCode.NOT_FOUND,
        )


class CrossOrganizationNetworkIntegrationAccessError(NetworkIntegrationError):
    """A caller acting within organization A reached an integration belonging
    to organization B.

    This is the exception that closes the defect class this codebase has
    already been bitten by fourteen times: ``RequirePermission`` resolves
    the scope it checks from the ``X-Organization-Id`` header, while a
    ``/{integration_id}`` handler resolves its row from the path. A caller
    holding ``network_integrations.update`` on their own tenant could
    otherwise repoint another tenant's controller URL at a host they
    control -- and that URL is where this platform sends that tenant's
    controller credentials. So the comparison happens in the service layer,
    on the loaded row, on every by-id path, and not only at the route.
    """

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a network integration belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
            code=ErrorCode.CROSS_ORGANIZATION,
        )


class CrossLocationNetworkIntegrationAccessError(NetworkIntegrationError):
    """A caller confined to particular sites reached an integration at another
    site.

    Distinct from the organization error above: both sites belong to the
    *same* organization, so the organization comparison sees nothing wrong.
    See ``app.domains.rbac.location_scope`` for why the confinement is
    derived from the caller's own grants rather than from ``X-Location-Id``.
    """

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a network integration at a location outside your own scope",
            status_code=status.HTTP_403_FORBIDDEN,
            code=ErrorCode.CROSS_LOCATION,
        )


class NetworkIntegrationOrganizationRequiredError(NetworkIntegrationError):
    """A customer-scoped call arrived with no organization context.

    ``CurrentOrganization`` resolves to ``None`` for a caller holding an
    active GLOBAL-scoped role, and ``None`` means "apply no organization
    filter" everywhere downstream in this codebase. On a *customer* route
    that is never the right reading: it would silently widen a tenant list
    to every tenant on the platform. So the customer paths refuse it
    outright and the platform paths ask for the unscoped read by name (see
    ``service.py``'s ``list_platform_integrations``).
    """

    def __init__(self) -> None:
        super().__init__(
            "An organization context (X-Organization-Id) is required for this "
            "operation",
            status_code=status.HTTP_400_BAD_REQUEST,
            code=ErrorCode.ORGANIZATION_REQUIRED,
        )


class NetworkIntegrationAlreadyExistsError(NetworkIntegrationError):
    def __init__(self, base_url: str, external_site_id: str | None) -> None:
        site = external_site_id or "(no site selected)"
        super().__init__(
            "An integration for this controller and site already exists in this "
            f"organization: {base_url} / {site}",
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.ALREADY_EXISTS,
        )


class NetworkIntegrationDisabledError(NetworkIntegrationError):
    def __init__(self) -> None:
        super().__init__(
            "This network integration is disabled",
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.DISABLED,
        )


class NetworkIntegrationCredentialsRequiredError(NetworkIntegrationError):
    def __init__(self) -> None:
        super().__init__(
            "This network integration has no stored controller credentials yet",
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.CREDENTIALS_REQUIRED,
        )


class NetworkIntegrationSiteNotSelectedError(NetworkIntegrationError):
    def __init__(self) -> None:
        super().__init__(
            "This network integration has no controller site selected yet",
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.SITE_NOT_SELECTED,
        )


class NetworkIntegrationUrlRejectedError(NetworkIntegrationError):
    """The submitted controller URL failed SSRF validation.

    ``reason`` is deliberately specific and safe to show a human: an
    operator typing a controller address needs to know *which* rule
    refused it, and none of the rules leak anything the caller did not
    already supply. See ``validators.py``.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Controller URL rejected: {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code=ErrorCode.URL_REJECTED,
        )


class NetworkIntegrationTlsPinRequiredError(NetworkIntegrationError):
    """``tls_mode='pinned'`` with no usable fingerprint on the request.

    A 422 from this platform rather than a 502 from the controller, because
    nothing was dialled: the request describes an integration that would
    claim to pin a certificate and would not actually pin anything. Storing
    it and discovering the problem on the first guest authorization is the
    failure mode this refuses.

    ``reason`` is safe to show: it is a statement about the shape of a value
    the caller sent, and a certificate fingerprint is public.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Certificate pinning rejected: {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code=ErrorCode.TLS_PIN_REQUIRED,
        )


class NetworkIntegrationEncryptionKeyNotConfiguredError(NetworkIntegrationError):
    """Refuses to store controller credentials under the public default key.

    ``network_integration_encryption_key`` defaults to a value committed to
    a public repository. Outside a developer machine, a ciphertext written
    under it is plaintext to anyone who reads the column -- and these are
    credentials to networks *customers* own. So a write is refused before
    anything reaches the database, on every path that encrypts (create,
    Master onboarding, rotate).

    503, not 4xx: the request is fine and a retry will succeed the moment
    the deployment sets a real key. The message does not name the env var;
    that is in the CRITICAL log line, where the person who can fix it looks.
    """

    def __init__(self) -> None:
        super().__init__(
            "Controller credentials cannot be saved yet: credential encryption "
            "is not configured on this server. Nothing was stored. Contact "
            "the platform administrator.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code=ErrorCode.ENCRYPTION_KEY_NOT_CONFIGURED,
        )


class NetworkIntegrationFleetDeviceUnavailableError(NetworkIntegrationError):
    """Master onboarding was asked for, but this service has no way to
    write the fleet row that makes it meaningful.

    ## Why this refuses instead of falling back

    The obvious alternative -- create the integration alone and skip the
    ``Router`` row -- returns ``201`` for a venue that still cannot log a
    single guest in, because ``guest_sessions.router_id`` is NOT NULL and
    nothing would ever populate it (contract §11.4). The operator would
    leave the wizard believing the site was live and discover otherwise
    from a guest complaint, which is the exact "a screen that writes a row
    and changes nothing on a device" failure this codebase already has a
    documented history of.

    A refusal is the honest outcome: nothing was created, and the message
    says the deployment is missing a dependency rather than blaming
    anything the operator typed.

    ## 500, not 4xx

    Nothing in the request caused this and no retry of it will help. The
    ``NetworkIntegrationService`` was constructed without a fleet device
    provisioner, which only happens if the service is being built somewhere
    other than the real FastAPI dependency wiring.
    """

    def __init__(self) -> None:
        super().__init__(
            "Controller onboarding is unavailable on this deployment: the "
            "fleet device registry is not wired into this service. No "
            "integration was created.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code=ErrorCode.FLEET_DEVICE_UNAVAILABLE,
        )


class NetworkIntegrationLocationRequiredError(NetworkIntegrationError):
    """A fleet row was asked for on an integration mapped to no venue.

    A fleet device must be somewhere -- ``routers.location_id`` is what the
    guest flow resolves a venue by -- and inventing a location would put a
    controller in a venue nobody chose. 409: the request is fine, the row
    is not ready for it, and mapping the location first fixes it (mapping
    also registers the fleet row on its own).
    """

    def __init__(self) -> None:
        super().__init__(
            "This integration is not mapped to a location yet. Choose the "
            "venue it serves first -- the controller is registered as that "
            "venue's device as soon as it is mapped.",
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.LOCATION_REQUIRED,
        )


class UnsupportedNetworkProviderError(NetworkIntegrationError):
    def __init__(self, provider: str) -> None:
        super().__init__(
            f"Unsupported network integration provider: {provider}",
            status_code=status.HTTP_400_BAD_REQUEST,
            code=ErrorCode.PROVIDER_UNSUPPORTED,
        )


class GuestSessionNotActiveError(NetworkIntegrationError):
    """The portal authorize call did not present a usable guest session.

    One exception, one message and one 403 for every failure of that
    check -- session absent, soft-deleted, not ``ACTIVE``, or belonging to
    a different organization/location than the request body claims. They
    are deliberately *not* distinguished in the response: this endpoint is
    unauthenticated and reachable by anyone on a venue's WiFi, so telling
    a caller "that session exists but belongs to another venue" turns it
    into an oracle for enumerating session ids and their tenancy. The
    distinction is recorded server-side in the event row, where the venue's
    own operator can see it.
    """

    def __init__(self) -> None:
        super().__init__(
            "No active guest session matches this authorization request",
            status_code=status.HTTP_403_FORBIDDEN,
            code=ErrorCode.GUEST_SESSION_NOT_ACTIVE,
        )


class NetworkIntegrationRateLimitedError(NetworkIntegrationError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(
            "Too many authorization attempts for this session. Try again in "
            f"{retry_after_seconds} seconds.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code=ErrorCode.RATE_LIMITED,
            data={"retry_after_seconds": retry_after_seconds},
        )


class NetworkIntegrationInventoryRequiresOpenApiError(NetworkIntegrationError):
    """An inventory read was attempted on a ``legacy``-mode integration.

    Contract change CR-002. A hotspot *operator* credential provably
    cannot read sites, devices or clients -- only the external-portal
    client-authorization call. The gateway refuses those requests in
    legacy mode rather than issuing them, and this domain refuses them one
    layer earlier still, before a provider is even resolved.

    ## Why this is an error and emphatically not an empty list

    Returning ``[]`` was the tempting option and it is the wrong one. To a
    venue owner looking at the devices table, an empty list does not read
    as "this credential type cannot answer that question" -- it reads as
    *"you have no access points"*. That is a false statement about their
    hardware, produced by this platform, on a screen they use to decide
    whether their network is working. It is the same class of falsehood
    ``app.domains.guest_access.device_adapters`` exists to document and
    fix: a UI asserting a fact the backend never established.

    ## Why not simply refuse legacy mode outright

    Because legacy mode is not a degraded configuration -- it is the mode
    the captive portal actually needs, and it is the *only* mode available
    on controllers below v5.13. An integration in legacy mode is fully
    functional for the thing this platform primarily uses Omada for. The
    honest shape is therefore "this capability needs Open API
    credentials", with a route to adding them, which is exactly what the
    message says.

    501, not 400: the caller's request is well-formed and the credentials
    are correct. The capability is not implemented by the vendor for this
    credential type.
    """

    def __init__(self, capability: str) -> None:
        super().__init__(
            f"Reading {capability} from the controller requires Open API "
            "credentials. This integration uses a hotspot operator login, "
            "which the controller only accepts for captive-portal "
            "authorization -- it cannot list controller inventory. Add Open "
            "API credentials (Settings > Platform Integration > Open API on "
            "the controller) to enable this. The captive portal continues to "
            "work as configured.",
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            code=ErrorCode.API_UNSUPPORTED,
            data={"capability": capability, "requires_auth_mode": "openapi"},
        )


class NetworkIntegrationDeauthorizationUnsupportedError(NetworkIntegrationError):
    """The provider declined to end one guest's authorization early.

    ## What this used to mean, and no longer does

    This used to be unconditional for Omada, on CR-001's claim that
    TP-Link publishes no client-deauthorization endpoint in any generation
    of the Omada API. TP-Link indeed publishes none -- and the controller
    has one regardless, in the Hotspot Manager API tree, reachable with
    the very operator session the portal authorization already opens. It
    is implemented (``omada.deauth``) and observed working on real
    hardware. A guest's network access therefore no longer ends only when
    the authorization duration expires.

    ## What it means now

    One thing: the integration has no credential that can open a hotspot
    session -- Open API client credentials and nothing else. Those can
    read the controller's inventory and cannot end an authorization.

    The useful property of that being the *only* remaining case is that it
    is self-limiting: the same missing credential also makes
    ``authorize_guest`` refuse, so an integration that cannot disconnect a
    guest was never able to connect one either. There is no configuration
    in which this platform puts a guest on a network it cannot take them
    off.

    ## Why this raises instead of returning success

    Unchanged, and still the point. The alternative -- reporting 200, or
    ending only this platform's own ``GuestSession`` row and calling that
    "disconnected" -- is the lie
    ``app.domains.guest_access.device_adapters`` was written to fix: a row
    reading "ended" while the device is still forwarding traffic. Ending
    the ``GuestSession`` is a separate, real, and still-required act
    (without it the next portal hit finds an ACTIVE session and re-admits
    the guest), and it is available on its own route; it simply must not
    be described as kicking the client off the network, because it isn't.
    """

    def __init__(self) -> None:
        super().__init__(
            "This integration has no hotspot operator credentials, so a "
            "guest's access cannot be ended on the controller -- Open API "
            "credentials can read the controller but cannot end an "
            "authorization. Nothing was changed on the network. Add an "
            "operator account to this integration, or end the guest's "
            "session on this platform instead, which prevents them "
            "re-authorizing but does not disconnect the device they are "
            "already using.",
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            code=ErrorCode.API_UNSUPPORTED,
        )


# ============================================================================
# "Configure controller automatically"
# ============================================================================


class ControllerSetupPreconditionsError(NetworkIntegrationError):
    """Automatic setup refused before the controller was contacted.

    Every missing piece is named at once (``data.missing``), in the order an
    operator would fix them, reusing ``PortalReadinessGap``'s wording where
    the fact is the same one. 409: the request is fine; the row is not ready.
    """

    def __init__(self, gaps: list[ControllerSetupGap]) -> None:
        reasons = [CONTROLLER_SETUP_GAP_LABELS[gap] for gap in gaps]
        joined = (
            reasons[0]
            if len(reasons) == 1
            else ", ".join(reasons[:-1]) + " and " + reasons[-1]
        )
        super().__init__(
            f"This controller cannot be configured automatically yet: {joined}. "
            "Nothing was changed on the controller.",
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.AUTOCONFIG_PRECONDITIONS,
            data={"missing": [gap.value for gap in gaps]},
        )


class ControllerSiteSharedError(NetworkIntegrationError):
    """Another organization's integration points at the same controller site.

    A site's portal list and Pre-Authentication Access are shared state on
    the controller. Two tenants each configuring them would be one tenant
    able to redirect the other's guests, so automatic setup refuses for both
    rather than guessing whose site it is. The other tenant is deliberately
    not named, and no id of theirs is returned.
    """

    def __init__(self) -> None:
        super().__init__(
            "This controller site is also connected to Wyfy Guest by another "
            "customer account, so it cannot be configured automatically from "
            "either one. Nothing was changed. Contact support to confirm who "
            "manages this site.",
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.CONTROLLER_SITE_SHARED,
        )


class GuestSsidInUseError(NetworkIntegrationError):
    """A second integration in the same organization wants the same SSID on
    the same controller site. One SSID can be bound to one portal."""

    def __init__(self) -> None:
        super().__init__(
            "Another location in your organization already uses this guest "
            "SSID on this controller site. Each location needs its own guest "
            "SSID. Nothing was changed.",
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.GUEST_SSID_IN_USE,
        )


class PortalConflictError(NetworkIntegrationError):
    """The guest SSID is bound to a portal this integration did not create.

    Refused with nothing changed. ``data`` names the portal so the operator
    can find it on their own controller -- that name came from the tenant's
    own controller, so it discloses nothing. ``take_over_ssid_portal`` is the
    explicit way through, and it removes only the SSID from that portal.
    """

    def __init__(
        self, message: str, *, portal_id: str | None, portal_name: str | None
    ) -> None:
        super().__init__(
            message,
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.PORTAL_CONFLICT,
            data={
                "portal_id": portal_id,
                "portal_name": portal_name,
                "resolution": "take_over_ssid_portal",
            },
        )


class GuestSsidNotFoundError(NetworkIntegrationError):
    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.GUEST_SSID_NOT_FOUND,
        )


class GuestSsidAmbiguousError(NetworkIntegrationError):
    def __init__(self, message: str, *, match_count: int | None) -> None:
        super().__init__(
            message,
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.GUEST_SSID_AMBIGUOUS,
            data={"match_count": match_count},
        )


# ============================================================================
# Provider (controller) failures
# ============================================================================


class ProviderError(NetworkIntegrationError):
    """Base for every failure that came from the third-party controller.

    ``service.py`` catches *this* class -- never a gateway exception -- to
    decide the integration's new ``status`` and to write an event row. That
    is the whole reason the hierarchy exists: the status mapping
    (``AUTH_FAILED`` vs ``CONNECTION_FAILED`` vs ``SYNC_ERROR``) is a
    business decision about what to show a venue owner, and it must not
    live in a module that imports a vendor SDK.
    """

    #: The vendor's own raw error code for this failure, as an integer, or
    #: ``None`` when the failure never reached the controller (a timeout, a
    #: refused connection).
    #:
    #: A class attribute with an instance override rather than a constructor
    #: argument, so that the ten subclasses below keep their one-argument
    #: signatures and ``providers/omada.py`` stays the only module that knows
    #: a vendor code exists. ``with_diagnostics`` is the setter.
    #:
    #: **Why an integer is safe to keep and a response body is not.** The
    #: gateway's contract (§2) lets exactly one piece of the raw controller
    #: response survive into an exception: this number. It cannot smuggle a
    #: credential, and it is the only thing that distinguishes Omada's
    #: ``-41500`` ("Invalid authentication type", a named field) from its
    #: ``-41501`` ("Failed to authenticate", a catch-all covering a wrong MAC,
    #: a stale timestamp, an unknown site, an AP that never saw the client and
    #: a missing required field). ``ErrorCode`` cannot carry that distinction
    #: -- both normalize to ``OMADA_AUTHORIZATION_FAILED`` -- so if this is
    #: dropped at the seam, the one discrimination the controller offers is
    #: gone for good.
    provider_code: int | None = None

    #: What we actually put on the wire, field by field, already free of
    #: secrets. ``None`` for every call except a portal authorization, which
    #: is the one place a support engineer needs to diff the request against
    #: the redirect that produced it.
    #:
    #: Opaque to this module and to ``service.py``: the keys are the vendor's
    #: spelling and only ``providers/omada.py`` puts them there. It is carried
    #: on the exception rather than returned alongside it because the failing
    #: call raises -- there is no return value to hang it on, and a support
    #: engineer needs it precisely when the call failed.
    request_snapshot: dict[str, object] | None = None

    def __init__(
        self,
        message: str,
        *,
        code: ErrorCode,
        status_code: int = status.HTTP_502_BAD_GATEWAY,
    ) -> None:
        super().__init__(message, status_code=status_code, code=code)

    def with_diagnostics(
        self,
        *,
        provider_code: int | None = None,
        request_snapshot: dict[str, object] | None = None,
    ) -> ProviderError:
        """Attach vendor diagnostics to an already-constructed error.

        Returns ``self`` so a raise site reads as one expression. Neither
        value is ever put in ``data`` and neither reaches the API response:
        they exist to be written to ``network_integration_events.context``,
        which is a different audience (an operator diffing a failure) with a
        different threat model (already org-scoped, already redacted on the
        way in) from an unauthenticated caller receiving a 502.

        Passing ``None`` leaves the existing value alone rather than clearing
        it, so a partial attachment cannot erase a fuller one.
        """
        if provider_code is not None:
            self.provider_code = provider_code
        if request_snapshot is not None:
            self.request_snapshot = request_snapshot
        return self


class ProviderAuthFailedError(ProviderError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or "The network controller rejected the stored credentials. "
            "Re-enter them to reconnect.",
            code=ErrorCode.AUTH_FAILED,
        )


class ProviderConnectionFailedError(ProviderError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message or "Could not reach the network controller.",
            code=ErrorCode.CONNECTION_FAILED,
        )


class ProviderTlsUntrustedError(ProviderError):
    """The controller answered; this platform would not trust its certificate.

    Separate from :class:`ProviderConnectionFailedError` because the copy
    that goes with a connection failure -- check the URL, check the port,
    check the firewall -- is actively misleading here. All three are already
    right. This is the defect that motivated the whole change: a self-signed
    controller, which is what nearly every self-hosted Omada install is,
    reported as unreachable.
    """

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or "The network controller answered, but this platform does not "
            "trust its HTTPS certificate. Self-hosted controllers ship a "
            "self-signed certificate, so this is expected -- run Test "
            "Connection to review the controller's certificate fingerprint "
            "and pin it to this integration.",
            code=ErrorCode.TLS_UNTRUSTED,
        )


class ProviderTlsPinMismatchError(ProviderError):
    """The certificate is not the one pinned to this integration.

    Its own code rather than a flavour of :class:`ProviderTlsUntrustedError`
    because it is the only one of the TLS failures that can mean an attack in
    progress, and the operator instruction differs accordingly: do not
    re-pin blindly.
    """

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or "The network controller presented a different HTTPS "
            "certificate than the one pinned to this integration. If the "
            "certificate was replaced on purpose, run Test Connection to "
            "review and confirm the new fingerprint. If it was not, stop: "
            "something is intercepting this connection.",
            code=ErrorCode.TLS_PIN_MISMATCH,
        )


class ProviderTimeoutError(ProviderError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message or "The network controller did not respond in time.",
            code=ErrorCode.TIMEOUT,
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
        )


class ProviderRateLimitedError(ProviderError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message or "The network controller is rate limiting this platform.",
            code=ErrorCode.PROVIDER_RATE_LIMITED,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )


class ProviderInvalidControllerError(ProviderError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or "The address given does not appear to be a supported network "
            "controller.",
            code=ErrorCode.INVALID_CONTROLLER,
        )


class ProviderSiteNotFoundError(ProviderError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message or "The controller has no such site.",
            code=ErrorCode.SITE_NOT_FOUND,
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ProviderClientNotFoundError(ProviderError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message or "The controller does not know that client.",
            code=ErrorCode.CLIENT_NOT_FOUND,
            status_code=status.HTTP_404_NOT_FOUND,
        )


class ProviderAuthorizationFailedError(ProviderError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message or "The controller refused to authorize that client.",
            code=ErrorCode.AUTHORIZATION_FAILED,
        )


class ProviderUnsupportedApiError(ProviderError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or "This controller's software version is older than the API this "
            "platform requires.",
            code=ErrorCode.API_UNSUPPORTED,
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
        )


class ProviderPermissionDeniedError(ProviderError):
    """The controller refused a call the credential is not allowed to make.

    502 like the other controller failures: the caller's request to this
    platform was fine and a 403 here would read as "you lack a Wyfy Guest
    permission", which is the wrong building entirely.
    """

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or "The network controller refused this request: the Open API app "
            "is not allowed to make it. Give the app a role with Modify "
            "access to Site Settings and Hotspot, with this site in its site "
            "privileges.",
            code=ErrorCode.PERMISSION_DENIED,
        )


class ProviderSessionExpiredError(ProviderError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message or "The controller session expired and could not be renewed.",
            code=ErrorCode.SESSION_EXPIRED,
        )


# Gateway normalized code -> this domain's exception. Used by
# ``providers/omada.py`` and by nothing else; a code the gateway invents
# that is not in this table falls back to ``ProviderConnectionFailedError``
# rather than escaping as an unhandled 500 (see that module).
PROVIDER_ERRORS_BY_CODE: dict[str, type[ProviderError]] = {
    ErrorCode.AUTH_FAILED.value: ProviderAuthFailedError,
    ErrorCode.CONNECTION_FAILED.value: ProviderConnectionFailedError,
    ErrorCode.TIMEOUT.value: ProviderTimeoutError,
    ErrorCode.PROVIDER_RATE_LIMITED.value: ProviderRateLimitedError,
    ErrorCode.INVALID_CONTROLLER.value: ProviderInvalidControllerError,
    ErrorCode.SITE_NOT_FOUND.value: ProviderSiteNotFoundError,
    ErrorCode.CLIENT_NOT_FOUND.value: ProviderClientNotFoundError,
    ErrorCode.AUTHORIZATION_FAILED.value: ProviderAuthorizationFailedError,
    ErrorCode.API_UNSUPPORTED.value: ProviderUnsupportedApiError,
    ErrorCode.SESSION_EXPIRED.value: ProviderSessionExpiredError,
    ErrorCode.TLS_UNTRUSTED.value: ProviderTlsUntrustedError,
    ErrorCode.TLS_PIN_MISMATCH.value: ProviderTlsPinMismatchError,
    ErrorCode.PERMISSION_DENIED.value: ProviderPermissionDeniedError,
}
