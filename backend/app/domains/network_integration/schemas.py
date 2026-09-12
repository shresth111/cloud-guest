"""Pydantic request/response schemas for the Network Integration domain API.

Follows the same pydantic v2 conventions as ``app.domains.isp.schemas`` /
``app.domains.mac_authorization.schemas``: plain ``str`` fields for every
UUID, explicit response-builder functions in ``router.py`` doing the
``str(...)`` conversion rather than ``ConfigDict(from_attributes=True)``
auto-mapping, and ``MessageResponse`` re-exported from the auth domain
rather than duplicated.

## There is no schema field for a credential, on any response

Search this file for ``client_secret`` and you will find it exactly twice,
both times on a *request*. The response models carry
``has_credentials: bool`` and nothing else. That is not an oversight to be
"improved" later: the whole point of storing these encrypted is that the
platform can use them and nobody can read them back, and a response field
-- however well-permissioned -- undoes that in one line. If a future
requirement seems to need the stored value on the client, it does not; it
needs a server-side operation.

The write-side fields are `Field(..., repr=False)` so that a Pydantic
model's own ``repr()`` -- which lands in tracebacks and in FastAPI's 422
validation output -- cannot carry the secret. That covers the accident;
``service.py`` never logs the model at all, which covers the rest.

## Why the MAC fields are ``MaskedMac`` on responses but plain ``str`` on
## requests

``app.common.masking`` masks at *serialization* time only -- the database
and every filter always see the real value (see that module's docstring).
A client MAC is guest PII in this codebase, so the client/authorization
response rows mask it exactly as ``app.domains.connected_devices.schemas``
and ``app.domains.guest.schemas`` already do. The portal *request* must
carry the real MAC, because it is what gets sent to the controller.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.common.masking import MaskedMac
from app.domains.auth.schemas import MessageResponse

from .constants import (
    DEFAULT_SESSION_DURATION_SECONDS,
    DEFAULT_SYNC_INTERVAL_SECONDS,
    MAX_SESSION_DURATION_SECONDS,
    MAX_SYNC_INTERVAL_SECONDS,
    MIN_SESSION_DURATION_SECONDS,
    MIN_SYNC_INTERVAL_SECONDS,
)
from .validators import validate_external_site_id

#: The controller's site, as it must be STORED: an id, never a display
#: name. Declared once and reused by every request model that can write the
#: column, so the refusal cannot be present on one write path and missing on
#: another -- which is how the live QA integration came to hold "wyfyguest"
#: in a column every controller call is addressed with.
#:
#: See `validators.validate_external_site_id` for the measurement that
#: settles it (the controller's own redirect carries the id, verified
#: 2026-09-12), for why a name cannot be resolved to an id on the
#: credentials this integration uses (CR-002), and for what each auth mode
#: should collect instead.
ExternalSiteId = Annotated[
    str | None,
    Field(max_length=128),
    AfterValidator(validate_external_site_id),
]

__all__ = [
    "ControllerConfigureRequest",
    "ControllerConfigureResponse",
    "ControllerConfigureStepResponse",
    "MessageResponse",
    "NetworkIntegrationAuthorizationResponse",
    "NetworkIntegrationClientListResponse",
    "NetworkIntegrationClientResponse",
    "NetworkIntegrationCreateRequest",
    "NetworkIntegrationCredentialRotateRequest",
    "NetworkIntegrationDeviceListResponse",
    "NetworkIntegrationDeviceResponse",
    "NetworkIntegrationDisconnectGuestRequest",
    "NetworkIntegrationDisconnectGuestResponse",
    "NetworkIntegrationEventListResponse",
    "NetworkIntegrationEventResponse",
    "NetworkIntegrationListResponse",
    "NetworkIntegrationResponse",
    "NetworkIntegrationSiteListResponse",
    "NetworkIntegrationSiteResponse",
    "NetworkIntegrationSsidListResponse",
    "NetworkIntegrationSsidResponse",
    "NetworkIntegrationStatusResponse",
    "NetworkIntegrationSyncResponse",
    "NetworkIntegrationUpdateRequest",
    "PlatformNetworkIntegrationUpdateRequest",
    "ControllerRadiusNasRequest",
    "ControllerRadiusNasResponse",
    "PlatformNetworkIntegrationListResponse",
    "PlatformNetworkIntegrationSummaryResponse",
    "PlatformOnboardRequest",
    "PlatformOnboardResponse",
    "PlatformTestConnectionRequest",
    "PlatformTestConnectionResponse",
    "PortalAuthorizeRequest",
    "PortalAuthorizeResponse",
    "TestConnectionRequest",
    "TestConnectionResponse",
]

_AuthMode = Literal["openapi", "legacy"]
_Provider = Literal["omada"]
_TlsMode = Literal["strict", "pinned", "insecure"]

#: Which captive-portal contract a venue is on. See
#: ``constants.PortalAuthMode``. Deliberately absent from every *customer*
#: request body on this domain: moving a venue to RADIUS mode needs an
#: inbound network path, a NAS client keyed on the controller's public
#: address and a certificate the guest's browser accepts, none of which a
#: self-service toggle can arrange -- so the field is reachable only on the
#: platform (Master console) update body, and the service re-checks that
#: rather than trusting the schema split.
_PortalMode = Literal["external_portal", "radius"]

_PORTAL_MODE_DESCRIPTION = (
    "Which captive-portal contract this venue is on. 'external_portal' "
    "(default, and what every existing integration is) is TP-Link authType "
    "4: the guest's browser posts to this platform and this platform calls "
    "the controller -- outbound only, works behind a venue's NAT. 'radius' "
    "is authType 2 with an External Web Portal: the guest's browser posts "
    "to the controller and the controller sends an inbound RADIUS "
    "Access-Request to this platform. RADIUS mode additionally requires an "
    "inbound UDP path to this platform's FreeRADIUS, a registered NAS "
    "client keyed on the controller's public address, and a certificate on "
    "the controller that a guest's browser will accept; setting this field "
    "arranges none of them."
)

#: Shared field definitions for the certificate-trust pair, so the create,
#: onboard, update, rotate and probe bodies cannot describe them three
#: different ways in the generated OpenAPI schema the frontend is built
#: from.
_TLS_MODE_DESCRIPTION = (
    "How this platform verifies the controller's HTTPS certificate. "
    "'strict' (default) is ordinary public-CA verification. 'pinned' "
    "requires the certificate to match tls_pinned_sha256 -- this is the "
    "right answer for a self-hosted controller, which ships a self-signed "
    "certificate that 'strict' will always refuse. 'insecure' performs no "
    "certificate check at all and is recorded as an explicit decision."
)
_TLS_PIN_DESCRIPTION = (
    "SHA-256 fingerprint of the controller's certificate, as 64 hex "
    "characters; colons and spaces are accepted and stripped. Required "
    "when tls_mode is 'pinned' and cleared otherwise. Obtain it by running "
    "Test Connection against the controller -- the response carries the "
    "fingerprint the controller is actually presenting, which is the value "
    "an operator confirms rather than one they have to go and find."
)


# ============================================================================
# Shared credential payload
# ============================================================================


#: The Omada ID (``omadacId``) of the controller this row points at.
#:
#: Optional everywhere, because on a controller this platform can reach
#: directly it is *discovered*: ``GET /api/info`` answers unauthenticated
#: and reports it, so asking an operator to copy a 32-character hex string
#: they do not need would be a worse wizard.
#:
#: It stops being optional in exactly one situation, and hardware found it on
#: 2026-09-11: a controller reached through TP-Link's cloud edge. One address
#: there fronts every controller in a region, so the unscoped ``/api/info``
#: 404s and there is nothing to discover from -- the id is what selects the
#: controller. Without this field a cloud-managed controller could be typed
#: into the wizard but never identified, and so never connected.
#:
#: Supplying it costs a cloud operator nothing: TP-Link hands them the Omada
#: ID on the same screen as the credentials, and its own console puts it in
#: the URL bar.
def _controller_id_field() -> Any:
    return Field(
        default=None,
        max_length=64,
        description=(
            "The controller's Omada ID (omadacId). Optional for a controller "
            "reached directly -- it is discovered from the controller itself. "
            "Required for a cloud-managed controller reached through a "
            "*-api-omada-controller.tplinkcloud.com address, where one host "
            "fronts many controllers and nothing can be discovered without "
            "it. Visible in the controller's own web address and on the "
            "Open API / hotspot credential screen."
        ),
    )


class _CredentialFields(BaseModel):
    """The four write-only credential fields, in one place.

    ``repr=False`` on the two secrets: see the module docstring. Which of
    the four are required is decided by ``auth_mode`` and enforced
    server-side by ``validators.validate_auth_mode_credentials`` rather
    than by a Pydantic discriminated union -- the error messages that
    function produces name the controller UI screen an operator has to go
    to, which a schema-level union cannot say.
    """

    client_id: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "Open API client id, from the controller's Settings > Platform "
            "Integration > Open API screen. Required when auth_mode is "
            "'openapi'. Write-only -- never returned by any endpoint."
        ),
    )
    client_secret: str | None = Field(
        default=None,
        max_length=512,
        repr=False,
        description=(
            "Open API client secret. Required when auth_mode is 'openapi'. "
            "Stored Fernet-encrypted; never returned by any endpoint, never "
            "logged."
        ),
    )
    username: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "Hotspot operator name. Required when auth_mode is 'legacy'; "
            "optional alongside client_id/client_secret when auth_mode is "
            "'openapi', but guest sign-in needs it in both modes -- the "
            "controller authorizes guests only through an operator login. "
            "Write-only."
        ),
    )
    password: str | None = Field(
        default=None,
        max_length=512,
        repr=False,
        description=(
            "Hotspot operator password. Required when auth_mode is 'legacy', "
            "and with username in 'openapi' mode for guest sign-in. Stored "
            "Fernet-encrypted; never returned by any endpoint, never logged."
        ),
    )


# ============================================================================
# Integration CRUD
# ============================================================================


class NetworkIntegrationCreateRequest(_CredentialFields):
    provider: _Provider = "omada"
    name: str = Field(min_length=1, max_length=120)
    base_url: str = Field(
        min_length=1,
        max_length=512,
        description=(
            "The controller's base address, e.g. "
            "https://controller.example.com:8043 -- scheme and host only, no "
            "path. Validated against this platform's SSRF rules at write "
            "time and again before every outbound request."
        ),
    )
    auth_mode: _AuthMode = "openapi"
    controller_id: str | None = _controller_id_field()
    location_id: str | None = Field(
        default=None,
        description=(
            "The WyfyGuest location this controller serves. Optional at "
            "create time so the connect wizard can save credentials before "
            "the operator picks a site, but an integration with no location "
            "is never selected for a captive-portal authorization -- that "
            "resolution is by location."
        ),
    )
    external_site_id: ExternalSiteId = None
    external_site_name: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "The site's human-readable label, for display only. Never used "
            "to address the controller and never compared against a portal "
            "redirect -- see `external_site_id`. A hotspot-operator login "
            "cannot list sites (CR-002), so on a legacy integration this is "
            "legitimately unknown and stays empty."
        ),
    )
    guest_ssid_id: str | None = Field(default=None, max_length=128)
    guest_ssid_name: str | None = Field(default=None, max_length=255)
    session_duration_seconds: int = Field(
        default=DEFAULT_SESSION_DURATION_SECONDS,
        ge=MIN_SESSION_DURATION_SECONDS,
        le=MAX_SESSION_DURATION_SECONDS,
        description=(
            "How long a guest's authorization lasts on the controller. An "
            "authorization can also be ended early: see the per-guest "
            "disconnect, which needs the same hotspot-operator credentials "
            "this integration already uses. Ending the WyfyGuest guest "
            "session on its own prevents re-authorization but does not "
            "disconnect the device. Capped at 7 days, which is a policy "
            "bound on how long an unattended grant may run, not a technical "
            "limit."
        ),
    )
    sync_interval_seconds: int = Field(
        default=DEFAULT_SYNC_INTERVAL_SECONDS,
        ge=MIN_SYNC_INTERVAL_SECONDS,
        le=MAX_SYNC_INTERVAL_SECONDS,
        description=(
            "How often this platform polls the controller for status, "
            "devices and clients. Floored at 60s: every tick is a live HTTPS "
            "round trip to customer-owned hardware, so an unbounded-downward "
            "knob would let a tenant point this platform at their own "
            "controller as a load generator."
        ),
    )
    is_enabled: bool = True
    tls_mode: _TlsMode = Field(default="strict", description=_TLS_MODE_DESCRIPTION)
    tls_pinned_sha256: str | None = Field(
        default=None, max_length=200, description=_TLS_PIN_DESCRIPTION
    )


class PlatformOnboardRequest(_CredentialFields):
    """Master-driven controller onboarding -- contract §11.6.

    Its own request model rather than a flag on
    ``NetworkIntegrationCreateRequest``, because three of its fields differ
    in *requiredness* rather than in value, and a shared model would have to
    make all three optional and then re-check them by hand:

    * ``organization_id`` is required here and absent there. A GLOBAL-scoped
      platform operator has no organization of their own, so the tenant is
      named in the body. It is re-verified downstream -- the router domain
      resolves ``location_id`` *with* this organization and rejects a
      location belonging to anyone else -- so a body that names a mismatched
      pair gets a 404 rather than a cross-tenant row.
    * ``location_id`` is required here and optional there. This path writes
      a fleet device, and a device must be somewhere.
    * ``controller_model`` is required here and does not exist there. It
      lands in ``routers.model``, which is NOT NULL.
    """

    organization_id: uuid.UUID = Field(
        description="The tenant this controller belongs to."
    )
    location_id: uuid.UUID = Field(
        description=(
            "The WyfyGuest location this controller serves. Required on this "
            "path -- unlike customer self-service -- because it is also the "
            "location of the fleet device row this creates."
        )
    )
    provider: _Provider = "omada"
    name: str = Field(min_length=1, max_length=120)
    base_url: str = Field(min_length=1, max_length=512)
    auth_mode: _AuthMode = "openapi"
    controller_id: str | None = _controller_id_field()
    controller_model: str = Field(
        min_length=1,
        max_length=100,
        description=(
            "The controller's model, e.g. 'OC200' or 'Omada Software "
            "Controller'. Stored on the fleet device row."
        ),
    )
    serial_number: str | None = Field(
        default=None,
        max_length=100,
        description=(
            "The controller's real serial number, for hardware controllers "
            "(OC200/OC300). Omit for a software controller: a visibly "
            "synthetic, deterministic identity is generated instead. Supply "
            "serial_number and mac_address together or neither."
        ),
    )
    mac_address: str | None = Field(
        default=None,
        max_length=17,
        description=(
            "The controller's real MAC address, for hardware controllers. "
            "Omit for a software controller -- a locally-administered "
            "address is generated, never a fabricated vendor one."
        ),
    )
    external_site_id: ExternalSiteId = None
    external_site_name: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "The site's human-readable label, for display only. Never used "
            "to address the controller and never compared against a portal "
            "redirect -- see `external_site_id`. A hotspot-operator login "
            "cannot list sites (CR-002), so on a legacy integration this is "
            "legitimately unknown and stays empty."
        ),
    )
    guest_ssid_id: str | None = Field(default=None, max_length=128)
    guest_ssid_name: str | None = Field(default=None, max_length=255)
    session_duration_seconds: int = Field(
        default=DEFAULT_SESSION_DURATION_SECONDS,
        ge=MIN_SESSION_DURATION_SECONDS,
        le=MAX_SESSION_DURATION_SECONDS,
    )
    sync_interval_seconds: int = Field(
        default=DEFAULT_SYNC_INTERVAL_SECONDS,
        ge=MIN_SYNC_INTERVAL_SECONDS,
        le=MAX_SYNC_INTERVAL_SECONDS,
    )
    is_enabled: bool = True
    tls_mode: _TlsMode = Field(default="strict", description=_TLS_MODE_DESCRIPTION)
    tls_pinned_sha256: str | None = Field(
        default=None, max_length=200, description=_TLS_PIN_DESCRIPTION
    )

    @model_validator(mode="after")
    def _identity_fields_travel_together(self) -> PlatformOnboardRequest:
        """Half a hardware identity is worse than none.

        A serial with no MAC would silently take the synthesized-MAC branch
        and pair a real serial number with a generated address, which reads
        as a genuine hardware record in the fleet table and is not one.
        Refusing is the only honest answer.
        """
        if (self.serial_number is None) != (self.mac_address is None):
            raise ValueError(
                "serial_number and mac_address must be supplied together, or "
                "both omitted for a software controller"
            )
        return self


class PlatformOnboardResponse(BaseModel):
    """The pair this path creates, so the wizard can navigate to either."""

    integration: NetworkIntegrationResponse
    router_id: uuid.UUID = Field(
        description="The fleet device row created for this controller."
    )
    router_serial_number: str
    router_vendor: str
    synthetic_identity: bool = Field(
        description=(
            "True when this platform generated the fleet row's serial and "
            "MAC because the controller has none of its own."
        )
    )


class NetworkIntegrationUpdateRequest(BaseModel):
    """Partial update. Deliberately carries **no** credential fields.

    Rotating a secret is a different operation with a different audit
    entry and a different permission story from renaming an integration,
    so it has its own endpoint (``POST /{id}/credentials``). Allowing
    credentials on the general PATCH would also mean every partial update
    request body is a potential secret, which is the kind of thing that
    ends up in a debug log.
    """

    name: str | None = Field(default=None, min_length=1, max_length=120)
    base_url: str | None = Field(default=None, min_length=1, max_length=512)
    auth_mode: _AuthMode | None = None
    controller_id: str | None = _controller_id_field()
    location_id: str | None = None
    external_site_id: ExternalSiteId = None
    external_site_name: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "The site's human-readable label, for display only. Never used "
            "to address the controller and never compared against a portal "
            "redirect -- see `external_site_id`. A hotspot-operator login "
            "cannot list sites (CR-002), so on a legacy integration this is "
            "legitimately unknown and stays empty."
        ),
    )
    guest_ssid_id: str | None = Field(default=None, max_length=128)
    guest_ssid_name: str | None = Field(default=None, max_length=255)
    session_duration_seconds: int | None = Field(
        default=None,
        ge=MIN_SESSION_DURATION_SECONDS,
        le=MAX_SESSION_DURATION_SECONDS,
    )
    sync_interval_seconds: int | None = Field(
        default=None,
        ge=MIN_SYNC_INTERVAL_SECONDS,
        le=MAX_SYNC_INTERVAL_SECONDS,
    )
    is_enabled: bool | None = None
    tls_mode: _TlsMode | None = Field(
        default=None, description=_TLS_MODE_DESCRIPTION
    )
    tls_pinned_sha256: str | None = Field(
        default=None,
        max_length=200,
        description=(
            _TLS_PIN_DESCRIPTION
            + " On this partial-update body, omitting it while setting "
            "tls_mode to 'pinned' reuses the fingerprint already on the "
            "row; there is none to reuse unless the integration was "
            "already pinned, because leaving 'pinned' clears it."
        ),
    )


class PlatformNetworkIntegrationUpdateRequest(NetworkIntegrationUpdateRequest):
    """The Master console's partial update: everything a customer may
    change, plus ``portal_mode``.

    A separate class rather than one more optional field on the shared body,
    because the difference is not cosmetic. ``portal_mode`` decides which of
    two incompatible contracts a venue's guests are put through, and the
    RADIUS one cannot work until somebody has arranged an inbound UDP path,
    a NAS client and a controller certificate. A customer-facing toggle for
    that would be a switch labelled "break guest WiFi until three other
    things happen elsewhere".

    The schema split is the *first* of two guards, not the only one:
    ``service.update_integration`` refuses the field outright when the
    caller is organization-scoped, so a body that somehow reached the
    customer route cannot set it either.
    """

    portal_mode: _PortalMode | None = Field(
        default=None, description=_PORTAL_MODE_DESCRIPTION
    )


class NetworkIntegrationCredentialRotateRequest(_CredentialFields):
    """New credentials for an existing integration.

    ``auth_mode`` is included because rotating credentials is exactly when
    a venue migrates from a legacy operator login to an Open API client --
    forcing that through a separate PATCH would leave a window where the
    stored mode and the stored secret disagree.
    """

    auth_mode: _AuthMode
    # Optional, and unchanged when omitted. Re-entering a password is the
    # moment an operator is most likely to be looking at a controller whose
    # certificate was just replaced along with it.
    tls_mode: _TlsMode | None = Field(
        default=None, description=_TLS_MODE_DESCRIPTION
    )
    tls_pinned_sha256: str | None = Field(
        default=None, max_length=200, description=_TLS_PIN_DESCRIPTION
    )


class NetworkIntegrationResponse(BaseModel):
    id: str
    organization_id: str
    location_id: str | None = None
    # Platform routes only -- resolved by a join, absent on customer routes
    # where the caller already knows which organization they are in.
    organization_name: str | None = None
    location_name: str | None = None
    # The fleet ("router") row that represents this controller, when one
    # exists. Exposed so a client can match an integration to its fleet
    # device directly instead of parsing `routerId=` back out of
    # `portal_url_host_and_query`. NULL for a self-service integration that
    # has no venue yet -- see `PortalReadinessGap.FLEET_DEVICE_MISSING`.
    router_id: uuid.UUID | None = None
    provider: str
    name: str
    status: str
    is_enabled: bool
    base_url: str
    auth_mode: str
    # Which captive-portal contract this venue is on -- see
    # `constants.PortalAuthMode`. Returned on every integration read so an
    # operator (and the Master console) can see which contract a venue is
    # on without inferring it from the portal URL's parameters.
    portal_mode: str
    tls_mode: str
    # Returned, unlike every credential on this row. A certificate
    # fingerprint is a hash of something the controller hands to anyone who
    # connects to it -- showing an operator what their integration is
    # pinned to is the mechanism that makes the pin auditable.
    tls_pinned_sha256: str | None = None
    tls_trust_decided_at: datetime | None = None
    controller_id: str | None = None
    controller_version: str | None = None
    external_site_id: str | None = None
    external_site_name: str | None = None
    guest_ssid_name: str | None = None
    guest_ssid_id: str | None = None
    session_duration_seconds: int
    sync_interval_seconds: int
    last_sync_at: datetime | None = None
    last_sync_status: str
    last_error_code: str | None = None
    last_error_message: str | None = None
    last_error_at: datetime | None = None
    device_count: int = 0
    client_count: int = 0
    active_authorization_count: int = 0
    # NEVER the credentials themselves. See the module docstring.
    has_credentials: bool
    # The External Portal Server URL for this venue, split the way TP-Link's
    # own form splits it -- a `Scheme` field and a `URL` field. See
    # `validators.build_external_portal_url`, which is the only place the
    # shape is decided.
    #
    # Returned to the operator ON PURPOSE, and this is not the same category
    # as `has_credentials: bool` two lines up. A credential is a secret this
    # platform holds on a customer's behalf and may never render; this is a
    # URL that will be in every one of that venue's guests' address bars
    # within minutes of being pasted, and there is no other way for the
    # operator to learn it. Nothing in it is a capability: the three ids are
    # the same three a MikroTik venue's portal URL already carries in plain
    # sight, and every one of them is re-proven against an ACTIVE
    # `GuestSession` at `POST /portal/authorize` before any device reaches a
    # controller.
    #
    # Both are NULL together, and only when the integration cannot serve a
    # guest at all (no mapped location, or no fleet device). A partial URL
    # would be something an operator pastes that turns every guest away;
    # `portal_readiness_gaps` below names the reason instead.
    portal_url_scheme: str | None = None
    portal_url_host_and_query: str | None = None
    # Everything standing between this integration and its first authorized
    # guest, machine-readable, from `validators.portal_readiness_gaps`.
    #
    # On the row rather than only inside `last_error_message`'s sentence
    # because the dashboard has to ACT on it: the portal-configuration block
    # shows a copyable URL or names a blocker, and parsing that decision out
    # of English prose is the coupling this domain's `ErrorCode` enum exists
    # to avoid.
    #
    # An empty list means "nothing missing", which is a stronger and
    # different statement from `status == CONNECTED` -- see
    # `PortalReadinessGap` on the venue that showed a green badge and
    # authorized nobody.
    portal_readiness_gaps: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class NetworkIntegrationListResponse(BaseModel):
    items: list[NetworkIntegrationResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class PlatformNetworkIntegrationListResponse(NetworkIntegrationListResponse):
    """Identical shape to the customer list. Separate class purely so the
    OpenAPI schema names the platform surface distinctly -- the frontend's
    Master console types are generated from it."""


# ============================================================================
# Connection testing / status / sync
# ============================================================================


class TestConnectionRequest(_CredentialFields):
    """Pre-save probe: credentials in the body, nothing persisted.

    This is the connect wizard's "Test Connection" button, pressed before
    an integration row exists. Nothing about this request is written to the
    database -- not the URL, not the credentials, not an event row against
    an integration that does not exist yet. The *audit* entry is still
    written, because a caller reaching out to an arbitrary URL with
    arbitrary credentials from this platform's network is exactly the kind
    of action worth having a record of.
    """

    provider: _Provider = "omada"
    base_url: str = Field(min_length=1, max_length=512)
    auth_mode: _AuthMode = "openapi"
    controller_id: str | None = _controller_id_field()
    tls_mode: _TlsMode = Field(default="strict", description=_TLS_MODE_DESCRIPTION)
    tls_pinned_sha256: str | None = Field(
        default=None, max_length=200, description=_TLS_PIN_DESCRIPTION
    )


class TestConnectionResponse(BaseModel):
    """The probe's answer, plus what the controller's certificate is.

    The TLS block is populated whether the probe succeeded or failed, which
    is deliberate: the failing probe against a self-signed controller is
    exactly when the operator needs the fingerprint, because that is the
    decision the failure is asking them to make. A wizard that only showed
    it on success would require them to switch verification off in order to
    discover that they did not have to.
    """

    ok: bool
    provider: str
    controller_id: str | None = None
    controller_version: str | None = None
    model: str | None = None
    supports_openapi: bool = False
    # Populated on failure. `error_code` is the machine code the frontend
    # maps; `message` is human-safe but the frontend owns the copy.
    error_code: str | None = None
    message: str | None = None
    # The certificate the controller presented on this probe. `None`
    # throughout when the observation could not be made at all -- which is
    # a different thing from "the controller has no certificate" and is
    # reported as absence rather than as a verdict.
    tls_fingerprint_sha256: str | None = None
    #: True when ordinary public-CA verification of this controller
    #: succeeded, i.e. the operator does not need to pin anything.
    tls_chain_trusted: bool | None = None
    #: Whether the observed certificate matches the fingerprint the request
    #: asked to pin. `None` when the request pinned nothing.
    tls_matches_pin: bool | None = None
    tls_certificate_subject: str | None = None
    tls_certificate_issuer: str | None = None
    tls_certificate_expires_at: datetime | None = None


class NetworkIntegrationStatusResponse(BaseModel):
    id: str
    status: str
    is_enabled: bool
    last_sync_at: datetime | None = None
    last_sync_status: str
    last_error_code: str | None = None
    last_error_message: str | None = None
    last_error_at: datetime | None = None
    device_count: int = 0
    client_count: int = 0
    active_authorization_count: int = 0
    consecutive_failure_count: int = 0
    next_sync_due_at: datetime | None = None


class NetworkIntegrationSyncResponse(BaseModel):
    id: str
    status: str
    synced: bool
    device_count: int = 0
    client_count: int = 0
    site_count: int = 0
    error_code: str | None = None
    message: str | None = None


# ============================================================================
# Live controller reads
# ============================================================================


class NetworkIntegrationSiteResponse(BaseModel):
    site_id: str
    name: str
    device_count: int | None = None
    client_count: int | None = None


class NetworkIntegrationSiteListResponse(BaseModel):
    sites: list[NetworkIntegrationSiteResponse]


class NetworkIntegrationSsidResponse(BaseModel):
    ssid_id: str | None = None
    name: str
    portal_enabled: bool | None = None


class NetworkIntegrationSsidListResponse(BaseModel):
    ssids: list[NetworkIntegrationSsidResponse]


# ============================================================================
# Platform draft probe (Master console "Add customer" wizard)
# ============================================================================


class PlatformTestConnectionRequest(TestConnectionRequest):
    """``POST /platform/test-connection``: the org-less pre-save probe.

    The customer probe's body plus one optional field. It exists because the
    Master console onboards a controller in the same wizard that creates the
    customer, so at the device step there is often no organization yet --
    and the customer probe requires one.

    Unlike the customer probe, the credential fields may all be omitted: the
    controller's certificate and unauthenticated identity are then probed on
    the address alone (``credentials_checked: false`` in the response). A
    partial credential is still refused.
    """

    site_id: str | None = Field(
        default=None,
        max_length=128,
        description=(
            "Optional. With Open API credentials, list the SSIDs of this site "
            "(an id from the response's `sites`). When omitted, SSIDs are "
            "listed only if the controller has exactly one site."
        ),
    )


class PlatformTestConnectionResponse(TestConnectionResponse):
    """The customer probe's answer, plus what the wizard needs to prefill.

    Every field inherited from :class:`TestConnectionResponse` means what it
    means there, including the certificate block being populated on failure.
    """

    #: ``"strict"`` when the certificate chains to a public CA (nothing to
    #: pin), ``"pinned"`` when it does not (pin ``tls_fingerprint_sha256``).
    #: ``None`` when no certificate could be observed at all -- there is then
    #: nothing to suggest, and guessing would be a trust decision made for the
    #: operator.
    suggested_tls_mode: Literal["strict", "pinned"] | None = None
    #: False when the request carried no credentials: only the address, the
    #: certificate and the controller's unauthenticated identity were probed,
    #: so ``ok`` says nothing about a password. True when they were used.
    credentials_checked: bool = False
    #: True when ``auth_mode`` is ``"legacy"`` (a hotspot operator login).
    #: That account cannot list sites or SSIDs (runbook §6), so the two lists
    #: below are empty *by construction*, not because the controller has none.
    inventory_requires_openapi: bool = False
    #: True only when ``sites`` was actually read from the controller.
    inventory_available: bool = False
    #: Set when Open API sign-in worked but reading sites/SSIDs did not. The
    #: probe still succeeds -- the connection and the credentials are fine.
    inventory_error_code: str | None = None
    inventory_message: str | None = None
    sites: list[NetworkIntegrationSiteResponse] = Field(default_factory=list)
    #: The site ``ssids`` belongs to -- the request's ``site_id``, or the only
    #: site when there is exactly one. ``None`` means no SSIDs were listed.
    ssids_site_id: str | None = None
    ssids: list[NetworkIntegrationSsidResponse] = Field(default_factory=list)


class NetworkIntegrationDeviceResponse(BaseModel):
    # An access point's own MAC is venue infrastructure, not guest PII --
    # unmasked, exactly as app.domains.monitored_hardware treats a venue's
    # own registered hardware. Contrast the client rows below.
    mac: str
    name: str | None = None
    device_type: str
    model: str | None = None
    status: str
    ip_address: str | None = None
    firmware_version: str | None = None
    uptime_seconds: int | None = None
    client_count: int | None = None


class NetworkIntegrationDeviceListResponse(BaseModel):
    devices: list[NetworkIntegrationDeviceResponse]


class NetworkIntegrationClientResponse(BaseModel):
    mac: MaskedMac
    name: str | None = None
    ip_address: str | None = None
    ssid: str | None = None
    ap_mac: str | None = None
    radio_id: int | None = None
    vlan_id: int | None = None
    is_guest: bool | None = None
    # Three-state, and never collapsed to False when the controller did not
    # say -- see providers/base.py::ProviderClient.
    is_authorized: bool | None = None
    connected_since: datetime | None = None
    duration_seconds: int | None = None
    traffic_down_bytes: int | None = None
    traffic_up_bytes: int | None = None
    signal_dbm: int | None = None


class NetworkIntegrationClientListResponse(BaseModel):
    clients: list[NetworkIntegrationClientResponse]


# ============================================================================
# Events / authorizations
# ============================================================================


class NetworkIntegrationEventResponse(BaseModel):
    id: str
    event_type: str
    status: str
    error_code: str | None = None
    message: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class NetworkIntegrationEventListResponse(BaseModel):
    items: list[NetworkIntegrationEventResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class NetworkIntegrationAuthorizationResponse(BaseModel):
    id: str
    integration_id: str
    client_mac: MaskedMac
    ssid_name: str | None = None
    status: str
    authorized_at: datetime | None = None
    expires_at: datetime | None = None
    deauthorized_at: datetime | None = None
    error_code: str | None = None


# ============================================================================
# Platform summary
# ============================================================================


class PlatformNetworkIntegrationSummaryResponse(BaseModel):
    tenant_count: int
    integration_count: int
    connected_count: int
    error_count: int
    disabled_count: int
    device_count: int
    client_count: int
    active_authorization_count: int
    last_sync_at: datetime | None = None


# ============================================================================
# Portal authorize (public)
# ============================================================================


class PortalAuthorizeRequest(BaseModel):
    """The captive-portal enforcement call.

    ``session_id`` is the ``GuestSession`` the platform itself has just
    issued through ``app.domains.guest``. It is a *claim*, not a
    credential: the server loads it, requires it to be ``ACTIVE``, and
    requires its own ``organization_id``/``location_id`` to match the two
    values below. A caller who supplies a session id belonging to another
    venue gets the same 403 as one who supplies a nonexistent id -- see
    ``exceptions.GuestSessionNotActiveError`` for why the two are
    deliberately indistinguishable in the response.

    The remaining fields are the controller's own portal-redirect query
    parameters, passed through with the vendor's spelling so that nothing
    is invented between the guest's browser and the controller. Both Omada
    redirect shapes are accepted: the EAP/AP path
    (``ap_mac``/``ssid_name``/``radio_id``) and the gateway path
    (``gateway_mac``/``vid``).

    ``client_ip`` (CR-004) is one of those pass-through parameters and is
    the one with a trap in it, so it is spelled out here:

    * **Top level, not nested.** This model takes pydantic's default
      ``extra="ignore"``, so a caller that posts
      ``{"context": {"client_ip": ...}}`` -- or any other nesting -- has
      the value dropped in silence and still gets a 2xx. That is exactly
      how the one shipped cross-repo bug in this integration behaved, and
      it is why the tests assert against the parsed model rather than
      against the JSON a caller believes it sent.
    * **Captured, never derived.** It carries whatever ``clientIp`` the
      controller put on its own redirect. The server must not fill it in
      from ``request.client.host`` or an ``X-Forwarded-For`` hop: this
      endpoint is reached through a proxy and a NAT, so those addresses are
      not the guest's, and authorizing a wrong address means authorizing
      the wrong device or nobody. Absent means absent -- it travels as
      ``None`` and the provider omits the field, which is also precisely
      the right body for a controller older than v6.2.10, where the
      parameter does not exist at all.
    * **It may be stale, and that is accepted deliberately.** The value is
      captured at redirect time; authorization happens after the guest
      finishes OTP, which can be minutes later, so a DHCP lease that
      changed in between makes this a stale address. Sending the captured
      value is still the correct behaviour: the alternative is a derived
      one that is wrong on every proxied request rather than on a rare
      re-lease, and the controller is the component that can tell.

    ``max_length`` is 45 so a full IPv6 form (including an IPv4-mapped
    ``::ffff:255.255.255.255``) fits.
    """

    session_id: str
    organization_id: str
    location_id: str
    provider: _Provider = "omada"
    client_mac: str = Field(min_length=12, max_length=32)
    site: str = Field(min_length=1, max_length=255)
    ap_mac: str | None = Field(default=None, max_length=32)
    ssid_name: str | None = Field(default=None, max_length=255)
    radio_id: int | None = Field(default=None, ge=0, le=16)
    gateway_mac: str | None = Field(default=None, max_length=32)
    vid: int | None = Field(default=None, ge=0, le=4094)
    t: str | None = Field(default=None, max_length=64)
    redirect_url: str | None = Field(default=None, max_length=2048)
    client_ip: str | None = Field(default=None, max_length=45)


class PortalAuthorizeResponse(BaseModel):
    authorized: bool
    provider: str
    expires_at: datetime | None = None
    # Echoed back from the request, unmodified and unvalidated as a
    # destination: this platform never fetches it, it is handed to the
    # guest's own browser to navigate to, and it came from the controller's
    # own redirect in the first place. Treating it as a URL this backend
    # would follow is what would make it an SSRF vector; it is not one.
    redirect_url: str | None = None


class NetworkIntegrationDisconnectGuestRequest(BaseModel):
    """Ask the controller to end one guest's access now.

    Only a MAC. The integration is the path parameter, the venue and the
    organization come from the integration row, and the guest session --
    if there is one -- is looked up from this platform's own
    authorization record rather than accepted from the caller. A request
    body that could name a session id would be a request body that could
    name *someone else's* session id, and nothing here needs it.

    ``client_mac`` is a plain ``str`` on the way in, per this module's
    convention: it is an identifier being supplied, not an identifier
    being disclosed, and it is normalized server-side (a caller may send
    colon, hyphen or bare-hex form).
    """

    client_mac: str = Field(min_length=12, max_length=32)
    # Free text, stored on the guest session and in the audit entry. Not
    # shown to the guest -- see the blocklist-reason work for why guest
    # visibility of a staff-written reason is its own decision.
    reason: str | None = Field(default=None, max_length=255)


class NetworkIntegrationDisconnectGuestResponse(BaseModel):
    """Three facts, not one, because they are three different facts.

    ``disconnected`` is the only one that means the device stopped
    forwarding traffic. ``had_active_authorization`` false alongside it is
    normal: the guest's grant had already lapsed, and the end state the
    caller asked for is the state that now holds. ``guest_session_ended``
    false means the session was already over, not that anything failed.

    A UI showing only "Disconnected" is correct; a UI explaining what
    happened should read all three rather than inferring two from one.

    ``mechanism`` is the fourth fact and the one that says how much the
    other three are worth at this venue -- see
    ``constants.DisconnectMechanism``. On ``controller_client_only``
    (RADIUS mode) the controller dropped the client but nothing stopped the
    guest logging back in, because this platform never issued the
    authorization and holds no row to revoke.
    """

    disconnected: bool
    provider: str
    client_mac: MaskedMac
    had_active_authorization: bool
    deauthorized_at: datetime | None = None
    guest_session_id: str | None = None
    guest_session_ended: bool = False
    mechanism: str = "controller_authorization"


class ControllerRadiusNasRequest(BaseModel):
    """Register this venue's controller as a RADIUS NAS client.

    ``controller_ip`` is the address the controller's Access-Requests will
    *arrive from*, which is not always the address this platform talks to
    it on: a controller behind its venue's NAT is reached on one address
    and egresses from another, and only the egress address can key a
    ``client{}`` stanza. It is therefore accepted explicitly and defaults
    to the host of ``base_url`` only when that host is already a literal
    IP.

    There is no ``shared_secret`` field, and there will not be one. The
    secret is generated by this platform and returned once, in the
    response, for the operator to paste into the controller's RADIUS
    profile. Accepting one would mean a RADIUS shared secret travelling in
    a request body somebody typed.
    """

    controller_ip: str | None = Field(
        default=None,
        max_length=45,
        description=(
            "The public IP the controller's RADIUS Access-Requests arrive "
            "from. Must be a literal, public, global unicast address -- a "
            "hostname is refused because clients.conf resolves one only at "
            "FreeRADIUS start-up. Defaults to the host of the integration's "
            "base_url when that host is itself an IP."
        ),
    )


class ControllerRadiusNasResponse(BaseModel):
    """What was registered, and the one-time secret.

    ``shared_secret`` is returned exactly once, on the call that created or
    rotated it, and is never readable again -- the same contract the
    router-side NAS registration already has. It has to be returned at all
    because the operator types it into the controller's RADIUS profile;
    there is no channel by which this platform could put it there itself.

    ``hub_confirmed`` is what the hub's FreeRADIUS agent answered, not what
    this platform intended. A row that exists with ``hub_confirmed:
    false`` means the database is ahead of the RADIUS server, which is the
    exact divergence that silently rejects every guest at a venue.
    """

    integration_id: str
    nas_identifier: str
    controller_ip: str
    shared_secret: str
    hub_confirmed: bool


# ============================================================================
# "Configure controller automatically"
# ============================================================================


class ControllerConfigureRequest(BaseModel):
    """Body of ``POST /{integration_id}/configure-controller`` (and its
    platform twin).

    ``extra="forbid"``, unlike the rest of this module, and on purpose: this
    endpoint writes to a customer's controller, and the failure mode of a
    permissive parser is a misspelt ``dryRun`` silently becoming a real run.
    A body that is not exactly this shape is a 422. ``dry_run`` has no
    default for the same reason -- the caller says which one it means.

    Nothing here names a site, an SSID, a URL or an operator: every value the
    run writes is derived from the integration row itself.
    """

    model_config = ConfigDict(extra="forbid")

    dry_run: bool
    take_over_ssid_portal: bool = False


class ControllerConfigureStepResponse(BaseModel):
    """One step of the run.

    ``step`` is ``ssid_takeover`` (only when take-over released the SSID from
    another portal), ``portal``, ``pre_auth_access`` or ``hotspot_operator``.
    ``outcome`` is ``created``, ``updated``, ``unchanged``, ``skipped`` or
    ``failed``; on a dry run it is what *would* happen. ``details`` carries
    identifiers and counts (portal id, entries preserved), never a
    credential. ``provider_code`` is the controller's raw error code on a
    failed step, for support.
    """

    step: str
    outcome: Literal["created", "updated", "unchanged", "skipped", "failed"]
    message: str
    provider_code: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ControllerConfigureResponse(BaseModel):
    """The report. ``ok`` is false when any step failed -- the run still
    returns 200 with the envelope's ``success`` false, so the per-step
    reasons reach the screen. Refusals before any write (preconditions, a
    foreign portal on the SSID, a shared site) are 409s with a typed
    ``data.code`` instead."""

    integration_id: str
    dry_run: bool
    ok: bool
    changed: bool
    steps: list[ControllerConfigureStepResponse]
    portal_id: str | None = None
    guest_ssid_id: str | None = None
    portal_url_scheme: str
    portal_url_host_and_query: str
    pre_auth_host: str
