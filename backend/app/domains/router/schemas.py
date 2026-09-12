"""Pydantic request/response schemas for the Router API.

Follows the same pydantic v2 conventions as ``app.domains.location.schemas``
(``ConfigDict``, ``from_attributes``, explicit ``Field`` descriptions).
``MessageResponse`` is re-exported from the auth domain rather than
duplicated, matching every other domain's own convention.

Credential and SNMP-transport fields (``api_username``/``api_secret``/
``snmp_*``) live on **one** pair of schemas -- ``RouterManagementAccessRequest``
and ``RouterPlatformResponse`` -- and those are served only by the
``/platform/routers/...`` routes, which are gated at ``ScopeType.GLOBAL``.

## Why they are not on the organization-scoped schemas

``routers.read``/``routers.create``/``routers.update`` are held at
**organization** scope by ``organization-owner`` -- the role
``LocationProvisioningService`` assigns to every venue owner it provisions
(``app.domains.rbac.seed``'s ``organization-owner`` has ``default_level=FULL``
and no ``ROUTERS`` override; ``organization-admin``/``msp-*``/``read-only``/
``auditor`` hold subsets of the same). The customer dashboard genuinely reads
``GET /locations/{id}/routers`` for venue liveness, so those three schemas are
customer-reachable by construction.

That made the router's shared secret and the platform's own RouterOS
management credential settable, and its SNMP transport configuration
(on/off, version, UDP port, whether a community is configured) readable, by a
venue owner. Splitting the field off the shape -- rather than remembering not
to populate/accept it -- is the same fix shape ``DELETE /routers/{id}`` already
uses for the same class of bug (see its own ``ScopeType.GLOBAL`` comment in
``router.py``), and the same one the WireGuard domain uses wholesale.

``api_secret``/``snmp_community`` remain write-only even on the platform
schema: the encrypted ciphertext is not something any API response should ever
echo back, encrypted or not.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domains.auth.schemas import MessageResponse

from .enums import RouterStatus
from .vendor_capabilities import SUPPORTED_ROUTER_VENDORS

__all__ = [
    "MessageResponse",
    "RouterResponse",
    "RouterListResponse",
    "RouterPlatformResponse",
    "RouterCreateRequest",
    "RouterVendorChangeRequest",
    "RouterUpdateRequest",
    "RouterManagementAccessRequest",
    "ProvisioningTokenResponse",
    "ProvisioningCheckInRequest",
    "ProvisioningCheckInResponse",
    "HeartbeatRequest",
]

_MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _validate_mac(value: str) -> str:
    normalized = value.strip().upper()
    if not _MAC_PATTERN.match(normalized):
        raise ValueError(
            "MAC address must be in colon-separated hex form, e.g. "
            "'AA:BB:CC:DD:EE:FF'"
        )
    return normalized


# ``api_username``/``api_secret`` are interpolated into a RouterOS console
# script executed over SSH -- see
# ``device_credential_rotator.GatewayDeviceCredentialRotator
# .rotate_password``'s ``/user set [find name="{username}"]
# password="{new_password}"``. RouterOS string literals use ``"`` as a
# delimiter and ``\``/``$`` for escaping/variable-expansion; a strict
# allowlist here is the first of two independent layers guarding this value
# (the second is ``_escape_routeros_string`` in that same module -- defense
# in depth, so a future loosening of this allowlist alone can't reopen the
# injection). Both fields are always either platform-generated
# (``generateApiSecret()``/the fixed ``API_ACCESS_USERNAME`` constant -- see
# ``master.routers.tsx``) or an operator-chosen replacement typed into the
# Master Console, never end-user free text that legitimately needs
# characters outside this set.
_API_CREDENTIAL_PATTERN = re.compile(r"^[A-Za-z0-9_.\-+=@!~]+$")


def _validate_api_credential_charset(value: str) -> str:
    if not _API_CREDENTIAL_PATTERN.match(value):
        raise ValueError(
            "must contain only letters, digits, and the characters "
            "_ . - + = @ ! ~ (no quotes, backslashes, semicolons, "
            "whitespace, or other punctuation)"
        )
    return value


# ``management_ip_address``/``public_ip_address`` end up used as a literal
# ``host`` in an outbound request (the WebFig proxy -- see
# ``router.py``'s ``proxy_webfig_request``: ``upstream_url = f"http://
# {host}/{path}"``), so an unvalidated value here is a request-forgery/
# open-redirect-shaped risk (e.g. embedding a port, path, or credentials
# via a crafted "host" string), not just a data-quality one. A real IP
# address is the overwhelming common case (routers self-report over
# WireGuard/DHCP), but a hostname is accepted too since nothing else in
# this domain assumes one shape or the other.
_HOSTNAME_LABEL_PATTERN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _validate_host_address(value: str) -> str:
    candidate = value.strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    if (
        candidate
        and len(candidate) <= 253
        and all(_HOSTNAME_LABEL_PATTERN.match(label) for label in candidate.split("."))
    ):
        return candidate
    raise ValueError(
        "must be a valid IPv4/IPv6 address or a syntactically valid hostname"
    )


# ============================================================================
# Response schemas
# ============================================================================


class RouterResponse(BaseModel):
    id: str
    location_id: str
    organization_id: str
    name: str
    serial_number: str
    mac_address: str
    model: str
    # Kept on this customer-reachable shape, deliberately, after asking
    # whether an organization-scoped caller should see it at all.
    #
    # The case for removing it: `vendor == "tplink_omada"` is the fact that
    # this venue is on a third-party controller, and the owner's decision is
    # that a venue admin has no business with the controller.
    #
    # The case that won: `vendor` is a statement about the *equipment in the
    # venue*, which its own admin already owns, can see, and in the Omada
    # case was very likely standing next to while somebody installed it. It
    # is not controller configuration -- no hostname, no site, no
    # credential, no identifier -- and this response carries nothing it can
    # be joined to now that `settings.network_integration_id` is redacted
    # (see CUSTOMER_FORBIDDEN_ROUTER_SETTINGS_KEYS below). Withholding it
    # would not withhold the fact either: `status` sits at
    # PENDING_PROVISIONING forever, `last_seen_at` is never set and
    # `has_api_credentials` is false on every controller-managed row, so the
    # shape is legible from the rest of this object regardless.
    #
    # What removing it *would* cost is the honesty this platform spent the
    # vendor-gating work buying. Product decision #2 is that Omada venues
    # legitimately lack QoS/VLAN/DHCP/port-forwarding/content-filtering, and
    # those modules answer 400. The customer dashboard reads this exact
    # field to say so in words -- it derives a "Managed by controller"
    # liveness verdict instead of reporting the row as an offline MikroTik,
    # disables the five inapplicable sidebar entries with a reason, and
    # renders an explanatory notice in place of each blocked page. Take
    # `vendor` away and every one of those degrades to the "reported as a
    # broken MikroTik" failure `app.domains.router.vendor_capabilities`
    # exists to prevent -- a venue that is serving guests perfectly,
    # described to its owner as broken hardware, with the five 400s left
    # unexplained.
    #
    # So: the vendor string stays, and the thing that made it actionable is
    # what leaves.
    vendor: str
    routeros_version: str | None = None
    management_ip_address: str | None = None
    public_ip_address: str | None = None
    status: RouterStatus
    last_seen_at: datetime | None = None
    last_health_check_at: datetime | None = None
    health_status: str | None = None
    has_api_credentials: bool = Field(
        ...,
        description=(
            "Whether the platform holds RouterOS API credentials for this "
            "device. Deliberately kept on this customer-reachable shape "
            "(unlike the snmp_* block, which moved to "
            "RouterPlatformResponse): it is a bare existence flag carrying "
            "no transport detail an attacker could act on, and the "
            "customer-facing network pages share this exact serialization "
            "via routerService.listForLocation()."
        ),
    )
    settings: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Free-form per-router configuration. On an organization-scoped "
            "response every key in CUSTOMER_FORBIDDEN_ROUTER_SETTINGS_KEYS "
            "has been removed -- see redact_customer_router_settings below."
        ),
    )
    # ---- FIX-PLAN D2: one status vocabulary, computed once, here -------
    #
    # Three surfaces gave three different answers about one router in one
    # session -- the venue dashboard from `location-liveness.ts`, Fix a
    # Problem from `connection-verdicts.ts`, the Master fleet from its own
    # local badge map. That was three independent derivations of a fact the
    # console cannot actually see: whether this platform is talking to the
    # controller. One server-computed value makes the contradiction
    # structurally impossible rather than fixed three times over.
    #
    # NULL ON EVERY AGENT-MANAGED ROW, AND THAT IS THE DESIGN. See
    # `vendor_capabilities.ControllerState` -- `Router.reachability_state`
    # is unexposed precisely so the platform never has two answers to "is
    # this router up", and a field carrying a value on an agent-managed row
    # would be that second answer. By EVIDENCE, not by label: a mislabelled
    # MikroTik is agent-managed here too, so this can never contradict a
    # heartbeat.
    controller_state: str | None = Field(
        default=None,
        description=(
            "The state of this platform's connection to the controller "
            "that runs this device's network: one of not_registered, "
            "disabled, credentials_rejected, certificate_unverified, "
            "unreachable, not_mapped, reachable. NULL when this row is not "
            "reached through a controller -- an agent checks in and "
            "status/last_seen_at are the answer. Never a claim about the "
            "venue's access points or a guest's internet."
        ),
    )
    controller_state_reason: str | None = Field(
        default=None,
        description=(
            "Why controller_state holds that value -- a machine-readable "
            "code (an OMADA_* error code, 'site_not_selected', "
            "'no_integration', 'integration_disabled', 'ok'), never prose. "
            "It is what distinguishes a certificate that was never trusted "
            "from one that CHANGED, which share a state because the next "
            "action is the same. The console owns the words."
        ),
    )
    controller_last_contacted_at: datetime | None = Field(
        default=None,
        description=(
            "When a scheduled sync last completed against the controller. "
            "NOT a liveness timestamp for this device and not comparable "
            "with last_seen_at: nothing heartbeats a controller, and a "
            "manual probe deliberately persists nothing, so this is the "
            "only honest answer to 'when did we last reach it'. Render it "
            "as 'Last contacted the controller', never as 'last seen'."
        ),
    )
    vendor_claim_is_contradicted: bool = Field(
        default=False,
        description=(
            "True when this row's vendor says it is controller-managed "
            "while its own data says an agent has run on it -- a "
            "heartbeat, a RouterOS version, a health check, or RouterOS "
            "API credentials on file. Reported beside controller_state "
            "rather than folded into it: this is a statement about the "
            "ROW, every controller_state value is a statement about a "
            "CONTROLLER, and it is also the reason controller_state is "
            "null on a row whose vendor claims otherwise."
        ),
    )

    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


#: Field names that must never appear on a customer-reachable router
#: response. Asserted directly in ``tests/unit/test_router.py`` --
#: re-adding any of them to ``RouterResponse`` fails the suite rather than
#: silently re-opening the disclosure.
CUSTOMER_FORBIDDEN_ROUTER_FIELDS: frozenset[str] = frozenset(
    {
        "api_username",
        "api_secret",
        "api_credentials_encrypted",
        "snmp_enabled",
        "snmp_community",
        "snmp_community_encrypted",
        "has_snmp_community",
        "snmp_version",
        "snmp_port",
    }
)


#: Keys that must never appear inside ``RouterResponse.settings`` on an
#: organization-scoped response.
#:
#: ``CUSTOMER_FORBIDDEN_ROUTER_FIELDS`` above cannot reach these, because
#: they are not *fields*: ``settings`` is a ``dict[str, Any]`` served
#: verbatim from a JSONB column, so a field-name allowlist has nothing to
#: match on. That is how the pair below reached a venue admin.
#:
#: ``network_integration_id`` is the one that matters. It is written by
#: ``network_integration.service.create_fleet_device`` as the back-reference
#: an operator needs when they find a controller row in the fleet table --
#: a reasonable thing to store, and a database key served straight to
#: ``GET /locations/{id}/routers``. It is also the *only* value on this
#: response that can be joined to anything actionable: the controller's
#: hostname, credentials, site mapping and the "configure controller" and
#: "delete" verbs all hang off ``/network-integrations/{id}``. Those routes
#: are GLOBAL-scoped now, so the id alone opens nothing today -- which is
#: exactly the argument that should not be the only thing standing between
#: a venue admin and a controller. Two independent failures are required
#: instead of one.
#:
#: ``synthetic_identity`` is lower severity and removed for honesty rather
#: than for a join: it tells a venue admin that the serial number and MAC
#: their fleet page is showing them were minted by this platform. That is a
#: fact about how the integration is modelled, not about their equipment.
#: (The identifiers themselves stay: ``synthesize_fleet_identity`` derives
#: them through SHA-256, so neither can be turned back into the
#: integration id.)
#:
#: **Inert for MikroTik by construction.** Both keys are written in exactly
#: one place -- the controller-managed fleet row created by
#: ``app.domains.network_integration`` -- and nothing in the product writes
#: either onto an agent-managed row. A MikroTik row's ``settings`` dict
#: contains neither, so the redaction below copies it and removes nothing.
#: ``tests/unit/test_router.py`` asserts that byte-for-byte rather than
#: leaving it to inspection.
CUSTOMER_FORBIDDEN_ROUTER_SETTINGS_KEYS: frozenset[str] = frozenset(
    {
        "network_integration_id",
        "synthetic_identity",
    }
)


def redact_customer_router_settings(
    settings: dict[str, Any] | None,
) -> dict[str, Any]:
    """``settings`` with every controller-identifying key removed.

    A denylist rather than an allowlist, deliberately, and the reasoning is
    the same one ``vendor_capabilities`` gives for its own closed list:
    ``routers.settings`` is an open extension point (captive-portal
    branding overrides, vendor quirk flags -- see ``Router.settings``), and
    an allowlist here would silently start withholding whatever a future
    domain puts in it, from MikroTik venues that have every right to see
    it. Every key named above is written by exactly one caller onto exactly
    the controller-managed rows, so a denylist takes nothing from anyone
    else.

    The tradeoff is stated rather than hidden: a *new* controller-shaped
    key added to a fleet row would leak until it is named above. What
    guards that is ``test_router.py``'s assertion that a fleet row built by
    ``network_integration.service`` carries nothing outside the redacted
    set -- so the seam that would introduce one fails the suite.
    """
    if not settings:
        return {}
    return {
        key: value
        for key, value in settings.items()
        if key not in CUSTOMER_FORBIDDEN_ROUTER_SETTINGS_KEYS
    }


class RouterPlatformResponse(RouterResponse):
    """``RouterResponse`` plus the SNMP transport configuration.

    Served only by ``GET /platform/routers/{router_id}`` and
    ``PUT /platform/routers/{router_id}/management-access``, both gated at
    ``ScopeType.GLOBAL`` -- i.e. only a Master-console (platform-scoped)
    role assignment reaches it, never an organization-scoped one, whatever
    ``X-Organization-Id`` the caller sends.

    ``has_snmp_community`` is still a boolean, never the community string
    itself: the plaintext leaves this codebase only through
    ``RouterService.get_decrypted_snmp_community`` on the polling path.
    """

    snmp_enabled: bool
    has_snmp_community: bool
    snmp_version: str | None = None
    snmp_port: int | None = None


class RouterListResponse(BaseModel):
    items: list[RouterResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class ProvisioningTokenResponse(BaseModel):
    """Returned exactly once, at generation time -- ``token`` (the plaintext
    bearer credential) is never retrievable again afterward."""

    router_id: str
    token: str
    expires_at: datetime


class ProvisioningCheckInResponse(BaseModel):
    """A deliberately minimal, device-facing response shape -- see
    ``docs/router/ROUTER_ARCHITECTURE.md`` §5 for why this endpoint's
    response is not the standard ``ApiResponse`` envelope: the calling
    device is not expected to parse a rich, user-facing API contract, only
    "did the check-in succeed and what should I do next".

    ``agent_credential``/``agent_credential_expires_at`` are an additive
    extension for ``app.domains.router_agent`` (Module 009 Part 2): the
    persistent bearer credential that module's device-facing endpoints
    (heartbeat/config-pull/status-push/action-poll) require, issued exactly
    once, right here -- the one-time provisioning token this check-in call
    just consumed is the device's last opportunity to authenticate itself
    before that credential exists, so there is no separate, later
    "activate" call the device could instead present it to.
    ``agent_credential`` is required: the bootstrap script authenticates
    its very next call (``GET /agent/wireguard-config``) with it. See
    ``app.domains.router_agent.service``'s module docstring for the full
    reasoning.

    ``tunnel_ip_address``/``wireguard_server_public_key``/
    ``wireguard_endpoint_host``/``wireguard_endpoint_port``/
    ``wireguard_hub_tunnel_address`` (Module 009 Part 3, zero-touch
    enrollment) are **required, always-present** fields, exactly like
    ``agent_credential``: the bootstrap script
    (``app.domains.network_config.renderers.render_bootstrap_script``)
    hard-depends on every one of them -- it checks each by name and
    ``:error``s out on the router if any is absent -- and the endpoint now
    provisions (or, on a re-run, rotates -- see
    ``WireGuardService.ensure_tunnel_for_check_in``) the tunnel on every
    successful check-in, so declaring them required makes a platform
    regression fail loudly here, as a clear response-validation error,
    rather than on a customer's router. Everything a thin bootstrap script
    needs to finish bringing up its own WireGuard interface (the tunnel
    address the platform just allocated it, and the hub's own public
    key/reachable endpoint/own tunnel address) is returned right here, in
    the same one round-trip as the agent credential above -- for the
    identical "this is the device's last authenticated moment before the
    one-time token is burned" reason, not a second, later call.
    ``wireguard_hub_tunnel_address`` specifically
    exists so the device's own ``allowed-address=`` can be the hub's real
    tunnel address (a ``/32``), not a fabricated or over-broad range -- see
    ``app.domains.network_config.renderers``'s WireGuard section for why
    that parameter is correctness-critical, not cosmetic, and
    ``_hub_tunnel_address`` there for the identical derivation this
    field's value mirrors."""

    router_id: str
    status: RouterStatus
    agent_credential: str = Field(
        description=(
            "Persistent app.domains.router_agent bearer credential, shown "
            "exactly once -- never retrievable again after this response."
        ),
    )
    agent_credential_expires_at: datetime | None = Field(default=None)
    tunnel_ip_address: str = Field(
        description=(
            "This router's WireGuard tunnel address -- allocated on first "
            "check-in, preserved across re-runs (rotation keeps the IP)."
        ),
    )
    wireguard_server_public_key: str = Field(
        description="The hub's own public key, for the device's peer entry.",
    )
    wireguard_endpoint_host: str = Field(
        description="The hub's reachable endpoint host, e.g. its public IP.",
    )
    wireguard_endpoint_port: int
    wireguard_hub_tunnel_address: str = Field(
        description=(
            "The hub's own tunnel-network address -- the correct, "
            "narrowest legal allowed-address=</32> for this peer's hub "
            "entry (see this class's own docstring)."
        ),
    )


# ============================================================================
# Request schemas
# ============================================================================


class RouterCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    serial_number: str = Field(..., min_length=1, max_length=100)
    mac_address: str = Field(..., min_length=17, max_length=17)
    model: str = Field(..., min_length=1, max_length=100)
    vendor: str = Field(
        default="mikrotik",
        max_length=50,
        description=(
            "Device vendor -- defaults to mikrotik (every device deployed "
            "today is one). See app.domains.router_provisioning.adapters "
            "for how a new vendor plugs into the provisioning workflow."
        ),
    )
    management_ip_address: str | None = Field(default=None, max_length=45)
    public_ip_address: str | None = Field(default=None, max_length=45)
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("mac_address")
    @classmethod
    def validate_mac_address(cls, value: str) -> str:
        return _validate_mac(value)

    @field_validator("management_ip_address", "public_ip_address")
    @classmethod
    def validate_host_address(cls, value: str | None) -> str | None:
        return _validate_host_address(value) if value is not None else value

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Front Desk AP",
                "serial_number": "HB31090ABCD",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "model": "hAP ac2",
            }
        }
    )


class RouterUpdateRequest(BaseModel):
    """``location_id``/``organization_id``/``status`` are deliberately not
    fields on this schema -- location/organization are immutable after
    creation, and status is owned exclusively by the dedicated
    ``suspend``/``reinstate``/``heartbeat``/decommission (``DELETE``)
    endpoints, mirroring ``LocationUpdateRequest``'s own shape."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    serial_number: str | None = Field(default=None, min_length=1, max_length=100)
    mac_address: str | None = Field(default=None, min_length=17, max_length=17)
    model: str | None = Field(default=None, min_length=1, max_length=100)
    # `vendor` IS DELIBERATELY NOT A FIELD HERE ANY MORE.
    #
    # It used to be, with a docstring saying it existed so a vendor could be
    # set "from the Master console". This route is not the Master console:
    # `PUT /routers/{router_id}` is `routers.update` at ORGANIZATION scope,
    # and `organization-owner` -- the role `LocationProvisioningService`
    # assigns to every venue owner it provisions -- holds that permission in
    # full. Any venue owner could relabel their own router's vendor, and
    # under the pure-label predicates that switched off their own device's
    # monitoring. The comment 60 lines down in `router.py` had already
    # spelled out why that scope is customer-reachable; the field simply
    # never got read against it.
    #
    # It now lives on `PUT /platform/routers/{id}/vendor`
    # (`RouterVendorChangeRequest` below), GLOBAL-scoped, requiring a written
    # reason and refusing when the device's own data contradicts the claim --
    # exactly the move `api_username`/`api_secret` made onto
    # `/platform/routers/{id}/management-access` for the identical reason.
    routeros_version: str | None = Field(default=None, max_length=50)
    management_ip_address: str | None = Field(default=None, max_length=45)
    public_ip_address: str | None = Field(default=None, max_length=45)
    settings: dict[str, Any] | None = None

    @field_validator("mac_address")
    @classmethod
    def validate_mac_address(cls, value: str | None) -> str | None:
        return _validate_mac(value) if value is not None else value

    @field_validator("management_ip_address", "public_ip_address")
    @classmethod
    def validate_host_address(cls, value: str | None) -> str | None:
        return _validate_host_address(value) if value is not None else value


class RouterVendorChangeRequest(BaseModel):
    """A deliberate, reasoned, GLOBAL-scoped change to ``routers.vendor``.

    ``vendor`` is the single most consequential column on a fleet row and was
    the least guarded: a free ``String(50)``, editable through an
    organization-scoped ``PUT``, from a bare ``<select>`` whose ``onChange``
    fired the request immediately. It decides whether the alert evaluator
    judges the device, whether the ZTP dashboard shows it, whether the
    readiness checklist runs, and whether seven device domains will talk to
    it at all.

    So this schema asks for three things the old one did not:

    * a ``vendor`` from a closed vocabulary of types the platform actually
      implements -- see :data:`SUPPORTED_ROUTER_VENDORS`;
    * a ``reason``, stored in the audit entry, because the question anyone
      asks about a vendor change afterwards is "why", and nothing recorded
      it;
    * an explicit ``override_contradicting_evidence`` when the device's own
      data says otherwise, so overruling a heartbeat is a thing somebody
      typed rather than a thing that happened.
    """

    vendor: str = Field(
        min_length=1,
        max_length=50,
        description=(
            "The device type to record. Must be one of "
            + ", ".join(SUPPORTED_ROUTER_VENDORS)
            + " -- the types this platform has working machinery for. A "
            "vendor it does not implement is not 'unsupported' in this "
            "column, it is silently treated as an agent-managed MikroTik."
        ),
    )
    reason: str = Field(
        min_length=8,
        max_length=500,
        description=(
            "Why this device's type is being changed. Recorded verbatim in "
            "the ROUTER_UPDATED audit entry alongside the old and new "
            "values. Required: seven production rows were relabelled in "
            "2026-09 and the audit trail could say neither what changed nor "
            "why."
        ),
    )
    override_contradicting_evidence: bool = Field(
        default=False,
        description=(
            "Proceed even though this device has behaved like an "
            "agent-managed device (it has heartbeated, reported a RouterOS "
            "version, or has RouterOS API credentials on file) or carries a "
            "MikroTik model string. Refused without this flag. Never "
            "overrides the network-integration check, which is not evidence "
            "about the device but a live row that depends on this value."
        ),
    )


class RouterManagementAccessRequest(BaseModel):
    """The router's platform-management credentials and SNMP transport
    configuration -- every field the *organization*-scoped create/update
    schemas above deliberately no longer carry.

    Served by ``PUT /platform/routers/{router_id}/management-access``
    (``routers.update`` at ``ScopeType.GLOBAL``). Every field is optional and
    ``exclude_unset`` is honoured by the route, so a caller that sends only
    ``api_secret`` rotates exactly that and leaves the SNMP block untouched.
    """

    api_username: str | None = Field(default=None, min_length=1, max_length=100)
    api_secret: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        description=(
            "RouterOS API password or API key, stored Fernet-encrypted -- "
            "never returned by any endpoint once submitted. Letters, "
            "digits, and _ . - + = @ ! ~ only -- see "
            "app.domains.router.device_credential_rotator for why."
        ),
    )
    snmp_enabled: bool | None = Field(
        default=None,
        description=(
            "Whether this router should be polled via SNMP for richer "
            "device metrics (CPU/memory/uptime/per-interface traffic "
            "counters) in addition to the existing RouterOS-API-based "
            "health check -- see "
            "app.domains.provisioning_engine.service"
            ".run_router_snmp_metrics_poll_sweep. Requires SNMP to "
            "actually be enabled, with a matching community string, on "
            "the physical device itself."
        ),
    )
    snmp_community: str | None = Field(
        default=None,
        description=(
            "SNMP community string (SNMPv1/v2c), stored Fernet-encrypted "
            "-- never returned by any endpoint once submitted. Falls back "
            "to the platform-wide Settings.snmp_default_community when "
            "unset and snmp_enabled is true."
        ),
    )
    snmp_version: str | None = Field(
        default=None,
        max_length=10,
        description=(
            "\"1\" or \"2c\" -- falls back to Settings.snmp_default_version "
            "when unset. SNMPv3 is not supported."
        ),
    )
    snmp_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description=(
            "SNMP agent UDP port -- falls back to "
            "Settings.snmp_default_port (161) when unset."
        ),
    )

    @field_validator("api_username", "api_secret")
    @classmethod
    def validate_api_credential_charset(cls, value: str | None) -> str | None:
        return _validate_api_credential_charset(value) if value is not None else value

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "api_username": "cloudguest-api",
                "api_secret": "s3cr3t",
            }
        }
    )


class ProvisioningCheckInRequest(BaseModel):
    """Presented by the physical device itself, not an authenticated
    platform user -- see ``docs/router/ROUTER_ARCHITECTURE.md`` §5.

    ``wireguard_public_key`` is the **legacy** device-generated-keypair
    enrollment path (Module 009 Part 3's original shape): the device's own
    WireGuard *public* key, generated on-device by the pre-fix bootstrap
    script's own ``/interface wireguard add``. Older rendered scripts still
    in the field may present it, so it stays accepted -- when supplied, the
    device keeps its own keypair and the platform stores only the public
    half (``EXTERNALLY_MANAGED_KEY_SENTINEL``). The current script sends
    only ``token``: the platform generates the pair at check-in and the
    device pulls the private half over HTTPS from
    ``GET /agent/wireguard-config``, authenticated by the just-issued
    ``agent_credential`` -- so no key material ever rides inside the
    pasted, WhatsApp-forwardable script blob in either flow. Either way a
    ``WireGuardPeer`` now exists (or is rotated) on every successful
    check-in -- see ``WireGuardService.ensure_tunnel_for_check_in``."""

    token: str = Field(..., min_length=1)
    wireguard_public_key: str | None = Field(default=None)

    @field_validator("wireguard_public_key", mode="before")
    @classmethod
    def normalize_wireguard_public_key(cls, value: object) -> object:
        """Whitespace-only means "not supplied" -- the platform-generated
        -keypair path, never an externally-managed peer keyed by an empty
        string (see ``WireGuardService.ensure_tunnel_for_check_in``)."""
        if not isinstance(value, str):
            return value
        return value.strip() or None


class HeartbeatRequest(BaseModel):
    routeros_version: str | None = Field(default=None, max_length=50)
    management_ip_address: str | None = Field(default=None, max_length=45)

    @field_validator("management_ip_address")
    @classmethod
    def validate_host_address(cls, value: str | None) -> str | None:
        return _validate_host_address(value) if value is not None else value


class DeviceConnectionResponse(BaseModel):
    """Decrypted device connection info -- see
    ``router.py::get_device_connection``'s own docstring for why this is
    the one endpoint in this domain that returns a plaintext credential
    rather than its encrypted-at-rest form."""

    host: str | None
    username: str | None
    password: str | None


class WebfigSessionResponse(BaseModel):
    """A short-lived, single-router-scoped opaque capability token -- see
    ``router.py``'s ``create_webfig_session`` for why this exists instead
    of just gating the WebFig proxy behind the normal ``Bearer`` auth
    every other endpoint here uses."""

    session_token: str
    expires_in: int


class BootstrapScriptPreviewResponse(BaseModel):
    """Server-rendered Step 1 bootstrap script.

    The one-time provisioning token is embedded in ``script``/``lines`` only
    -- it is minted by this call and never retrievable again afterward.

    ``mode`` echoes which rendering was produced (``onsite`` -- the
    cleanup-first fresh-enrollment paste, the default -- or ``remote`` --
    the validate-first, scheduler-staged live re-provision; see
    ``app.domains.network_config.constants.BootstrapMode``).
    ``revert_window_minutes`` is populated for ``remote`` only: how long
    the on-device automatic revert stays armed before restoring the
    previous tunnel if the cutover never confirms itself.
    """

    router_id: str
    location_code: str
    mode: str
    revert_window_minutes: int | None = None
    lines: list[str]
    script: str
    script_single_line: str = Field(
        description=(
            "The same script joined with ';' instead of newlines -- this is "
            "what a human must paste. RouterOS runs each pasted line as its "
            "own command with its own scope, so a ``:local`` set on one line "
            "is already gone by the next: a multi-line paste makes every "
            "field check fail with 'check-in response missing ...' even "
            "though the platform returned every field (confirmed on a real "
            "RouterOS 7.23.3 device). Joined with ';' the whole script runs "
            "in one scope, and ``:error`` aborts the remainder instead of "
            "letting later lines run against half-built state. Clients copy "
            "THIS field; ``script`` is for on-screen display only."
        ),
    )
    line_count: int
    token_expires_at: datetime


class DeviceInterfaceResponse(BaseModel):
    """One real, currently-available interface on the physical device --
    see ``device_adapters.list_available_device_interfaces``'s own
    docstring for what "available" excludes (already bound to a
    dhcp-server/dhcp-client, or loopback)."""

    name: str
    type: str | None
    running: bool
    disabled: bool
    bridge: str | None
    has_ip_address: bool


class DeviceInterfacesResponse(BaseModel):
    interfaces: list[DeviceInterfaceResponse]
