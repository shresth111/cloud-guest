"""SSRF defence and pure input validation for the Network Integration domain.

The controller URL on a ``network_integrations`` row is typed in by a venue
operator and then handed to a server-side HTTP client that runs inside this
platform's own network. That is the textbook SSRF shape, and it is worse
than the usual one in two specific ways worth stating plainly:

1. **The platform authenticates to whatever answers.** The request carries
   the tenant's own controller credentials. A URL that resolves somewhere
   an attacker controls does not merely fetch a page -- it hands over a
   secret.
2. **The response comes back to the caller.** ``GET
   /{id}/sites``/``/devices``/``/clients`` render what the controller
   returned. An attacker who can steer the request can read the response
   body, which is the difference between blind SSRF and a full read
   primitive against internal HTTP services.

So the rules below are refusals, not warnings, and there is no "allow
anyway" override on a per-integration basis -- only two deployment-wide
settings (``omada_allow_private_controller_urls``, ``omada_require_https``)
which exist for local development and which
``Settings``'s own field docs say so about.

## Validated twice, deliberately

``validate_controller_url`` is called at write time (create/update, and the
pre-save ``POST /test-connection``) *and* again immediately before every
outbound request from ``providers/omada.py``.

That is not belt-and-braces; the second call is the one that matters. The
write-time check resolves the hostname and finds a public address. Nothing
stops the attacker's own DNS server from returning ``169.254.169.254`` on
the *next* lookup -- the classic DNS-rebinding bypass, and with a short TTL
it needs no privileged position at all. A check that happens only at write
time is a check the attacker schedules around.

## What this module cannot enforce, honestly

Two of the shared contract's §6 requirements are not enforceable from
here, because the HTTP client does not live in this repository:

* **"no redirects followed to a different host"** -- that is an ``httpx``
  transport policy set where the request is issued, i.e. in
  ``wyfy_device_gateway.omada``. This module cannot see a redirect.
* **"a hard request timeout"** -- passed *to* the gateway on every call as
  ``ControllerCredentials.timeout_seconds`` (contract §2), so it is
  specified here and applied there.

Both are recorded in ``/Users/shresth/wyfy-omada/CHANGE-REQUESTS.md`` as
gateway-side obligations rather than left as a comment claiming a defence
this file does not implement. Re-resolving before each request closes the
rebinding hole; it does **not** close a redirect to an internal host, and
until the gateway pins that, this is a real residual gap.

## Why ``getaddrinfo`` in a thread

DNS resolution is blocking. ``asyncio.to_thread`` keeps it off the event
loop, matching how the rest of this codebase handles blocking device I/O
(``app.domains.provisioning_engine``'s adapters). Every address the name
resolves to is checked, not just the first: a hostname with both a public
A record and a private one must be refused, and taking ``[0]`` would make
which record the resolver happened to order first into a security control.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import socket
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode, urlsplit

from app.core.config import Settings, get_settings
from app.domains.network_config.renderers import GUEST_PORTAL_HOST

from .constants import (
    DEFAULT_CONTROLLER_PORTS,
    GUEST_OPERATOR_CREDENTIAL_FIELDS,
    MAX_SESSION_DURATION_SECONDS,
    MAX_SYNC_INTERVAL_SECONDS,
    MIN_SESSION_DURATION_SECONDS,
    MIN_SYNC_INTERVAL_SECONDS,
    PORTAL_READINESS_GAP_LABELS,
    ControllerAuthMode,
    ControllerTlsMode,
    PortalReadinessGap,
)
from .crypto import stored_credential_fields
from .exceptions import NetworkIntegrationUrlRejectedError

#: Lowercase hex alphabet, for the fingerprint check. A frozenset rather
#: than a regex because the check is per-character over a 64-character
#: string and the intent reads better.
_HEX_DIGITS: frozenset[str] = frozenset("0123456789abcdef")

__all__ = [
    "CLOUD_METADATA_ADDRESSES",
    "ExternalPortalUrl",
    "build_external_portal_url",
    "ValidatedControllerUrl",
    "allowed_controller_ports",
    "assert_address_is_public",
    "describe_mac_wire_format",
    "describe_portal_readiness_gaps",
    "describe_redirect_shape",
    "normalize_client_mac",
    "normalize_tls_fingerprint",
    "parse_controller_url",
    "portal_readiness_gaps",
    "portal_redirect_timestamp_age_seconds",
    "summarize_redirect_url",
    "synthesize_fleet_identity",
    "validate_auth_mode_credentials",
    "validate_controller_url",
    "validate_session_duration_seconds",
    "validate_sync_interval_seconds",
    "validate_tls_trust",
]


# Cloud instance-metadata endpoints. Named explicitly on top of the
# link-local/reserved rules that already cover them, because these are the
# single highest-value SSRF targets in any cloud deployment (they hand out
# IAM credentials to an unauthenticated HTTP GET) and an explicit rule is
# one that cannot be lost to a future refactor of the range checks. This
# platform runs on AWS ap-south-1 today, hence both the IPv4 IMDS address
# and its IPv6 counterpart.
CLOUD_METADATA_ADDRESSES: frozenset[str] = frozenset(
    {
        "169.254.169.254",
        "fd00:ec2::254",
        # GCP/Azure use the same IPv4 link-local address; Alibaba's
        # 100.100.100.200 is inside the CGNAT range already refused below.
    }
)

_MAC_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")
_MAC_SEPARATORS = re.compile(r"[:-]")


@dataclass(frozen=True, slots=True)
class ValidatedControllerUrl:
    """The result of a successful validation.

    ``base_url`` is the *normalized* form -- lowercased scheme and host,
    explicit port, no trailing slash, no path, no query, no fragment. It is
    what gets persisted and what gets sent to the gateway, so two operators
    typing ``https://Controller.example.com:8043/`` and
    ``https://controller.example.com:8043`` produce one row, not two, and
    the partial unique index on ``(organization_id, provider, base_url,
    external_site_id)`` actually means something.
    """

    base_url: str
    scheme: str
    host: str
    port: int
    resolved_addresses: tuple[str, ...]


def allowed_controller_ports(settings: Settings | None = None) -> frozenset[int]:
    """The port allowlist for this deployment: the built-in set plus
    anything ``Settings.omada_extra_allowed_controller_ports`` adds."""
    app_settings = settings or get_settings()
    return DEFAULT_CONTROLLER_PORTS | frozenset(
        app_settings.omada_extra_allowed_controller_ports
    )


def parse_controller_url(
    raw: str, *, settings: Settings | None = None
) -> tuple[str, str, int]:
    """Every check that needs no network: returns ``(scheme, host, port)``.

    Split out from :func:`validate_controller_url` so the syntactic rules
    are unit-testable without DNS, and so the pre-request re-validation can
    skip straight to the resolution step when nothing about the string has
    changed. Raises :class:`NetworkIntegrationUrlRejectedError` with a
    reason a human can act on.
    """
    app_settings = settings or get_settings()
    candidate = (raw or "").strip()
    if not candidate:
        raise NetworkIntegrationUrlRejectedError("the URL is empty")
    if len(candidate) > 2048:
        raise NetworkIntegrationUrlRejectedError("the URL is unreasonably long")

    # Reject control characters and whitespace outright before parsing.
    # `urlsplit` tolerates several of them, and a URL containing a newline
    # is a request-smuggling attempt against whatever client receives it,
    # not a typo.
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in candidate):
        raise NetworkIntegrationUrlRejectedError(
            "the URL contains whitespace or control characters"
        )

    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if not scheme:
        raise NetworkIntegrationUrlRejectedError(
            "the URL must start with https:// (for example "
            "https://controller.example.com:8043)"
        )

    allowed_schemes = (
        {"https"} if app_settings.omada_require_https else {"https", "http"}
    )
    if scheme not in allowed_schemes:
        if scheme == "http":
            raise NetworkIntegrationUrlRejectedError(
                "plain http is not allowed -- the controller credentials would "
                "cross the network in the clear. Use https://"
            )
        raise NetworkIntegrationUrlRejectedError(
            f"the scheme '{scheme}' is not allowed; use https://"
        )

    # `username@host` in a URL is never a legitimate way to configure a
    # controller, and it is a well-worn trick for making a hostile URL read
    # as a trusted one to a human reviewer.
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise NetworkIntegrationUrlRejectedError(
            "credentials must not be embedded in the URL"
        )

    if parts.path not in ("", "/"):
        raise NetworkIntegrationUrlRejectedError(
            "give the controller's base address only, with no path -- the "
            "controller id is discovered automatically"
        )
    if parts.query or parts.fragment:
        raise NetworkIntegrationUrlRejectedError(
            "the URL must not carry a query string or fragment"
        )

    host = (parts.hostname or "").lower()
    if not host:
        raise NetworkIntegrationUrlRejectedError("the URL names no host")
    if len(host) > 253:
        raise NetworkIntegrationUrlRejectedError("the hostname is too long")

    try:
        port = parts.port
    except ValueError as exc:
        raise NetworkIntegrationUrlRejectedError(
            "the port is not a number"
        ) from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    permitted = allowed_controller_ports(app_settings)
    if port not in permitted:
        raise NetworkIntegrationUrlRejectedError(
            f"port {port} is not in this platform's controller port allowlist "
            f"({', '.join(str(p) for p in sorted(permitted))})"
        )
    return scheme, host, port


def assert_address_is_public(
    address: str, *, allow_private: bool = False
) -> None:
    """Refuse an address that is not a routable public one.

    ``allow_private`` (from ``Settings.omada_allow_private_controller_urls``)
    relaxes the RFC1918/ULA/loopback rules for a developer running a
    controller on their own LAN. It does **not** relax the cloud-metadata
    refusal: there is no development scenario that needs this platform to
    fetch ``169.254.169.254``, and leaving that reachable behind a
    convenience flag is how a staging misconfiguration becomes a credential
    leak.
    """
    if address in CLOUD_METADATA_ADDRESSES:
        raise NetworkIntegrationUrlRejectedError(
            "that address is a cloud instance-metadata endpoint"
        )
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise NetworkIntegrationUrlRejectedError(
            "the host did not resolve to a usable IP address"
        ) from exc

    # Always refused, flag or no flag.
    if ip.is_multicast:
        raise NetworkIntegrationUrlRejectedError(
            "the host resolves to a multicast address"
        )
    if ip.is_unspecified:
        raise NetworkIntegrationUrlRejectedError(
            "the host resolves to an unspecified address"
        )
    if ip.is_reserved:
        raise NetworkIntegrationUrlRejectedError(
            "the host resolves to a reserved address"
        )
    if ip.is_link_local:
        raise NetworkIntegrationUrlRejectedError(
            "the host resolves to a link-local address"
        )
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        # ::ffff:127.0.0.1 is loopback wearing an IPv6 costume. Re-check the
        # embedded address rather than trusting the IPv6 predicates, which
        # report an IPv4-mapped loopback as global.
        assert_address_is_public(str(ip.ipv4_mapped), allow_private=allow_private)
        return
    # 100.64.0.0/10 -- carrier-grade NAT. Not covered by `is_private` on
    # every Python version, and a CGNAT address on a cloud host is
    # somebody else's network.
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    if isinstance(ip, ipaddress.IPv4Address) and ip in cgnat:
        raise NetworkIntegrationUrlRejectedError(
            "the host resolves to a carrier-grade NAT address"
        )

    if allow_private:
        return

    if ip.is_loopback:
        raise NetworkIntegrationUrlRejectedError(
            "the host resolves to a loopback address"
        )
    if ip.is_private:
        raise NetworkIntegrationUrlRejectedError(
            "the host resolves to a private (RFC1918 / IPv6 ULA) address. A "
            "controller must be reachable at a public address, or this "
            "deployment must explicitly allow private controller URLs."
        )
    if not ip.is_global:
        raise NetworkIntegrationUrlRejectedError(
            "the host resolves to a non-routable address"
        )


async def _resolve(host: str, port: int) -> tuple[str, ...]:
    """Every address ``host`` currently resolves to, IPv4 and IPv6.

    A literal IP address short-circuits: ``getaddrinfo`` would happily
    echo it back, but doing the syscall for a value that needs no lookup
    means a hostile literal cannot make the platform emit DNS traffic to a
    resolver of the attacker's choosing.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return (host,)

    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise NetworkIntegrationUrlRejectedError(
            f"the hostname '{host}' could not be resolved"
        ) from exc
    except OSError as exc:  # pragma: no cover -- resolver-level failure
        raise NetworkIntegrationUrlRejectedError(
            f"the hostname '{host}' could not be resolved"
        ) from exc

    addresses = {info[4][0] for info in infos if info[4]}
    if not addresses:
        raise NetworkIntegrationUrlRejectedError(
            f"the hostname '{host}' resolved to no addresses"
        )
    return tuple(sorted(addresses))


async def validate_controller_url(
    raw: str,
    *,
    settings: Settings | None = None,
    resolver=_resolve,
) -> ValidatedControllerUrl:
    """Full validation: syntax, then DNS, then every resolved address.

    ``resolver`` is injectable purely so tests can exercise the address
    rules (including a hostname that resolves to a mix of public and
    private addresses) without depending on real DNS or on the machine's
    own network. Production never passes it.
    """
    app_settings = settings or get_settings()
    scheme, host, port = parse_controller_url(raw, settings=app_settings)
    addresses = await resolver(host, port)
    for address in addresses:
        assert_address_is_public(
            address,
            allow_private=app_settings.omada_allow_private_controller_urls,
        )
    return ValidatedControllerUrl(
        base_url=f"{scheme}://{host}:{port}",
        scheme=scheme,
        host=host,
        port=port,
        resolved_addresses=addresses,
    )


# ============================================================================
# Pure, non-network validation
# ============================================================================


def validate_auth_mode_credentials(
    *,
    auth_mode: ControllerAuthMode,
    client_id: str | None,
    client_secret: str | None,
    username: str | None,
    password: str | None,
) -> dict[str, str]:
    """Return the credential set to encrypt, or raise ``ValueError``.

    Enforces "the fields you supplied must match the mode you chose"
    rather than silently ignoring the pair that does not apply.

    ## Open API takes an operator login too, and has to

    Open API mode used to *refuse* a hotspot operator username/password.
    That made every Open API integration unable to let a single guest
    online: the controller's only external-portal authorization endpoint
    takes an operator login in either mode (the gateway's
    ``authorize_guest`` says so and refuses without one), so the mode the
    dashboard recommended was the one mode that could never serve a venue.

    So the operator pair is optional in Open API mode -- the app alone is
    still a valid row for inventory, and ``portal_readiness_gaps`` names
    ``GUEST_OPERATOR_MISSING`` until the pair is added -- but when it is
    given it must be given whole. Half a login is refused here rather than
    discovered at the first guest.

    Legacy mode is unchanged: an Open API client id/secret there is still a
    mistake, because legacy mode never uses it.
    """
    if auth_mode is ControllerAuthMode.OPENAPI:
        if not client_id or not client_secret:
            raise ValueError(
                "Open API mode requires both client_id and client_secret "
                "(Settings > Platform Integration > Open API on the controller)"
            )
        if bool(username) != bool(password):
            raise ValueError(
                "The hotspot operator account needs both its name and its "
                "password (controller: Hotspot Manager > Operators) -- or "
                "leave both empty and add it later. Guest sign-in cannot "
                "work until it is added."
            )
        credentials = {"client_id": client_id, "client_secret": client_secret}
        if username and password:
            credentials["username"] = username
            credentials["password"] = password
        return credentials

    if not username or not password:
        raise ValueError(
            "Legacy mode requires both the hotspot operator username and password"
        )
    if client_id or client_secret:
        raise ValueError(
            "Legacy mode does not use an Open API client_id/client_secret -- "
            "remove them or switch auth_mode to 'openapi'"
        )
    return {"username": username, "password": password}


def normalize_tls_fingerprint(raw: str | None) -> str | None:
    """Canonicalize a SHA-256 certificate fingerprint, or ``None``.

    Accepts the shapes a human will actually paste -- ``openssl x509
    -fingerprint -sha256`` prints ``AB:CD:...``, browsers print
    space-separated pairs, and an operator copying from the Omada UI gets
    something else again. Refusing a correct fingerprint because it arrived
    with colons would send them looking for a different tool, and in practice
    they would find "switch verification off" first.

    Returns ``None`` both for absent input and for input that is not 64 hex
    characters once separators are stripped. The caller decides which of
    those two is an error, because "no fingerprint" is legitimate in
    ``strict`` and ``insecure`` modes and is a refusal in ``pinned``.

    A fingerprint is a hash of a certificate the controller hands to anybody
    who connects. It is public, safe to store unencrypted, safe to log, and
    safe to return from an API -- unlike everything else on this row that
    concerns the controller.
    """
    if raw is None:
        return None
    candidate = "".join(
        ch for ch in raw.strip().lower() if ch not in {":", " ", "-", "\t"}
    )
    if len(candidate) != 64 or any(ch not in _HEX_DIGITS for ch in candidate):
        return None
    return candidate


def validate_tls_trust(
    *, tls_mode: ControllerTlsMode, tls_pinned_sha256: str | None
) -> tuple[ControllerTlsMode, str | None]:
    """Return the ``(mode, fingerprint)`` pair to persist, or raise.

    Three rules, each of which exists because the alternative stores a row
    that lies about itself:

    * ``pinned`` without a usable fingerprint is refused. An integration that
      claims to pin and pins nothing is worse than one that admits it is
      insecure, because the next person to read the row believes it.
    * ``strict`` and ``insecure`` **clear** any fingerprint rather than
      keeping it. A stored pin that is not consulted is a fact about the past
      presented as a fact about the present; if the operator switches back to
      pinned later they re-confirm the certificate, which is the step that
      made the pin mean anything.
    * Nothing here touches host, port, scheme or address rules. Certificate
      trust and reachability are different questions, and widening the second
      while answering the first is how an SSRF defence quietly erodes. This
      function cannot make any address reachable that was not reachable
      before.

    Raises ``ValueError``; the caller maps it to
    ``NetworkIntegrationTlsPinRequiredError``.
    """
    if tls_mode is not ControllerTlsMode.PINNED:
        return tls_mode, None
    normalized = normalize_tls_fingerprint(tls_pinned_sha256)
    if normalized is None:
        raise ValueError(
            "pinned mode needs the controller certificate's SHA-256 "
            "fingerprint (64 hexadecimal characters). Run Test Connection "
            "against the controller to capture and confirm it."
        )
    return tls_mode, normalized


def validate_session_duration_seconds(value: int) -> int:
    if not MIN_SESSION_DURATION_SECONDS <= value <= MAX_SESSION_DURATION_SECONDS:
        raise ValueError(
            "session_duration_seconds must be between "
            f"{MIN_SESSION_DURATION_SECONDS} and {MAX_SESSION_DURATION_SECONDS}"
        )
    return value


def validate_sync_interval_seconds(value: int) -> int:
    if not MIN_SYNC_INTERVAL_SECONDS <= value <= MAX_SYNC_INTERVAL_SECONDS:
        raise ValueError(
            "sync_interval_seconds must be between "
            f"{MIN_SYNC_INTERVAL_SECONDS} and {MAX_SYNC_INTERVAL_SECONDS}"
        )
    return value


def normalize_client_mac(raw: str) -> str:
    """Canonical uppercase colon-separated form, or ``ValueError``.

    Stored and compared in this one form for the same reason
    ``app.domains.mac_authorization.validators.normalize_mac_address``
    does it: Omada's portal redirect uses dashes
    (``AA-BB-CC-DD-EE-FF``), its API replies sometimes use colons, and a
    table that stores whatever arrived cannot answer "have we already
    authorized this device" at all.

    Note the *wire* form sent back to the controller is not necessarily
    this one -- ``providers/omada.py`` owns whatever spelling the Omada
    API wants, which is exactly the kind of vendor detail that must not
    leak out of the provider layer.
    """
    candidate = (raw or "").strip()
    if not _MAC_PATTERN.match(candidate):
        raise ValueError(
            f"Not a valid MAC address: {candidate!r} (expected six "
            "colon- or dash-separated hex octets)"
        )
    return _MAC_SEPARATORS.sub(":", candidate).upper()


# Marks a fleet serial number as minted by this platform rather than read
# off a device.
#
# Single-provider by construction, and honestly so: this helper takes only
# an integration id, so it cannot vary the prefix by provider. That is a
# deliberate limit, not an oversight -- today exactly one provider needs a
# synthetic identity, and inventing a per-provider prefix scheme for a
# second provider that does not exist yet would be guessing at its
# requirements. When one arrives, this takes a provider argument and this
# constant becomes a lookup; the derivation below does not change.
_SYNTHETIC_SERIAL_PREFIX = "OMADA-"


def synthesize_fleet_identity(integration_id: uuid.UUID) -> tuple[str, str]:
    """A serial number and MAC for a controller that has neither.

    Returns ``(serial_number, mac_address)``.

    ## Why anything is synthesized at all

    ``routers.serial_number`` and ``routers.mac_address`` are both NOT NULL
    and both uniquely indexed -- reasonably, since every row in that table
    until now described a physical box with a serial plate. An Omada
    *software* controller running in a VM has no plate and no NIC of its
    own that means anything to this platform, but it still needs a fleet
    row (contract §11.3). Something has to go in those columns.

    ## The rule that matters: never fabricate a vendor MAC

    The dangerous mistake here would be to generate a plausible-looking
    TP-Link MAC. MAC addresses are the join key for client lookups,
    ``mac_authorization``, DHCP leases and the guest session tables; a
    fabricated address drawn from a real manufacturer's OUI can collide
    with an actual access point somewhere in the fleet, and the resulting
    bug would surface as one venue's guest being authorized against another
    venue's device.

    So the address is drawn from the **locally administered** space: bit 1
    of the first octet set, bit 0 (the multicast bit) clear. IEEE 802
    reserves that space for administrator-assigned addresses and forbids
    any manufacturer from burning one into hardware, which makes a
    collision with real equipment impossible by construction rather than
    unlikely by probability. The ``OMADA-`` serial prefix serves the same
    purpose for a human reading the fleet table: it should be obvious at a
    glance that this identifier was minted, not read off a device.

    ## Why it is derived from the integration id

    Deterministic, so a retried or resumed onboarding computes the same
    pair and collides with its own previous row on the unique index instead
    of quietly creating a second inventory device for one controller.
    Derived from the id rather than random for exactly that reason.

    A hash rather than the raw bytes so that neither column leaks a
    database key into a surface an operator may screenshot or paste into a
    support ticket.
    """
    digest = hashlib.sha256(integration_id.bytes).digest()
    serial = f"{_SYNTHETIC_SERIAL_PREFIX}{digest[:6].hex().upper()}"
    # Set the locally-administered bit, clear the multicast bit, and leave
    # the remaining six bits of the first octet to the digest.
    first_octet = (digest[6] & 0b1111_1100) | 0b10
    mac = ":".join(f"{octet:02X}" for octet in (first_octet, *digest[7:12]))
    return serial, mac


def parse_uuid(value: str, *, field_name: str) -> uuid.UUID:
    """``ValueError`` with a field name, rather than a bare ``badly formed
    hexadecimal UUID string`` the caller cannot attribute to a field."""
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(f"{field_name} is not a valid UUID") from exc


# ============================================================================
# "Configured enough to authorize anybody"
# ============================================================================


def portal_readiness_gaps(
    integration: object, *, settings: Settings | None = None
) -> tuple[PortalReadinessGap, ...]:
    """Everything standing between this integration and its first
    authorized guest, in the order an operator would fix it.

    ## Read this against `service.authorize_portal_client`, not against the
    ## wizard

    Each member of :class:`PortalReadinessGap` is a branch that method
    really takes, and nothing else is included -- see that enum's own
    docstring for why `guest_ssid_id` is absent despite being a step in
    the setup flow. Deriving the list from the *setup screens* instead
    would produce a check that agrees with the UI and disagrees with the
    code, which is the failure this whole idea is meant to catch.

    ## Why a function rather than a column

    Every input is already a column on the row, so a derived
    `is_portal_ready` flag would be a second copy of the same facts, able
    to disagree with them the moment a mapping is edited by anything that
    forgets to recompute it. Computing it on read means a half-configured
    integration cannot look finished.

    Duck-typed on purpose: `ReadinessService` holds whatever its lookup
    Protocol returned, and the sweep holds a real `NetworkIntegration`.
    Neither should have to convert for the other.
    """
    gaps: list[PortalReadinessGap] = []
    ciphertext = getattr(integration, "credentials_encrypted", None)
    if not ciphertext:
        gaps.append(PortalReadinessGap.CREDENTIALS_MISSING)
    elif getattr(integration, "auth_mode", None) == ControllerAuthMode.OPENAPI.value:
        # Names only -- see `stored_credential_fields`. `None` ("cannot
        # tell") adds nothing: an unreadable ciphertext is a key-management
        # fault that `_credentials_for` reports on its own path, and naming
        # a missing operator account over it would send somebody to the
        # controller to create an account that may already be stored.
        fields = stored_credential_fields(ciphertext, settings=settings)
        if fields is not None and not fields >= GUEST_OPERATOR_CREDENTIAL_FIELDS:
            gaps.append(PortalReadinessGap.GUEST_OPERATOR_MISSING)
    if getattr(integration, "location_id", None) is None:
        gaps.append(PortalReadinessGap.LOCATION_NOT_MAPPED)
    if not getattr(integration, "external_site_id", None):
        gaps.append(PortalReadinessGap.SITE_NOT_SELECTED)
    if getattr(integration, "router_id", None) is None:
        # Last, because it is normally the consequence of an earlier gap:
        # the fleet row is registered the moment the integration is mapped
        # to a venue (`ensure_fleet_device`), so on a row created today it
        # only survives LOCATION_NOT_MAPPED. On a row created before the
        # customer path did that, it is fixed with the "Register controller"
        # action (`POST /{id}/fleet-device`).
        gaps.append(PortalReadinessGap.FLEET_DEVICE_MISSING)
    return tuple(gaps)


def describe_portal_readiness_gaps(gaps: Sequence[PortalReadinessGap]) -> str:
    """One sentence naming what is missing and what it costs.

    The cost half is the point. "Site not selected" reads like a setting
    somebody has not got round to; "no guest at this venue can get online"
    is the same fact and the reason it is urgent. An operator who does not
    know the second one has no way to rank this against everything else on
    their screen.
    """
    if not gaps:
        return "This integration is fully configured."
    reasons = [PORTAL_READINESS_GAP_LABELS[gap] for gap in gaps]
    if len(reasons) == 1:
        joined = reasons[0]
    else:
        joined = ", ".join(reasons[:-1]) + " and " + reasons[-1]
    return (
        f"This integration cannot authorize any guest: {joined}. "
        "Until it is finished, guests at this venue complete sign-in and "
        "still have no internet."
    )


# ============================================================================
# The External Portal Server URL an operator pastes into their controller
# ============================================================================

# The host the guest portal SPA is actually served from.
#
# Imported from `network_config.renderers` rather than re-declared, and that
# is deliberate. That constant's own docstring says the value "must stay
# equal to the host in the `location.replace()` those generated login.html
# pages perform, or this function walls in a host no guest is sent to while
# the host they ARE sent to stays blocked" -- and the walled-garden renderer
# is the thing that decides which hosts a pre-auth guest can reach at all.
#
# An Omada venue lands on the SAME host, through the same portal route, as a
# MikroTik venue. If these two ever named different hosts, one of the two
# vendors' guests would be sent somewhere the other vendor's walled garden
# does not permit. A third copy of the string is a third thing to drift, so
# there is one.
_GUEST_PORTAL_HOST = GUEST_PORTAL_HOST

# The route the guest portal SPA is mounted at. The SAME route a MikroTik
# guest lands on -- see `build_external_portal_url`.
_GUEST_PORTAL_PATH = "/portal"


@dataclass(frozen=True, slots=True)
class ExternalPortalUrl:
    """One venue's External Portal Server URL, split the way TP-Link's own
    form splits it.

    `ExternalServerPortalSetting` has three fields, not one: `hostType`
    (`1: IP`, `2: URL`), `serverUrlScheme` (pattern `http|https`) and
    `serverUrl`. Handing an operator a single `https://...` string produces
    a validation error from the controller, because `serverUrl`'s own
    pattern contains no scheme:

        ^(([-a-zA-Z0-9@:%._+~#=]{2,256}\\.[a-z]{2,63})|(<IPv4>))
         ((:<port>)?)(/([-a-zA-Z0-9@:%_+.~#?&//=]*))?$

    Two further things that pattern decides, both checked mechanically
    against the real published regex and both asserted in the tests:

    * `?`, `&` and `=` are inside the PATH character class, so a query
      string is legal -- but only *after* a `/`. `auth.wyfyguest.com/portal
      ?organizationId=...` matches; `auth.wyfyguest.com?organizationId=...`
      is REJECTED. The `/portal` segment is not cosmetic; it is what makes
      the query string reachable at all.
    * `hostType: 1` (IP + port) has no path field whatsoever, so an
      IP-configured portal cannot carry a query string either. Omada venues
      must use `hostType: 2`.
    """

    scheme: str
    """Goes in the controller's own `Scheme` field. Never inside the URL."""

    host_and_query: str
    """Goes in the controller's `URL` field: host, path and query, no
    scheme."""


def build_external_portal_url(
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID | None,
    router_id: uuid.UUID | None,
    provider: str,
) -> ExternalPortalUrl | None:
    """The URL a venue operator pastes into their Omada controller.

    ## It is the MikroTik URL, and that is the whole design

    ``buildPortalUrl()`` in the frontend's ``RouterDetailTabs.tsx`` stamps
    this exact shape into the RouterOS override page at provisioning time.
    An Omada guest now lands on the same route, with the same three ids, and
    sees the same portal -- because the controller **appends** its own
    parameters to a configured query string with ``&``, which was observed
    on real hardware on 2026-09-11 rather than inferred:

        configured: portal.example/omada?locationId=LOC123&orgId=ORG456
        emitted:    ...?locationId=LOC123&orgId=ORG456&clientMac=...&site=...

    An earlier design read TP-Link doc 132060's redirect *template* -- which
    is written as a literal concatenation with a hardcoded ``?`` -- as
    evidence the controller might emit ``...?ours=X?clientMac=...`` and
    silently swallow ``clientMac``. That reading was wrong. The pessimistic
    branch is closed, and with it the only technical reason to give Omada
    guests a different entry point from MikroTik guests.

    ## What is deliberately NOT in the URL

    * ``mac``/``ip`` -- RouterOS's ``$(mac)``/``$(ip)`` substitutions. Omada
      supplies the same facts under its own names (``clientMac``,
      ``clientIp``) by appending them, so putting placeholders here would
      produce two contradictory answers to one question.
    * ``dst``/``link-login-only`` -- RouterOS-only. An Omada venue has no
      NAS login URL to POST to; the equivalent step is
      ``POST /network-integrations/portal/authorize``.
    * ``hspage`` -- RouterOS's own stamp for *which of its five stock
      hotspot pages* redirected the browser here, which
      ``portal-nas-state.ts`` reads as evidence about whether the NAS gate
      is already open. No Omada controller ever served one of those pages,
      so any value here would be a claim about a router that is not in the
      path. That file's three-valued handling exists precisely so that
      *absent* is a legal answer; this leaves it absent.

    ``netProvider`` IS included, and is the one parameter that is ours
    rather than either vendor's. ``/portal/success`` branches on it to
    choose between the controller authorize call and the RouterOS
    ``link-login-only`` form POST. It is stamped here, from the integration
    row, because this is the only place that knows the answer for certain --
    inferring it downstream from "``clientMac`` is present" would put the
    decision in whichever parameter happened to survive the trip.

    ## Returns ``None`` rather than a URL that cannot work

    An integration with no mapped location, or no fleet device, has no
    ``locationId``/``routerId`` to put in the URL -- and
    ``guest_sessions.router_id`` is NOT NULL, so a guest arriving at such a
    link would complete OTP and fail at session creation. Returning a
    partial URL would be handing an operator something to paste that turns
    every guest away. ``portal_readiness_gaps`` names the reason.
    """
    if location_id is None or router_id is None:
        return None
    query = urlencode(
        {
            "organizationId": str(organization_id),
            "locationId": str(location_id),
            "routerId": str(router_id),
            "netProvider": provider,
        }
    )
    return ExternalPortalUrl(
        # The bare word, not `https:`. The controller's own field pattern is
        # literally `http|https`.
        scheme="https",
        host_and_query=f"{_GUEST_PORTAL_HOST}{_GUEST_PORTAL_PATH}?{query}",
    )
# Portal-redirect diagnostics
# ============================================================================
#
# Everything below is pure and answers one question: what could this platform
# have known about a portal redirect *before* it called the controller? It
# exists because the controller's own answer to a failed authorization is
# almost content-free -- Omada collapses a wrong MAC, a stale timestamp, an
# unknown site, an AP that never saw the client and a missing required field
# into a single `-41501 "Failed to authenticate."` (measured against a live
# 6.3.0.100 controller, 2026-09-11). Nothing here can make the controller more
# specific. What it can do is remove candidates from that list using facts we
# held all along, so the residue an engineer has to investigate is smaller.
#
# Every function returns a *description*, never a verdict, and none of them
# refuses anything. A redirect this module finds odd is still authorized: the
# platform has never run against enough Omada firmware revisions to know which
# oddities are faults and which are normal, and a guard built on that guess
# would deny real guests internet in order to enforce a hunch. Describing is
# honest; refusing would not be.


def describe_mac_wire_format(raw: str | None) -> str:
    """Name the spelling of a MAC as it arrived, without normalizing it.

    ``normalize_client_mac`` answers "is this a MAC, and what is its canonical
    form". This answers the different question an engineer diffing a failed
    authorization is actually asking: *in what shape did we hand it to the
    controller*. The portal path sends the redirect's own spelling on the wire
    (``providers/omada.py`` passes ``context.client_mac`` through untouched,
    deliberately -- see that module), while the row this platform stores is
    normalized. So the two can differ, and if Omada is fussy about case or
    separator on some firmware, that difference is the whole bug and is
    invisible in every record we keep today.

    Returns one of ``"colon-upper"``, ``"colon-lower"``, ``"colon-mixed"``,
    ``"hyphen-upper"``, ``"hyphen-lower"``, ``"hyphen-mixed"``, ``"bare"``,
    ``"empty"`` or ``"unrecognised"``. Never raises.
    """
    candidate = (raw or "").strip()
    if not candidate:
        return "empty"
    if _MAC_PATTERN.match(candidate):
        separator = "colon" if ":" in candidate else "hyphen"
        letters = [char for char in candidate if char.isalpha()]
        if not letters:
            # All-digit MAC: the case question does not arise. "upper" would
            # be a claim about evidence that is not there.
            return f"{separator}-nocase"
        if all(char.isupper() for char in letters):
            return f"{separator}-upper"
        if all(char.islower() for char in letters):
            return f"{separator}-lower"
        return f"{separator}-mixed"
    if re.fullmatch(r"[0-9A-Fa-f]{12}", candidate):
        return "bare"
    return "unrecognised"


def portal_redirect_timestamp_age_seconds(
    raw: str | None, *, now: datetime | None = None
) -> float | None:
    """How old the redirect's ``t`` parameter is, in seconds, or ``None``.

    ``None`` means "could not be determined" -- absent, non-numeric, or
    implausible once interpreted -- and is deliberately not 0, which would
    read as "brand new".

    ## The units are inferred, and the inference is stated rather than hidden

    Omada's portal redirect carries ``t`` as an epoch, and this platform has
    never confirmed against hardware whether it is seconds or milliseconds;
    the authorize *body*'s ``time`` field is separately verified to be
    milliseconds, which is suggestive and is not the same field. So the value
    is disambiguated by magnitude: a number large enough to be a millisecond
    epoch of the current era is read as milliseconds, otherwise as seconds.
    That guess is wrong only for a value more than ~1000x out of date, which
    is a broken redirect either way.

    A negative age (a redirect timestamped in the future) is returned as-is
    rather than clamped, because clock skew between the controller and this
    platform is itself a candidate explanation for a failed authorization and
    hiding it would remove the evidence for it.
    """
    candidate = (raw or "").strip()
    if not candidate:
        return None
    try:
        value = int(candidate)
    except ValueError:
        return None
    if value <= 0:
        return None
    # 1e11 seconds is the year 5138; 1e11 milliseconds is 1973. Anything at or
    # above the boundary is therefore milliseconds on any clock this code will
    # ever see, and anything below it is seconds.
    seconds = value / 1000.0 if value >= 100_000_000_000 else float(value)
    reference = (now or datetime.now(UTC)).timestamp()
    return round(reference - seconds, 3)


def summarize_redirect_url(raw: str | None) -> dict[str, object] | None:
    """The shape of the controller's ``redirect_url``, without its values.

    Returns ``{"origin", "path", "query_keys", "length"}``, or ``None`` when
    there is no URL.

    ## Why the query *values* are dropped and the keys are kept

    This is the one field on the portal request that is an arbitrary
    third-party string of unbounded content, and it is the only one that has
    ever plausibly carried a token: it is the address the controller wants the
    guest's browser sent to after sign-in, and venues put session handles,
    voucher codes and analytics identifiers in exactly that position. Nothing
    in ``REDACTED_CONTEXT_KEYS`` would catch one, because the redaction pass
    matches dictionary keys and this arrives as a single opaque string.

    Keeping the keys and dropping the values is what a diff of a failed
    authorization actually needs -- "the controller redirected to a different
    host than last time", "the ``clientMac`` parameter the portal expects is
    missing" -- and it answers those without persisting a value nobody has
    audited into a column the customer dashboard renders.

    ``length`` is kept because a redirect truncated by the 2048-character
    schema bound looks identical to a short one in every other field here.

    Never raises: a URL this cannot parse is described as unparseable rather
    than discarded, since "the controller sent us something that is not a URL"
    is itself a finding.
    """
    candidate = (raw or "").strip()
    if not candidate:
        return None
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return {
            "origin": None,
            "path": None,
            "query_keys": [],
            "length": len(candidate),
        }
    has_origin = bool(parts.scheme or parts.netloc)
    origin = f"{parts.scheme}://{parts.netloc}" if has_origin else None
    query_keys = sorted(
        {key for key, _ in parse_qsl(parts.query, keep_blank_values=True)}
    )
    return {
        "origin": origin,
        "path": parts.path or None,
        "query_keys": query_keys,
        "length": len(candidate),
    }


def describe_redirect_shape(
    *,
    ap_mac: str | None,
    ssid_name: str | None,
    radio_id: int | None,
    gateway_mac: str | None,
    vid: int | None,
) -> str:
    """Which of Omada's two redirect shapes this one is, if either.

    Omada enforces the portal from either an EAP (``apMac`` + ``ssidName`` +
    ``radioId``) or a gateway (``gatewayMac`` + ``vid``), and the authorize
    body is selected by which of those arrived. The two failure modes worth
    naming are the ones the body-builder cannot report on its own:

    * ``"neither"`` -- no device fields at all, so the body goes out with a
      MAC, a time and an auth type and nothing identifying the session the
      controller is meant to match it to. That is a guaranteed ``-41501`` and
      it is decidable here, before the call.
    * ``"ambiguous"`` -- both shapes present. The builder resolves this by
      preferring the gateway fields and silently dropping the AP ones, which
      is a defensible tie-break and is not a fact anyone can see afterwards.

    ``"ap-partial"`` is the third: an AP-shaped redirect missing one of its
    three fields. Not necessarily fatal -- the fields are individually
    optional in the body -- but it is a strong candidate when the controller
    will not say what it disliked.
    """
    has_gateway = gateway_mac is not None or vid is not None
    ap_fields = [ap_mac, ssid_name, radio_id]
    has_ap = any(field is not None for field in ap_fields)
    if has_gateway and has_ap:
        return "ambiguous"
    if has_gateway:
        complete = gateway_mac is not None and vid is not None
        return "gateway" if complete else "gateway-partial"
    if has_ap:
        return "ap" if all(field is not None for field in ap_fields) else "ap-partial"
    return "neither"
