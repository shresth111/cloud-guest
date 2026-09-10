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
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.config import Settings, get_settings

from .constants import (
    DEFAULT_CONTROLLER_PORTS,
    MAX_SESSION_DURATION_SECONDS,
    MAX_SYNC_INTERVAL_SECONDS,
    MIN_SESSION_DURATION_SECONDS,
    MIN_SYNC_INTERVAL_SECONDS,
    ControllerAuthMode,
)
from .exceptions import NetworkIntegrationUrlRejectedError

__all__ = [
    "CLOUD_METADATA_ADDRESSES",
    "ValidatedControllerUrl",
    "allowed_controller_ports",
    "assert_address_is_public",
    "normalize_client_mac",
    "parse_controller_url",
    "synthesize_fleet_identity",
    "validate_auth_mode_credentials",
    "validate_controller_url",
    "validate_session_duration_seconds",
    "validate_sync_interval_seconds",
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
    rather than silently ignoring the pair that does not apply. A venue
    operator who picks Open API and fills in the operator username has
    made a mistake that would otherwise surface hours later as
    ``AUTH_FAILED`` with nothing to explain it.
    """
    if auth_mode is ControllerAuthMode.OPENAPI:
        if not client_id or not client_secret:
            raise ValueError(
                "Open API mode requires both client_id and client_secret "
                "(Settings > Platform Integration > Open API on the controller)"
            )
        if username or password:
            raise ValueError(
                "Open API mode does not use an operator username/password -- "
                "remove them or switch auth_mode to 'legacy'"
            )
        return {"client_id": client_id, "client_secret": client_secret}

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
