"""The one implementation of "push this NAS client to the real FreeRADIUS
server", shared by the operator-facing registration endpoint and by
``app.domains.hub_reconciliation``.

Extracted from ``router.register_external_radius_nas``, where it had been
inline, for a reason the 2026-08-27 fault makes concrete rather than
stylistic. The ``client{}`` stanza the hub holds is keyed on the router's
WireGuard tunnel address (``radius_agent.add_client`` writes
``ipaddr = <tunnel_ip>/32``), and that address changes -- every hub
re-allocation moves it. Until now the push existed at exactly one call
site, the operator clicking "Generate", so a peer that moved by any other
route left the stanza behind, pointing at an address no device owned. The
symptom is total and silent: FreeRADIUS drops an Access-Request from an
address it has no client for without a reply, and nothing is logged
anywhere.

Making the push callable from the reconciliation pass is what lets the NAS
binding *follow* the peer instead of being a one-time derivation. Keeping
it in one place is what stops the retry/error-reporting behaviour below
from being reimplemented differently in the second caller.

``add_client`` is idempotent on ``nas_identifier`` -- it strips every
stanza with that shortname and writes exactly one -- so re-pushing is
always safe and always converges, whether or not a previous attempt got
part-way.

## Two shapes of NAS, not one address with two names

Everything above describes a **router** NAS: a MikroTik behind a venue's
NAT, reachable only through the WireGuard tunnel, whose stanza is keyed on
a tunnel address this platform allocated and can move.

An Omada controller in RADIUS mode is a different animal and
``push_controller_nas_client`` exists because pretending otherwise would
be a lie in a variable name:

===================  ==============================  ===========================
                     router NAS                      controller NAS
===================  ==============================  ===========================
address              WireGuard tunnel IP             the controller's **public**
                     (``10.20.0.x``), allocated by   address, owned by the venue
                     us                              or its ISP
who can change it    this platform, on a peer         the venue's ISP, with no
                     re-allocation                    notice to anyone
reachability         only from inside the tunnel      the public internet, which
                                                      is why the hub's security
                                                      group is the only thing
                                                      standing in front of it
how it is verified   the peer exists in WireGuard     nothing verifies it; the
                                                      address is asserted
what sends to us     RouterOS, one device             the controller, on behalf
                                                      of every AP at the venue
===================  ==============================  ===========================

All 19 ``client{}`` stanzas captured from the live hub on 2026-08-22 are
tunnel-keyed; not one is a public address. A controller stanza is the first
of its kind on that box, and it is the only one whose source address a
stranger can spoof from the internet the moment UDP 1812 is open --
which is why ``push_controller_nas_client`` refuses anything that is not a
global unicast address, refuses the tunnel range outright, and why the
runbook makes removing the ``0.0.0.0/0`` catch-all client a prerequisite
rather than a cleanup task.

What the two shapes share, deliberately, is the write path and its one
guarantee: **one stanza per shortname**. ``add_client`` strips every stanza
carrying the shortname and writes exactly one, so a controller whose public
address moves converges on a re-push exactly as a router whose tunnel
address moves does, and neither can accumulate a second stanza holding a
still-valid secret.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# RETRY A 5xx, ONCE-PLUS-TWO. Established 2026-08-27 after the failure
# which started all of this proved TRANSIENT, not structural: the same call
# succeeded unchanged when replayed later.
#
# The bridge is a `ThreadingHTTPServer` doing read-modify-write on
# `clients.conf` plus `systemctl restart freeradius`, and a separate 60s
# `wyfy-radius-sync.timer` on the same host runs `systemctl reload
# freeradius`. So there is a recurring window in which a perfectly valid
# request loses a race, systemd returns non-zero, `_validate_and_restart`
# restores the backup and raises, and the caller sees an opaque 500.
# `ops/hub-agents/radius_agent.py` now takes a process-local lock, closing
# the half this codebase owns; the sync timer is outside it.
#
# 5xx ONLY. A 4xx from this bridge is deterministic -- 401 is a secret
# mismatch, 400 a malformed payload -- and retrying it just triples the
# latency before reporting the same thing.
RETRY_DELAYS = (0.5, 2.0)


class RadiusBridgePushError(Exception):
    """The NAS client could not be written to the real RADIUS server.

    Carries the bridge's own explanation, which is frequently the only
    description of the failure that exists anywhere: the agent answers
    every fault as ``{"error": "<str(exception)>"}`` and its
    ``log_message`` writes access lines at DEBUG only, so a discarded
    response body used to leave nothing in either system. Losing that body
    once cost a multi-hour investigation.

    ``transport`` distinguishes "no request/response exchange completed"
    from "the bridge answered and refused" -- the first is worth retrying
    at a higher level, the second is not.
    """

    def __init__(self, detail: str, *, transport: bool, status_code: int | None):
        super().__init__(detail)
        self.detail = detail
        self.transport = transport
        self.status_code = status_code


def bridge_error_detail(resp: httpx.Response) -> str:
    """The hub agent's own explanation of a >=400, in a form safe to put in
    an API error detail. Truncated because ``_validate_and_restart`` embeds
    up to 2000 characters of ``freeradius -CX`` output in it."""
    try:
        body = resp.json()
    except ValueError:
        return (resp.text or "<empty response body>")[:600]
    if isinstance(body, dict) and "error" in body:
        return str(body["error"])[:600]
    return str(body)[:600]


class RadiusClientAddressRejected(ValueError):
    """The address offered for a NAS stanza is not one this platform will
    key a shared secret on. Raised before any request is made."""


# The WireGuard overlay every router NAS lives on. A controller address
# inside it is not a controller address -- it is a copy-paste of a router's,
# and keying a stanza on it would give an internet-facing secret to whatever
# peer currently holds that tunnel IP.
_TUNNEL_NETWORK = ipaddress.ip_network("10.20.0.0/24")


def validate_controller_nas_address(raw: str) -> str:
    """The address a controller stanza may be keyed on, or a refusal.

    Public, global unicast, literal. Each refusal below is a different
    real mistake rather than defensive noise:

    * **a hostname** -- ``clients.conf`` resolves a hostname once, at
      FreeRADIUS start-up, and then never again. A venue on a dynamic
      address would authenticate until the next restart and then stop, with
      the stanza still looking correct in the file. If a venue needs to be
      followed by name, that needs a resolver that re-runs, which is a
      service and not a string.
    * **a private/loopback/link-local/reserved address** -- an Access-Request
      from a venue arrives from its *public* NAT address. A private address
      here is somebody reading the controller's LAN address off its own
      settings page, and the stanza it produces matches nothing, silently:
      FreeRADIUS drops a packet from an unknown client with no reply and no
      log line (the 2026-08-18 incident's root cause #1 in a different
      costume).
    * **anything inside the WireGuard range** -- see ``_TUNNEL_NETWORK``.
    * **a network rather than a host** (``1.2.3.0/24``) -- the hub agent
      writes ``ipaddr = <what we sent>/32``, so a prefix here produces a
      malformed stanza at best and a far wider client than anyone intended
      at worst. Widening the client is exactly the ``0.0.0.0/0`` catch-all
      defect this platform is trying to remove, not add to.
    """
    candidate = (raw or "").strip()
    if not candidate:
        raise RadiusClientAddressRejected("a controller NAS address is required")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise RadiusClientAddressRejected(
            f"{candidate!r} is not a literal IP address. A controller NAS "
            "client must be keyed on the controller's public IP: a hostname "
            "would be resolved once at FreeRADIUS start-up and never again."
        ) from exc
    if address.version == 4 and address in _TUNNEL_NETWORK:
        raise RadiusClientAddressRejected(
            f"{candidate} is inside the WireGuard tunnel range "
            f"({_TUNNEL_NETWORK}); that is a router NAS address, not a "
            "controller's public address"
        )
    if not address.is_global or address.is_multicast:
        raise RadiusClientAddressRejected(
            f"{candidate} is not a public address. A controller reaches this "
            "platform's RADIUS server from its public NAT address; a private "
            "or reserved address here produces a stanza that matches nothing "
            "and fails silently."
        )
    return str(address)


async def push_nas_client(
    *, tunnel_ip: str, nas_identifier: str, secret: str
) -> None:
    """Writes (or rewrites) ``nas_identifier``'s ``client{}`` stanza on the
    real FreeRADIUS server, bound to ``tunnel_ip`` -- **a router NAS**, i.e.
    a device on the WireGuard overlay. For an Omada controller, which has a
    public address and no tunnel, use ``push_controller_nas_client``.

    Returns only when the hub has confirmed the write with a 2xx. Raises
    ``RadiusBridgePushError`` otherwise -- there is no "probably worked"
    return value, because the entire class of bug this module keeps being
    bitten by is an operation reporting success having changed nothing.
    """
    await _push_client_stanza(
        address=tunnel_ip,
        nas_identifier=nas_identifier,
        secret=secret,
        require_message_authenticator=None,
    )


async def push_controller_nas_client(
    *, controller_ip: str, nas_identifier: str, secret: str
) -> str:
    """Writes (or rewrites) a **controller** NAS stanza, keyed on the
    controller's public address. Returns the normalized address written.

    Everything ``push_nas_client`` guarantees holds here too -- one stanza
    per shortname, a 2xx or an exception, never a "probably". What is
    different is spelled out in this module's docstring and enforced in
    two places:

    1. ``validate_controller_nas_address`` refuses anything that is not a
       literal, global unicast host address, **before** any request leaves
       this process. A bad address here does not produce a bad stanza; it
       produces a refusal.
    2. ``require_message_authenticator`` is requested as ``yes``. Every
       Access-Request an Omada controller sends carries a
       Message-Authenticator -- measured on the wire, 2026-09-11, PAP and
       CHAP alike -- so demanding it costs this venue nothing and closes
       BlastRADIUS (CVE-2024-3596) on the one client of ours whose source
       address is reachable from the internet.

    **The hub agent deployed today ignores that second flag**, and this
    function deliberately does not pretend otherwise: it returns the
    address it wrote and says nothing about hardening. ``ops/hub-agents/
    radius_agent.py`` in this repository understands the flag; the hub is
    running an older copy and nobody currently has shell on it (it is
    absent from SSM, its security group allows SSH from two /32s that are
    not ours, and EC2 Instance Connect is unsupported on its Debian 12
    AMI). Until that agent is redeployed the stanza lands with the agent's
    own default, and the runbook says so in those terms rather than
    leaving a reader to infer it from a flag that appears to have been set.
    """
    address = validate_controller_nas_address(controller_ip)
    await _push_client_stanza(
        address=address,
        nas_identifier=nas_identifier,
        secret=secret,
        require_message_authenticator=True,
    )
    return address


async def _push_client_stanza(
    *,
    address: str,
    nas_identifier: str,
    secret: str,
    require_message_authenticator: bool | None,
) -> None:
    """The one HTTP conversation with the hub agent, shared by both shapes.

    ## Why the payload carries the address twice

    The agent running on the hub today reads ``payload["tunnel_ip"]`` and
    nothing else -- a ``KeyError`` and an opaque 500 if it is absent. The
    copy in this repository reads ``address`` and falls back to
    ``tunnel_ip``. Both keys are sent, with the same value, so this call
    works against either version.

    That is a compatibility shim, not a naming opinion: ``tunnel_ip`` is
    the wrong word for a controller's public address and that is the whole
    point of the second key. It can be dropped the day the hub is
    confirmed to be running an agent that reads ``address`` -- which needs
    shell on the hub, which nobody has (see
    ``push_controller_nas_client``).
    """
    settings = get_settings()
    resp: httpx.Response | None = None
    last_transport_error: httpx.HTTPError | None = None

    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    settings.hub_radius_agent_url,
                    headers={
                        "X-Agent-Secret": settings.hub_radius_agent_secret,
                        "Content-Type": "application/json",
                    },
                    json={
                        # Both keys, same value -- see this function's
                        # docstring. `tunnel_ip` is what the deployed agent
                        # reads; `address` is what the agent in this repo
                        # reads and what the word should have been.
                        "tunnel_ip": address,
                        "address": address,
                        "nas_identifier": nas_identifier,
                        "secret": secret,
                    }
                    | (
                        {
                            "require_message_authenticator": (
                                require_message_authenticator
                            )
                        }
                        if require_message_authenticator is not None
                        else {}
                    ),
                )
        except httpx.HTTPError as exc:
            # A transport failure is also worth one more try -- the restart
            # this races with drops connections as well as failing them.
            last_transport_error = exc
            resp = None
        else:
            last_transport_error = None
            if resp.status_code < 500:
                break
        if attempt < len(RETRY_DELAYS):
            logger.warning(
                "radius_bridge_retrying",
                extra={
                    "nas_identifier": nas_identifier,
                    "attempt": attempt + 1,
                    "status_code": None if resp is None else resp.status_code,
                    "detail": (
                        str(last_transport_error)
                        if last_transport_error is not None
                        else bridge_error_detail(resp)
                    ),
                },
            )
            await asyncio.sleep(RETRY_DELAYS[attempt])

    if last_transport_error is not None:
        raise RadiusBridgePushError(
            f"Could not reach the RADIUS server bridge after "
            f"{len(RETRY_DELAYS) + 1} attempts: {last_transport_error!s}",
            transport=True,
            status_code=None,
        ) from last_transport_error

    assert resp is not None  # noqa: S101 -- the only other path raises above
    if resp.status_code >= 400:
        raise RadiusBridgePushError(
            f"The RADIUS server bridge refused this registration "
            f"(HTTP {resp.status_code}): {bridge_error_detail(resp)}",
            transport=False,
            status_code=resp.status_code,
        )


__all__ = [
    "push_nas_client",
    "push_controller_nas_client",
    "validate_controller_nas_address",
    "bridge_error_detail",
    "RadiusBridgePushError",
    "RadiusClientAddressRejected",
    "RETRY_DELAYS",
]
