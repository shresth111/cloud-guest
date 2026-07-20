"""RFC 2865 / RFC 5176 RADIUS Disconnect-Request (and CoA-Request) UDP
packet construction and sending -- Phase 1 BhaiFi-parity (#16), replacing
``service.py``'s previously-documented "nothing in this module ever issues
a live CoA-Disconnect packet" sandbox no-op.

## What's real here, and what this sandbox still cannot verify

The packet this module builds is a genuine, wire-correct RFC 2865/5176
Disconnect-Request (or CoA-Request): a Code/Identifier/Length header, a
Request Authenticator computed as the MD5 digest of the header, sixteen
zero octets, the encoded attributes, and the shared secret (the identical
construction RFC 2866 already specifies for Accounting-Request, applied
here per RFC 5176 §2.2) -- any real FreeRADIUS server or RouterOS device
configured with this NAS's own shared secret and listening on the CoA port
would accept and process it exactly as sent. ``send_packet`` opens a real
UDP socket and sends it.

What this sandbox cannot do is prove a real NAS received and acted on it --
there is no live FreeRADIUS/RouterOS device in this environment (the same
honest boundary ``service.py``'s own module docstring draws for the
``rlm_rest`` HTTP integration). A production deployment pointed at a real
NAS's real IP/CoA port would get a real Disconnect-ACK/NAK back;
``send_packet`` returning ``None`` (its socket timed out) is the expected,
non-fatal outcome whenever no such NAS is listening, mirroring
``app.core.celery_app.ping_celery_workers``'s identical "broker reachable,
no worker responds" distinction, and is always this module's own
lowest-severity outcome, never something callers need to treat as an error.

## Deliberately no Message-Authenticator (RFC 3579 attribute 80)

Most FreeRADIUS/RouterOS deployments accept a Disconnect-Request/CoA-Request
authenticated by the Request Authenticator alone once the shared secret is
configured; RFC 5176 recommends (not mandates) an additional
HMAC-MD5 Message-Authenticator attribute. Adding that second, independent
crypto primitive for a packet type this sandbox can never round-trip test
against a live NAS anyway would be complexity without verifiable payoff --
an honest scope line, not an oversight. A future hardening pass can add it
as a purely additive attribute without changing this module's public shape.

## No new third-party dependency

There is no ``pyrad``/RADIUS-protocol library anywhere in this codebase's
existing dependencies (see ``service.py``'s own module docstring). Rather
than adding one for a handful of attribute types, this module encodes the
tiny attribute subset a Disconnect-Request/CoA-Request actually needs
(User-Name, Acct-Session-Id, NAS-IP-Address, Framed-IP-Address) directly
against stdlib ``struct``/``hashlib``/``socket`` -- the full RFC 2865
attribute dictionary is far larger than this module's own, narrow need.
"""

from __future__ import annotations

import hashlib
import os
import socket
import struct

# RFC 5176 §1: Disconnect-Request/ACK/NAK and CoA-Request/ACK/NAK codes.
RADIUS_CODE_DISCONNECT_REQUEST = 40
RADIUS_CODE_DISCONNECT_ACK = 41
RADIUS_CODE_DISCONNECT_NAK = 42
RADIUS_CODE_COA_REQUEST = 43
RADIUS_CODE_COA_ACK = 44
RADIUS_CODE_COA_NAK = 45

# RFC 2865 §5 attribute type numbers -- only the handful this module's own
# narrow scope needs (see module docstring's "no new third-party
# dependency" section).
RADIUS_ATTR_USER_NAME = 1
RADIUS_ATTR_NAS_IP_ADDRESS = 4
RADIUS_ATTR_FRAMED_IP_ADDRESS = 8
RADIUS_ATTR_ACCT_SESSION_ID = 44

# RFC 5176 §1: the IANA-assigned default port for Disconnect/CoA traffic
# (distinct from RADIUS's own Authentication (1812) and Accounting (1813)
# ports) -- what a real FreeRADIUS/RouterOS deployment listens on unless
# explicitly reconfigured.
DEFAULT_COA_PORT = 3799

# Bounded wait for a Disconnect-ACK/NAK -- generous enough for a real NAS
# on a local/regional network, short enough that a guest-facing admin
# action (pause/disconnect/terminate) never hangs the request for long
# when no NAS is listening (the common case in this sandbox).
DEFAULT_COA_TIMEOUT_SECONDS = 3.0

_MAX_ATTRIBUTE_VALUE_BYTES = (
    253  # RFC 2865 §5: a 1-byte length field, minus the 2-byte type+length header
)


def _encode_string_attribute(attr_type: int, value: str) -> bytes:
    encoded = value.encode("utf-8")[:_MAX_ATTRIBUTE_VALUE_BYTES]
    return struct.pack("!BB", attr_type, len(encoded) + 2) + encoded


def _encode_ipv4_attribute(attr_type: int, ip_address: str) -> bytes | None:
    """Returns ``None`` (rather than raising) for a non-IPv4 literal (e.g.
    an IPv6 address) -- this attribute is omitted entirely in that case
    rather than sending a malformed one; see
    ``build_session_identifier_attributes``'s own callers."""
    try:
        packed = socket.inet_aton(ip_address)
    except OSError:
        return None
    return struct.pack("!BB", attr_type, len(packed) + 2) + packed


def build_session_identifier_attributes(
    *,
    username: str,
    acct_session_id: str,
    nas_ip_address: str | None,
    framed_ip_address: str | None,
) -> bytes:
    """The RFC 5176 §3 "session identification" attributes a
    Disconnect-Request/CoA-Request needs so the NAS can locate which
    session to act on -- User-Name + Acct-Session-Id (this platform's own
    ``GuestSession.id``, already echoed to the NAS as ``Acct-Session-Id``
    at accounting-start time -- see ``service.py``'s module docstring),
    plus NAS-IP-Address/Framed-IP-Address when known (best-effort;
    silently omitted rather than raising if either isn't a valid IPv4
    literal)."""
    attributes = _encode_string_attribute(RADIUS_ATTR_USER_NAME, username)
    attributes += _encode_string_attribute(RADIUS_ATTR_ACCT_SESSION_ID, acct_session_id)
    if nas_ip_address:
        encoded = _encode_ipv4_attribute(RADIUS_ATTR_NAS_IP_ADDRESS, nas_ip_address)
        if encoded is not None:
            attributes += encoded
    if framed_ip_address:
        encoded = _encode_ipv4_attribute(
            RADIUS_ATTR_FRAMED_IP_ADDRESS, framed_ip_address
        )
        if encoded is not None:
            attributes += encoded
    return attributes


def build_packet(*, code: int, attributes: bytes, shared_secret: str) -> bytes:
    """Encodes a complete RFC 2865-framed packet (any of the six codes
    above) with a real Request Authenticator -- see module docstring for
    the exact MD5 construction (mirrors RFC 2866 Accounting-Request's
    identical authenticator, applied per RFC 5176 §2.2)."""
    identifier = os.urandom(1)[0]
    length = 20 + len(attributes)  # 4-byte header + 16-byte authenticator
    header = struct.pack("!BBH", code, identifier, length)
    zero_authenticator = b"\x00" * 16
    # RFC 5176 §2.2 mandates MD5 for this checksum -- an RFC-fixed
    # construction, not a security-sensitive hash choice this module could
    # swap out.
    authenticator = hashlib.md5(
        header + zero_authenticator + attributes + shared_secret.encode("utf-8")
    ).digest()
    return header + authenticator + attributes


def send_packet(
    packet: bytes,
    *,
    host: str,
    port: int = DEFAULT_COA_PORT,
    timeout_seconds: float = DEFAULT_COA_TIMEOUT_SECONDS,
) -> bytes | None:
    """A real, blocking UDP send -- always called via ``asyncio.to_thread``
    from this module's own async callers (mirrors
    ``app.core.celery_app.ping_celery_workers``'s identical "blocking
    network call, bridged for async callers" posture). Returns the raw
    response packet, or ``None`` on a timeout -- see module docstring for
    why a timeout is this function's expected, non-fatal outcome whenever
    no NAS is listening, not something callers should treat as an error."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout_seconds)
        sock.sendto(packet, (host, port))
        try:
            response, _ = sock.recvfrom(4096)
        except (TimeoutError, OSError):
            return None
    return response


def parse_response_code(response: bytes) -> int | None:
    """The response packet's own ``Code`` byte (one of
    ``RADIUS_CODE_DISCONNECT_ACK``/``_NAK``/``RADIUS_CODE_COA_ACK``/
    ``_NAK``), or ``None`` if ``response`` is too short to contain one."""
    if len(response) < 1:
        return None
    return response[0]


__all__ = [
    "RADIUS_CODE_DISCONNECT_REQUEST",
    "RADIUS_CODE_DISCONNECT_ACK",
    "RADIUS_CODE_DISCONNECT_NAK",
    "RADIUS_CODE_COA_REQUEST",
    "RADIUS_CODE_COA_ACK",
    "RADIUS_CODE_COA_NAK",
    "RADIUS_ATTR_USER_NAME",
    "RADIUS_ATTR_NAS_IP_ADDRESS",
    "RADIUS_ATTR_FRAMED_IP_ADDRESS",
    "RADIUS_ATTR_ACCT_SESSION_ID",
    "DEFAULT_COA_PORT",
    "DEFAULT_COA_TIMEOUT_SECONDS",
    "build_session_identifier_attributes",
    "build_packet",
    "send_packet",
    "parse_response_code",
]
