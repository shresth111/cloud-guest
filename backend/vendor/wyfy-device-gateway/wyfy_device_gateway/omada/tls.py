"""Certificate trust for Omada controllers: strict, pinned, or explicitly off.

## The problem this module exists for

An Omada controller ships a self-signed certificate. Not "sometimes" -- the
software controller this package was first pointed at answers on :8043 with
``CN=localhost``, issuer ``CN=localhost``, and TP-Link has no mechanism that
would make it anything else out of the box. Ordinary verification therefore
fails on essentially every real deployment, which left exactly two outcomes:
the integration cannot be created at all, or certificate checking is switched
off wholesale. Neither is acceptable as the only option, and the second is
what actually happens when it is the only alternative to the first.

Pinning is the third answer, and on this population it is the *right* one. A
self-signed certificate is a perfectly good identity -- it just is not an
identity anyone else vouches for. Recording its SHA-256 and requiring it on
every connection gives a stronger guarantee than public-CA verification would
have: an interceptor needs that exact key, not merely any certificate any CA
will sign for that name.

## Where the pin is actually enforced, and what that does and does not buy

Two places, because neither alone is enough:

1. **A preflight handshake, before the HTTP client is built** --
   :func:`assert_peer_certificate_matches`. This is the one that protects the
   *credentials*: it opens its own TLS connection, reads the certificate, and
   refuses before a single byte of a request -- and therefore before any
   operator password or Open API secret -- is written to the socket.
2. **A per-response check on the real connection** --
   :class:`PinVerifyingTransport`. The preflight and the request are two
   different TCP connections, so the preflight alone proves something about
   the wrong socket. This re-reads the certificate of the connection each
   response actually arrived on, and raises if it is not the pinned one.

The honest residual: (2) runs after the request has been sent, so a
peer that presents the pinned certificate on the preflight connection and a
different one microseconds later on the request connection would receive one
request before being caught. Closing that gap properly needs a hook inside
the TLS handshake that Python's ``ssl`` module does not offer, and the attack
it would prevent requires the attacker to already hold the pinned
certificate's key for the preflight -- at which point (2) is what they fail,
not what they beat. This is written down rather than rounded off because a
pin that is described as stronger than it is is the failure mode worth
avoiding here.

## What this module deliberately does not do

It does not widen what may be dialled. Host and port come from a ``base_url``
the caller has already SSRF-validated (contract section 6); this module
parses that string and connects to that host on that port and nothing else.
Certificate trust and reachability are separate questions and this change
touches only the first.

No dependency on ``cryptography``: this package's dependency list is
deliberately short, and everything here needs is ``ssl`` and ``hashlib``. The
raw DER is handed back to the caller, which is free to parse it with whatever
it already has -- the backend does exactly that to show an operator a subject
and an expiry alongside the fingerprint.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
from urllib.parse import urlsplit

import httpx

from ..controller_contract import ControllerCredentials, ControllerTlsMode
from .errors import (
    OmadaConnectionError,
    OmadaTimeoutError,
    OmadaTlsPinMismatchError,
    OmadaTlsTrustError,
)

logger = logging.getLogger(__name__)

__all__ = [
    "PinVerifyingTransport",
    "assert_peer_certificate_matches",
    "fingerprint_of",
    "is_certificate_verification_failure",
    "normalize_fingerprint",
    "observe_certificate",
    "require_pin",
    "split_host_port",
    "ssl_verify_argument",
]

#: Default ports by scheme, for a ``base_url`` that omitted one. The caller's
#: own validation normally supplies an explicit port; this is the fallback so
#: a missing one is a sensible connection rather than a ``TypeError``.
_DEFAULT_PORTS = {"https": 443, "http": 80}


def fingerprint_of(certificate_der: bytes) -> str:
    """SHA-256 of a DER-encoded certificate, lowercase hex, no separators.

    The whole certificate, not the SubjectPublicKeyInfo. SPKI pinning
    survives a renewal that keeps the key, which sounds like an advantage
    until you notice what it costs here: the operator confirming the pin is
    looking at a fingerprint, and the fingerprint every other tool on their
    machine will show them -- ``openssl x509 -fingerprint -sha256``, a
    browser's certificate viewer, the Omada UI itself -- is the certificate's,
    not the key's. A pin the operator cannot independently verify is a pin
    they will confirm without reading. Certificate pinning is chosen for
    exactly that reason, and the cost is real: reissuing the certificate
    requires re-pinning.
    """
    return hashlib.sha256(certificate_der).hexdigest()


def normalize_fingerprint(raw: str | None) -> str | None:
    """Accept the shapes a human will paste; return one canonical form.

    ``openssl`` prints ``AB:CD:...``; browsers print space-separated pairs;
    the Omada UI prints neither consistently. Rejecting a fingerprint because
    it arrived with colons would send the operator to find a different tool.
    Returns ``None`` for empty input, and ``None`` for anything that is not 64
    hex characters after separators are stripped -- the caller decides whether
    that is a validation error or an absent value.
    """
    if raw is None:
        return None
    candidate = "".join(
        ch for ch in raw.strip().lower() if ch not in {":", " ", "-", "\t"}
    )
    if not candidate:
        return None
    if len(candidate) != 64 or any(ch not in "0123456789abcdef" for ch in candidate):
        return None
    return candidate


def split_host_port(base_url: str) -> tuple[str, int]:
    """``"https://host:8043"`` -> ``("host", 8043)``.

    Used only to open the preflight socket to the address the caller already
    validated. It does not re-derive or re-authorize anything.
    """
    parts = urlsplit(base_url)
    host = parts.hostname
    if not host:
        raise OmadaConnectionError()
    port = parts.port or _DEFAULT_PORTS.get(parts.scheme, 443)
    return host, port


def require_pin(creds: ControllerCredentials) -> str:
    """The pin for ``PINNED`` mode, or a refusal.

    Raising here rather than falling back to ``INSECURE`` is the point. An
    integration that says it is pinned and is not is a lie told to whoever
    reads the row later, and it would be told at exactly the moment the pin
    mattered.
    """
    pin = normalize_fingerprint(creds.tls_pinned_sha256)
    if pin is None:
        raise OmadaTlsPinMismatchError(
            "This integration is set to pin the Omada controller's HTTPS "
            "certificate, but no fingerprint is recorded on it. Run Test "
            "Connection to capture and confirm the controller's certificate."
        )
    return pin


def ssl_verify_argument(creds: ControllerCredentials) -> bool | ssl.SSLContext:
    """What to hand ``httpx``'s ``verify=``.

    ``PINNED`` returns a context with verification off, which looks alarming
    in isolation and is not: OpenSSL is being told not to check the *chain*
    because there is no chain to check, and the certificate's identity is
    checked instead by :func:`assert_peer_certificate_matches` and
    :class:`PinVerifyingTransport`. Leaving chain verification on in this mode
    would simply make pinning unusable for the self-signed controllers it
    exists to serve.
    """
    if creds.tls_mode is ControllerTlsMode.STRICT:
        return True
    if creds.tls_mode is ControllerTlsMode.INSECURE:
        return False
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def is_certificate_verification_failure(exc: BaseException) -> bool:
    """Whether a transport exception is "I did not trust the certificate".

    ``httpx`` reports a failed handshake as a ``ConnectError`` -- the same
    class it reports a refused TCP connection as -- so the distinction has to
    be recovered from the chained cause. ``ssl.SSLCertVerificationError`` is
    the exact and only signal that means *verification* failed, as opposed to
    a protocol error or a reset mid-handshake, both of which really are
    connectivity problems and must keep reporting as such.

    The string check is a second line for a stack that raised a plain
    ``SSLError``; it looks only at OpenSSL's own reason code, never at
    anything a peer supplied.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        if isinstance(current, ssl.SSLError):
            reason = getattr(current, "reason", "") or ""
            if "CERTIFICATE_VERIFY_FAILED" in str(reason).upper():
                return True
        current = current.__cause__ or current.__context__
    return False


async def _handshake_certificate(
    host: str, port: int, *, timeout: float, context: ssl.SSLContext
) -> bytes:
    """One TLS handshake; the peer's DER certificate; nothing sent.

    ``server_hostname`` is passed even for a bare IP literal, which is what a
    self-hosted controller usually is. Python omits SNI in that case rather
    than sending an invalid one, and with ``check_hostname`` off there is
    nothing for it to mismatch against -- verified against a live controller
    on an IP address.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=timeout,
        )
    except TimeoutError as exc:
        raise OmadaTimeoutError() from exc
    except (OSError, ssl.SSLError) as exc:
        if is_certificate_verification_failure(exc):
            raise OmadaTlsTrustError() from exc
        raise OmadaConnectionError() from exc

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:  # pragma: no cover - not reachable over TLS
            raise OmadaConnectionError()
        certificate = ssl_object.getpeercert(binary_form=True)
        if not certificate:  # pragma: no cover - defensive
            raise OmadaConnectionError()
        return bytes(certificate)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            # The certificate is already in hand; a messy close teaches us
            # nothing and must not turn a successful observation into a
            # failure.
            pass


async def observe_certificate(
    creds: ControllerCredentials,
) -> tuple[bytes, bool]:
    """``(DER certificate, would STRICT have worked)``.

    Two handshakes, deliberately. The first is unverified and always
    succeeds if anything is listening, because its job is to obtain the
    certificate an operator is about to be asked to confirm -- including, and
    especially, when that certificate is untrusted. The second asks the
    separate question "is this already fine without pinning", so the wizard
    can tell an operator they do not need to pin at all.

    Two handshakes is the right cost for an operator-initiated probe and the
    wrong cost for a request path, which is why nothing on the request path
    calls this.
    """
    host, port = split_host_port(creds.base_url)
    timeout = creds.timeout_seconds

    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    certificate = await _handshake_certificate(
        host, port, timeout=timeout, context=unverified
    )

    trusted = True
    try:
        await _handshake_certificate(
            host, port, timeout=timeout, context=ssl.create_default_context()
        )
    except OmadaTlsTrustError:
        trusted = False
    except (OmadaConnectionError, OmadaTimeoutError):
        # The unverified handshake worked a moment ago, so this is not a
        # reachability answer -- report "not trusted" rather than inventing
        # either verdict.
        trusted = False

    return certificate, trusted


async def assert_peer_certificate_matches(
    creds: ControllerCredentials, expected_sha256: str
) -> None:
    """Preflight: refuse before any credential is written to a socket.

    See the module docstring for why this exists alongside
    :class:`PinVerifyingTransport` rather than instead of it.
    """
    host, port = split_host_port(creds.base_url)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    certificate = await _handshake_certificate(
        host, port, timeout=creds.timeout_seconds, context=context
    )
    actual = fingerprint_of(certificate)
    if actual != expected_sha256:
        # Both fingerprints are public certificate hashes, so logging them is
        # safe and is the only way an operator finds out what changed.
        logger.warning(
            "omada_tls_pin_mismatch",
            extra={"expected_sha256": expected_sha256, "observed_sha256": actual},
        )
        raise OmadaTlsPinMismatchError()


class PinVerifyingTransport(httpx.AsyncBaseTransport):
    """Wraps a transport and checks the pin on the connection each response
    actually arrived on.

    Wrapping rather than subclassing ``httpx.AsyncHTTPTransport`` so that a
    caller-injected transport -- which is how every test in this package
    removes the network -- is still wrapped and still exercised. A transport
    with no TLS underneath it (``httpx.MockTransport``) exposes no
    ``ssl_object``, and this class then does nothing, which is the correct
    behaviour: there is no certificate to check because there is no TLS.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport, expected_sha256: str) -> None:
        self._inner = inner
        self._expected = expected_sha256

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        stream = response.extensions.get("network_stream")
        ssl_object = (
            stream.get_extra_info("ssl_object") if stream is not None else None
        )
        if ssl_object is None:
            return response
        certificate = ssl_object.getpeercert(binary_form=True)
        if not certificate:  # pragma: no cover - defensive
            return response
        actual = fingerprint_of(bytes(certificate))
        if actual != self._expected:
            logger.warning(
                "omada_tls_pin_mismatch_on_request",
                extra={"expected_sha256": self._expected, "observed_sha256": actual},
            )
            await response.aclose()
            raise OmadaTlsPinMismatchError()
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()
