"""Certificate trust: strict, pinned, insecure -- and the error that says so.

Two things are under test here and they are worth naming separately.

The first is the **classification** defect: a controller that answers, on the
right port, with a certificate nothing vouches for used to be reported as
``OMADA_CONNECTION_FAILED`` -- "check that the controller URL and port are
correct and that the controller is reachable from the server". Every one of
those was already true. The tests below hold the line that a rejected
certificate gets its own code and that an ordinary connection failure still
gets the old one, because the easy way to fix the first is to break the
second.

The second is **pinning**: that a pin is enforced on the connection each
response actually arrived on, that a mode claiming to pin with nothing to pin
to refuses rather than degrading, and that the modes map to the ``httpx``
``verify`` argument they say they do.

Nothing here opens a socket. The handshake-level helpers
(``observe_certificate``, ``assert_peer_certificate_matches``) are exercised
against the live controller separately; what a unit test can prove about them
is their hashing and their comparison, which is what is proven here.
"""

from __future__ import annotations

import hashlib
import ssl
from typing import Any

import httpx
import pytest

from wyfy_device_gateway.controller_contract import (
    ControllerAuthMode,
    ControllerTlsMode,
)
from wyfy_device_gateway.omada.adapter import OmadaControllerAdapter
from wyfy_device_gateway.omada.auth import SessionCache
from wyfy_device_gateway.omada.client import OmadaHttpClient
from wyfy_device_gateway.omada.errors import (
    OmadaConnectionError,
    OmadaTlsPinMismatchError,
    OmadaTlsTrustError,
)
from wyfy_device_gateway.omada import tls

from omada_support import FakeOmadaController, make_creds, no_sleep

#: A certificate body that is not a certificate. Only its hash matters to
#: everything under test, and a real DER blob would add nothing but bytes.
CERT_BYTES = b"not-really-a-certificate"
CERT_SHA256 = hashlib.sha256(CERT_BYTES).hexdigest()
OTHER_BYTES = b"a-different-certificate"
OTHER_SHA256 = hashlib.sha256(OTHER_BYTES).hexdigest()


def _client(controller: FakeOmadaController, **kw: Any) -> OmadaHttpClient:
    return OmadaHttpClient(
        kw.pop("creds", make_creds(ControllerAuthMode.OPENAPI)),
        cache=SessionCache(),
        transport=controller.transport(),
        sleep=no_sleep,
        **kw,
    )


class _FakeSslObject:
    def __init__(self, der: bytes) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = False) -> bytes:
        assert binary_form is True
        return self._der


class _FakeStream:
    """Stands in for httpcore's network stream on a mocked response."""

    def __init__(self, der: bytes | None) -> None:
        self._ssl = None if der is None else _FakeSslObject(der)

    def get_extra_info(self, name: str) -> Any:
        return self._ssl if name == "ssl_object" else None


class _StubTransport(httpx.AsyncBaseTransport):
    def __init__(self, der: bytes | None) -> None:
        self._der = der
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(
            200,
            json={"errorCode": 0, "msg": "Success.", "result": {}},
            extensions={"network_stream": _FakeStream(self._der)},
        )

    async def aclose(self) -> None:  # pragma: no cover - nothing to close
        return None


def _ssl_verification_error() -> httpx.ConnectError:
    """The exception shape ``httpx`` actually produces for a refused cert.

    ``httpx`` wraps every transport failure in ``ConnectError`` -- the same
    class it uses for a refused TCP connection -- and the only thing that
    distinguishes a rejected certificate is the chained ``__cause__``. So the
    fixture chains a real ``ssl.SSLCertVerificationError``, because a test
    that asserted on the message string would pass against a classifier that
    does not look at the chain at all.
    """
    cause = ssl.SSLCertVerificationError(
        1,
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        "self-signed certificate (_ssl.c:1032)",
    )
    error = httpx.ConnectError("certificate verify failed")
    error.__cause__ = cause
    return error


# --- fingerprint handling --------------------------------------------------


def test_normalize_fingerprint_accepts_the_shapes_a_human_will_paste():
    """openssl prints colons; browsers print spaces; both must work.

    Refusing a correct fingerprint over punctuation sends the operator to
    find another tool, and the tool they find first is the checkbox that
    turns verification off.
    """
    colons = ":".join(CERT_SHA256[i : i + 2] for i in range(0, 64, 2)).upper()
    assert tls.normalize_fingerprint(colons) == CERT_SHA256
    assert tls.normalize_fingerprint(CERT_SHA256.upper()) == CERT_SHA256
    assert tls.normalize_fingerprint(f"  {CERT_SHA256}  ") == CERT_SHA256


@pytest.mark.parametrize(
    "bad",
    ["", None, "abc", CERT_SHA256[:-1], CERT_SHA256[:-1] + "z", "0" * 65],
)
def test_normalize_fingerprint_rejects_anything_that_is_not_a_sha256(bad):
    assert tls.normalize_fingerprint(bad) is None


def test_fingerprint_is_the_sha256_of_the_der_bytes():
    assert tls.fingerprint_of(CERT_BYTES) == CERT_SHA256


def test_split_host_port_reads_the_validated_base_url():
    assert tls.split_host_port("https://10.0.0.5:8043") == ("10.0.0.5", 8043)
    assert tls.split_host_port("https://controller.example.com") == (
        "controller.example.com",
        443,
    )


# --- mode -> httpx verify argument -----------------------------------------


def test_strict_mode_asks_httpx_for_ordinary_verification():
    creds = make_creds(tls_mode=ControllerTlsMode.STRICT)
    assert tls.ssl_verify_argument(creds) is True
    assert creds.verify_tls is True


def test_insecure_mode_turns_verification_off_and_says_so():
    creds = make_creds(tls_mode=ControllerTlsMode.INSECURE)
    assert tls.ssl_verify_argument(creds) is False
    assert creds.verify_tls is False


def test_pinned_mode_disables_chain_checking_because_the_pin_is_the_check():
    """A self-signed certificate has no chain to verify; the pin replaces it.

    ``verify_tls`` reads ``False`` here and that is deliberately narrow: it
    means "the chain is not what is being checked", not "nothing is checked".
    """
    creds = make_creds(
        tls_mode=ControllerTlsMode.PINNED, tls_pinned_sha256=CERT_SHA256
    )
    context = tls.ssl_verify_argument(creds)
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode is ssl.CERT_NONE
    assert context.check_hostname is False
    assert creds.verify_tls is False


def test_pinned_without_a_fingerprint_refuses_instead_of_degrading():
    """The whole point. A pin that quietly is not enforced is decoration."""
    creds = make_creds(tls_mode=ControllerTlsMode.PINNED)
    with pytest.raises(OmadaTlsPinMismatchError):
        tls.require_pin(creds)


def test_pinned_with_a_malformed_fingerprint_also_refuses():
    creds = make_creds(
        tls_mode=ControllerTlsMode.PINNED, tls_pinned_sha256="not-a-hash"
    )
    with pytest.raises(OmadaTlsPinMismatchError):
        tls.require_pin(creds)


# --- classifying a transport failure ---------------------------------------


def test_a_chained_certificate_error_is_recognised_as_a_trust_failure():
    assert tls.is_certificate_verification_failure(_ssl_verification_error()) is True


def test_an_ordinary_connect_failure_is_not_a_trust_failure():
    """The regression guard. Widening the TLS classification until every
    connect error matches it would 'fix' the defect by inventing a new one."""
    error = httpx.ConnectError("connection refused")
    error.__cause__ = ConnectionRefusedError(61, "Connection refused")
    assert tls.is_certificate_verification_failure(error) is False


def test_a_bare_transport_error_is_not_a_trust_failure():
    assert tls.is_certificate_verification_failure(httpx.ReadError("reset")) is False


# --- the client's error mapping --------------------------------------------


async def test_a_refused_certificate_reports_tls_untrusted_not_connection_failed():
    """The defect, in one assertion.

    A self-hosted Omada controller answers on the right port with a
    self-signed certificate. Before this, that was ``OMADA_CONNECTION_FAILED``
    and the operator was told to check a URL that was already correct.
    """
    controller = FakeOmadaController()
    controller.fail_times = 99
    controller.failure_exc = _ssl_verification_error()

    async with _client(controller) as client:
        with pytest.raises(OmadaTlsTrustError) as excinfo:
            await client.request("GET", "/api/info", authenticated=False)

    assert excinfo.value.code == "OMADA_TLS_UNTRUSTED"
    message = str(excinfo.value)
    assert "certificate" in message.lower()
    # The old copy sent people to the wrong place. It must not come back.
    assert "url and port are correct" not in message.lower()


async def test_an_unreachable_controller_still_reports_connection_failed():
    """Kept honest in the other direction: not every transport error is TLS."""
    controller = FakeOmadaController()
    controller.fail_times = 99
    refused = httpx.ConnectError("connection refused")
    refused.__cause__ = ConnectionRefusedError(61, "Connection refused")
    controller.failure_exc = refused

    async with _client(controller) as client:
        with pytest.raises(OmadaConnectionError) as excinfo:
            await client.request("GET", "/api/info", authenticated=False)

    assert excinfo.value.code == "OMADA_CONNECTION_FAILED"


# --- pin enforcement on the live connection --------------------------------


async def test_a_matching_pin_lets_the_request_through():
    creds = make_creds(
        tls_mode=ControllerTlsMode.PINNED, tls_pinned_sha256=CERT_SHA256
    )
    transport = _StubTransport(CERT_BYTES)
    client = OmadaHttpClient(
        creds, cache=SessionCache(), transport=transport, sleep=no_sleep
    )
    async with client:
        result = await client.request("GET", "/api/info", authenticated=False)
    assert result is not None
    assert transport.requests


async def test_a_changed_certificate_is_caught_on_the_real_connection():
    """The pin is checked on the connection the response came back on.

    A preflight handshake alone proves something about a different socket.
    This is the half that notices the certificate the request actually met.
    """
    creds = make_creds(
        tls_mode=ControllerTlsMode.PINNED, tls_pinned_sha256=CERT_SHA256
    )
    transport = _StubTransport(OTHER_BYTES)
    client = OmadaHttpClient(
        creds, cache=SessionCache(), transport=transport, sleep=no_sleep
    )
    async with client:
        with pytest.raises(OmadaTlsPinMismatchError) as excinfo:
            await client.request("GET", "/api/info", authenticated=False)

    assert excinfo.value.code == "OMADA_TLS_PIN_MISMATCH"
    assert "intercept" in str(excinfo.value).lower()


async def test_a_connection_with_no_tls_underneath_is_left_alone():
    """``MockTransport`` exposes no certificate; checking one would be
    inventing a fact. Pinning must no-op rather than fail there."""
    creds = make_creds(
        tls_mode=ControllerTlsMode.PINNED, tls_pinned_sha256=CERT_SHA256
    )
    transport = _StubTransport(None)
    client = OmadaHttpClient(
        creds, cache=SessionCache(), transport=transport, sleep=no_sleep
    )
    async with client:
        assert await client.request("GET", "/api/info", authenticated=False) is not None


async def test_strict_mode_does_not_wrap_the_transport_at_all():
    """No pin, no per-response certificate read. Verified by the mode's own
    transport surviving untouched."""
    creds = make_creds(tls_mode=ControllerTlsMode.STRICT)
    transport = _StubTransport(OTHER_BYTES)
    client = OmadaHttpClient(
        creds, cache=SessionCache(), transport=transport, sleep=no_sleep
    )
    async with client:
        # A certificate that matches no pin, and no complaint, because
        # nothing is pinned.
        assert await client.request("GET", "/api/info", authenticated=False) is not None


# --- the adapter's observation ---------------------------------------------


async def test_inspect_tls_reports_the_fingerprint_and_whether_it_matches(monkeypatch):
    async def fake_observe(creds):
        return CERT_BYTES, False

    monkeypatch.setattr(
        "wyfy_device_gateway.omada.adapter.observe_certificate", fake_observe
    )
    adapter = OmadaControllerAdapter()

    unpinned = await adapter.inspect_tls(make_creds())
    assert unpinned.fingerprint_sha256 == CERT_SHA256
    assert unpinned.chain_trusted is False
    # No pin configured is reported as "no opinion", never as a mismatch.
    assert unpinned.matches_pin is None

    matching = await adapter.inspect_tls(
        make_creds(tls_mode=ControllerTlsMode.PINNED, tls_pinned_sha256=CERT_SHA256)
    )
    assert matching.matches_pin is True

    mismatched = await adapter.inspect_tls(
        make_creds(tls_mode=ControllerTlsMode.PINNED, tls_pinned_sha256=OTHER_SHA256)
    )
    assert mismatched.matches_pin is False


async def test_inspect_tls_sends_no_request_at_all(monkeypatch):
    """It exists to be safe to call at an address we do not trust yet.

    An observation that authenticated first would be useless for the only
    situation it is for.
    """
    async def fake_observe(creds):
        return CERT_BYTES, True

    monkeypatch.setattr(
        "wyfy_device_gateway.omada.adapter.observe_certificate", fake_observe
    )
    controller = FakeOmadaController()
    adapter = OmadaControllerAdapter(transport=controller.transport())

    await adapter.inspect_tls(make_creds(ControllerAuthMode.LEGACY))

    assert controller.requests == []


# --- credentials carry the decision ----------------------------------------


def test_the_legacy_copy_keeps_the_trust_decision():
    """``authorize_guest`` rebuilds the credentials in legacy mode. Dropping
    the pin there would silently un-pin the one call that matters most."""
    from wyfy_device_gateway.omada.adapter import _as_legacy

    creds = make_creds(
        ControllerAuthMode.OPENAPI,
        username="op",
        password="pw",
        tls_mode=ControllerTlsMode.PINNED,
        tls_pinned_sha256=CERT_SHA256,
    )
    copied = _as_legacy(creds)
    assert copied.tls_mode is ControllerTlsMode.PINNED
    assert copied.tls_pinned_sha256 == CERT_SHA256
