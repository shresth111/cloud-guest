"""The app-server half of the hotspot certificate push.

Two things are under test and they are proven to different depths.

The **PEM server** is exercised over a real loopback socket with a real HTTP
client, so its four controls -- not routable from the internet, bound to one
peer, single use, short TTL -- are genuinely proven rather than asserted. That
matters more than usual here: for as long as one of these URLs is valid,
whoever reaches it gets the Let's Encrypt private key for the whole guest
fleet.

The **orchestration** is tested against a fake adapter. What a real router
does with the URL is not knowable here; see
``vendor/wyfy-device-gateway/tests/test_mikrotik_hotspot_cert_push.py`` for
the device-side sequence and for the two things that still need one supervised
hardware run.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from wyfy_device_gateway.contract import (
    HotspotCertificatePush,
    HotspotCertificatePushResult,
)

from app.domains.router.ephemeral_pem_server import (
    EphemeralPemServer,
    EphemeralPemServerError,
)
from app.domains.router.hotspot_cert_push import (
    PushTarget,
    certificate_san_names,
    push_certificate_to_routers,
    select_push_targets,
)

LOOPBACK = "127.0.0.1"


# ---------------------------------------------------------------------------
# a tiny HTTP client -- deliberately raw
# ---------------------------------------------------------------------------


async def _get(host: str, port: int, path: str) -> tuple[int, bytes]:
    """One GET, spoken by hand.

    A real client library would normalize the request; RouterOS's ``/tool
    fetch`` is not a real client library, and the point of these tests is what
    the server does with the bytes it actually receives.
    """
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    await writer.drain()
    raw = await reader.read()
    writer.close()
    await writer.wait_closed()
    head, _, body = raw.partition(b"\r\n\r\n")
    status = int(head.split()[1])
    return status, body


# ---------------------------------------------------------------------------
# EphemeralPemServer
# ---------------------------------------------------------------------------


async def test_a_granted_url_serves_the_payload_once():
    async with EphemeralPemServer(bind_host=LOOPBACK) as server:
        url = server.grant(
            b"-----BEGIN PRIVATE KEY-----\n", peer_ip=LOOPBACK, label="r1"
        )
        path = "/" + url.rsplit("/", 1)[1]

        first_status, body = await _get(LOOPBACK, server.port, path)
        second_status, _ = await _get(LOOPBACK, server.port, path)

    assert first_status == 200
    assert body == b"-----BEGIN PRIVATE KEY-----\n"
    # Single use is the whole point: a URL that still works after the router
    # has collected it is a private key lying around in a log.
    assert second_status == 404


async def test_a_grant_for_another_router_is_refused():
    """Every router on the tunnel can reach this listener. Only the one a
    grant was minted for may collect it."""
    async with EphemeralPemServer(bind_host=LOOPBACK) as server:
        url = server.grant(b"secret", peer_ip="10.20.0.99", label="some-other-router")
        path = "/" + url.rsplit("/", 1)[1]

        status, body = await _get(LOOPBACK, server.port, path)

        assert status == 404
        assert b"secret" not in body
        assert any("bound to 10.20.0.99" in r for r in server.rejections)

        # and it is still collectable by the router it belongs to -- a
        # stranger must not be able to burn someone else's grant, or anyone
        # on the tunnel could deny every venue its renewal
        assert len(server._grants) == 1


async def test_an_expired_grant_is_refused():
    async with EphemeralPemServer(bind_host=LOOPBACK, ttl_seconds=0) as server:
        url = server.grant(b"secret", peer_ip=LOOPBACK, label="r1")
        path = "/" + url.rsplit("/", 1)[1]
        await asyncio.sleep(0.01)

        status, body = await _get(LOOPBACK, server.port, path)

    assert status == 404
    assert b"secret" not in body


async def test_an_unknown_token_is_refused():
    async with EphemeralPemServer(bind_host=LOOPBACK) as server:
        server.grant(b"secret", peer_ip=LOOPBACK, label="r1")

        status, body = await _get(LOOPBACK, server.port, "/nope")

    assert status == 404
    assert b"secret" not in body


async def test_path_traversal_and_non_get_are_refused():
    async with EphemeralPemServer(bind_host=LOOPBACK) as server:
        url = server.grant(b"secret", peer_ip=LOOPBACK, label="r1")
        token = url.rsplit("/", 1)[1]

        for path in (f"/../{token}", f"/{token}?x=1", "/"):
            status, body = await _get(LOOPBACK, server.port, path)
            assert status == 404, path
            assert b"secret" not in body

        reader, writer = await asyncio.open_connection(LOOPBACK, server.port)
        writer.write(f"POST /{token} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        raw = await reader.read()
        writer.close()
        await writer.wait_closed()

    assert b"404" in raw
    assert b"secret" not in raw


async def test_grants_die_with_the_server():
    server = EphemeralPemServer(bind_host=LOOPBACK)
    await server.start()
    port = server.port
    server.grant(b"secret", peer_ip=LOOPBACK, label="r1")
    await server.close()

    assert server._grants == {}
    with pytest.raises(OSError):
        await asyncio.open_connection(LOOPBACK, port)


@pytest.mark.parametrize("bind_host", ["0.0.0.0", "::"])
async def test_wildcard_bind_is_refused(bind_host):
    """On the app server a wildcard listener includes the public interface.
    This is the control that keeps the fleet private key off it."""
    with pytest.raises(EphemeralPemServerError) as excinfo:
        await EphemeralPemServer(bind_host=bind_host).start()

    assert "wildcard" in str(excinfo.value)


async def test_hostname_bind_is_refused():
    """What this is reachable from must be readable in the command that
    started it, not dependent on what DNS says at the time."""
    with pytest.raises(EphemeralPemServerError) as excinfo:
        await EphemeralPemServer(bind_host="localhost").start()

    assert "not an IP literal" in str(excinfo.value)


async def test_a_grant_must_name_a_real_peer():
    async with EphemeralPemServer(bind_host=LOOPBACK) as server:
        with pytest.raises(EphemeralPemServerError):
            server.grant(b"secret", peer_ip="not-an-ip", label="r1")


async def test_an_oversized_request_line_is_dropped():
    """A RouterOS fetch request is tiny; nothing legitimate sends 64KB of
    request line."""
    async with EphemeralPemServer(bind_host=LOOPBACK) as server:
        server.grant(b"secret", peer_ip=LOOPBACK, label="r1")

        status, body = await _get(LOOPBACK, server.port, "/" + "a" * 65_536)

    assert status == 404
    assert b"secret" not in body


async def test_tokens_are_unguessable_and_never_repeat():
    async with EphemeralPemServer(bind_host=LOOPBACK) as server:
        tokens = {
            server.grant(b"x", peer_ip=LOOPBACK, label=f"r{i}").rsplit("/", 1)[1]
            for i in range(50)
        }

    assert len(tokens) == 50
    assert all(len(token) >= 40 for token in tokens)


async def test_a_fixed_port_is_honoured():
    """An ephemeral port is right when this runs on the host that holds the
    tunnel address. It does not, today -- it runs in a bridged container, and
    publishing a listener out of one needs a port that is known in advance."""
    import socket

    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        chosen = probe.getsockname()[1]

    async with EphemeralPemServer(bind_host=LOOPBACK, bind_port=chosen) as server:
        assert server.port == chosen
        url = server.grant(b"x", peer_ip=LOOPBACK, label="r1")
        assert url.startswith(f"http://{LOOPBACK}:{chosen}/")


async def test_an_ipv6_bind_address_is_bracketed_in_the_url():
    """``http://::1:41234/tok`` is not a URL. RouterOS would fail to fetch it
    and the failure would look exactly like the one genuinely unproven thing
    in this path -- the router being unable to reach the app server at all."""
    try:
        server = EphemeralPemServer(bind_host="::1")
        await server.start()
    except OSError:
        pytest.skip("no IPv6 loopback on this host")

    try:
        url = server.grant(b"x", peer_ip="::1", label="r1")
        assert url.startswith(f"http://[::1]:{server.port}/")
    finally:
        await server.close()


async def test_port_is_not_readable_before_start():
    with pytest.raises(EphemeralPemServerError):
        _ = EphemeralPemServer(bind_host=LOOPBACK).port


# ---------------------------------------------------------------------------
# SAN extraction
# ---------------------------------------------------------------------------


def _self_signed(names: list[str]) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
    )
    if names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def test_san_names_come_off_the_leaf_only():
    """certbot writes leaf-then-chain. The chain's names are not ours to
    claim, and claiming them would wave through a push onto a router whose
    portal hostname this certificate does not actually cover."""
    leaf_pem, _ = _self_signed(["wifi.wyfyguest.com", "*.portal.wyfyguest.com"])
    intermediate_pem, _ = _self_signed(["intermediate.example"])

    assert certificate_san_names(leaf_pem + intermediate_pem) == (
        "wifi.wyfyguest.com",
        "*.portal.wyfyguest.com",
    )


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------


@dataclass
class _Row:
    name: str
    status: str = "online"
    management_ip_address: str | None = "10.20.0.50"
    api_username: str | None = "wyfy-api"
    api_credentials_encrypted: str | None = "enc:hunter2"


def test_select_push_targets_reports_every_reason_a_router_is_unreachable():
    rows = [
        _Row("good"),
        _Row("sleeping", status="offline"),
        _Row("never-joined", management_ip_address=None),
        _Row("no-credential", api_credentials_encrypted=None),
        _Row("no-username", api_username=None),
        _Row("bad-key"),
    ]

    def _decrypt(ciphertext: str) -> str:
        if ciphertext == "boom":
            raise ValueError("wrong Fernet key")
        return ciphertext.removeprefix("enc:")

    rows[-1].api_credentials_encrypted = "boom"

    targets, skipped = select_push_targets(rows, decrypt=_decrypt)

    assert [t.name for t in targets] == ["good"]
    assert targets[0].secret == "hunter2"
    # Every unreachable router is *reported*. A router silently missing from a
    # renewal is indistinguishable from a fleet that is fully covered.
    assert {s.name for s in skipped} == {
        "sleeping",
        "never-joined",
        "no-credential",
        "no-username",
        "bad-key",
    }
    assert "not reachable" in next(s for s in skipped if s.name == "sleeping").reason
    assert "decrypt" in next(s for s in skipped if s.name == "bad-key").reason


def test_one_undecryptable_credential_does_not_abort_the_fleet():
    def _decrypt(ciphertext: str) -> str:
        if ciphertext == "boom":
            raise ValueError("wrong Fernet key")
        return "ok"

    rows = [_Row("a", api_credentials_encrypted="boom"), _Row("b")]

    targets, skipped = select_push_targets(rows, decrypt=_decrypt)

    assert [t.name for t in targets] == ["b"]
    assert [s.name for s in skipped] == ["a"]


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------


class _FakeAdapter:
    """Stands in for the RouterOS adapter, and -- when ``collect`` is set --
    for the router too: it really performs the GETs the device would.

    The requests come from 127.0.0.1 because that is the only loopback
    address every developer machine and CI box has (macOS assigns no
    127.0.0.2 without an explicit alias, and a test that depends on one is a
    test that passes here and fails there). So a target whose host is
    127.0.0.1 models the router collecting its OWN grant, and a target whose
    host is anything else models a grant being collected from the wrong
    address -- which is exactly the pair worth proving.
    """

    def __init__(self, *, collect: bool = False, fail_for: set[str] | None = None):
        self.calls: list[tuple[str, HotspotCertificatePush]] = []
        self.collected: list[tuple[int, bytes]] = []
        self._collect = collect
        self._fail_for = fail_for or set()

    async def push_hotspot_certificate(
        self, creds: Any, *, push: HotspotCertificatePush
    ) -> HotspotCertificatePushResult:
        self.calls.append((creds.host, push))
        if creds.host in self._fail_for:
            raise RuntimeError("router unreachable")
        if self._collect:
            for url in (push.fullchain_url, push.privkey_url):
                host, port, path = _split(url)
                self.collected.append(await _get(host, port, path))
        return HotspotCertificatePushResult(
            cert_name=push.cert_name,
            hotspot_profile=push.hotspot_profile,
            profile_dns_name="wifi.wyfyguest.com",
            certificates_imported=2,
            private_keys_imported=1,
            bound_ssl_certificate=push.cert_name,
            bound_login_by=push.login_by,
            leaf_has_private_key=True,
            leaf_invalid_after="feb/14/2027 12:00:00",
            chain_issuer_present=True,
            chain_cert_names=(f"{push.cert_name}-chain-1",),
        )


def _split(url: str) -> tuple[str, int, str]:
    rest = url.removeprefix("http://")
    hostport, _, path = rest.partition("/")
    host, _, port = hostport.partition(":")
    return host, int(port), "/" + path


def _targets(*hosts: str) -> list[PushTarget]:
    return [
        PushTarget(name=f"router-{i}", host=host, username="api", secret="s")
        for i, host in enumerate(hosts, start=1)
    ]


async def test_the_router_really_collects_both_pems():
    """The whole loop, over a real socket: mint two grants, let the "router"
    fetch them from its own address, get the actual PEM bytes back."""
    leaf_pem, key_pem = _self_signed(["wifi.wyfyguest.com"])
    adapter = _FakeAdapter(collect=True)

    outcomes = await push_certificate_to_routers(
        _targets(LOOPBACK),
        fullchain_pem=leaf_pem,
        privkey_pem=key_pem,
        bind_host=LOOPBACK,
        adapter=adapter,
    )

    assert [o.ok for o in outcomes] == [True]
    assert adapter.collected == [(200, leaf_pem), (200, key_pem)]


async def test_a_grant_is_useless_from_any_address_but_the_routers_own():
    """Every venue on the tunnel is handed the same private key during a
    fleet renewal, and every venue can reach this listener. Binding each
    grant to its own router's address is what stops one from collecting
    another's -- here the "router" fetches from 127.0.0.1 while its grant was
    minted for 10.20.0.50, and gets nothing."""
    leaf_pem, key_pem = _self_signed(["wifi.wyfyguest.com"])
    adapter = _FakeAdapter(collect=True)

    outcomes = await push_certificate_to_routers(
        _targets("10.20.0.50"),
        fullchain_pem=leaf_pem,
        privkey_pem=key_pem,
        bind_host=LOOPBACK,
        adapter=adapter,
    )

    assert [o.ok for o in outcomes] == [True]  # the fake adapter does not check
    assert [status for status, _ in adapter.collected] == [404, 404]
    assert all(key_pem not in body for _, body in adapter.collected)


async def test_every_router_gets_its_own_single_use_urls():
    leaf_pem, key_pem = _self_signed(["wifi.wyfyguest.com"])
    adapter = _FakeAdapter()

    await push_certificate_to_routers(
        _targets("10.20.0.50", "10.20.0.72"),
        fullchain_pem=leaf_pem,
        privkey_pem=key_pem,
        bind_host=LOOPBACK,
        adapter=adapter,
    )

    urls = [
        url
        for _, push in adapter.calls
        for url in (push.fullchain_url, push.privkey_url)
    ]
    assert len(set(urls)) == 4
    assert all(url.startswith(f"http://{LOOPBACK}:") for url in urls)


async def test_one_unreachable_venue_does_not_stop_the_rest():
    leaf_pem, key_pem = _self_signed(["wifi.wyfyguest.com"])

    outcomes = await push_certificate_to_routers(
        _targets("10.20.0.50", "10.20.0.72"),
        fullchain_pem=leaf_pem,
        privkey_pem=key_pem,
        bind_host=LOOPBACK,
        adapter=_FakeAdapter(fail_for={"10.20.0.50"}),
    )

    assert [o.ok for o in outcomes] == [False, True]
    assert "unreachable" in (outcomes[0].error or "")


async def test_the_listener_is_gone_when_the_push_ends():
    """The private key is reachable for the duration of one push and not one
    second longer -- including when the push fails."""
    leaf_pem, key_pem = _self_signed(["wifi.wyfyguest.com"])
    ports: list[int] = []

    class _RecordPort(_FakeAdapter):
        async def push_hotspot_certificate(self, creds, *, push):
            ports.append(_split(push.privkey_url)[1])
            raise RuntimeError("boom")

    await push_certificate_to_routers(
        _targets("10.20.0.50"),
        fullchain_pem=leaf_pem,
        privkey_pem=key_pem,
        bind_host=LOOPBACK,
        adapter=_RecordPort(),
    )

    with pytest.raises(OSError):
        await asyncio.open_connection(LOOPBACK, ports[0])


async def test_the_certificates_sans_are_handed_to_the_adapter():
    leaf_pem, key_pem = _self_signed(["wifi.wyfyguest.com", "*.portal.wyfyguest.com"])
    adapter = _FakeAdapter()

    await push_certificate_to_routers(
        _targets("10.20.0.50"),
        fullchain_pem=leaf_pem,
        privkey_pem=key_pem,
        bind_host=LOOPBACK,
        adapter=adapter,
    )

    _, push = adapter.calls[0]
    assert push.expected_dns_names == (
        "wifi.wyfyguest.com",
        "*.portal.wyfyguest.com",
    )


async def test_a_certificate_with_no_sans_is_refused_before_anything_is_served():
    """Without SANs no router's portal hostname can be checked, and a push
    that cannot check is a push that can install a certificate producing the
    exact browser warning this effort exists to remove."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-sans.example")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    adapter = _FakeAdapter()

    with pytest.raises(ValueError, match="subjectAltName"):
        await push_certificate_to_routers(
            _targets("10.20.0.50"),
            fullchain_pem=cert.public_bytes(serialization.Encoding.PEM),
            privkey_pem=b"",
            bind_host=LOOPBACK,
            adapter=adapter,
        )

    assert adapter.calls == []
