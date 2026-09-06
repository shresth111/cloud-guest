"""Push a renewed hotspot TLS certificate to the fleet over the RouterOS API.

## What this replaces, and why

``ops/letsencrypt-hotspot/renew-hotspot-certs.sh`` moves the PEMs with ``scp``
and drives the re-import over ``ssh``. Measured against the live fleet on
2026-09-06: on the only reachable router, ports 21/22/23/80/443/8291 all *time
out* -- filtered by a firewall drop, not refused -- and only 8728/8729 answer.
The push mechanism therefore cannot work on any router in the fleet, and the
certificate expires **2026-11-16**. A bound-but-expired certificate is not
cosmetic: with ``login-by=https,http-pap`` it produces the confirmed
three-symptom failure (no login page on Windows/macOS, the captive window
never closing, an Android certificate warning) that PR #153 exists to prevent.

This module is the mechanism that script should call instead of ``scp`` +
``ssh``. It leaves the script in place -- certbot, the renewal window, the
deploy-hook marker and the DNS-01 hooks are all still its job, and none of
that is broken. Only the transport changes:

* the routers are reached on **8728**, the port the firewall leaves open, with
  the **per-router API credential the setup generator already stores**
  (``Router.api_username`` / ``api_credentials_encrypted``) rather than one
  shared SSH password that, measured 2026-08-23, authenticated to exactly one
  router in the fleet;
* the PEMs are **pulled by the router** (``/tool fetch``) from a listener that
  exists only for the seconds a push takes -- see
  :mod:`app.domains.router.ephemeral_pem_server` for what makes handing a
  private key to a URL acceptable, which is four separate controls and not a
  note in a docstring.

## Honest status

The device-side sequence is unit-tested against a fake RouterOS transport
(``vendor/wyfy-device-gateway/tests/test_mikrotik_hotspot_cert_push.py``) and
the URL server is tested over a real loopback socket. Neither has run against
hardware. Two things need exactly one supervised device run before anyone
trusts an unattended renewal: that ``/certificate import`` behaves over the
API on this firmware, and that a router can originate a connection back to the
app server over the tunnel at all -- every use of that tunnel so far has been
app-server-to-router. Both fail loudly and non-destructively if they do not;
see the adapter's own docstring for why the router is left on its working
certificate in that case.

A third thing is not a test's or a device's to settle but a deployment's: the
process that mints the URLs has to be able to bind the tunnel address, and a
bridged docker container cannot. See ``push_certificate_to_routers``'
``bind_port`` for the two ways out. It is a sibling of the two blockers being
handled elsewhere (the GoDaddy API credential and ``/opt/wyfy`` not being
mounted into the api container), and like them it needs a human, not a commit.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from wyfy_device_gateway.contract import (
    DeviceCredentials,
    DeviceVendor,
    HotspotCertificatePush,
    HotspotCertificatePushResult,
)

from app.domains.router.ephemeral_pem_server import EphemeralPemServer

logger = logging.getLogger(__name__)

# The stable RouterOS /certificate name and hotspot profile the fleet uses.
# Both are literals in renew-hotspot-certs.sh today; keeping the same values
# is what makes this a transport change rather than a re-provisioning.
DEFAULT_CERT_NAME = "wyfy-hotspot-fleet"
DEFAULT_HOTSPOT_PROFILE = "hsprof1"

# Two real HTTP downloads by the device plus two imports, on venue uplinks
# that are not always good. Sized like run_speed_test's caller is told to
# size its timeout, not like a health-check read.
DEFAULT_PUSH_TIMEOUT_SECONDS = 120

_ONLINE_STATUS = "online"


@dataclass(frozen=True, slots=True)
class PushTarget:
    """One router this push can actually reach, with its own credential."""

    name: str
    host: str
    username: str
    secret: str
    cert_name: str = DEFAULT_CERT_NAME
    hotspot_profile: str = DEFAULT_HOTSPOT_PROFILE


@dataclass(frozen=True, slots=True)
class SkippedRouter:
    """A router that exists but cannot be pushed to, and why.

    Reported rather than dropped. A router silently missing from a renewal is
    indistinguishable from a fleet that is fully covered, and that confusion
    is how a venue ends up serving an expired certificate until a guest
    complains.
    """

    name: str
    reason: str


@dataclass(frozen=True, slots=True)
class PushOutcome:
    name: str
    host: str
    result: HotspotCertificatePushResult | None
    error: str | None

    @property
    def ok(self) -> bool:
        return self.error is None


def certificate_san_names(fullchain_pem: bytes) -> tuple[str, ...]:
    """The DNS names the leaf of ``fullchain_pem`` is actually valid for.

    Handed to the adapter so it can refuse a router whose portal redirects to
    a hostname this certificate does not cover. Installing a certificate that
    does not match the address in the guest's URL bar produces the exact
    full-screen browser warning the whole certificate effort exists to remove,
    while succeeding in every log -- so this is read off the PEM rather than
    assumed from the certificate's name.

    The *first* certificate in the file is the leaf, by PEM convention and by
    what certbot writes; the rest are the chain and their names are not ours
    to claim.
    """
    leaf = x509.load_pem_x509_certificate(fullchain_pem)
    try:
        san = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return ()
    return tuple(san.value.get_values_for_type(x509.DNSName))


def select_push_targets(
    routers: Iterable[object],
    *,
    cert_name: str = DEFAULT_CERT_NAME,
    hotspot_profile: str = DEFAULT_HOTSPOT_PROFILE,
    decrypt: object = None,
) -> tuple[list[PushTarget], list[SkippedRouter]]:
    """Split ``Router`` rows into "can be pushed to" and "cannot, because".

    A pure function over already-loaded rows rather than a query, so the rules
    below are testable without a database. The rules are the ones the fleet
    was actually measured against on 2026-08-23, not a guess at what a fleet
    looks like:

    * **online only** -- an offline router cannot be pushed to, and trying
      turns every renewal into a wall of connection failures with a real
      failure hidden somewhere inside it;
    * **must have a management address** -- no tunnel address means it has
      never joined the tunnel, so there is nothing to fetch from;
    * **must have its own stored API credential** -- the setup generator
      issues one per router. The push that used one shared SSH password
      across the fleet could only ever have reached the single router that
      predates the generator, and it did not know that.

    One router's bad credential must never abort the fleet, so a decryption
    failure is a skip, not a raise.

    Note for whoever merges this: a separate in-flight branch replaces
    ``renew-hotspot-certs.sh``'s hand-written ``ROUTERS`` array with a
    ``fleet-inventory.py`` helper that applies these same three rules and
    prints them for the shell to consume. That file does not exist on this
    branch and this function is not a copy of it -- it is the same rules
    expressed as a library function, which is what lets them be unit-tested.
    If both land, one of the two should go; this is the testable one.
    """
    if decrypt is None:
        from app.domains.router.crypto import decrypt_secret

        decrypt = decrypt_secret

    targets: list[PushTarget] = []
    skipped: list[SkippedRouter] = []
    for router in routers:
        name = str(getattr(router, "name", None) or getattr(router, "id", "unnamed"))
        status = str(getattr(router, "status", "") or "")
        if status.lower() != _ONLINE_STATUS:
            skipped.append(
                SkippedRouter(name, f"status={status or 'unknown'}, not reachable")
            )
            continue
        host = getattr(router, "management_ip_address", None)
        if not host:
            skipped.append(
                SkippedRouter(name, "no management address (has it joined the tunnel?)")
            )
            continue
        username = getattr(router, "api_username", None)
        ciphertext = getattr(router, "api_credentials_encrypted", None)
        if not username or not ciphertext:
            skipped.append(
                SkippedRouter(
                    name,
                    "no stored API credential -- re-run the setup script for "
                    "this router",
                )
            )
            continue
        try:
            secret = decrypt(ciphertext)
        except Exception as exc:  # noqa: BLE001 - one router must not stop the fleet
            skipped.append(
                SkippedRouter(name, f"credential could not be decrypted: {exc!r}")
            )
            continue
        if not secret:
            skipped.append(
                SkippedRouter(name, "credential decrypts to an empty string")
            )
            continue
        targets.append(
            PushTarget(
                name=name,
                host=str(host),
                username=str(username),
                secret=secret,
                cert_name=cert_name,
                hotspot_profile=hotspot_profile,
            )
        )
    return targets, skipped


async def push_certificate_to_routers(
    targets: Sequence[PushTarget],
    *,
    fullchain_pem: bytes,
    privkey_pem: bytes,
    bind_host: str,
    bind_port: int = 0,
    adapter: object = None,
    timeout_seconds: int = DEFAULT_PUSH_TIMEOUT_SECONDS,
    ttl_seconds: int | None = None,
) -> list[PushOutcome]:
    """Push one certificate to every target, one router at a time.

    Sequential on purpose. These are venue routers on venue uplinks and the
    operation rebinds the captive portal they are currently serving; doing
    the whole fleet at once means a single bad PEM takes every venue down
    simultaneously, and a serialized run lets an operator stop after the
    first failure. Two dozen routers at a few seconds each is not a runtime
    problem worth trading that for.

    One router's failure never stops the others -- an unreachable venue must
    not prevent the rest of the fleet from being renewed -- so failures are
    collected and returned. The caller decides what a partial success means;
    the CLI treats any failure as a non-zero exit.

    ``bind_host`` is this host's own WireGuard tunnel address. Every grant
    minted below is bound to the individual router that may collect it, so
    router A cannot fetch router B's URL even though both are on the tunnel
    and both are, at that moment, being handed the *same* private key. That
    is not a contradiction: binding the grant is what keeps the key off any
    address that has not been given one, including every other device on the
    tunnel and every process on this box.

    ``bind_port`` defaults to 0 -- an ephemeral port, which is the right
    choice when this runs somewhere that already holds the tunnel address.
    It exists because that may not be where it runs. The api container this
    is invoked inside is on a docker bridge network, and a bridged container
    cannot bind the host's WireGuard address at all; a fixed port is what
    lets an operator publish one (``-p <tunnel-ip>:<port>:<port>``) so the
    router has something to reach. Whichever way that is solved, it must be
    solved before a real run -- see the module docstring's "Honest status".
    """
    if adapter is None:
        from wyfy_device_gateway.registry import get_adapter

        adapter = get_adapter(DeviceVendor.MIKROTIK)

    san_names = certificate_san_names(fullchain_pem)
    if not san_names:
        raise ValueError(
            "the certificate being pushed carries no subjectAltName DNS "
            "entries, so no router's portal hostname can be checked against "
            "it -- refusing to push blind"
        )

    outcomes: list[PushOutcome] = []
    server_kwargs = {} if ttl_seconds is None else {"ttl_seconds": ttl_seconds}
    async with EphemeralPemServer(
        bind_host=bind_host, bind_port=bind_port, **server_kwargs
    ) as server:
        for target in targets:
            push = HotspotCertificatePush(
                cert_name=target.cert_name,
                hotspot_profile=target.hotspot_profile,
                fullchain_url=server.grant(
                    fullchain_pem, peer_ip=target.host, label=f"{target.name}/fullchain"
                ),
                privkey_url=server.grant(
                    privkey_pem, peer_ip=target.host, label=f"{target.name}/privkey"
                ),
                expected_dns_names=san_names,
            )
            creds = DeviceCredentials(
                vendor=DeviceVendor.MIKROTIK,
                host=target.host,
                username=target.username,
                secret=target.secret,
                timeout_seconds=timeout_seconds,
            )
            try:
                result = await asyncio.wait_for(
                    adapter.push_hotspot_certificate(creds, push=push),
                    # Belt and braces over creds.timeout_seconds: that one is
                    # the librouteros socket timeout, which does not bound a
                    # /tool fetch the router never finishes answering.
                    timeout=timeout_seconds * 2,
                )
            except Exception as exc:  # noqa: BLE001 - one venue must not stop the rest
                logger.warning(
                    "hotspot_cert_push_failed",
                    extra={"router": target.name, "host": target.host},
                )
                outcomes.append(
                    PushOutcome(
                        name=target.name, host=target.host, result=None, error=str(exc)
                    )
                )
                continue
            outcomes.append(
                PushOutcome(
                    name=target.name, host=target.host, result=result, error=None
                )
            )
    return outcomes
