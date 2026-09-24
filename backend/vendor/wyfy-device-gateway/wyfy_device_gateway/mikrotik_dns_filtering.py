"""Point a MikroTik's own resolver at a Cloudflare Gateway DoH endpoint --
and put it back exactly as it was if that breaks name resolution.

## Why this is its own module

Everything else this gateway writes is additive: a VLAN, a queue, a
sinkhole entry. This is not. ``/ip dns use-doh-server`` is a *whole-router*
setting: once it is set, every name the router resolves -- for itself and
for every guest that uses it as their resolver -- goes over DoH to that one
URL, and RouterOS does **not** fall back to plain DNS when the DoH upstream
fails. A wrong URL, an untrusted certificate or a Cloudflare location that
was deleted underneath us is not a feature that fails to switch on; it is
a venue where no guest can open a web page.

So the write is wrapped in the discipline every other gateway write only
needs part of:

1. **Snapshot** the router's current ``/ip dns`` DoH settings (and the
   certificate trust setting, when this push changes it) *before* writing.
2. **Write**, then **read back** -- a ``set`` that returned cleanly and
   changed nothing is a known RouterOS/fake shape (see
   ``tests/fake_write_transport.py``'s ``silently_ignore_updates``).
3. **Probe**: flush the DNS cache and resolve a known name *through the
   router*, with a bounded number of attempts.
4. **On any failure after the first write, restore the snapshot** and say
   whether the restore itself read back clean.

A disable path (:func:`restore_dns_resolver`) puts the snapshot back the
same way.

## What this deliberately never touches

``/ip dns static``. Content filtering's sinkhole entries and the hotspot's
``dns-name`` entry live there, and RouterOS answers a static entry locally
before any upstream -- DoH included -- is consulted, so both keep working
unchanged with Gateway as the upstream. ``servers``/``dynamic-servers`` are
read (they are what resolves the DoH hostname itself) and never written.

## Certificate trust, per RouterOS version

``verify-doh-cert=yes`` needs the DoH server's root CA to be trusted.

* **7.21 and later**: ``/certificate settings builtin-trust-store`` is a
  list of services allowed to use the built-in CA store. Its documented
  default (``default``) already includes ``dns``; only if the list has been
  narrowed is ``dns`` appended -- never replaced.
* **7.19 / 7.20**: ``/certificate settings builtin-trust-anchors=trusted``.
* **Older than 7.19**: refused (``ROUTEROS_TOO_OLD``). Trusting a CA there
  means fetching and importing a PEM onto the device, which is a separate,
  certificate-lifecycle feature this module does not pretend to be. The
  planner already refuses anything below 7.

## Bypass hardening (opt-in, separate, in layers)

:func:`apply_dns_bypass_hardening` extends the platform's existing
pre-login DoT/DoH drops (``cloudguest-block-dot-udp``/``-tcp``,
``cloudguest-block-doh``, all ``hotspot=!auth``) to *authenticated* guests,
in individually switchable layers (:data:`BYPASS_LAYERS`): canary/opt-out
domains, DoT/DoQ ports, DoH by IP (with a synced address-list), DoH by
hostname (NXDOMAIN + ``tls-host``), a plain-DNS redirect, and -- off by
default -- VPN transports. New objects only -- the existing ones are never
modified -- each carrying a ``cloudguest-dnsf-`` comment marker; filter
rows are placed directly above ``cloudguest-block-dot-udp`` so they sit
with the rules they extend and above the firewall band (see the function's
own docstring for why that position, and what it means for customer allow
rules).

The ``/ip dns static`` rule above is about *other people's* entries: the
bypass layers add and remove only static entries carrying their own
marker (``cloudguest-dnsf-canary`` / ``cloudguest-dnsf-doh-host``) and skip
any name another entry already answers.

## Honest scope

Nothing in this module has been run against a real router. The probe
(``/execute ... as-string`` running ``:resolve``) and the ``hotspot=auth``
matcher in ``chain=dstnat`` are the two device behaviours most in need of a
hardware check; both are called out where they are used.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from librouteros.exceptions import LibRouterosError

from .contract import DeviceCredentials
from .mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikConnectionError,
    MikroTikDeviceError,
    _describe_exception,
    _is_truthy,
)

__all__ = [
    "BYPASS_FILTER_MARKERS",
    "BYPASS_LAYERS",
    "BYPASS_NAT_MARKERS",
    "BypassApplyResult",
    "BypassCounters",
    "CANARY_DOMAINS",
    "DEFAULT_BYPASS_LAYERS",
    "LayerCounters",
    "VPN_FILTER_MARKERS",
    "DnsResolverSnapshot",
    "DohApplyResult",
    "DnsRestoreResult",
    "MikroTikConnectionError",
    "MikroTikDnsFilteringError",
    "MikroTikDnsFilteringRefusedError",
    "MikroTikDohProbeFailedError",
    "apply_dns_bypass_hardening",
    "apply_gateway_doh",
    "normalize_hostname",
    "parse_routeros_version",
    "read_dns_bypass_counters",
    "remove_dns_bypass_hardening",
    "restore_dns_resolver",
]

_DNS = ("ip", "dns")
_DNS_CACHE_FLUSH = "/ip/dns/cache/flush"
_CERT_SETTINGS = ("certificate", "settings")
_RESOURCE = ("system", "resource")
_FILTER = ("ip", "firewall", "filter")
_NAT = ("ip", "firewall", "nat")
_ADDRESS_LIST = ("ip", "firewall", "address-list")

_TRUST_STORE = "builtin-trust-store"  # RouterOS >= 7.21
_TRUST_ANCHORS = "builtin-trust-anchors"  # RouterOS 7.19 / 7.20

# Values of builtin-trust-store under which DNS (DoH) may use the built-in
# CA store. `default` is documented as including `dns`.
_TRUST_STORE_COVERS_DNS = frozenset({"all", "default", "dns"})

# The pre-login drops this platform already provisions, which the bypass
# hardening extends. Read off the lab router (PRD §37.1).
_EXISTING_DOT_UDP = "cloudguest-block-dot-udp"
_DOH_ADDRESS_LIST = "cloudguest-doh-ips"

#: The forward-chain rows the bypass hardening owns, in the order they are
#: placed (all directly above ``cloudguest-block-dot-udp``).
BYPASS_FILTER_MARKERS: tuple[str, ...] = (
    "cloudguest-dnsf-block-dot-udp-auth",
    "cloudguest-dnsf-block-dot-tcp-auth",
    "cloudguest-dnsf-block-doh-auth",
)
#: The dstnat rows the bypass hardening owns.
BYPASS_NAT_MARKERS: tuple[str, ...] = (
    "cloudguest-dnsf-redirect-dns-udp",
    "cloudguest-dnsf-redirect-dns-tcp",
)

_BYPASS_FILTER_ROWS: tuple[dict[str, str], ...] = (
    {
        "chain": "forward",
        "action": "drop",
        "hotspot": "auth",
        "protocol": "udp",
        "dst-port": "853",
        "comment": BYPASS_FILTER_MARKERS[0],
    },
    {
        "chain": "forward",
        "action": "drop",
        "hotspot": "auth",
        "protocol": "tcp",
        "dst-port": "853",
        "comment": BYPASS_FILTER_MARKERS[1],
    },
    {
        "chain": "forward",
        "action": "drop",
        "hotspot": "auth",
        "protocol": "tcp",
        "dst-port": "443",
        "dst-address-list": _DOH_ADDRESS_LIST,
        "comment": BYPASS_FILTER_MARKERS[2],
    },
)
# `hotspot=auth` in chain=dstnat: the hotspot matcher is documented as a
# common firewall matcher, and the hotspot's own dynamic dstnat rules use it,
# but this exact rule has not been run on hardware. [UNVERIFIED]
_BYPASS_NAT_ROWS: tuple[dict[str, str], ...] = (
    {
        "chain": "dstnat",
        "action": "redirect",
        "hotspot": "auth",
        "protocol": "udp",
        "dst-port": "53",
        "to-ports": "53",
        "comment": BYPASS_NAT_MARKERS[0],
    },
    {
        "chain": "dstnat",
        "action": "redirect",
        "hotspot": "auth",
        "protocol": "tcp",
        "dst-port": "53",
        "to-ports": "53",
        "comment": BYPASS_NAT_MARKERS[1],
    },
)


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class MikroTikDnsFilteringError(MikroTikDeviceError):
    """Base for this module's own failures. Carries a stable ``code`` so the
    backend can map it to a sentence without parsing ``detail``."""

    def __init__(self, host: str, code: str, detail: str) -> None:
        self.code = code
        super().__init__(host, f"{code}: {detail}")


class MikroTikDnsFilteringRefusedError(MikroTikDnsFilteringError):
    """Refused before any write: the router cannot safely take this change.

    Codes: ``ROUTEROS_TOO_OLD``, ``ROUTEROS_VERSION_UNKNOWN``,
    ``TRUST_SETTING_UNKNOWN``, ``DNS_BOOTSTRAP_MISSING``,
    ``BYPASS_ANCHOR_MISSING``.
    """


class MikroTikDohProbeFailedError(MikroTikDnsFilteringError):
    """The switch was written and name resolution through the router then
    failed (or the write did not read back). ``rolled_back`` says whether the
    snapshot was restored *and read back clean*; ``False`` means the router
    may be left without working DNS and needs a human now."""

    def __init__(
        self,
        host: str,
        detail: str,
        *,
        rolled_back: bool,
        rollback_error: str | None,
        snapshot: DnsResolverSnapshot | None = None,
    ) -> None:
        self.rolled_back = rolled_back
        self.rollback_error = rollback_error
        # What the router was restored to (or should have been). Carried so
        # a caller whose rollback FAILED still holds the one thing a later
        # disable needs.
        self.snapshot = snapshot
        suffix = (
            "previous DNS settings restored"
            if rolled_back
            else f"ROLLBACK FAILED: {rollback_error or 'restore did not read back'}"
        )
        super().__init__(host, "DOH_PROBE_FAILED", f"{detail}; {suffix}")


# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DnsResolverSnapshot:
    """What the router had before the platform pointed it at Gateway.

    ``trust_setting`` is recorded only when this platform changed it, so a
    restore never rewrites a setting nobody here touched.
    """

    use_doh_server: str
    verify_doh_cert: bool
    trust_setting: str | None = None
    trust_setting_value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DnsResolverSnapshot:
        return cls(
            use_doh_server=str(data.get("use_doh_server") or ""),
            verify_doh_cert=bool(data.get("verify_doh_cert", False)),
            trust_setting=data.get("trust_setting"),
            trust_setting_value=data.get("trust_setting_value"),
        )


@dataclass(frozen=True, slots=True)
class DohApplyResult:
    snapshot: DnsResolverSnapshot
    changed: bool
    probe_address: str
    routeros_version: str


@dataclass(frozen=True, slots=True)
class DnsRestoreResult:
    changed: bool
    probe_ok: bool
    probe_error: str | None


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)(?:\.(\d+))?")


def parse_routeros_version(raw: object) -> tuple[int, int, int] | None:
    """``"7.23.3 (stable)"`` -> ``(7, 23, 3)``; ``"7.19rc2"`` -> ``(7, 19, 0)``;
    anything unparseable -> ``None``."""
    match = _VERSION_RE.match(str(raw or ""))
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _split_list(value: object) -> list[str]:
    return [t.strip() for t in str(value or "").split(",") if t.strip()]


def _first_row(api, segments: tuple[str, ...]) -> dict[str, Any]:  # noqa: ANN001
    return dict(next(iter(api.path(*segments)), {}))


def _parse_probe_reply(rows: list[dict[str, Any]]) -> str | None:
    """``/execute ... as-string`` answers with the script's output in
    ``ret``. ``:put [:resolve x]`` prints one address."""
    for row in rows:
        for token in str(row.get("ret", "")).split():
            try:
                return str(ipaddress.ip_address(token))
            except ValueError:
                continue
    return None


# ---------------------------------------------------------------------------
# the writer
# ---------------------------------------------------------------------------


class _DnsFilteringWriter:
    """Synchronous body of every public coroutine below, run in a thread.

    ``sleep`` is injectable so tests do not wait between probe attempts.
    """

    def __init__(
        self, creds: DeviceCredentials, *, sleep: Callable[[float], None] | None
    ):
        self.creds = creds
        self.host = creds.host
        # Looked up at call time, not bound at import, so a test can patch it.
        self.sleep = sleep or (lambda seconds: time.sleep(seconds))

    def connect(self):  # noqa: ANN201
        return MikroTikAdapter()._connect_api(self.creds)

    # -- reads -------------------------------------------------------------

    def version(self, api) -> tuple[tuple[int, int, int], str]:  # noqa: ANN001
        raw = _first_row(api, _RESOURCE).get("version", "")
        parsed = parse_routeros_version(raw)
        if parsed is None:
            raise MikroTikDnsFilteringRefusedError(
                self.host,
                "ROUTEROS_VERSION_UNKNOWN",
                f"could not read the RouterOS version (got {raw!r})",
            )
        return parsed, str(raw)

    def trust_plan(
        self, api, version: tuple[int, int, int]  # noqa: ANN001
    ) -> tuple[str, str | None, str | None]:
        """``(setting, current_value, value_to_write_or_None)``."""
        if version < (7, 19, 0):
            raise MikroTikDnsFilteringRefusedError(
                self.host,
                "ROUTEROS_TOO_OLD",
                "RouterOS 7.19 or later is required to verify the DoH "
                "certificate against the built-in CA store; this router runs "
                f"{'.'.join(map(str, version))}. Upgrade RouterOS first.",
            )
        row = _first_row(api, _CERT_SETTINGS)
        if version >= (7, 21, 0):
            if _TRUST_STORE not in row:
                raise MikroTikDnsFilteringRefusedError(
                    self.host,
                    "TRUST_SETTING_UNKNOWN",
                    f"/certificate settings has no {_TRUST_STORE}",
                )
            current = str(row.get(_TRUST_STORE) or "")
            tokens = _split_list(current)
            if _TRUST_STORE_COVERS_DNS & set(tokens):
                return _TRUST_STORE, current, None
            kept = [t for t in tokens if t != "untrusted"]
            return _TRUST_STORE, current, ",".join([*kept, "dns"])
        if _TRUST_ANCHORS not in row:
            raise MikroTikDnsFilteringRefusedError(
                self.host,
                "TRUST_SETTING_UNKNOWN",
                f"/certificate settings has no {_TRUST_ANCHORS}",
            )
        current = row.get(_TRUST_ANCHORS)
        if str(current).strip().lower() == "trusted" or current is True:
            return _TRUST_ANCHORS, str(current), None
        return _TRUST_ANCHORS, str(current), "trusted"

    @staticmethod
    def dns_state(api) -> dict[str, Any]:  # noqa: ANN001
        return _first_row(api, _DNS)

    # -- writes ------------------------------------------------------------

    def write_dns(self, api, *, url: str, verify: bool) -> None:  # noqa: ANN001
        api.path(*_DNS).update(
            **{"use-doh-server": url, "verify-doh-cert": "yes" if verify else "no"}
        )

    def write_trust(self, api, setting: str, value: str) -> None:  # noqa: ANN001
        api.path(*_CERT_SETTINGS).update(**{setting: value})

    def flush_cache(self, api) -> None:  # noqa: ANN001
        list(api(_DNS_CACHE_FLUSH))

    def probe(self, api, hostname: str, attempts: int, interval: float) -> str:  # noqa: ANN001
        """Resolve ``hostname`` through the router's own resolver.

        ``:resolve`` is a scripting command, reached over the API through
        ``/execute`` with ``as-string`` (which waits for the script and
        returns its output). [UNVERIFIED on hardware: the exact reply shape
        of ``/execute as-string``; a trap or an unparseable reply is treated
        as failure, which errs towards rollback.]
        """
        script = f':put [:resolve "{hostname}"]'
        last_error = "no attempt made"
        for attempt in range(max(1, attempts)):
            if attempt:
                self.sleep(interval)
            try:
                self.flush_cache(api)
                rows = [dict(r) for r in api("/execute", script=script, **{"as-string": ""})]
            except (LibRouterosError, OSError) as exc:
                last_error = _describe_exception(exc)
                continue
            address = _parse_probe_reply(rows)
            if address is not None:
                return address
            last_error = f"unparseable reply {rows!r}"
        raise _ProbeFailed(f"resolving {hostname} through the router failed: {last_error}")

    def restore(self, api, snapshot: DnsResolverSnapshot) -> str | None:  # noqa: ANN001
        """Put ``snapshot`` back and read it back. Returns ``None`` when the
        router now reads as the snapshot, else a description of what did
        not."""
        try:
            self.write_dns(
                api, url=snapshot.use_doh_server, verify=snapshot.verify_doh_cert
            )
            if snapshot.trust_setting and snapshot.trust_setting_value is not None:
                self.write_trust(api, snapshot.trust_setting, snapshot.trust_setting_value)
            self.flush_cache(api)
            state = self.dns_state(api)
        except (LibRouterosError, OSError) as exc:
            return _describe_exception(exc)
        if str(state.get("use-doh-server") or "") != snapshot.use_doh_server:
            return (
                f"use-doh-server reads {state.get('use-doh-server')!r} after "
                f"restoring {snapshot.use_doh_server!r}"
            )
        return None


class _ProbeFailed(Exception):
    pass


def _apply_sync(
    creds: DeviceCredentials,
    *,
    doh_url: str,
    probe_hostname: str,
    rollback_to: DnsResolverSnapshot | None,
    probe_attempts: int,
    probe_interval_seconds: float,
    sleep: Callable[[float], None] | None,
) -> DohApplyResult:
    writer = _DnsFilteringWriter(creds, sleep=sleep)
    api = writer.connect()
    try:
        try:
            version, raw_version = writer.version(api)
            trust_setting, trust_current, trust_new = writer.trust_plan(api, version)
            state = writer.dns_state(api)
        except LibRouterosError as exc:
            raise MikroTikDeviceError(creds.host, f"read before DoH switch: {exc}") from exc

        current_url = str(state.get("use-doh-server") or "")
        current_verify = _is_truthy(state.get("verify-doh-cert", False))
        already = current_url == doh_url and current_verify and trust_new is None

        if not _split_list(state.get("servers")) and not _split_list(
            state.get("dynamic-servers")
        ):
            # The DoH hostname itself has to be resolved by plain DNS first.
            # With no upstream at all, the switch cannot work -- refuse
            # before writing rather than probe and roll back.
            raise MikroTikDnsFilteringRefusedError(
                creds.host,
                "DNS_BOOTSTRAP_MISSING",
                "the router has no DNS servers (static or dynamic) to resolve "
                "the DoH hostname with",
            )

        if current_url == doh_url:
            # Re-push (or a drifted verify/trust on our own URL). What the
            # router holds now is *ours*, so the rollback target is the
            # snapshot the caller kept from the first push -- never the
            # current state, which would "restore" Gateway.
            snapshot = rollback_to or DnsResolverSnapshot(
                use_doh_server="", verify_doh_cert=False
            )
        else:
            snapshot = DnsResolverSnapshot(
                use_doh_server=current_url,
                verify_doh_cert=current_verify,
                trust_setting=trust_setting if trust_new is not None else None,
                trust_setting_value=trust_current if trust_new is not None else None,
            )

        def _fail(detail: str) -> MikroTikDohProbeFailedError:
            rollback_error = writer.restore(api, snapshot)
            return MikroTikDohProbeFailedError(
                creds.host,
                detail,
                rolled_back=rollback_error is None,
                rollback_error=rollback_error,
                snapshot=snapshot,
            )

        if not already:
            try:
                if trust_new is not None:
                    writer.write_trust(api, trust_setting, trust_new)
                writer.write_dns(api, url=doh_url, verify=True)
                after = writer.dns_state(api)
            except (LibRouterosError, OSError) as exc:
                raise _fail(f"writing the DoH settings failed: {_describe_exception(exc)}") from exc
            if str(after.get("use-doh-server") or "") != doh_url or not _is_truthy(
                after.get("verify-doh-cert", False)
            ):
                raise _fail(
                    "the DoH settings did not read back after the write "
                    f"(use-doh-server={after.get('use-doh-server')!r}, "
                    f"verify-doh-cert={after.get('verify-doh-cert')!r})"
                )

        try:
            address = writer.probe(
                api, probe_hostname, probe_attempts, probe_interval_seconds
            )
        except _ProbeFailed as exc:
            raise _fail(str(exc)) from exc

        return DohApplyResult(
            snapshot=snapshot,
            changed=not already,
            probe_address=address,
            routeros_version=raw_version,
        )
    finally:
        MikroTikAdapter._safe_close(api)


async def apply_gateway_doh(
    creds: DeviceCredentials,
    *,
    doh_url: str,
    probe_hostname: str,
    rollback_to: DnsResolverSnapshot | None = None,
    probe_attempts: int = 3,
    probe_interval_seconds: float = 1.0,
    sleep: Callable[[float], None] | None = None,
) -> DohApplyResult:
    """Switch the router's resolver to ``doh_url``, verified, or leave it as
    it was.

    ``rollback_to`` is the snapshot the caller stored from the first
    successful push. It matters only on a re-push, where the router already
    holds ``doh_url`` and its current state is therefore not the thing to
    restore.

    Raises :class:`MikroTikDnsFilteringRefusedError` before any write,
    :class:`MikroTikDohProbeFailedError` after a write that did not work
    (having restored the snapshot), :class:`MikroTikConnectionError` when the
    router cannot be reached at all.
    """
    return await asyncio.to_thread(
        _apply_sync,
        creds,
        doh_url=doh_url,
        probe_hostname=probe_hostname,
        rollback_to=rollback_to,
        probe_attempts=probe_attempts,
        probe_interval_seconds=probe_interval_seconds,
        sleep=sleep,
    )


def _restore_sync(
    creds: DeviceCredentials,
    *,
    snapshot: DnsResolverSnapshot,
    expected_doh_url: str | None,
    probe_hostname: str,
    sleep: Callable[[float], None] | None,
) -> DnsRestoreResult:
    writer = _DnsFilteringWriter(creds, sleep=sleep)
    api = writer.connect()
    try:
        try:
            state = writer.dns_state(api)
        except LibRouterosError as exc:
            raise MikroTikDeviceError(creds.host, f"read before DNS restore: {exc}") from exc
        current_url = str(state.get("use-doh-server") or "")
        changed = False
        if expected_doh_url is not None and current_url not in (
            expected_doh_url,
            snapshot.use_doh_server,
        ):
            # Somebody pointed the router somewhere else since we switched
            # it. Restoring our snapshot would silently undo their change.
            raise MikroTikDnsFilteringRefusedError(
                creds.host,
                "DNS_CHANGED_EXTERNALLY",
                f"use-doh-server is {current_url!r}, neither ours nor the "
                "snapshot; not overwriting a change made outside the platform",
            )
        if current_url != snapshot.use_doh_server or (
            snapshot.trust_setting and snapshot.trust_setting_value is not None
        ):
            error = writer.restore(api, snapshot)
            if error is not None:
                raise MikroTikDeviceError(creds.host, f"DNS restore failed: {error}")
            changed = True
        try:
            writer.probe(api, probe_hostname, 2, 1.0)
        except _ProbeFailed as exc:
            # Nothing further to fall back to: this *is* the pre-platform
            # state. Reported, not raised -- the restore itself succeeded.
            return DnsRestoreResult(changed=changed, probe_ok=False, probe_error=str(exc))
        return DnsRestoreResult(changed=changed, probe_ok=True, probe_error=None)
    finally:
        MikroTikAdapter._safe_close(api)


async def restore_dns_resolver(
    creds: DeviceCredentials,
    *,
    snapshot: DnsResolverSnapshot,
    expected_doh_url: str | None,
    probe_hostname: str,
    sleep: Callable[[float], None] | None = None,
) -> DnsRestoreResult:
    """Put the pre-platform DNS settings back. Idempotent: a router already
    at the snapshot is only probed. Refuses (``DNS_CHANGED_EXTERNALLY``) when
    the router carries a DoH URL that is neither ours nor the snapshot's."""
    return await asyncio.to_thread(
        _restore_sync,
        creds,
        snapshot=snapshot,
        expected_doh_url=expected_doh_url,
        probe_hostname=probe_hostname,
        sleep=sleep,
    )


def _ensure_rows(
    menu, desired: tuple[dict[str, str], ...], *, place_before: str | None  # noqa: ANN001
) -> None:
    """Find-by-comment, then converge. One row per marker; extras removed,
    drifted fields updated, missing rows added (above ``place_before`` when
    given)."""
    rows = [dict(r) for r in menu]
    for want in desired:
        mine = [r for r in rows if r.get("comment") == want["comment"]]
        if not mine:
            fields = dict(want)
            if place_before is not None:
                fields["place-before"] = place_before
            menu.add(**fields)
            continue
        keep, extras = mine[0], mine[1:]
        changed = {
            k: v for k, v in want.items() if str(keep.get(k, "")) != v
        }
        if _is_truthy(keep.get("disabled", False)):
            changed["disabled"] = "no"
        if changed:
            menu.update(**{".id": keep[".id"], **changed})
        if extras:
            menu.remove(*[r[".id"] for r in extras])


# ---------------------------------------------------------------------------
# bypass hardening, in layers
# ---------------------------------------------------------------------------
#
# Each layer is individually switchable per router and converges on every
# call: an enabled layer's objects are made to exist exactly once, a
# disabled layer's objects are removed. Only objects carrying one of this
# module's ``cloudguest-dnsf-`` comment markers are ever written or removed;
# the platform's pre-login drops, the bootstrap's own ``cloudguest-doh``
# address-list entries, content filtering's ``/ip dns static`` sinkhole and
# anything a customer or operator added are read (to avoid duplicating
# them) and never modified.
#
# **Every filter row is ``chain=forward hotspot=auth``.** The router's own
# traffic -- its WireGuard management tunnel, its DoH upstream, its 8728
# API -- is ``chain=input``/``chain=output`` and cannot match a forward
# rule. :func:`_assert_guest_forward_only` re-checks that on every write,
# so a future edit that "simplifies" a chain fails before it reaches a
# router.

#: Firefox (default-on DoH only) and Apple iCloud Private Relay both look
#: these names up through the network's resolver and stand down when the
#: answer is NXDOMAIN. Sources in the backend PR; neither applies to a user
#: who explicitly chose DoH / "max protection" in Firefox.
LAYER_CANARY_DOMAINS = "canary_domains"
#: DoT (tcp/udp 853) and DoQ (udp 853, RFC 9250) for logged-in guests.
LAYER_ENCRYPTED_DNS_PORTS = "encrypted_dns_ports"
#: DoH by destination IP: tcp/443 to ``cloudguest-doh-ips``, plus keeping
#: that list fresh from the platform's synced public DoH-server list.
LAYER_DOH_IP_LIST = "doh_ip_list"
#: DoH by name: NXDOMAIN for known DoH hostnames (bootstrap by name fails)
#: and ``tls-host`` drops for a short, curated set (DoH by IP with a
#: visible SNI).
LAYER_DOH_HOSTNAMES = "doh_hostnames"
#: Logged-in guests' plain DNS (udp/tcp 53) redirected to the router.
LAYER_PLAIN_DNS_REDIRECT = "plain_dns_redirect"
#: Common VPN transports. OFF by default: hotel and business guests use
#: corporate VPNs legitimately.
LAYER_VPN_BLOCK = "vpn_block"

BYPASS_LAYERS: tuple[str, ...] = (
    LAYER_CANARY_DOMAINS,
    LAYER_ENCRYPTED_DNS_PORTS,
    LAYER_DOH_IP_LIST,
    LAYER_DOH_HOSTNAMES,
    LAYER_PLAIN_DNS_REDIRECT,
    LAYER_VPN_BLOCK,
)
#: What "bypass hardening on" means when no layer set is named. Everything
#: except VPN blocking, which is always an explicit per-venue choice.
DEFAULT_BYPASS_LAYERS: frozenset[str] = frozenset(BYPASS_LAYERS) - {LAYER_VPN_BLOCK}

CANARY_DOMAINS: tuple[str, ...] = (
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com",
)

_STATIC = ("ip", "dns", "static")
_CANARY_COMMENT = "cloudguest-dnsf-canary"
_DOH_HOST_COMMENT = "cloudguest-dnsf-doh-host"
_DOH_SYNC_COMMENT = "cloudguest-dnsf-doh-sync"
_SNI_PREFIX = "cloudguest-dnsf-doh-sni-auth:"

#: Hard ceilings enforced on the device side too, whatever the backend
#: sends: an address-list or static table this size is already large for a
#: small board, and a per-packet ``tls-host`` rule is expensive.
MAX_DOH_IPV4 = 5000
MAX_DOH_HOSTNAMES = 5000
MAX_SNI_HOSTNAMES = 50

#: Never sinkholed, whatever a list says: the router's own Gateway DoH
#: upstream lives under this suffix, and ``/ip dns static`` answers the
#: router's *own* lookups too -- sinkholing it would cut the venue's DNS.
_NEVER_SINKHOLE_SUFFIXES: tuple[str, ...] = ("cloudflare-gateway.com",)

VPN_FILTER_MARKERS: tuple[str, ...] = (
    "cloudguest-dnsf-vpn-ike-auth",
    "cloudguest-dnsf-vpn-esp-auth",
    "cloudguest-dnsf-vpn-openvpn-udp-auth",
    "cloudguest-dnsf-vpn-openvpn-tcp-auth",
    "cloudguest-dnsf-vpn-wireguard-auth",
    "cloudguest-dnsf-vpn-pptp-auth",
    "cloudguest-dnsf-vpn-gre-auth",
    "cloudguest-dnsf-vpn-l2tp-auth",
)


def _guest_drop(comment: str, **match: str) -> dict[str, str]:
    return {
        "chain": "forward",
        "action": "drop",
        "hotspot": "auth",
        **match,
        "comment": comment,
    }


_VPN_FILTER_ROWS: tuple[dict[str, str], ...] = (
    # IKE and IPsec NAT-T.
    _guest_drop(VPN_FILTER_MARKERS[0], protocol="udp", **{"dst-port": "500,4500"}),
    # IPsec ESP (IP protocol 50) -- no ports.
    _guest_drop(VPN_FILTER_MARKERS[1], protocol="ipsec-esp"),
    _guest_drop(VPN_FILTER_MARKERS[2], protocol="udp", **{"dst-port": "1194"}),
    _guest_drop(VPN_FILTER_MARKERS[3], protocol="tcp", **{"dst-port": "1194"}),
    # WireGuard's *default* port only; WireGuard can run on any UDP port.
    _guest_drop(VPN_FILTER_MARKERS[4], protocol="udp", **{"dst-port": "51820"}),
    _guest_drop(VPN_FILTER_MARKERS[5], protocol="tcp", **{"dst-port": "1723"}),
    _guest_drop(VPN_FILTER_MARKERS[6], protocol="gre"),
    _guest_drop(VPN_FILTER_MARKERS[7], protocol="udp", **{"dst-port": "1701"}),
)

_LAYER_FILTER_MARKERS: dict[str, tuple[str, ...]] = {
    LAYER_ENCRYPTED_DNS_PORTS: BYPASS_FILTER_MARKERS[:2],
    LAYER_DOH_IP_LIST: BYPASS_FILTER_MARKERS[2:],
    LAYER_VPN_BLOCK: VPN_FILTER_MARKERS,
}


def _layer_of_comment(comment: str) -> str | None:
    if comment.startswith(_SNI_PREFIX):
        return LAYER_DOH_HOSTNAMES
    for layer, markers in _LAYER_FILTER_MARKERS.items():
        if comment in markers:
            return layer
    if comment in BYPASS_NAT_MARKERS:
        return LAYER_PLAIN_DNS_REDIRECT
    if comment == _CANARY_COMMENT:
        return LAYER_CANARY_DOMAINS
    if comment == _DOH_HOST_COMMENT:
        return LAYER_DOH_HOSTNAMES
    if comment == _DOH_SYNC_COMMENT:
        return LAYER_DOH_IP_LIST
    return None


def _owned_filter_comment(comment: str) -> bool:
    return comment.startswith(_SNI_PREFIX) or any(
        comment in markers for markers in _LAYER_FILTER_MARKERS.values()
    )


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


def normalize_hostname(raw: object) -> str | None:
    """A lower-case DNS hostname with at least two labels, or ``None``.
    Wildcards, IP literals, underscores and anything with whitespace are
    refused -- the value ends up in ``/ip dns static name=`` and in a
    ``tls-host=`` matcher, and nothing but a plain hostname belongs there."""
    name = str(raw or "").strip().lower().rstrip(".")
    if not _HOSTNAME_RE.match(name):
        return None
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    return None


def _is_never_sinkholed(name: str, extra: tuple[str, ...]) -> bool:
    for suffix in (*_NEVER_SINKHOLE_SUFFIXES, *extra):
        if suffix and (name == suffix or name.endswith("." + suffix)):
            return True
    return False


def _global_ipv4(raw: object) -> str | None:
    try:
        address = ipaddress.IPv4Address(str(raw).strip())
    except ValueError:
        return None
    if not address.is_global or address.is_multicast:
        return None
    return str(address)


def _sni_row(hostname: str) -> dict[str, str]:
    # tls-host is a RouterOS >= 6.41 matcher; the planner refuses anything
    # below 7, so every router this reaches has it.
    return _guest_drop(
        f"{_SNI_PREFIX}{hostname}",
        protocol="tcp",
        **{"dst-port": "443", "tls-host": hostname},
    )


def _assert_guest_forward_only(rows: tuple[dict[str, str], ...], host: str) -> None:
    """Defence in depth for the one property this whole feature must never
    lose: nothing here may match the router's own traffic."""
    for row in rows:
        if row.get("chain") != "forward" or row.get("hotspot") != "auth":
            raise MikroTikDnsFilteringError(
                host,
                "UNSAFE_BYPASS_RULE",
                f"refusing to write {row.get('comment')!r}: bypass rules must be "
                "chain=forward hotspot=auth",
            )


@dataclass(frozen=True, slots=True)
class BypassApplyResult:
    layers: tuple[str, ...]
    doh_ipv4_added: int = 0
    doh_ipv4_removed: int = 0
    doh_ipv4_present: int = 0
    hostnames_added: int = 0
    hostnames_removed: int = 0
    hostnames_present: int = 0
    #: Names already answered by an entry this module does not own (content
    #: filtering's sinkhole, an operator's own entry) -- left alone.
    hostnames_skipped_foreign: int = 0
    sni_rules: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "layers": list(self.layers)}


@dataclass(frozen=True, slots=True)
class LayerCounters:
    layer: str
    rules_present: int
    counters_available: bool
    packets: int | None
    bytes: int | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class BypassCounters:
    router_uptime: str | None
    layers: tuple[LayerCounters, ...]


def _chunks(items: list[Any], size: int = 200) -> list[list[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _converge_rows(
    menu,  # noqa: ANN001
    desired: tuple[dict[str, str], ...],
    *,
    owned: Callable[[str], bool],
    place_before: str | None,
) -> None:
    """Desired rows exist once each (added above ``place_before``, drifted
    fields corrected); every other row ``owned`` claims is removed. Adds
    happen before removes: a half-applied change is an extra drop, never a
    gap."""
    _ensure_rows(menu, desired, place_before=place_before)
    wanted = {row["comment"] for row in desired}
    stale = [
        r[".id"]
        for r in menu
        if owned(str(r.get("comment", ""))) and r.get("comment") not in wanted
    ]
    for chunk in _chunks(stale):
        menu.remove(*chunk)


def _converge_static(
    menu, names: list[str], *, comment: str  # noqa: ANN001
) -> tuple[int, int, int, int]:
    """NXDOMAIN entries for ``names`` carrying ``comment``. Returns
    ``(added, removed, present, skipped_foreign)``."""
    rows = [dict(r) for r in menu]
    foreign = {
        str(r.get("name", "")).lower()
        for r in rows
        if r.get("comment") != comment and r.get("name")
    }
    ours: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("comment") == comment:
            ours.setdefault(str(row.get("name", "")).lower(), []).append(row)
    desired = [n for n in dict.fromkeys(names) if n not in foreign]
    skipped = sum(1 for n in dict.fromkeys(names) if n in foreign)
    added = 0
    for name in desired:
        mine = ours.get(name)
        if not mine:
            menu.add(name=name, type="NXDOMAIN", comment=comment)
            added += 1
            continue
        keep = mine[0]
        changed: dict[str, str] = {}
        if str(keep.get("type", "")).upper() != "NXDOMAIN":
            changed["type"] = "NXDOMAIN"
        if _is_truthy(keep.get("disabled", False)):
            changed["disabled"] = "no"
        if changed:
            menu.update(**{".id": keep[".id"], **changed})
    wanted = set(desired)
    stale = [
        row[".id"]
        for name, mine in ours.items()
        for i, row in enumerate(mine)
        if name not in wanted or i > 0
    ]
    for chunk in _chunks(stale):
        menu.remove(*chunk)
    return added, len(stale), len(desired), skipped


def _converge_address_list(
    menu, addresses: list[str]  # noqa: ANN001
) -> tuple[int, int, int]:
    """Our synced entries in ``cloudguest-doh-ips`` become exactly
    ``addresses`` minus whatever the list already holds under another
    comment (the bootstrap's own ten). Returns ``(added, removed,
    present)``."""
    rows = [dict(r) for r in menu if r.get("list") == _DOH_ADDRESS_LIST]
    foreign = {
        str(r.get("address", "")) for r in rows if r.get("comment") != _DOH_SYNC_COMMENT
    }
    ours: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("comment") == _DOH_SYNC_COMMENT:
            ours.setdefault(str(row.get("address", "")), []).append(row)
    desired = [a for a in dict.fromkeys(addresses) if a not in foreign]
    added = 0
    for address in desired:
        if address not in ours:
            menu.add(list=_DOH_ADDRESS_LIST, address=address, comment=_DOH_SYNC_COMMENT)
            added += 1
    wanted = set(desired)
    stale = [
        row[".id"]
        for address, mine in ours.items()
        for i, row in enumerate(mine)
        if address not in wanted or i > 0
    ]
    for chunk in _chunks(stale):
        menu.remove(*chunk)
    return added, len(stale), len(desired)


def _own_doh_host(api) -> str | None:  # noqa: ANN001
    """The hostname of the router's own DoH upstream, if any -- never
    sinkholed, whatever list it appears on."""
    url = str(_first_row(api, _DNS).get("use-doh-server") or "")
    match = re.match(r"^https://([^/:]+)", url)
    return match.group(1).lower() if match else None


def _hardening_converge_sync(
    creds: DeviceCredentials,
    *,
    layers: frozenset[str],
    doh_ipv4: tuple[str, ...],
    doh_hostnames: tuple[str, ...],
    sni_hostnames: tuple[str, ...],
    require_anchor: bool,
) -> BypassApplyResult:
    unknown = sorted(set(layers) - set(BYPASS_LAYERS))
    if unknown:
        raise MikroTikDnsFilteringRefusedError(
            creds.host, "UNKNOWN_BYPASS_LAYER", f"unknown layer(s) {unknown}"
        )
    # Validate everything before the first write.
    ipv4 = [a for a in dict.fromkeys(_global_ipv4(x) for x in doh_ipv4) if a]
    if len(ipv4) > MAX_DOH_IPV4:
        raise MikroTikDnsFilteringRefusedError(
            creds.host,
            "BLOCKLIST_TOO_LARGE",
            f"{len(ipv4)} DoH addresses exceeds the cap of {MAX_DOH_IPV4}",
        )
    hosts = [h for h in dict.fromkeys(normalize_hostname(x) for x in doh_hostnames) if h]
    if len(hosts) > MAX_DOH_HOSTNAMES:
        raise MikroTikDnsFilteringRefusedError(
            creds.host,
            "BLOCKLIST_TOO_LARGE",
            f"{len(hosts)} DoH hostnames exceeds the cap of {MAX_DOH_HOSTNAMES}",
        )
    sni = [h for h in dict.fromkeys(normalize_hostname(x) for x in sni_hostnames) if h]
    if len(sni) > MAX_SNI_HOSTNAMES:
        raise MikroTikDnsFilteringRefusedError(
            creds.host,
            "BLOCKLIST_TOO_LARGE",
            f"{len(sni)} tls-host rules exceeds the cap of {MAX_SNI_HOSTNAMES}",
        )

    api = MikroTikAdapter()._connect_api(creds)
    try:
        try:
            own_host = _own_doh_host(api)
            keep_out = (own_host,) if own_host else ()
            hosts = [h for h in hosts if not _is_never_sinkholed(h, keep_out)]
            sni = [h for h in sni if not _is_never_sinkholed(h, keep_out)]

            filter_rows: list[dict[str, str]] = []
            if LAYER_VPN_BLOCK in layers:
                filter_rows.extend(_VPN_FILTER_ROWS)
            if LAYER_DOH_HOSTNAMES in layers:
                filter_rows.extend(_sni_row(h) for h in sni)
            if LAYER_ENCRYPTED_DNS_PORTS in layers:
                filter_rows.extend(_BYPASS_FILTER_ROWS[:2])
            if LAYER_DOH_IP_LIST in layers:
                filter_rows.extend(_BYPASS_FILTER_ROWS[2:])
            desired_filter = tuple(filter_rows)
            _assert_guest_forward_only(desired_filter, creds.host)

            filter_menu = api.path(*_FILTER)
            anchor = next(
                (
                    dict(r)
                    for r in filter_menu
                    if r.get("comment") == _EXISTING_DOT_UDP
                    and r.get("chain") == "forward"
                ),
                None,
            )
            list_menu = api.path(*_ADDRESS_LIST)
            has_list = any(r.get("list") == _DOH_ADDRESS_LIST for r in list_menu)
            missing: list[str] = []
            if require_anchor and desired_filter and anchor is None:
                missing.append(f"filter rule {_EXISTING_DOT_UDP}")
            if require_anchor and LAYER_DOH_IP_LIST in layers and not (has_list or ipv4):
                missing.append(f"address-list {_DOH_ADDRESS_LIST}")
            if missing:
                raise MikroTikDnsFilteringRefusedError(
                    creds.host,
                    "BYPASS_ANCHOR_MISSING",
                    "this router was not provisioned with the platform's "
                    f"DoT/DoH drops ({', '.join(missing)} not found); not "
                    "guessing where the extension belongs",
                )

            # Filter rows first (drops before anything they depend on is
            # removed), then NAT, then the lists and static entries.
            _converge_rows(
                filter_menu,
                desired_filter,
                owned=_owned_filter_comment,
                place_before=anchor[".id"] if anchor else None,
            )
            _converge_rows(
                api.path(*_NAT),
                _BYPASS_NAT_ROWS if LAYER_PLAIN_DNS_REDIRECT in layers else (),
                owned=lambda c: c in BYPASS_NAT_MARKERS,
                place_before=None,
            )
            ip_added, ip_removed, ip_present = _converge_address_list(
                list_menu, ipv4 if LAYER_DOH_IP_LIST in layers else []
            )
            static_menu = api.path(*_STATIC)
            _converge_static(
                static_menu,
                list(CANARY_DOMAINS) if LAYER_CANARY_DOMAINS in layers else [],
                comment=_CANARY_COMMENT,
            )
            h_added, h_removed, h_present, h_skipped = _converge_static(
                static_menu,
                hosts if LAYER_DOH_HOSTNAMES in layers else [],
                comment=_DOH_HOST_COMMENT,
            )
        except LibRouterosError as exc:
            raise MikroTikDeviceError(creds.host, f"dns bypass hardening: {exc}") from exc
    finally:
        MikroTikAdapter._safe_close(api)
    return BypassApplyResult(
        layers=tuple(sorted(layers)),
        doh_ipv4_added=ip_added,
        doh_ipv4_removed=ip_removed,
        doh_ipv4_present=ip_present,
        hostnames_added=h_added,
        hostnames_removed=h_removed,
        hostnames_present=h_present,
        hostnames_skipped_foreign=h_skipped,
        sni_rules=len(sni) if LAYER_DOH_HOSTNAMES in layers else 0,
    )


async def apply_dns_bypass_hardening(
    creds: DeviceCredentials,
    *,
    layers: frozenset[str] | set[str] | None = None,
    doh_ipv4: tuple[str, ...] | list[str] = (),
    doh_hostnames: tuple[str, ...] | list[str] = (),
    sni_hostnames: tuple[str, ...] | list[str] = (),
) -> BypassApplyResult:
    """Converge the router's bypass hardening on exactly ``layers``
    (default :data:`DEFAULT_BYPASS_LAYERS`); layers not named are removed.

    **Position.** Every filter row goes directly above the existing
    ``cloudguest-block-dot-udp`` -- beside the rules they extend, and, on a
    router with the firewall sentinel band installed, *above* the band (the
    band sits directly above ``cloudguest-fw-fwd-established``, below the
    existing DoT/DoH drops). A customer firewall *allow* rule inside the
    band therefore cannot re-open these for logged-in guests. Every row is
    ``chain=forward hotspot=auth``: never the router's own input/output.

    The two dstnat redirects are appended (NAT order relative to the
    hotspot's own dynamic rules is not ours to change) and match
    ``hotspot=auth`` only. [UNVERIFIED on hardware.]

    ``doh_ipv4`` fills ``cloudguest-doh-ips`` (our entries only);
    ``doh_hostnames`` become ``type=NXDOMAIN`` static entries;
    ``sni_hostnames`` become ``tls-host`` drops. All are re-validated here
    (global IPv4 literals, plain hostnames, hard caps) whatever the caller
    sent, and the router's own DoH upstream host -- plus anything under
    ``cloudflare-gateway.com`` -- is never sinkholed.

    Refuses (``BYPASS_ANCHOR_MISSING``) on a router without the platform's
    existing drops when a filter layer is requested. Idempotent.
    """
    chosen = frozenset(DEFAULT_BYPASS_LAYERS if layers is None else layers)
    return await asyncio.to_thread(
        _hardening_converge_sync,
        creds,
        layers=chosen,
        doh_ipv4=tuple(doh_ipv4),
        doh_hostnames=tuple(doh_hostnames),
        sni_hostnames=tuple(sni_hostnames),
        require_anchor=True,
    )


async def remove_dns_bypass_hardening(creds: DeviceCredentials) -> None:
    """Remove exactly the objects the bypass hardening owns -- every
    layer's rows, synced address-list entries and static entries. Leaves
    the bootstrap's own ``cloudguest-doh`` entries and every foreign static
    entry alone. Idempotent."""
    await asyncio.to_thread(
        _hardening_converge_sync,
        creds,
        layers=frozenset(),
        doh_ipv4=(),
        doh_hostnames=(),
        sni_hostnames=(),
        require_anchor=False,
    )


def _as_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _counters_sync(creds: DeviceCredentials) -> BypassCounters:
    api = MikroTikAdapter()._connect_api(creds)
    try:
        try:
            uptime = _first_row(api, _RESOURCE).get("uptime")
            rows: dict[str, list[dict[str, Any]]] = {layer: [] for layer in BYPASS_LAYERS}
            for segments in (_FILTER, _NAT):
                for row in api.path(*segments):
                    layer = _layer_of_comment(str(row.get("comment", "")))
                    if layer is not None:
                        rows[layer].append(dict(row))
            static_counts: dict[str, int] = {}
            for row in api.path(*_STATIC):
                layer = _layer_of_comment(str(row.get("comment", "")))
                if layer is not None:
                    static_counts[layer] = static_counts.get(layer, 0) + 1
        except LibRouterosError as exc:
            raise MikroTikDeviceError(creds.host, f"read bypass counters: {exc}") from exc
    finally:
        MikroTikAdapter._safe_close(api)

    out: list[LayerCounters] = []
    for layer in BYPASS_LAYERS:
        mine = rows[layer]
        if not mine:
            reason = (
                "answered by NXDOMAIN static DNS entries, which RouterOS does "
                "not count"
                if static_counts.get(layer)
                else "no rule for this layer is on the router"
            )
            out.append(LayerCounters(layer, 0, False, None, None, reason))
            continue
        packets = [_as_int(r.get("packets")) for r in mine]
        sizes = [_as_int(r.get("bytes")) for r in mine]
        if any(p is None for p in packets) or any(b is None for b in sizes):
            out.append(
                LayerCounters(
                    layer,
                    len(mine),
                    False,
                    None,
                    None,
                    "the router did not return packet/byte counters for these rules",
                )
            )
            continue
        out.append(
            LayerCounters(
                layer,
                len(mine),
                True,
                sum(p for p in packets if p is not None),
                sum(b for b in sizes if b is not None),
                None,
            )
        )
    return BypassCounters(
        router_uptime=str(uptime) if uptime is not None else None, layers=tuple(out)
    )


async def read_dns_bypass_counters(creds: DeviceCredentials) -> BypassCounters:
    """Packet/byte counters of the bypass rules, per layer.

    Counters are cumulative since the rule was added or the router last
    rebooted, whichever is later, and count *packets*, not attempts (one
    blocked connection is usually several retransmitted packets). NXDOMAIN
    static entries have no hit counter at all, so the canary layer and the
    name half of the DoH-hostname layer are reported unavailable rather than
    as zero. [UNVERIFIED on hardware: that the API ``print`` of
    ``/ip firewall filter`` returns ``packets``/``bytes`` without ``stats``;
    if it does not, every layer reads unavailable, never zero.]
    """
    return await asyncio.to_thread(_counters_sync, creds)
