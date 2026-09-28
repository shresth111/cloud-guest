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

## Bypass hardening (opt-in, separate)

:func:`apply_dns_bypass_hardening` extends the platform's existing
pre-login DoT/DoH drops (``cloudguest-block-dot-udp``/``-tcp``,
``cloudguest-block-doh``, all ``hotspot=!auth``) to *authenticated* guests,
and redirects authenticated guests' plain DNS (udp/tcp 53) to the router.
New rows only -- the existing ones are never modified -- each carrying a
``cloudguest-dnsf-`` comment marker, placed directly above
``cloudguest-block-dot-udp`` so they sit with the rules they extend and
above the firewall band (see the function's own docstring for why that
position, and what it means for customer allow rules).

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
    "BYPASS_NAT_MARKERS",
    "DnsResolverSnapshot",
    "DohApplyResult",
    "DnsRestoreResult",
    "MikroTikConnectionError",
    "MikroTikDnsFilteringError",
    "MikroTikDnsFilteringRefusedError",
    "MikroTikDohProbeFailedError",
    "apply_dns_bypass_hardening",
    "apply_gateway_doh",
    "parse_routeros_version",
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


# ---------------------------------------------------------------------------
# bypass hardening
# ---------------------------------------------------------------------------


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


def _hardening_apply_sync(creds: DeviceCredentials) -> None:
    api = MikroTikAdapter()._connect_api(creds)
    try:
        try:
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
            has_list = any(
                r.get("list") == _DOH_ADDRESS_LIST for r in api.path(*_ADDRESS_LIST)
            )
            if anchor is None or not has_list:
                missing = [
                    name
                    for name, ok in (
                        (f"filter rule {_EXISTING_DOT_UDP}", anchor is not None),
                        (f"address-list {_DOH_ADDRESS_LIST}", has_list),
                    )
                    if not ok
                ]
                raise MikroTikDnsFilteringRefusedError(
                    creds.host,
                    "BYPASS_ANCHOR_MISSING",
                    "this router was not provisioned with the platform's "
                    f"DoT/DoH drops ({', '.join(missing)} not found); not "
                    "guessing where the extension belongs",
                )
            # Adds before anything else: a partially-applied hardening is two
            # extra drops, never a gap.
            _ensure_rows(filter_menu, _BYPASS_FILTER_ROWS, place_before=anchor[".id"])
            _ensure_rows(api.path(*_NAT), _BYPASS_NAT_ROWS, place_before=None)
        except LibRouterosError as exc:
            raise MikroTikDeviceError(creds.host, f"apply_dns_bypass_hardening: {exc}") from exc
    finally:
        MikroTikAdapter._safe_close(api)


def _hardening_remove_sync(creds: DeviceCredentials) -> None:
    api = MikroTikAdapter()._connect_api(creds)
    try:
        try:
            for segments, markers in (
                (_FILTER, BYPASS_FILTER_MARKERS),
                (_NAT, BYPASS_NAT_MARKERS),
            ):
                menu = api.path(*segments)
                ids = [r[".id"] for r in menu if r.get("comment") in markers]
                if ids:
                    menu.remove(*ids)
        except LibRouterosError as exc:
            raise MikroTikDeviceError(creds.host, f"remove_dns_bypass_hardening: {exc}") from exc
    finally:
        MikroTikAdapter._safe_close(api)


async def apply_dns_bypass_hardening(creds: DeviceCredentials) -> None:
    """Extend the pre-login DoT/DoH drops to authenticated guests, and
    redirect authenticated guests' plain DNS to the router.

    **Position.** The three drops go directly above the existing
    ``cloudguest-block-dot-udp`` -- beside the rules they extend, and, on a
    router with the firewall sentinel band installed, *above* the band (the
    band sits directly above ``cloudguest-fw-fwd-established``, below the
    existing DoT/DoH drops). That is deliberate and it has one consequence
    worth stating: a customer firewall *allow* rule inside the band cannot
    re-open DoT/DoH for logged-in guests. The rows match only udp/tcp 853 and
    tcp/443 to ``cloudguest-doh-ips``, so -- like the content-filter drop --
    they cannot touch the portal, the management tunnel or 8728.

    The two dstnat redirects are appended (NAT order relative to the
    hotspot's own dynamic rules is not ours to change) and match
    ``hotspot=auth`` only, so a pre-login guest is still handled by the
    hotspot's own DNS interception. [UNVERIFIED on hardware.]

    Refuses (``BYPASS_ANCHOR_MISSING``) on a router without the platform's
    existing drops and address-list. Idempotent; only rows carrying a
    ``cloudguest-dnsf-`` marker are ever written or removed.
    """
    await asyncio.to_thread(_hardening_apply_sync, creds)


async def remove_dns_bypass_hardening(creds: DeviceCredentials) -> None:
    """Remove exactly the rows :func:`apply_dns_bypass_hardening` owns.
    Idempotent."""
    await asyncio.to_thread(_hardening_remove_sync, creds)
