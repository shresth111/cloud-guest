"""Router I/O for DNS filtering -- the plug between this domain and
``wyfy_device_gateway.mikrotik_dns_filtering``, over librouteros on 8728
(the transport that reaches fleet routers; see
``app.domains.content_filtering.device_adapters`` for why not the port-22
script pipeline).

Same shape as the other device domains: own credentials dataclass, own
Protocol naming only what this domain needs, one MikroTik implementation,
a vendor registry whose refusal names the feature in the venue's words.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from fastapi import status
from wyfy_device_gateway.contract import DeviceCredentials as _GatewayCredentials
from wyfy_device_gateway.contract import DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)
from wyfy_device_gateway.mikrotik_dns_filtering import (
    BypassApplyResult,
    BypassCounters,
    DnsResolverSnapshot,
    DnsRestoreResult,
    DohApplyResult,
    MikroTikDnsFilteringRefusedError,
    MikroTikDohProbeFailedError,
    apply_dns_bypass_hardening,
    apply_gateway_doh,
    read_dns_bypass_counters,
    remove_dns_bypass_hardening,
    restore_dns_resolver,
)

from app.domains.router.device_domain_gate import unsupported_vendor_message

from .constants import FEATURE_NAME
from .exceptions import (
    DnsFilteringDeviceConnectionError,
    DnsFilteringDeviceOperationError,
    UnsupportedDnsFilteringVendorError,
)

_DEFAULT_API_PORT = 8728
# The probe waits on RouterOS's own query timeouts (up to ~10s per attempt),
# so the socket timeout must outlast one attempt.
_DEFAULT_TIMEOUT_SECONDS = 20


@dataclass(frozen=True, slots=True)
class DnsFilteringCredentials:
    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS

    def __repr__(self) -> str:  # never print the password
        return (
            f"DnsFilteringCredentials(host={self.host!r}, username={self.username!r})"
        )


class BaseDnsFilteringAdapter(Protocol):
    vendor: str

    async def apply_doh(
        self,
        credentials: DnsFilteringCredentials,
        *,
        doh_url: str,
        probe_hostname: str,
        rollback_to: dict[str, Any] | None,
    ) -> DohApplyResult: ...

    async def restore_dns(
        self,
        credentials: DnsFilteringCredentials,
        *,
        snapshot: dict[str, Any],
        expected_doh_url: str | None,
        probe_hostname: str,
    ) -> DnsRestoreResult: ...

    async def apply_bypass_hardening(
        self,
        credentials: DnsFilteringCredentials,
        *,
        layers: frozenset[str],
        doh_ipv4: list[str],
        doh_hostnames: list[str],
        sni_hostnames: list[str],
    ) -> BypassApplyResult: ...

    async def remove_bypass_hardening(
        self, credentials: DnsFilteringCredentials
    ) -> None: ...

    async def read_bypass_counters(
        self, credentials: DnsFilteringCredentials
    ) -> BypassCounters: ...


def _translate(operation: str, exc: MikroTikDeviceError) -> Exception:
    # Narrowest first: MikroTikConnectionError subclasses MikroTikDeviceError.
    if isinstance(exc, MikroTikConnectionError):
        return DnsFilteringDeviceConnectionError(exc.host, exc.detail)
    if isinstance(exc, MikroTikDohProbeFailedError):
        error = DnsFilteringDeviceOperationError(
            operation, exc.detail, code=exc.code, rolled_back=exc.rolled_back
        )
        error.snapshot = exc.snapshot.to_dict() if exc.snapshot else None
        return error
    if isinstance(exc, MikroTikDnsFilteringRefusedError):
        # Refused before any write: the router is fine, it just cannot take
        # this change as it stands. 409, with the stable code.
        return DnsFilteringDeviceOperationError(
            operation, exc.detail, code=exc.code, status_code=status.HTTP_409_CONFLICT
        )
    return DnsFilteringDeviceOperationError(operation, exc.detail)


class MikroTikDnsFilteringAdapter:
    vendor = "mikrotik"

    @staticmethod
    def _creds(credentials: DnsFilteringCredentials) -> _GatewayCredentials:
        return _GatewayCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

    async def apply_doh(
        self,
        credentials: DnsFilteringCredentials,
        *,
        doh_url: str,
        probe_hostname: str,
        rollback_to: dict[str, Any] | None,
    ) -> DohApplyResult:
        try:
            return await apply_gateway_doh(
                self._creds(credentials),
                doh_url=doh_url,
                probe_hostname=probe_hostname,
                rollback_to=(
                    DnsResolverSnapshot.from_dict(rollback_to) if rollback_to else None
                ),
            )
        except MikroTikDeviceError as exc:
            raise _translate("apply_doh", exc) from exc

    async def restore_dns(
        self,
        credentials: DnsFilteringCredentials,
        *,
        snapshot: dict[str, Any],
        expected_doh_url: str | None,
        probe_hostname: str,
    ) -> DnsRestoreResult:
        try:
            return await restore_dns_resolver(
                self._creds(credentials),
                snapshot=DnsResolverSnapshot.from_dict(snapshot),
                expected_doh_url=expected_doh_url,
                probe_hostname=probe_hostname,
            )
        except MikroTikDeviceError as exc:
            raise _translate("restore_dns", exc) from exc

    async def apply_bypass_hardening(
        self,
        credentials: DnsFilteringCredentials,
        *,
        layers: frozenset[str],
        doh_ipv4: list[str],
        doh_hostnames: list[str],
        sni_hostnames: list[str],
    ) -> BypassApplyResult:
        try:
            return await apply_dns_bypass_hardening(
                self._creds(credentials),
                layers=layers,
                doh_ipv4=doh_ipv4,
                doh_hostnames=doh_hostnames,
                sni_hostnames=sni_hostnames,
            )
        except MikroTikDeviceError as exc:
            raise _translate("apply_bypass_hardening", exc) from exc

    async def read_bypass_counters(
        self, credentials: DnsFilteringCredentials
    ) -> BypassCounters:
        try:
            return await read_dns_bypass_counters(self._creds(credentials))
        except MikroTikDeviceError as exc:
            raise _translate("read_bypass_counters", exc) from exc

    async def remove_bypass_hardening(
        self, credentials: DnsFilteringCredentials
    ) -> None:
        try:
            await remove_dns_bypass_hardening(self._creds(credentials))
        except MikroTikDeviceError as exc:
            raise _translate("remove_bypass_hardening", exc) from exc


_ADAPTERS: dict[str, BaseDnsFilteringAdapter] = {
    "mikrotik": MikroTikDnsFilteringAdapter()
}


def get_dns_filtering_adapter(vendor: str) -> BaseDnsFilteringAdapter:
    adapter = _ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedDnsFilteringVendorError(
            unsupported_vendor_message(feature=FEATURE_NAME, vendor=vendor)
        )
    return adapter


__all__ = [
    "BaseDnsFilteringAdapter",
    "DnsFilteringCredentials",
    "MikroTikDnsFilteringAdapter",
    "get_dns_filtering_adapter",
]
