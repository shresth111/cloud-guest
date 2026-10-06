"""SNMP on a fleet router: which devices can do it, its configuration, a real
read-back test, and pushing the agent config to the device.

## What existed before 2026-10-06, and why none of it ever ran

Migration 0079 added an SNMP block to ``routers`` and a 300 s poll sweep
(``provisioning_engine.service.run_router_snmp_metrics_poll_sweep``) that
writes into the same ``router_health_snapshots`` table the RouterOS-API
sweep does. Three things kept it dark on every router: nothing in any UI
could set ``snmp_enabled``; nothing anywhere turned the agent on (RouterOS
ships ``/snmp enabled=no``); and the sweep wrote nothing at all when it
skipped or failed a router, so the outage had no symptom. This module, the
``/platform/routers/{id}/snmp`` routes and the Master console panel close
all three.

## Which devices support it -- per vendor, stated plainly

* **MikroTik** -- yes. RouterOS has a standard SNMP agent (v1/v2c/v3,
  MIB-II, IF-MIB, HOST-RESOURCES-MIB). The platform reaches it over the
  same WireGuard path it already uses for the RouterOS API (8728).
* **TP-Link Omada** -- not polled by the platform. EAPs do have an SNMP
  agent (set per site in the controller), but they sit on the venue LAN
  with no tunnel back to us; the platform reaches Omada only through the
  controller API, which already reports AP uptime, CPU/memory, clients and
  traffic. Polling the APs would need a path that does not exist.
* **Aruba Instant On** -- no. Instant On APs expose no SNMP agent (and no
  local API); everything comes from the Instant On cloud.

A vendor we have not assessed gets ``unknown`` -- never "supported".

## Reachability -- what is and is not verified (2026-10-06)

The poller runs in the Celery worker on the app host and sends from that
host's VPC address. Routers accept anything arriving on the WireGuard
interface (``cloudguest-fw-allow-wg-mgmt``), so the router side is open.
**The hub's AWS security group is not**: it admits TCP 8728-8729 and ICMP
from the app host, and no UDP 161. Until that rule exists every poll times
out, and the panel will say "no response" -- truthfully. See the PR for the
owner step.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from fastapi import status
from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.mikrotik_snmp import (
    SnmpApplyResult,
    SnmpDeviceConfig,
    SnmpDeviceState,
)
from wyfy_device_gateway.registry import get_adapter
from wyfy_device_gateway.snmp_poller import (
    SnmpConnectionError,
    SnmpCredentialError,
    SnmpCredentials,
    SnmpDeviceError,
    SnmpIdentity,
    SnmpPoller,
)

from app.core.config import Settings, get_settings
from app.domains.rbac.enums import AuditAction

from .crypto import decrypt_secret, encrypt_secret
from .exceptions import RouterError
from .models import Router
from .vendor_capabilities import vendor_of

if TYPE_CHECKING:
    from .service import RouterService

logger = logging.getLogger(__name__)

__all__ = [
    "SNMP_VERSIONS",
    "SNMP_V3_AUTH_PROTOCOLS",
    "SNMP_V3_PRIV_PROTOCOLS",
    "SnmpSupport",
    "SnmpPollStatus",
    "SnmpVendorSupport",
    "snmp_support_for",
    "resolve_snmp_credentials",
    "build_device_config",
    "poller_source_addresses",
    "SnmpNotSupportedError",
    "SnmpNotConfiguredError",
    "SnmpConfigInvalidError",
    "SnmpDeviceUnreachableError",
    "SnmpTestOutcome",
    "SnmpApplyOutcome",
    "RouterSnmpService",
]

SNMP_VERSIONS: tuple[str, ...] = ("2c", "3")
SNMP_V3_AUTH_PROTOCOLS: tuple[str, ...] = ("SHA1", "MD5")
SNMP_V3_PRIV_PROTOCOLS: tuple[str, ...] = ("AES", "DES")

#: Longest detail string persisted (matches the column).
_DETAIL_MAX = 500


class SnmpSupport(StrEnum):
    SUPPORTED = "supported"
    #: The device has an agent, but the platform has no network path to it.
    NOT_REACHABLE = "not_reachable"
    NOT_SUPPORTED = "not_supported"
    UNKNOWN = "unknown"


class SnmpPollStatus(StrEnum):
    OK = "ok"
    #: No reply at all: firewall/SG drop, agent off, or (v2c) a wrong
    #: community -- an SNMP agent stays silent on a bad community, so these
    #: cannot be told apart on the wire.
    NO_RESPONSE = "no_response"
    #: The agent answered with an error, or the request could not be built.
    ERROR = "error"
    #: Enabled, but no host or no credential to poll with.
    NOT_CONFIGURED = "not_configured"


@dataclass(frozen=True, slots=True)
class SnmpVendorSupport:
    vendor: str
    support: SnmpSupport
    reason: str
    #: Where this device's health numbers come from instead, if not SNMP.
    metrics_via: str | None


_VENDOR_SUPPORT: dict[str, tuple[SnmpSupport, str, str | None]] = {
    "mikrotik": (
        SnmpSupport.SUPPORTED,
        "RouterOS has a standard SNMP agent. The platform polls it over the "
        "management tunnel.",
        None,
    ),
    "tplink_omada": (
        SnmpSupport.NOT_REACHABLE,
        "Omada access points have an SNMP agent, but they sit on the venue "
        "network with no tunnel to the platform, so it cannot poll them.",
        "Omada controller API",
    ),
    "aruba_instant_on": (
        SnmpSupport.NOT_SUPPORTED,
        "Aruba Instant On access points do not offer SNMP; they are managed "
        "only from the Instant On cloud.",
        "Instant On cloud",
    ),
}


def snmp_support_for(router_or_vendor: object) -> SnmpVendorSupport:
    vendor = vendor_of(router_or_vendor)
    support, reason, via = _VENDOR_SUPPORT.get(
        vendor,
        (
            SnmpSupport.UNKNOWN,
            "SNMP support for this device type has not been assessed.",
            None,
        ),
    )
    return SnmpVendorSupport(
        vendor=vendor, support=support, reason=reason, metrics_via=via
    )


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class SnmpNotSupportedError(RouterError):
    CODE = "SNMP_NOT_SUPPORTED_FOR_VENDOR"

    def __init__(self, router_id: uuid.UUID, support: SnmpVendorSupport) -> None:
        super().__init__(
            f"SNMP is not available for router {router_id}: {support.reason}",
            status_code=status.HTTP_409_CONFLICT,
        )
        self.data = {
            "code": self.CODE,
            "vendor": support.vendor,
            "support": support.support.value,
        }


class SnmpNotConfiguredError(RouterError):
    CODE = "SNMP_NOT_CONFIGURED"

    def __init__(self, router_id: uuid.UUID, missing: str) -> None:
        super().__init__(
            f"SNMP cannot run for router {router_id}: {missing}",
            status_code=status.HTTP_409_CONFLICT,
        )
        self.data = {"code": self.CODE, "missing": missing}


class SnmpConfigInvalidError(RouterError):
    CODE = "SNMP_CONFIG_INVALID"

    def __init__(self, detail: str) -> None:
        super().__init__(detail, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
        self.data = {"code": self.CODE}


class SnmpDeviceUnreachableError(RouterError):
    """The RouterOS API (8728) write failed -- distinct from an SNMP
    no-response, which is a test *result*, not an error."""

    CODE = "SNMP_DEVICE_WRITE_FAILED"

    def __init__(self, router_id: uuid.UUID, detail: str) -> None:
        super().__init__(
            f"Could not write SNMP settings to router {router_id}: {detail}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )
        self.data = {"code": self.CODE}


# ---------------------------------------------------------------------------
# credential resolution (shared by the sweep, the test and the push)
# ---------------------------------------------------------------------------


def _decrypt(value: str | None) -> str | None:
    return decrypt_secret(value) if value else None


def _host(router: Router) -> str | None:
    return router.management_ip_address or router.public_ip_address


def resolve_snmp_credentials(
    router: Router, settings: Settings | None = None
) -> SnmpCredentials | None:
    """What the poller should send, or ``None`` when there is nothing to
    send with (no host, or no community/user anywhere). The platform-wide
    default community applies to v1/v2c only; v3 is per-router by nature."""
    settings = settings or get_settings()
    host = _host(router)
    version = router.snmp_version or settings.snmp_default_version
    own = _decrypt(router.snmp_community_encrypted)
    community = own if version == "3" else (own or settings.snmp_default_community)
    if not host or not community:
        return None
    return SnmpCredentials(
        host=host,
        community=community,
        port=router.snmp_port or settings.snmp_default_port,
        version=version,
        timeout_seconds=settings.snmp_poll_timeout_seconds,
        v3_auth_protocol=router.snmp_v3_auth_protocol,
        v3_auth_password=_decrypt(router.snmp_v3_auth_password_encrypted),
        v3_priv_protocol=router.snmp_v3_priv_protocol,
        v3_priv_password=_decrypt(router.snmp_v3_priv_password_encrypted),
    )


def poller_source_addresses(settings: Settings | None = None) -> tuple[str, ...]:
    settings = settings or get_settings()
    return tuple(
        part.strip()
        for part in settings.snmp_poller_source_addresses.split(",")
        if part.strip()
    )


def build_device_config(
    credentials: SnmpCredentials, settings: Settings | None = None
) -> SnmpDeviceConfig:
    """The ``/snmp community`` row that makes the device answer exactly
    ``credentials`` -- and nobody but the poller."""
    addresses = poller_source_addresses(settings)
    if credentials.version == "3":
        security = "private" if credentials.v3_priv_password else "authorized"
        return SnmpDeviceConfig(
            name=credentials.community,
            addresses=addresses,
            security=security,
            auth_protocol=(credentials.v3_auth_protocol or "SHA1").upper(),
            auth_password=credentials.v3_auth_password,
            priv_protocol=(
                (credentials.v3_priv_protocol or "AES").upper()
                if credentials.v3_priv_password
                else None
            ),
            priv_password=credentials.v3_priv_password,
        )
    return SnmpDeviceConfig(
        name=credentials.community, addresses=addresses, security="none"
    )


def _clip(text: str) -> str:
    return text if len(text) <= _DETAIL_MAX else text[: _DETAIL_MAX - 1] + "…"


# ---------------------------------------------------------------------------
# service
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SnmpTestOutcome:
    ok: bool
    status: SnmpPollStatus
    detail: str | None
    identity: SnmpIdentity | None
    target_host: str | None
    target_port: int | None
    version: str | None
    tested_at: datetime


@dataclass(frozen=True, slots=True)
class SnmpApplyOutcome:
    action: str  # "apply" | "remove"
    verified: bool
    changed: list[str]
    mismatches: list[str]
    unverified: list[str]
    state: SnmpDeviceState | None
    allowed_sources: tuple[str, ...]
    applied_at: datetime


class RouterSnmpService:
    """Master-console SNMP operations for one router. Every route that uses
    this is pinned to ``ScopeType.GLOBAL``."""

    def __init__(
        self,
        router_service: RouterService,
        *,
        poller: SnmpPoller | None = None,
        device_adapter_resolver=get_adapter,  # noqa: ANN001
        settings: Settings | None = None,
    ) -> None:
        self.router_service = router_service
        self.poller = poller or SnmpPoller()
        self.device_adapter_resolver = device_adapter_resolver
        self.settings = settings or get_settings()

    async def _router(self, router_id: uuid.UUID) -> Router:
        return await self.router_service.get_router(
            router_id, requesting_organization_id=None
        )

    def _require_supported(self, router: Router) -> None:
        support = snmp_support_for(router)
        if support.support is not SnmpSupport.SUPPORTED:
            raise SnmpNotSupportedError(router.id, support)

    # -- read --------------------------------------------------------------

    async def get(self, router_id: uuid.UUID) -> Router:
        return await self._router(router_id)

    # -- configure ---------------------------------------------------------

    async def update_config(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> Router:
        """Store the SNMP config. Secrets are write-only: absent = keep,
        ``""`` is refused by the schema, so there is no way to blank one by
        accident. Disabling never needs credentials; enabling is refused
        for vendors that cannot be polled."""
        router = await self._router(router_id)
        enabling = data.get("enabled") is True
        if enabling:
            self._require_supported(router)

        version = (
            data.get("version")
            or router.snmp_version
            or self.settings.snmp_default_version
        )
        update: dict[str, object] = {}
        if "enabled" in data and data["enabled"] is not None:
            update["snmp_enabled"] = bool(data["enabled"])
        if data.get("version") is not None:
            update["snmp_version"] = str(data["version"])
        if "port" in data:
            update["snmp_port"] = data["port"]

        secret_fields: list[str] = []
        name = data.get("community") or data.get("v3_username")
        if name:
            update["snmp_community_encrypted"] = encrypt_secret(str(name))
            secret_fields.append("snmp_community")
        if version == "3":
            if data.get("v3_auth_protocol") is not None:
                update["snmp_v3_auth_protocol"] = str(data["v3_auth_protocol"])
            if data.get("v3_priv_protocol") is not None:
                update["snmp_v3_priv_protocol"] = str(data["v3_priv_protocol"])
            if data.get("v3_auth_password"):
                update["snmp_v3_auth_password_encrypted"] = encrypt_secret(
                    str(data["v3_auth_password"])
                )
                secret_fields.append("snmp_v3_auth_password")
            if data.get("v3_priv_password"):
                update["snmp_v3_priv_password_encrypted"] = encrypt_secret(
                    str(data["v3_priv_password"])
                )
                secret_fields.append("snmp_v3_priv_password")
            if data.get("v3_clear_privacy") is True:
                update["snmp_v3_priv_password_encrypted"] = None
                update["snmp_v3_priv_protocol"] = None
        elif version != router.snmp_version and router.snmp_version == "3":
            # Leaving v3: the USM passphrases mean nothing to v2c. Drop them
            # rather than keep secrets nothing uses.
            update["snmp_v3_auth_password_encrypted"] = None
            update["snmp_v3_priv_password_encrypted"] = None
            update["snmp_v3_auth_protocol"] = None
            update["snmp_v3_priv_protocol"] = None

        final_enabled = update.get("snmp_enabled", router.snmp_enabled)
        if final_enabled:
            has_name = bool(
                update.get("snmp_community_encrypted")
                or router.snmp_community_encrypted
            )
            if version == "3":
                has_auth = (
                    update.get("snmp_v3_auth_password_encrypted")
                    if "snmp_v3_auth_password_encrypted" in update
                    else router.snmp_v3_auth_password_encrypted
                )
                if not has_name:
                    raise SnmpConfigInvalidError("SNMPv3 needs a user name.")
                if not has_auth:
                    raise SnmpConfigInvalidError(
                        "SNMPv3 needs an authentication passphrase."
                    )
            elif not has_name and not self.settings.snmp_default_community:
                raise SnmpConfigInvalidError(
                    "Set a community string before turning SNMP on."
                )

        if not update:
            return router
        updated = await self.router_service.repository.update_router(
            router, {**update, "updated_by": actor_user_id}
        )
        changed = sorted(
            {k for k in update if not k.endswith("_encrypted")} | set(secret_fields)
        )
        await self.router_service._audit(  # noqa: SLF001 -- same domain
            actor_user_id,
            AuditAction.ROUTER_SNMP_CONFIG_UPDATED,
            router=updated,
            description=(
                f"SNMP settings updated on router '{updated.name}': "
                + ", ".join(changed)
            ),
            # Field NAMES only -- never a value, never a secret.
            metadata={"fields": changed},
        )
        return updated

    # -- test --------------------------------------------------------------

    async def test(
        self, router_id: uuid.UUID, *, actor_user_id: uuid.UUID | None
    ) -> SnmpTestOutcome:
        """A real SNMP GET of sysName/sysDescr/sysUpTime against the device,
        with the stored credentials. Never fabricates success: a timeout is
        reported as ``no_response`` with what it can and cannot mean."""
        router = await self._router(router_id)
        self._require_supported(router)
        credentials = resolve_snmp_credentials(router, self.settings)
        now = datetime.now(UTC)
        if credentials is None:
            missing = (
                "no management address"
                if not _host(router)
                else "no community / user name"
            )
            raise SnmpNotConfiguredError(router.id, missing)
        identity: SnmpIdentity | None = None
        try:
            identity = await self.poller.read_identity(credentials)
            outcome_status, detail = SnmpPollStatus.OK, None
        except SnmpConnectionError as exc:
            outcome_status = SnmpPollStatus.NO_RESPONSE
            detail = (
                f"No SNMP reply from {credentials.host}:{credentials.port} "
                f"({exc.detail}). A firewall drop, the agent being off, and a "
                "wrong community all look like this."
            )
        except (SnmpDeviceError, SnmpCredentialError) as exc:
            outcome_status, detail = SnmpPollStatus.ERROR, str(exc)
        await self.router_service._audit(  # noqa: SLF001
            actor_user_id,
            AuditAction.ROUTER_SNMP_TESTED,
            router=router,
            description=f"SNMP test on router '{router.name}': {outcome_status.value}",
            metadata={"status": outcome_status.value, "version": credentials.version},
        )
        return SnmpTestOutcome(
            ok=outcome_status is SnmpPollStatus.OK,
            status=outcome_status,
            detail=_clip(detail) if detail else None,
            identity=identity,
            target_host=credentials.host,
            target_port=credentials.port,
            version=credentials.version,
            tested_at=now,
        )

    # -- script (what /apply writes, for review) -----------------------------

    async def render_script(self, router_id: uuid.UUID) -> tuple[str, list[str]]:
        """The RouterOS commands ``apply_to_device`` is equivalent to, with
        every secret masked. Returns ``(action, lines)``."""
        from app.domains.network_config.snmp_renderer import (
            render_snmp_config,
            render_snmp_removal,
        )

        router = await self._router(router_id)
        self._require_supported(router)
        if not router.snmp_enabled:
            return "remove", render_snmp_removal()
        credentials = resolve_snmp_credentials(router, self.settings)
        if credentials is None:
            raise SnmpNotConfiguredError(router.id, "no community / user name")
        config = build_device_config(credentials, self.settings)
        return "apply", render_snmp_config(config, mask_secrets=True)

    # -- device push ---------------------------------------------------------

    def _api_credentials(self, router: Router) -> DeviceCredentials:
        host = _host(router)
        secret = self.router_service.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise SnmpNotConfiguredError(
                router.id, "no RouterOS API credentials to write the device with"
            )
        return DeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=host,
            username=router.api_username,
            secret=secret,
        )

    async def read_device(self, router_id: uuid.UUID) -> SnmpDeviceState:
        router = await self._router(router_id)
        self._require_supported(router)
        adapter = self.device_adapter_resolver(DeviceVendor.MIKROTIK)
        try:
            return await adapter.read_snmp_state(self._api_credentials(router))
        except SnmpNotConfiguredError:
            raise
        except Exception as exc:  # noqa: BLE001 -- surfaced as a 502 with detail
            raise SnmpDeviceUnreachableError(router.id, str(exc)) from exc

    async def apply_to_device(
        self, router_id: uuid.UUID, *, actor_user_id: uuid.UUID | None
    ) -> SnmpApplyOutcome:
        """Converge the device onto the stored config over the RouterOS API:
        enabled -> agent on + our read-only community; disabled -> our
        community removed. Always read back; ``verified`` is the read-back,
        not the write."""
        router = await self._router(router_id)
        self._require_supported(router)
        api_creds = self._api_credentials(router)
        adapter = self.device_adapter_resolver(DeviceVendor.MIKROTIK)
        sources = poller_source_addresses(self.settings)
        if router.snmp_enabled:
            credentials = resolve_snmp_credentials(router, self.settings)
            if credentials is None:
                raise SnmpNotConfiguredError(router.id, "no community / user name")
            if not sources:
                raise SnmpConfigInvalidError(
                    "CLOUDGUEST_SNMP_POLLER_SOURCE_ADDRESSES is empty; refusing "
                    "to open the SNMP agent to every address."
                )
            config = build_device_config(credentials, self.settings)
            action = "apply"
            call = adapter.apply_snmp_config(api_creds, config)
        else:
            action = "remove"
            call = adapter.remove_snmp_config(api_creds)
        try:
            result: SnmpApplyResult = await call
        except Exception as exc:  # noqa: BLE001 -- surfaced as a 502 with detail
            raise SnmpDeviceUnreachableError(router.id, str(exc)) from exc

        now = datetime.now(UTC)
        verified = result.verified
        if verified and action == "apply":
            await self.router_service.repository.update_router(
                router, {"snmp_device_applied_at": now}
            )
        elif action == "remove" or not verified:
            await self.router_service.repository.update_router(
                router, {"snmp_device_applied_at": None}
            )
        await self.router_service._audit(  # noqa: SLF001
            actor_user_id,
            AuditAction.ROUTER_SNMP_APPLIED,
            router=router,
            description=(
                f"SNMP {action} on router '{router.name}': "
                f"{'verified' if verified else 'NOT verified'}"
            ),
            metadata={
                "action": action,
                "verified": verified,
                "changed": list(result.changed),
                "mismatches": list(result.mismatches),
            },
        )
        return SnmpApplyOutcome(
            action=action,
            verified=verified,
            changed=list(result.changed),
            mismatches=list(result.mismatches),
            unverified=list(result.unverified),
            state=result.state,
            allowed_sources=sources,
            applied_at=now,
        )
