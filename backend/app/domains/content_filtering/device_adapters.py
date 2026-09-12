"""Real device I/O for the Content Filtering domain -- the piece that was
missing.

## What this closes

Until now this domain wrote a ``ContentFilterRule`` row, returned 201, and
never contacted the router. ``service.py``'s own module docstring said so
plainly -- "No live device push in this pass" -- and deferred real
provisioning to ``app.domains.network_config``'s script pipeline.

The consequence is the worst shape a gap can take. A VLAN that never
reached a device is visibly missing: guests cannot join it. A blocked site
that never reached a device is *invisibly* missing -- the customer typed
``facebook.com``, the dashboard answered "blocked", and every guest on
that router kept reaching it. The feature reported a security property it
did not have, which is worse than not shipping it.

The writer was never the missing piece.
``wyfy_device_gateway.mikrotik_adapter.configure_content_filter_rule``
already issued the real RouterOS commands over **librouteros on port
8728** -- the transport that actually reaches fleet routers -- and had
zero callers anywhere in ``app/``. Someone built the right thing and never
plugged it in. This module is the plug, exactly as
``app.domains.vlan.device_adapters`` and ``app.domains.dhcp
.device_adapters`` are for theirs.

## Why 8728 and not the existing "Push config" pipeline

``network_config``'s push path renders a script and ships it with SFTP +
``/import`` over **asyncssh on port 22**, which is filtered on the fleet.
That path cannot reach a real router, and its handler returns 202
``success: true`` regardless -- so a domain routed through it inherits
both problems, and this one already had. Every ``configure_*`` method in
the gateway, and every read this platform performs, uses 8728.

## Shape

Mirrors ``app.domains.vlan.device_adapters`` deliberately -- own narrow
credentials dataclass, own Protocol naming only what this domain needs, a
concrete MikroTik implementation delegating to
``wyfy_device_gateway.registry.get_adapter``, and a small vendor registry.
Cross-domain composition in this codebase happens at the service layer via
duck-typed Protocols, never by importing another domain's adapter.

``MikroTikConnectionError`` subclasses ``MikroTikDeviceError``, so it must
be caught first or every connection failure is reported as an operation
failure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from wyfy_device_gateway.contract import ContentFilterRuleConfig, DeviceVendor
from wyfy_device_gateway.contract import DeviceCredentials as _GatewayDeviceCredentials
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikConnectionError,
    MikroTikDeviceError,
)
from wyfy_device_gateway.registry import get_adapter

from .exceptions import (
    ContentFilterDeviceConnectionError,
    ContentFilterDeviceOperationError,
    UnsupportedContentFilterVendorError,
)

logger = logging.getLogger(__name__)

_DEFAULT_API_PORT = 8728
_DEFAULT_TIMEOUT_SECONDS = 10


@dataclass(frozen=True, slots=True)
class ContentFilterCredentials:
    """What an adapter needs to open a real connection, resolved by the
    caller from the target ``Router``'s own connection fields. Mirrors
    ``app.domains.vlan.device_adapters.VlanCredentials`` field-for-field --
    an independently-defined identical shape, not an import, so the two
    domains' device-I/O layers stay uncoupled."""

    host: str
    username: str
    password: str
    api_port: int = _DEFAULT_API_PORT
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS


class BaseContentFilterAdapter(Protocol):
    """What a vendor implements to plug real content-filtering operations
    into this domain."""

    vendor: str

    async def configure_content_filter_rule(
        self,
        credentials: ContentFilterCredentials,
        *,
        rule_id: str,
        value_type: str,
        value: str,
        label: str,
    ) -> None:
        """Realizes one blocked site on the device.

        ``value_type`` changes which objects are built, not how they look:

        * ``"domain"`` -- two ``/ip dns static`` entries pointed at the
          platform's sinkhole address, one matching the name exactly and
          one matching every subdomain of it (RouterOS treats ``name=``
          and ``regexp=`` as mutually exclusive per entry, so one entry
          cannot cover both).
        * ``"ip_cidr"`` -- one ``/ip firewall address-list`` membership,
          plus the one router-global ``/ip firewall filter`` DROP rule
          that gives that list any effect at all. A populated list with no
          rule referencing it looks configured and blocks nothing.

        ``rule_id`` is the device-side identity and nothing else: every
        object is stamped with a comment marker derived from it, and a
        later push finds its own objects by that marker. It has to be
        passed even though RouterOS never matches on it, because ``value``
        -- the blocked site -- is the one field a customer edits, so
        keying on it would leave the previous sinkhole behind still
        blocking a site they already unblocked.

        Idempotent: re-pushing an unchanged rule adds nothing and raises
        nothing, and re-pushing a *changed* one updates the existing device
        objects rather than failing on "already have such item".
        """
        ...

    async def delete_content_filter_rule(
        self,
        credentials: ContentFilterCredentials,
        *,
        rule_id: str,
    ) -> None:
        """Takes one blocked site back off the device.

        Deleting a rule row never touched the device -- the row went away
        and the site stayed blocked, drift this platform had no way to
        see. Takes only ``rule_id``: the objects are found by the rule's
        identity, so entries left from a value the customer has since
        edited are still removed rather than orphaned. Idempotent, so
        removing what is already absent is a no-op.
        """
        ...


class MikroTikContentFilterAdapter:
    """Real MikroTik implementation, delegating to the shared gateway."""

    vendor = "mikrotik"

    def _gateway_credentials(
        self, credentials: ContentFilterCredentials
    ) -> _GatewayDeviceCredentials:
        return _GatewayDeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=credentials.host,
            username=credentials.username,
            secret=credentials.password,
            port=credentials.api_port,
            timeout_seconds=credentials.timeout_seconds,
        )

    async def configure_content_filter_rule(
        self,
        credentials: ContentFilterCredentials,
        *,
        rule_id: str,
        value_type: str,
        value: str,
        label: str,
    ) -> None:
        creds = self._gateway_credentials(credentials)
        config = ContentFilterRuleConfig(
            rule_id=rule_id, value_type=value_type, value=value, label=label
        )
        try:
            await get_adapter(DeviceVendor.MIKROTIK).configure_content_filter_rule(
                creds, rule=config
            )
        # MikroTikConnectionError subclasses MikroTikDeviceError -- catch the
        # narrower one first, or every connection failure is mislabelled.
        except MikroTikConnectionError as exc:
            raise ContentFilterDeviceConnectionError(
                credentials.host, exc.detail
            ) from exc
        except MikroTikDeviceError as exc:
            raise ContentFilterDeviceOperationError(
                "configure_content_filter_rule", exc.detail
            ) from exc

    async def delete_content_filter_rule(
        self,
        credentials: ContentFilterCredentials,
        *,
        rule_id: str,
    ) -> None:
        creds = self._gateway_credentials(credentials)
        # value_type/value/label are required by the shape but unread on the
        # delete path, which matches on the rule's identity alone -- so the
        # current blocked value, whatever it is, cannot change what is
        # removed. Both mechanisms are swept, so a rule re-typed since its
        # last push does not leave the other one's objects behind.
        config = ContentFilterRuleConfig(
            rule_id=rule_id, value_type="", value="", label=""
        )
        try:
            await get_adapter(DeviceVendor.MIKROTIK).delete_content_filter_rule(
                creds, rule=config
            )
        except MikroTikConnectionError as exc:
            raise ContentFilterDeviceConnectionError(
                credentials.host, exc.detail
            ) from exc
        except MikroTikDeviceError as exc:
            raise ContentFilterDeviceOperationError(
                "delete_content_filter_rule", exc.detail
            ) from exc


_CONTENT_FILTER_ADAPTERS: dict[str, BaseContentFilterAdapter] = {
    "mikrotik": MikroTikContentFilterAdapter()
}


def get_content_filter_adapter(vendor: str) -> BaseContentFilterAdapter:
    """Raises :class:`~.exceptions.UnsupportedContentFilterVendorError` if
    no adapter is registered for ``vendor``.

    ``Router.vendor`` is a free ``String(50)``, so a row carrying
    ``"MikroTik"`` or ``"mikrotik_routeros"`` lands here rather than in the
    gateway's own enum lookup -- and gets this domain's typed 400 instead of
    an opaque error from inside the gateway.
    """
    adapter = _CONTENT_FILTER_ADAPTERS.get(vendor)
    if adapter is None:
        raise UnsupportedContentFilterVendorError(vendor)
    return adapter


def list_supported_content_filter_vendors() -> list[str]:
    return sorted(_CONTENT_FILTER_ADAPTERS)


__all__ = [
    "BaseContentFilterAdapter",
    "ContentFilterCredentials",
    "MikroTikContentFilterAdapter",
    "get_content_filter_adapter",
    "list_supported_content_filter_vendors",
]
