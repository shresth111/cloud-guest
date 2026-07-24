"""Network Configuration Management business logic: render a router's own
enabled DHCP/VLAN/Port Forwarding/Hotspot/QoS/WireGuard/RADIUS rows into
RouterOS script text, and push it through
``app.domains.router_provisioning``'s already-real
config-version/apply/rollback pipeline. See ``__init__.py``'s own module
docstring for the full design rationale.

## Composition, not duplication, with eight other domains

Every read here composes a narrow, duck-typed Protocol satisfied
structurally by a real, already-existing service -- the identical
composition-over-duplication pattern every domain in this codebase
establishes. Version history/diff/rollback are pure pass-throughs to
``RouterProvisioningLookupProtocol``; this module owns no version state
of its own.

``wireguard_lookup``/``radius_nas_lookup`` are the two composed lookups
this module gained to close the device-config-generation gap: a real,
working platform-side WireGuard/RADIUS system already existed
(``app.domains.wireguard``, ``app.domains.guest.service.RadiusService``)
with nothing rendering the RouterOS commands a router needs to actually
speak either protocol back to the platform. Both are optional
(``None`` when not composed, or when a given router genuinely has neither
a tunnel nor a NAS client registered yet -- see
``_gather_wireguard_and_radius``), unlike the five original lookups, which
were always required: WireGuard tunnel creation and RADIUS NAS
registration are each their own, independently-triggered operation
(``LocationProvisioningService.provision_location`` creates a tunnel at
step (e) but never a NAS client -- see
``app.domains.location.provisioning_service`` -- registration is a
separate, later admin action via ``RadiusService.register_nas``), so
unlike a DHCP pool or a VLAN, which are always rows some admin explicitly
created before ever calling this service, a WireGuard tunnel or a NAS
client can legitimately not exist yet for a router this service is asked
to render/push a config for.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol

from app.domains.dhcp.models import DhcpPool
from app.domains.dns.models import DnsRecord
from app.domains.firewall.models import FirewallRule
from app.domains.guest.constants import NasStatus
from app.domains.guest.models import RadiusNasClient
from app.domains.hotspot.models import HotspotProfile
from app.domains.port_forwarding.models import PortForwardingRule
from app.domains.qos.models import QosTrafficRule
from app.domains.router_provisioning.models import ConfigVersion, ProvisioningJob
from app.domains.vlan.models import Vlan
from app.domains.wireguard.exceptions import WireGuardPeerNotFoundError
from app.domains.wireguard.models import WireGuardPeer, WireGuardServer

from .exceptions import EmptyNetworkConfigError
from .renderers import render_network_config


class DhcpLookupProtocol(Protocol):
    async def list_pools_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[DhcpPool]: ...


class VlanLookupProtocol(Protocol):
    async def list_vlans_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[Vlan]: ...


class DnsLookupProtocol(Protocol):
    async def list_records_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[DnsRecord]: ...


class PortForwardingLookupProtocol(Protocol):
    async def list_rules_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[PortForwardingRule]: ...


class HotspotLookupProtocol(Protocol):
    async def list_profiles_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[HotspotProfile]: ...


class FirewallLookupProtocol(Protocol):
    async def list_rules_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[FirewallRule]: ...


class QosLookupProtocol(Protocol):
    async def list_rules_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[QosTrafficRule]: ...


class WireGuardLookupProtocol(Protocol):
    """The subset of ``WireGuardService``'s surface this module needs to
    render a router's own tunnel -- see ``_gather_wireguard_and_radius``
    for why both methods are consulted together."""

    async def get_peer(
        self, *, router_id: uuid.UUID, requesting_organization_id: uuid.UUID | None
    ) -> WireGuardPeer: ...

    async def get_server(self, server_id: uuid.UUID) -> WireGuardServer: ...


class RadiusNasLookupProtocol(Protocol):
    """The subset of ``RadiusService``'s surface this module needs to find
    (at most) one active NAS client for a router."""

    async def list_nas_clients(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        status: NasStatus | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[RadiusNasClient], object]: ...


class RouterProvisioningLookupProtocol(Protocol):
    async def create_version_from_content(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        rendered_content: str,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion: ...

    async def apply_version(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, ProvisioningJob]: ...

    async def get_version(
        self,
        *,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion: ...

    async def list_versions(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ConfigVersion], object]: ...

    async def diff_versions(
        self,
        *,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        other_version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, ConfigVersion, list[str]]: ...

    async def rollback_to_version(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        target_version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion: ...


@dataclass(frozen=True, slots=True)
class NetworkConfigPreview:
    """Read model for :meth:`NetworkConfigService.preview_config` -- a
    dry-run rendering that never touches the database."""

    router_id: uuid.UUID
    rendered_content: str
    dhcp_pool_count: int
    vlan_count: int
    port_forwarding_rule_count: int
    hotspot_profile_count: int
    qos_traffic_rule_count: int
    dns_record_count: int
    firewall_rule_count: int
    has_wireguard_peer: bool
    has_radius_nas_client: bool


class NetworkConfigService:
    """Core Network Configuration Management business logic -- see module
    docstring."""

    def __init__(
        self,
        dhcp_lookup: DhcpLookupProtocol,
        vlan_lookup: VlanLookupProtocol,
        port_forwarding_lookup: PortForwardingLookupProtocol,
        hotspot_lookup: HotspotLookupProtocol,
        qos_lookup: QosLookupProtocol,
        router_provisioning_lookup: RouterProvisioningLookupProtocol,
        *,
        dns_lookup: DnsLookupProtocol,
        firewall_lookup: FirewallLookupProtocol,
        wireguard_lookup: WireGuardLookupProtocol | None = None,
        radius_nas_lookup: RadiusNasLookupProtocol | None = None,
    ) -> None:
        self.dhcp_lookup = dhcp_lookup
        self.vlan_lookup = vlan_lookup
        self.port_forwarding_lookup = port_forwarding_lookup
        self.hotspot_lookup = hotspot_lookup
        self.qos_lookup = qos_lookup
        self.router_provisioning_lookup = router_provisioning_lookup
        self.dns_lookup = dns_lookup
        self.firewall_lookup = firewall_lookup
        # Both optional (default ``None``, additive keyword-only args --
        # every existing caller/test that builds this service without them
        # keeps working unchanged): the device-config-generation layer for
        # WireGuard/RADIUS was added after this service's original five
        # categories, and a deployment that has not composed either lookup
        # in yet should still be able to render/push its other categories.
        self.wireguard_lookup = wireguard_lookup
        self.radius_nas_lookup = radius_nas_lookup

    async def _gather_enabled_rows(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> tuple[
        list[DhcpPool],
        list[Vlan],
        list[PortForwardingRule],
        list[HotspotProfile],
        list[QosTrafficRule],
        list[DnsRecord],
        list[FirewallRule],
    ]:
        pools = await self.dhcp_lookup.list_pools_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        vlans = await self.vlan_lookup.list_vlans_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        rules = await self.port_forwarding_lookup.list_rules_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        hotspot_profiles = await self.hotspot_lookup.list_profiles_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        qos_traffic_rules = await self.qos_lookup.list_rules_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        dns_records = await self.dns_lookup.list_records_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        firewall_rules = await self.firewall_lookup.list_rules_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return (
            [p for p in pools if p.is_enabled],
            [v for v in vlans if v.is_enabled],
            [r for r in rules if r.is_enabled],
            [h for h in hotspot_profiles if h.is_enabled],
            [q for q in qos_traffic_rules if q.is_enabled],
            [d for d in dns_records if d.is_enabled],
            [f for f in firewall_rules if f.is_enabled],
        )

    async def _gather_wireguard_and_radius(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> tuple[WireGuardPeer | None, WireGuardServer | None, RadiusNasClient | None]:
        """Resolves, at most, one active ``WireGuardPeer``/``WireGuardServer``
        pair and one active ``RadiusNasClient`` for ``router_id`` -- both
        genuinely optional (``None`` when not yet composed via
        ``wireguard_lookup``/``radius_nas_lookup``, or not yet provisioned
        for this specific router), never invented. See
        ``render_network_config``'s own docstring for why a WireGuard
        tunnel can real-world exist with no NAS client registered yet, and
        why that ordering is not enforced here."""
        peer: WireGuardPeer | None = None
        server: WireGuardServer | None = None
        if self.wireguard_lookup is not None:
            try:
                peer = await self.wireguard_lookup.get_peer(
                    router_id=router_id,
                    requesting_organization_id=requesting_organization_id,
                )
            except WireGuardPeerNotFoundError:
                peer = None
            if peer is not None and peer.is_revoked():
                # A revoked peer has no live tunnel to describe -- see
                # ``WireGuardPeer.is_revoked``'s own docstring; its
                # ``tunnel_ip_address`` is a placeholder, not a real
                # address (``WireGuardService.revoke_tunnel``).
                peer = None
            if peer is not None:
                server = await self.wireguard_lookup.get_server(peer.server_id)

        nas_client: RadiusNasClient | None = None
        if self.radius_nas_lookup is not None:
            clients, _ = await self.radius_nas_lookup.list_nas_clients(
                requesting_organization_id=requesting_organization_id,
                router_id=router_id,
                status=NasStatus.ACTIVE,
                page=1,
                page_size=1,
            )
            nas_client = clients[0] if clients else None

        return peer, server, nas_client

    async def preview_config(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> NetworkConfigPreview:
        (
            pools,
            vlans,
            rules,
            hotspot_profiles,
            qos_traffic_rules,
            dns_records,
            firewall_rules,
        ) = await self._gather_enabled_rows(
            router_id, requesting_organization_id=requesting_organization_id
        )
        peer, server, nas_client = await self._gather_wireguard_and_radius(
            router_id, requesting_organization_id=requesting_organization_id
        )
        rendered = render_network_config(
            dhcp_pools=pools,
            vlans=vlans,
            port_forwarding_rules=rules,
            hotspot_profiles=hotspot_profiles,
            qos_traffic_rules=qos_traffic_rules,
            dns_records=dns_records,
            firewall_rules=firewall_rules,
            wireguard_peer=peer,
            wireguard_server=server,
            radius_nas_client=nas_client,
            # See renderers.render_network_config's own docstring: this
            # deployment's hub and its FreeRADIUS instance are co-located
            # on the same VM, confirmed live this session -- there is no
            # separate "RADIUS server host" column anywhere to draw from
            # instead.
            radius_server_host=server.endpoint_host if server is not None else None,
        )
        return NetworkConfigPreview(
            router_id=router_id,
            rendered_content=rendered,
            dhcp_pool_count=len(pools),
            vlan_count=len(vlans),
            port_forwarding_rule_count=len(rules),
            hotspot_profile_count=len(hotspot_profiles),
            qos_traffic_rule_count=len(qos_traffic_rules),
            dns_record_count=len(dns_records),
            firewall_rule_count=len(firewall_rules),
            has_wireguard_peer=peer is not None,
            has_radius_nas_client=nas_client is not None,
        )

    async def push_config(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, ProvisioningJob]:
        (
            pools,
            vlans,
            rules,
            hotspot_profiles,
            qos_traffic_rules,
            dns_records,
            firewall_rules,
        ) = await self._gather_enabled_rows(
            router_id, requesting_organization_id=requesting_organization_id
        )
        peer, server, nas_client = await self._gather_wireguard_and_radius(
            router_id, requesting_organization_id=requesting_organization_id
        )
        rendered = render_network_config(
            dhcp_pools=pools,
            vlans=vlans,
            port_forwarding_rules=rules,
            hotspot_profiles=hotspot_profiles,
            qos_traffic_rules=qos_traffic_rules,
            dns_records=dns_records,
            firewall_rules=firewall_rules,
            wireguard_peer=peer,
            wireguard_server=server,
            radius_nas_client=nas_client,
            radius_server_host=server.endpoint_host if server is not None else None,
        )
        if not rendered:
            raise EmptyNetworkConfigError(router_id)

        version = await self.router_provisioning_lookup.create_version_from_content(
            actor_user_id=actor_user_id,
            router_id=router_id,
            rendered_content=rendered,
            requesting_organization_id=requesting_organization_id,
        )
        return await self.router_provisioning_lookup.apply_version(
            actor_user_id=actor_user_id,
            router_id=router_id,
            version_id=version.id,
            requesting_organization_id=requesting_organization_id,
        )

    async def get_version(
        self,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion:
        return await self.router_provisioning_lookup.get_version(
            router_id=router_id,
            version_id=version_id,
            requesting_organization_id=requesting_organization_id,
        )

    async def list_versions(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ConfigVersion], object]:
        return await self.router_provisioning_lookup.list_versions(
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
            page=page,
            page_size=page_size,
        )

    async def diff_versions(
        self,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        other_version_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, ConfigVersion, list[str]]:
        return await self.router_provisioning_lookup.diff_versions(
            router_id=router_id,
            version_id=version_id,
            other_version_id=other_version_id,
            requesting_organization_id=requesting_organization_id,
        )

    async def rollback_and_apply(
        self,
        router_id: uuid.UUID,
        target_version_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, ProvisioningJob]:
        rolled_back = await self.router_provisioning_lookup.rollback_to_version(
            actor_user_id=actor_user_id,
            router_id=router_id,
            target_version_id=target_version_id,
            requesting_organization_id=requesting_organization_id,
        )
        return await self.router_provisioning_lookup.apply_version(
            actor_user_id=actor_user_id,
            router_id=router_id,
            version_id=rolled_back.id,
            requesting_organization_id=requesting_organization_id,
        )


__all__ = [
    "DhcpLookupProtocol",
    "VlanLookupProtocol",
    "PortForwardingLookupProtocol",
    "HotspotLookupProtocol",
    "QosLookupProtocol",
    "DnsLookupProtocol",
    "FirewallLookupProtocol",
    "WireGuardLookupProtocol",
    "RadiusNasLookupProtocol",
    "RouterProvisioningLookupProtocol",
    "NetworkConfigPreview",
    "NetworkConfigService",
]
