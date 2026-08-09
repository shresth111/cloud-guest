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

``isp_link_lookup``/``agent_credential_issuer``/``router_lookup`` are three
more optional, additive lookups (same "``None`` when not composed" posture
as ``wireguard_lookup``/``radius_nas_lookup`` above) backing exactly one
new method, ``push_isp_netwatch_config`` -- see that method's own
docstring, and ``renderers.py``'s own "Netwatch" module-docstring section,
for the full real-time-detection design this closes the loop on.
Deliberately **not** folded into ``_gather_enabled_rows``/
``render_network_config``'s combined script: unlike DHCP/VLAN/etc., a
Netwatch push has a real, singular side effect neither of those categories
carry (rotating the router's own persistent agent credential -- see
``push_isp_netwatch_config``), which no admin should trigger merely as a
side effect of an unrelated DHCP/VLAN push.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol

from app.domains.content_filtering.models import ContentFilterRule
from app.domains.dhcp.models import DhcpPool
from app.domains.dns.models import DnsRecord
from app.domains.firewall.models import FirewallRule
from app.domains.guest.constants import NasStatus
from app.domains.guest.models import RadiusNasClient
from app.domains.hotspot.models import HotspotProfile
from app.domains.isp.constants import IspConnectionMode
from app.domains.isp.models import IspLink
from app.domains.mac_authorization.models import MacAuthorizationEntry
from app.domains.port_forwarding.models import PortForwardingRule
from app.domains.qos.models import QosTrafficRule
from app.domains.router.models import Router
from app.domains.router_provisioning.models import ConfigVersion, ProvisioningJob
from app.domains.vlan.models import Vlan
from app.domains.wireguard.exceptions import WireGuardPeerNotFoundError
from app.domains.wireguard.models import WireGuardPeer, WireGuardServer

from .exceptions import (
    EmptyNetworkConfigError,
    NetwatchIntegrationUnavailableError,
    NoNetwatchTargetsError,
)
from .renderers import render_isp_netwatch_config, render_network_config


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


class MacAuthorizationLookupProtocol(Protocol):
    """The subset of ``MacAuthorizationService``'s surface this module
    needs to render a router's own currently-valid whitelist entries."""

    async def list_active_entries_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[MacAuthorizationEntry]: ...


class ContentFilterLookupProtocol(Protocol):
    """The subset of ``ContentFilterService``'s surface this module needs
    to render a router's own currently-enabled content-filtering rules."""

    async def list_rules_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[ContentFilterRule]: ...


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


class IspLinkLookupProtocol(Protocol):
    """The subset of ``IspService``'s surface
    ``push_isp_netwatch_config`` needs to find a router's own enabled
    ISP links -- the identical ``list_links`` real, tenant-scoped read
    every ``GET /isp/links`` call already uses, never a second, parallel
    query."""

    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[IspLink], object]: ...


class AgentCredentialIssuerProtocol(Protocol):
    """The single ``RouterAgentService`` method
    ``push_isp_netwatch_config`` needs -- reused directly (its own real
    rotate-in-place-if-one-already-exists behavior), never reimplemented.
    See that method's own docstring for why rotating this credential is
    the real mechanism that closes the loop for
    ``renderers.render_isp_netwatch_entry``'s own embedded plaintext."""

    async def issue_credential_for_router(
        self, router: Router
    ) -> tuple[object, str]: ...


class RouterLookupProtocol(Protocol):
    """The single ``RouterService`` method
    ``push_isp_netwatch_config`` needs to resolve the real ``Router`` row
    ``AgentCredentialIssuerProtocol.issue_credential_for_router`` requires
    -- mirrors ``app.domains.isp.service.RouterLookupProtocol``'s own
    identical single-method subset."""

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...


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
    mac_authorization_entry_count: int
    content_filter_rule_count: int


@dataclass(frozen=True, slots=True)
class NetwatchPushResult:
    """The real result of :meth:`NetworkConfigService
    .push_isp_netwatch_config` -- the applied ``ConfigVersion``/queued
    ``ProvisioningJob`` (identical shape to :meth:`push_config`'s own
    return) plus ``watched_link_count``, since a caller genuinely needs to
    know how many of the router's ISP links actually got a real Netwatch
    entry (vs. silently skipped for being DHCP/PPPOE-mode)."""

    version: ConfigVersion
    job: ProvisioningJob
    watched_link_count: int


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
        mac_authorization_lookup: MacAuthorizationLookupProtocol | None = None,
        isp_link_lookup: IspLinkLookupProtocol | None = None,
        agent_credential_issuer: AgentCredentialIssuerProtocol | None = None,
        router_lookup: RouterLookupProtocol | None = None,
        content_filter_lookup: ContentFilterLookupProtocol | None = None,
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
        # Optional, additive, same story as wireguard_lookup/radius_nas_lookup
        # above: the real device-config-generation seam for MAC
        # Authorization (previously pure database bookkeeping with zero
        # effect on the physical device -- see
        # app.domains.mac_authorization.service module docstring).
        self.mac_authorization_lookup = mac_authorization_lookup
        # Optional, additive, same "None until composed" posture as every
        # lookup above -- back exactly one method, push_isp_netwatch_config
        # (see that method's own docstring). All three are required
        # together for that one method to work at all (raises
        # NetwatchIntegrationUnavailableError if any is missing); every
        # *other* method on this service is completely unaffected by
        # whether they're composed.
        self.isp_link_lookup = isp_link_lookup
        self.agent_credential_issuer = agent_credential_issuer
        self.router_lookup = router_lookup
        # Optional, additive, identical story to mac_authorization_lookup
        # above: the real device-config-generation seam for Content
        # Filtering (see app.domains.content_filtering's own module
        # docstring for the full DNS-sinkhole/address-list scope this
        # composes into render_content_filter_rule/
        # render_content_filter_enforcement).
        self.content_filter_lookup = content_filter_lookup

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

    async def _gather_mac_authorization(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[MacAuthorizationEntry]:
        if self.mac_authorization_lookup is None:
            return []
        return await self.mac_authorization_lookup.list_active_entries_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )

    async def _gather_content_filter_rules(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[ContentFilterRule]:
        if self.content_filter_lookup is None:
            return []
        rules = await self.content_filter_lookup.list_rules_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return [r for r in rules if r.is_enabled]

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
        mac_authorization_entries = await self._gather_mac_authorization(
            router_id, requesting_organization_id=requesting_organization_id
        )
        content_filter_rules = await self._gather_content_filter_rules(
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
            mac_authorization_entries=mac_authorization_entries,
            content_filter_rules=content_filter_rules,
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
            mac_authorization_entry_count=len(mac_authorization_entries),
            content_filter_rule_count=len(content_filter_rules),
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
        mac_authorization_entries = await self._gather_mac_authorization(
            router_id, requesting_organization_id=requesting_organization_id
        )
        content_filter_rules = await self._gather_content_filter_rules(
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
            mac_authorization_entries=mac_authorization_entries,
            content_filter_rules=content_filter_rules,
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

    async def push_isp_netwatch_config(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        api_base_url: str,
    ) -> NetwatchPushResult:
        """Configures real RouterOS Netwatch entries (one per qualifying
        ``IspLink``) on ``router_id`` -- the faster, router-side,
        complementary detection path alongside
        ``app.domains.isp.service.run_health_check_sweep``'s existing
        30-second server-side poll. See ``renderers.py``'s own "Netwatch"
        module-docstring section for the full design write-up; this
        method is that design's one real, stateful step.

        **Rotates the router's own persistent agent credential first,
        every time.** ``renderers.render_isp_netwatch_entry`` embeds a
        plaintext ``X-Agent-Credential`` directly into each Netwatch
        entry's own ``up-script``/``down-script`` -- the only way a
        RouterOS script triggered independently, at an arbitrary later
        time, can authenticate its own callback the same way every other
        device-facing call in this codebase already does. This platform
        holds no recoverable plaintext copy of an already-issued
        credential (only its hash -- see
        ``app.domains.router_agent.models.RouterAgentCredential``'s own
        docstring), so the only way to have a genuine plaintext in hand at
        push time is to mint one right now via
        ``AgentCredentialIssuerProtocol.issue_credential_for_router``,
        which rotates the existing credential in place if one already
        exists. **Real, honest side effect worth calling out plainly**:
        this invalidates whatever credential the router was using a
        moment before -- harmless for every *documented* use of that
        credential in this codebase today (heartbeat/config-pull/status/
        actions all re-authenticate per call, and nothing currently keeps
        a long-lived, unattended script depending on one specific
        credential value staying valid forever -- see
        ``render_agent_heartbeat_scheduler``'s own docstring, which
        documents that even that renderer is not wired into any live call
        site yet), but a real fact an operator triggering this action
        should know, not a silently-absorbed side effect.

        Raises ``NetwatchIntegrationUnavailableError`` if this service was
        not constructed with all three of ``isp_link_lookup``/
        ``agent_credential_issuer``/``router_lookup`` composed (every real
        production wiring always composes all three -- see
        ``dependencies.py``), and ``NoNetwatchTargetsError`` if the router
        has no enabled, ``STATIC``-mode ISP link with a known
        ``gateway_ip_address`` to watch (mirrors
        ``EmptyNetworkConfigError``'s own "don't push nothing" posture for
        the main config-push flow)."""
        if (
            self.isp_link_lookup is None
            or self.agent_credential_issuer is None
            or self.router_lookup is None
        ):
            raise NetwatchIntegrationUnavailableError(router_id)

        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        links, _meta = await self.isp_link_lookup.list_links(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=1,
            page_size=100,
        )
        watched_links = [
            link
            for link in links
            if link.is_enabled
            and link.connection_mode == IspConnectionMode.STATIC.value
            and link.gateway_ip_address
        ]
        if not watched_links:
            raise NoNetwatchTargetsError(router_id)

        issue_credential = self.agent_credential_issuer.issue_credential_for_router
        _credential, plaintext = await issue_credential(router)
        rendered = render_isp_netwatch_config(
            watched_links, api_base_url=api_base_url, agent_credential=plaintext
        )

        version = await self.router_provisioning_lookup.create_version_from_content(
            actor_user_id=actor_user_id,
            router_id=router_id,
            rendered_content=rendered,
            requesting_organization_id=requesting_organization_id,
        )
        applied_version, job = await self.router_provisioning_lookup.apply_version(
            actor_user_id=actor_user_id,
            router_id=router_id,
            version_id=version.id,
            requesting_organization_id=requesting_organization_id,
        )
        return NetwatchPushResult(
            version=applied_version, job=job, watched_link_count=len(watched_links)
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
    "MacAuthorizationLookupProtocol",
    "ContentFilterLookupProtocol",
    "IspLinkLookupProtocol",
    "AgentCredentialIssuerProtocol",
    "RouterLookupProtocol",
    "RouterProvisioningLookupProtocol",
    "NetworkConfigPreview",
    "NetwatchPushResult",
    "NetworkConfigService",
]
