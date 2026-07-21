"""Network Configuration Management business logic: render a router's own
enabled DHCP/VLAN/Port Forwarding rows into RouterOS script text, and push
it through ``app.domains.router_provisioning``'s already-real config-
version/apply/rollback pipeline. See ``__init__.py``'s own module
docstring for the full design rationale.

## Composition, not duplication, with four other domains

Every read here composes a narrow, duck-typed Protocol satisfied
structurally by a real, already-existing service -- the identical
composition-over-duplication pattern every domain in this codebase
establishes. Version history/diff/rollback are pure pass-throughs to
``RouterProvisioningLookupProtocol``; this module owns no version state
of its own.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol

from app.domains.dhcp.models import DhcpPool
from app.domains.port_forwarding.models import PortForwardingRule
from app.domains.router_provisioning.models import ConfigVersion, ProvisioningJob
from app.domains.vlan.models import Vlan

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


class PortForwardingLookupProtocol(Protocol):
    async def list_rules_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[PortForwardingRule]: ...


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


class NetworkConfigService:
    """Core Network Configuration Management business logic -- see module
    docstring."""

    def __init__(
        self,
        dhcp_lookup: DhcpLookupProtocol,
        vlan_lookup: VlanLookupProtocol,
        port_forwarding_lookup: PortForwardingLookupProtocol,
        router_provisioning_lookup: RouterProvisioningLookupProtocol,
    ) -> None:
        self.dhcp_lookup = dhcp_lookup
        self.vlan_lookup = vlan_lookup
        self.port_forwarding_lookup = port_forwarding_lookup
        self.router_provisioning_lookup = router_provisioning_lookup

    async def _gather_enabled_rows(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> tuple[list[DhcpPool], list[Vlan], list[PortForwardingRule]]:
        pools = await self.dhcp_lookup.list_pools_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        vlans = await self.vlan_lookup.list_vlans_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        rules = await self.port_forwarding_lookup.list_rules_for_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return (
            [p for p in pools if p.is_enabled],
            [v for v in vlans if v.is_enabled],
            [r for r in rules if r.is_enabled],
        )

    async def preview_config(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> NetworkConfigPreview:
        pools, vlans, rules = await self._gather_enabled_rows(
            router_id, requesting_organization_id=requesting_organization_id
        )
        rendered = render_network_config(
            dhcp_pools=pools, vlans=vlans, port_forwarding_rules=rules
        )
        return NetworkConfigPreview(
            router_id=router_id,
            rendered_content=rendered,
            dhcp_pool_count=len(pools),
            vlan_count=len(vlans),
            port_forwarding_rule_count=len(rules),
        )

    async def push_config(
        self,
        router_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, ProvisioningJob]:
        pools, vlans, rules = await self._gather_enabled_rows(
            router_id, requesting_organization_id=requesting_organization_id
        )
        rendered = render_network_config(
            dhcp_pools=pools, vlans=vlans, port_forwarding_rules=rules
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
    "RouterProvisioningLookupProtocol",
    "NetworkConfigPreview",
    "NetworkConfigService",
]
