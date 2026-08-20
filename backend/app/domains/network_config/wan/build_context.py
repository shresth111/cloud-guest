"""Build WAN render contexts from ``IspLink`` rows."""

from __future__ import annotations

import uuid

from app.domains.isp.constants import IspConnectionMode, IspLinkRole, WanRoutingMode
from app.domains.isp.models import IspLink
from app.domains.isp.service import get_decrypted_pppoe_password
from app.domains.network_config.exceptions import MissingStaticWanAddressError
from app.domains.router.models import Router

from .context import WanRenderContext, WanRenderLink


def _default_pppoe_interface_name(slot: int) -> str:
    return f"cloudguest-pppoe-wan{slot}"


def _sort_wan_links(links: list[IspLink]) -> list[IspLink]:
    def sort_key(link: IspLink) -> tuple[int, int]:
        role_rank = 0 if link.role == IspLinkRole.PRIMARY.value else 1
        return role_rank, link.priority

    return sorted(links, key=sort_key)


def build_wan_render_context(
    *,
    router: Router,
    links: list[IspLink],
    lan_bridge: str = "bridge1",
    static_addresses: dict[uuid.UUID, str] | None = None,
) -> WanRenderContext:
    """Resolve enabled ISP links into a render context.

    ``static_addresses`` maps ``isp_link.id`` → ``ip/prefix`` for STATIC
    links (not stored on ``isp_links`` today).
    """
    enabled = [link for link in links if link.is_enabled]
    ordered = _sort_wan_links(enabled)
    static_map = static_addresses or {}

    dns_parts: list[str] = []
    for link in ordered:
        if link.dns_primary:
            dns_parts.append(link.dns_primary)
        if link.dns_secondary and link.dns_secondary not in dns_parts:
            dns_parts.append(link.dns_secondary)
    dns_servers = ",".join(dns_parts) if dns_parts else "8.8.8.8,1.1.1.1"

    render_links: list[WanRenderLink] = []
    for idx, link in enumerate(ordered, start=1):
        physical = (link.physical_interface or link.interface or "").strip()
        if not physical:
            continue
        mode = IspConnectionMode(link.connection_mode)
        if mode is IspConnectionMode.PPPOE:
            effective = (
                link.routing_interface or _default_pppoe_interface_name(idx)
            ).strip()
            password = get_decrypted_pppoe_password(link)
            render_links.append(
                WanRenderLink(
                    link_id=link.id,
                    slot=idx,
                    connection_mode=mode,
                    physical_interface=physical,
                    effective_interface=effective,
                    pppoe_username=link.pppoe_username,
                    pppoe_password=password,
                    load_balance_weight=link.load_balance_weight,
                )
            )
        elif mode is IspConnectionMode.STATIC:
            static_address = static_map.get(link.id)
            if not static_address:
                raise MissingStaticWanAddressError(link.id)
            render_links.append(
                WanRenderLink(
                    link_id=link.id,
                    slot=idx,
                    connection_mode=mode,
                    physical_interface=physical,
                    effective_interface=(
                        link.routing_interface or physical
                    ).strip(),
                    gateway=link.gateway_ip_address,
                    static_address=static_map.get(link.id),
                    load_balance_weight=link.load_balance_weight,
                )
            )
        else:
            render_links.append(
                WanRenderLink(
                    link_id=link.id,
                    slot=idx,
                    connection_mode=mode,
                    physical_interface=physical,
                    effective_interface=(
                        link.routing_interface or physical
                    ).strip(),
                    load_balance_weight=link.load_balance_weight,
                )
            )

    try:
        wan_mode = WanRoutingMode(router.wan_routing_mode)
    except ValueError:
        wan_mode = WanRoutingMode.LOAD_BALANCE

    return WanRenderContext(
        links=render_links,
        wan_routing_mode=wan_mode,
        lan_bridge=lan_bridge,
        dns_servers=dns_servers,
    )
