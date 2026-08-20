"""Assemble basic WAN profile script sections."""

from __future__ import annotations

from app.domains.network_config.constants import DNS_SECTION_HEADER

from .context import WanRenderContext
from .renderers import (
    render_stale_defconf_dhcp_cleanup,
    render_wan_addressing_section,
    render_wan_bridge_section,
    render_wan_dns_section,
    render_wan_mangle_section,
    render_wan_routing_section,
)

WAN_BRIDGE_HEADER = "# --- WAN + Bridge (CloudGuest-managed) ---"
WAN_CLEANUP_HEADER = "# --- Stale Factory-Default DHCP Client Cleanup ---"
WAN_ADDRESSING_HEADER = "# --- WAN Addressing ---"
WAN_ROUTING_HEADER = "# --- WAN Routing ---"
WAN_MANGLE_HEADER = "# --- Basic Mangle Rules (multi-WAN) ---"


def render_basic_wan_config(ctx: WanRenderContext) -> str:
    """Render the ``basic`` WAN profile as one importable RouterOS script."""
    if not ctx.links:
        return ""

    sections: list[str] = []
    bridge_lines = render_wan_bridge_section(ctx)
    if bridge_lines:
        sections.append(WAN_BRIDGE_HEADER)
        sections.extend(bridge_lines)

    cleanup = render_stale_defconf_dhcp_cleanup()
    sections.append(WAN_CLEANUP_HEADER)
    sections.extend(cleanup)

    addressing = render_wan_addressing_section(ctx)
    if addressing:
        sections.append(WAN_ADDRESSING_HEADER)
        sections.extend(addressing)

    routing = render_wan_routing_section(ctx)
    if routing:
        sections.append(WAN_ROUTING_HEADER)
        sections.extend(routing)

    mangle = render_wan_mangle_section(ctx)
    if mangle:
        sections.append(WAN_MANGLE_HEADER)
        sections.extend(mangle)

    dns_lines = render_wan_dns_section(ctx)
    sections.append(DNS_SECTION_HEADER)
    sections.extend(dns_lines)

    return "\n".join(sections) + "\n"
