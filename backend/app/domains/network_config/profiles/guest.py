"""Guest-network profile renderers (bridge, ports, DHCP cleanup)."""

from __future__ import annotations

from .constants import wyfy_comment


def _escape_routeros_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_create_bridge(name: str) -> list[str]:
    esc = _escape_routeros_string(name)
    comment = wyfy_comment("bridge", "guest")
    return [
        f':if ([:len [/interface bridge find where name="{esc}"]] = 0) do={{',
        f'  /interface bridge add name="{esc}" comment="{comment}" disabled=no',
        "}",
    ]


def render_remove_bridge_port(*, bridge: str, interface: str) -> list[str]:
    bridge_esc = _escape_routeros_string(bridge)
    iface_esc = _escape_routeros_string(interface)
    return [
        (
            f':local wyfyPort [/interface bridge port find where '
            f'bridge="{bridge_esc}" interface="{iface_esc}"]'
        ),
        ":if ([:len $wyfyPort] > 0) do={ /interface bridge port remove $wyfyPort }",
    ]


def render_dhcp_client_cleanup(interface: str) -> list[str]:
    """Remove a stale DHCP client (e.g. defconf on ``bridgeLocal``)."""
    iface_esc = _escape_routeros_string(interface)
    return [
        f':local wyfyClient [/ip dhcp-client find where interface="{iface_esc}"]',
        ":if ([:len $wyfyClient] > 0) do={ /ip dhcp-client remove $wyfyClient }",
    ]


def render_add_bridge_ports(*, bridge: str, interfaces: list[str]) -> list[str]:
    bridge_esc = _escape_routeros_string(bridge)
    lines: list[str] = []
    for index, interface in enumerate(interfaces, start=1):
        iface_esc = _escape_routeros_string(interface)
        comment = wyfy_comment("bridge-port", f"guest-{index}")
        lines.extend(
            [
                (
                    f':if ([:len [/interface bridge port find where '
                    f'bridge="{bridge_esc}" interface="{iface_esc}"]] = 0) do={{'
                ),
                (
                    f'  /interface bridge port add bridge="{bridge_esc}" '
                    f'interface="{iface_esc}" comment="{comment}"'
                ),
                "}",
            ]
        )
    return lines


__all__ = [
    "render_create_bridge",
    "render_remove_bridge_port",
    "render_dhcp_client_cleanup",
    "render_add_bridge_ports",
]
