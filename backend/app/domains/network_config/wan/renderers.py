"""RouterOS script renderers for basic WAN profiles."""

from __future__ import annotations

from app.domains.isp.constants import IspConnectionMode, WanRoutingMode

from .context import WanRenderContext, WanRenderLink
from .pcc import build_weighted_pcc_plan

WAN_RENAME_WARNING = (
    "# WAN interfaces must already exist on the device under the names "
    "configured in WyFyGuest -- do NOT rename interfaces to match this script."
)


def _escape_routeros_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _wan_existence_check_lines(physical_names: list[str]) -> list[str]:
    lines: list[str] = []
    for name in physical_names:
        expr = f'"{_escape_routeros_string(name)}"'
        lines.extend(
            [
                f":if ([:len [/interface find where name={expr}]] = 0) do={{",
                f'  :put ("*** ERROR: WAN interface \\"" . {expr} . "\\" was not found on this device. Re-check /interface print and re-generate with the CURRENT name. Aborting. ***")',
                f'  :error ("cloudguest-setup: WAN interface " . {expr} . " not found")',
                "}",
            ]
        )
    return lines


def render_wan_bridge_section(ctx: WanRenderContext) -> list[str]:
    lines = [WAN_RENAME_WARNING]
    lines.append(
        ':if ([:len [/interface list find where name="WAN"]] = 0) do={ /interface list add name="WAN" }'
    )
    lines.append(
        f':if ([:len [/interface bridge find where name="{_escape_routeros_string(ctx.lan_bridge)}"]] = 0) do={{ /interface bridge add name="{_escape_routeros_string(ctx.lan_bridge)}" }}'
    )
    lines.append(
        f'/interface bridge set [find name="{_escape_routeros_string(ctx.lan_bridge)}"] disabled=no'
    )
    lines.extend(
        _wan_existence_check_lines([link.physical_interface for link in ctx.links])
    )
    for link in ctx.links:
        n = link.slot
        phys = _escape_routeros_string(link.physical_interface)
        lines.append(
            f':local wan{n}Port [/interface bridge port find where interface="{phys}"]'
        )
        lines.append(
            f":if ([:len $wan{n}Port] > 0) do={{ /interface bridge port remove $wan{n}Port }}"
        )
        if link.connection_mode is IspConnectionMode.PPPOE:
            continue
        eff = _escape_routeros_string(link.effective_interface)
        lines.append(
            f':if ([:len [/interface list member find where interface="{eff}" list="WAN"]] = 0) do={{ /interface list member add list="WAN" interface="{eff}" }}'
        )
        lines.append(
            f':if ([:len [/ip firewall nat find where chain=srcnat out-interface="{eff}" action=masquerade]] = 0) do={{ /ip firewall nat add chain=srcnat out-interface="{eff}" action=masquerade comment="cloudguest-nat-wan{n}" }}'
        )
    return lines


def render_stale_defconf_dhcp_cleanup() -> list[str]:
    return [
        ':local staleDefconfClient [/ip dhcp-client find where interface="bridgeLocal"]',
        ":if ([:len $staleDefconfClient] > 0) do={ /ip dhcp-client remove $staleDefconfClient }",
    ]


def render_wan_addressing_section(ctx: WanRenderContext) -> list[str]:
    lines: list[str] = []
    for link in ctx.links:
        n = link.slot
        phys = _escape_routeros_string(link.physical_interface)
        if link.connection_mode is IspConnectionMode.STATIC:
            address = link.static_address
            if not address:
                continue
            lines.append(
                f':foreach staleAddr in=[/ip address find where interface="{phys}" dynamic=yes] do={{ /ip address remove $staleAddr }}'
            )
            lines.append(
                f':if ([:len [/ip address find where interface="{phys}" address="{_escape_routeros_string(address)}"]] = 0) do={{'
            )
            lines.append(
                f'  /ip address add address="{_escape_routeros_string(address)}" interface="{phys}" comment="cloudguest-addr-wan{n}"'
            )
            lines.append("}")
        elif link.connection_mode is IspConnectionMode.DHCP:
            lines.append(
                f':local wan{n}CloudguestClient [/ip dhcp-client find where interface="{phys}" comment="cloudguest-dhcp-wan{n}"]'
            )
            lines.append(f":if ([:len $wan{n}CloudguestClient] = 0) do={{")
            lines.append(
                f'  :local wan{n}OtherClient [/ip dhcp-client find where interface="{phys}"]'
            )
            lines.append(
                f"  :if ([:len $wan{n}OtherClient] > 0) do={{ /ip dhcp-client remove $wan{n}OtherClient }}"
            )
            lines.append(
                f'  :foreach staleAddr in=[/ip address find where interface="{phys}" dynamic=yes] do={{ /ip address remove $staleAddr }}'
            )
            lines.append(
                f'  /ip dhcp-client add interface="{phys}" disabled=no add-default-route=no use-peer-dns=no comment="cloudguest-dhcp-wan{n}"'
            )
            lines.append("}")
        elif link.connection_mode is IspConnectionMode.PPPOE:
            eff = _escape_routeros_string(link.effective_interface)
            user = _escape_routeros_string(link.pppoe_username or "")
            password = _escape_routeros_string(link.pppoe_password or "")
            lines.append(
                f':local wan{n}CloudguestPppoeClient [/interface pppoe-client find where interface="{phys}" comment="cloudguest-pppoe-wan{n}"]'
            )
            lines.append(f":if ([:len $wan{n}CloudguestPppoeClient] = 0) do={{")
            lines.append(
                f'  :local wan{n}OtherPppoeClient [/interface pppoe-client find where interface="{phys}"]'
            )
            lines.append(
                f"  :if ([:len $wan{n}OtherPppoeClient] > 0) do={{ /interface pppoe-client remove $wan{n}OtherPppoeClient }}"
            )
            lines.append(
                f'  :foreach staleAddr in=[/ip address find where interface="{phys}" dynamic=yes] do={{ /ip address remove $staleAddr }}'
            )
            lines.append(
                f'  /interface pppoe-client add name="{eff}" interface="{phys}" user="{user}" password="{password}" disabled=no add-default-route=no comment="cloudguest-pppoe-wan{n}"'
            )
            lines.append("}")
            lines.append(
                f':if ([:len [/interface list member find where interface="{eff}" list="WAN"]] = 0) do={{ /interface list member add list="WAN" interface="{eff}" }}'
            )
            lines.append(
                f':if ([:len [/ip firewall nat find where chain=srcnat out-interface="{eff}" action=masquerade]] = 0) do={{ /ip firewall nat add chain=srcnat out-interface="{eff}" action=masquerade comment="cloudguest-nat-wan{n}" }}'
            )
    return lines


def render_wan_routing_section(ctx: WanRenderContext) -> list[str]:
    lines: list[str] = []
    for link in ctx.links:
        n = link.slot
        if link.connection_mode is IspConnectionMode.STATIC:
            gw = _escape_routeros_string(link.gateway or "")
            lines.append(f':local wan{n}Gw "{gw}"')
        elif link.connection_mode is IspConnectionMode.PPPOE:
            eff = _escape_routeros_string(link.effective_interface)
            lines.append(f':local wan{n}Gw ""')
            lines.append(
                f':if ([:len [/interface pppoe-client find where name="{eff}"]] > 0) do={{ :do {{ :set wan{n}Gw ([/interface pppoe-client monitor [find name="{eff}"] once as-value]->"remote-address") }} on-error={{ :log warning "cloudguest: PPPoE WAN{n} gateway not resolved yet" }} }}'
            )
        else:
            phys = _escape_routeros_string(link.physical_interface)
            lines.append(f':local wan{n}Gw ""')
            lines.append(
                f':if ([:len [/ip dhcp-client find where interface="{phys}"]] > 0) do={{ :set wan{n}Gw [/ip dhcp-client get [find interface="{phys}"] gateway] }}'
            )

    multi = len(ctx.links) > 1
    load_balance = ctx.wan_routing_mode is WanRoutingMode.LOAD_BALANCE
    for link in ctx.links:
        n = link.slot
        lines.append(f":if ($wan{n}Gw != \"\") do={{")
        lines.append(
            f'  :local plainRoute{n} [/ip route find where comment="cloudguest-plain-wan{n}"]'
        )
        lines.append(
            f'  :if ([:len $plainRoute{n}] = 0) do={{ :set plainRoute{n} [/ip route find where dst-address="0.0.0.0/0" gateway=$wan{n}Gw routing-mark=""] }}'
        )
        lines.append(f"  :if ([:len $plainRoute{n}] = 0) do={{")
        lines.append(
            f'    /ip route add dst-address=0.0.0.0/0 gateway=$wan{n}Gw distance={n} check-gateway=ping comment="cloudguest-plain-wan{n}"'
        )
        lines.append(
            f"  }} else={{ /ip route set $plainRoute{n} gateway=$wan{n}Gw distance={n} check-gateway=ping comment=\"cloudguest-plain-wan{n}\" }}"
        )
        if multi and load_balance:
            lines.append(
                f'  :if ([:len [/ip route find where comment="cloudguest-route-wan{n}"]] = 0) do={{'
            )
            lines.append(
                f'    /ip route add dst-address=0.0.0.0/0 gateway=$wan{n}Gw routing-mark="to_wan{n}" distance=1 check-gateway=ping comment="cloudguest-route-wan{n}"'
            )
            lines.append(
                f'  }} else={{ /ip route set [find comment="cloudguest-route-wan{n}"] gateway=$wan{n}Gw }}'
            )
            next_n = (n % len(ctx.links)) + 1
            lines.append(
                f'  :if ([:len [/ip route find where comment="cloudguest-backup-wan{next_n}-via-wan{n}"]] = 0) do={{'
            )
            lines.append(
                f'    /ip route add dst-address=0.0.0.0/0 gateway=$wan{n}Gw routing-mark="to_wan{next_n}" distance=2 check-gateway=ping comment="cloudguest-backup-wan{next_n}-via-wan{n}"'
            )
            lines.append(
                f'  }} else={{ /ip route set [find comment="cloudguest-backup-wan{next_n}-via-wan{n}"] gateway=$wan{n}Gw }}'
            )
        lines.append("}")

    if multi and ctx.wan_routing_mode is WanRoutingMode.FAILOVER_ONLY:
        lines.append(
            ':foreach r in=[/ip route find where comment~"^cloudguest-route-wan"] do={ /ip route remove $r }'
        )
        lines.append(
            ':foreach r in=[/ip route find where comment~"^cloudguest-backup-wan"] do={ /ip route remove $r }'
        )
    return lines


def render_wan_mangle_section(ctx: WanRenderContext) -> list[str]:
    if len(ctx.links) < 2 or ctx.wan_routing_mode is not WanRoutingMode.LOAD_BALANCE:
        return []
    weights = [link.load_balance_weight for link in ctx.links]
    weighted_plan = None
    if all(w is not None and w > 0 for w in weights):
        weighted_plan = build_weighted_pcc_plan([int(w) for w in weights if w is not None])
    lines: list[str] = []
    lan = _escape_routeros_string(ctx.lan_bridge)
    if weighted_plan is not None:
        lines.append(
            ':foreach r in=[/ip firewall mangle find where comment~"^cloudguest-mangle-pcc-wan"] do={ /ip firewall mangle remove $r }'
        )
    for idx, link in enumerate(ctx.links):
        n = link.slot
        wan_if = _escape_routeros_string(link.effective_interface)
        lines.append(
            f':if ([:len [/ip firewall mangle find where comment="cloudguest-mangle-input-wan{n}"]] = 0) do={{'
        )
        lines.append(
            f'  /ip firewall mangle add chain=input in-interface="{wan_if}" action=mark-connection new-connection-mark="wan{n}_conn" passthrough=yes comment="cloudguest-mangle-input-wan{n}"'
        )
        lines.append("}")
        if weighted_plan is not None:
            for i in weighted_plan.indices_by_wan[idx]:
                lines.append(
                    f':if ([:len [/ip firewall mangle find where comment="cloudguest-mangle-pcc-wan{n}-idx{i}"]] = 0) do={{'
                )
                lines.append(
                    f'  /ip firewall mangle add chain=prerouting in-interface="{lan}" dst-address-type=!local connection-mark=no-mark per-connection-classifier=both-addresses-and-ports:{weighted_plan.total}/{i} action=mark-connection new-connection-mark="wan{n}_conn" passthrough=yes comment="cloudguest-mangle-pcc-wan{n}-idx{i}"'
                )
                lines.append("}")
        else:
            lines.append(
                f':if ([:len [/ip firewall mangle find where comment="cloudguest-mangle-pcc-wan{n}"]] = 0) do={{'
            )
            lines.append(
                f'  /ip firewall mangle add chain=prerouting in-interface="{lan}" dst-address-type=!local connection-mark=no-mark per-connection-classifier=both-addresses-and-ports:{len(ctx.links)}/{idx} action=mark-connection new-connection-mark="wan{n}_conn" passthrough=yes comment="cloudguest-mangle-pcc-wan{n}"'
            )
            lines.append("}")
        lines.append(
            f':if ([:len [/ip firewall mangle find where comment="cloudguest-mangle-route-wan{n}"]] = 0) do={{'
        )
        lines.append(
            f'  /ip firewall mangle add chain=prerouting connection-mark="wan{n}_conn" action=mark-routing new-routing-mark="to_wan{n}" passthrough=yes comment="cloudguest-mangle-route-wan{n}"'
        )
        lines.append("}")
    return lines


def render_wan_dns_section(ctx: WanRenderContext) -> list[str]:
    servers = _escape_routeros_string(ctx.dns_servers)
    return [
        f'/ip dns set servers="{servers}" allow-remote-requests=yes',
        ':if ([:len [/ip firewall filter find where comment="cloudguest-fw-block-wan-dns"]] = 0) do={ /ip firewall filter add chain=input in-interface-list=WAN protocol=udp dst-port=53 action=drop comment="cloudguest-fw-block-wan-dns" }',
        ':if ([:len [/ip firewall filter find where comment="cloudguest-fw-block-wan-dns-tcp"]] = 0) do={ /ip firewall filter add chain=input in-interface-list=WAN protocol=tcp dst-port=53 action=drop comment="cloudguest-fw-block-wan-dns-tcp" }',
    ]
