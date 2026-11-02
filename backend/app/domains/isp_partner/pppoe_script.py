# ruff: noqa: E501 -- RouterOS script text is kept verbatim
"""The RouterOS PPPoE-server step (Phase 2b, JAZE-6).

The partner app appends this block to the main setup script, before the
TR-069 step, which may reboot at the very end. The existing generator is not
edited. Every line is one self-contained console statement, and every object
is found by its ``wyfy-pppoe`` comment and replaced, so pasting it twice
gives the same router (RouterOS 6.x and 7.x syntax).

What it writes:
  /ip pool                 wyfy-pppoe-pool (the subscriber address range)
  /ppp profile             wyfy-pppoe (local address, pool, DNS, interface-list LAN,
                           only-one=yes (no when the ISP sells multi-device
                           PPPoE packages and enforcement is on), change-tcp-mss)
  /ppp aaa                 use-radius=yes accounting=yes interim-update
  /radius                  service=ppp -> hub tunnel IP, ports 1922/1923 (X2),
                           the router's existing NAS secret, the tunnel source
  /interface pppoe-server  server on the chosen interface, chap/mschap2/pap,
                           one-session-per-host
  /ip firewall nat         srcnat masquerade for the pool, WAN out only

Nothing is written to the hotspot, the existing ``service=hotspot`` RADIUS
entry, or the firewall filter chain.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

__all__ = ["PPPOE_COMMENT", "PppoeScriptParams", "render_pppoe_script", "ros_quote"]

PPPOE_COMMENT = "wyfy-pppoe"
POOL_NAME = "wyfy-pppoe-pool"
PROFILE_NAME = "wyfy-pppoe"
SERVICE_NAME = "wyfy"


def ros_quote(value: str) -> str:
    """A RouterOS double-quoted string literal. Newlines are refused."""
    if "\n" in value or "\r" in value:
        raise ValueError("newline in RouterOS value")
    return (
        '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'
    )


def _ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def _range(value: str) -> str:
    lo, _, hi = value.strip().partition("-")
    a, b = ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip())
    if a.version != 4 or b.version != 4 or int(b) < int(a):
        raise ValueError("pool range must be an IPv4 a-b range, low to high")
    return f"{a}-{b}"


def _cidr(value: str) -> str:
    net = ipaddress.ip_network(value.strip(), strict=False)
    if net.version != 4:
        raise ValueError("pool cidr must be IPv4")
    return str(net)


_IFACE_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")


def _iface(value: str) -> str:
    v = value.strip()
    if not v or len(v) > 64 or any(c not in _IFACE_OK for c in v):
        raise ValueError("interface name may use letters, digits, - _ . only")
    return v


@dataclass(frozen=True)
class PppoeScriptParams:
    interface: str
    local_address: str
    pool_range: str
    pool_cidr: str
    dns_servers: tuple[str, ...]
    hub_tunnel_ip: str
    router_tunnel_ip: str
    nas_secret: str
    auth_port: int
    acct_port: int
    interim_seconds: int
    #: ENFORCE-3: ``only-one=no`` lets the router accept a second session of
    #: the same username, so a package's "max devices" above 1 can work; our
    #: RADIUS concurrency gate then enforces the limit. True (``only-one=yes``)
    #: is the JAZE-6 default and what every setup gets while the enforcement
    #: flag is off.
    only_one: bool = True

    def validated(self) -> PppoeScriptParams:
        local = _ip(self.local_address)
        pool = _range(self.pool_range)
        cidr = _cidr(self.pool_cidr)
        net = ipaddress.ip_network(cidr)
        lo, _, hi = pool.partition("-")
        if ipaddress.ip_address(lo) not in net or ipaddress.ip_address(hi) not in net:
            raise ValueError("pool range must sit inside the pool cidr")
        if ipaddress.ip_address(local) not in net:
            raise ValueError("local address must sit inside the pool cidr")
        if not (1 <= self.auth_port <= 65535 and 1 <= self.acct_port <= 65535):
            raise ValueError("bad RADIUS port")
        if not self.nas_secret:
            raise ValueError("router has no RADIUS NAS secret yet")
        return PppoeScriptParams(
            interface=_iface(self.interface),
            local_address=local,
            pool_range=pool,
            pool_cidr=cidr,
            dns_servers=tuple(_ip(d) for d in self.dns_servers) or (local,),
            hub_tunnel_ip=_ip(self.hub_tunnel_ip),
            router_tunnel_ip=_ip(self.router_tunnel_ip),
            nas_secret=self.nas_secret,
            auth_port=self.auth_port,
            acct_port=self.acct_port,
            interim_seconds=self.interim_seconds,
            only_one=bool(self.only_one),
        )


def render_pppoe_script(params: PppoeScriptParams) -> str:
    p = params.validated()
    c = ros_quote(PPPOE_COMMENT)
    dns = ",".join(p.dns_servers)
    interim = f"{max(60, p.interim_seconds) // 60}m"
    lines = [
        f"# Wyfy PPPoE server step ({PPPOE_COMMENT}). Safe to paste again.",
        f':put "wyfy: PPPoE server on {p.interface}, pool {p.pool_range}"',
        # pool
        f"/ip pool remove [find where name={ros_quote(POOL_NAME)}]",
        f"/ip pool add name={ros_quote(POOL_NAME)} ranges={p.pool_range} comment={c}",
        # profile (interface-list only when a LAN list exists, so DNS and the
        # router's own services answer subscribers under the existing input
        # rules that trust LAN)
        f"/ppp profile remove [find where name={ros_quote(PROFILE_NAME)}]",
        f"/ppp profile add name={ros_quote(PROFILE_NAME)} local-address={p.local_address} remote-address={ros_quote(POOL_NAME)} dns-server={dns} only-one={"yes" if p.only_one else "no"} change-tcp-mss=yes use-encryption=default comment={c}",
        f':if ([:len [/interface list find where name="LAN"]] > 0) do={{ /ppp profile set [find where name={ros_quote(PROFILE_NAME)}] interface-list=LAN }}',
        # AAA through our RADIUS
        f"/ppp aaa set use-radius=yes accounting=yes interim-update={interim}",
        f"/radius remove [find where comment={c}]",
        f"/radius add service=ppp address={p.hub_tunnel_ip} src-address={p.router_tunnel_ip} secret={ros_quote(p.nas_secret)} authentication-port={p.auth_port} accounting-port={p.acct_port} timeout=3s comment={c}",
        # the server
        f"/interface pppoe-server server remove [find where service-name={ros_quote(SERVICE_NAME)}]",
        f"/interface pppoe-server server add service-name={ros_quote(SERVICE_NAME)} interface={ros_quote(p.interface)} default-profile={ros_quote(PROFILE_NAME)} authentication=pap,chap,mschap2 one-session-per-host=yes keepalive-timeout=30 disabled=no",
        # NAT for the pool, only towards WAN
        f"/ip firewall nat remove [find where comment={c}]",
        f':if ([:len [/interface list find where name="WAN"]] > 0) do={{ /ip firewall nat add chain=srcnat src-address={p.pool_cidr} out-interface-list=WAN action=masquerade comment={c} }} else={{ /ip firewall nat add chain=srcnat src-address={p.pool_cidr} action=masquerade comment={c} }}',
        ':put "wyfy: PPPoE server step done"',
    ]
    return "\n".join(lines) + "\n"
