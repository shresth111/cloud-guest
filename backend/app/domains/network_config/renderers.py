"""Pure functions that turn real ``DhcpPool``/``Vlan``/``PortForwardingRule``
rows into real RouterOS script text (``/ip pool``, ``/ip dhcp-server``,
``/interface vlan``, ``/ip address``, ``/ip firewall nat``).

Every function here takes already-filtered, already-enabled rows -- "which
rows get rendered" (``is_enabled``, tenant scoping) is ``service.py``'s own
concern; these functions only decide "how does *this one* row become a
RouterOS command."

## DHCP: the subnet-mask gap, honestly handled

``DhcpPool`` stores an address *range* (``address_range_start``/
``address_range_end``) and an optional ``gateway_ip_address`` -- it has no
subnet-mask/CIDR column at all. RouterOS's own ``/ip dhcp-server network``
entry (which is what actually carries the gateway/DNS/lease-time options
out to clients) needs a real CIDR block, not a bare range. Rather than
fabricate a conventional ``/24`` that could be flatly wrong for a given
deployment, :func:`_smallest_enclosing_network` computes the mathematically
smallest real CIDR block that is guaranteed to contain the configured
range (searching prefix lengths from ``/32`` down until one fully covers
both bounds) -- an honest, exact answer to "what block *at minimum* must
this subnet be," not a guess at what the admin actually intended. If the
real LAN subnet is wider than this pool's own configured range (a common,
legitimate setup -- e.g. pool ``.100-.200`` inside a ``/24``), the
resulting network entry will be narrower than reality and the pushed
config's ``/ip dhcp-server network`` block should be widened by the admin
after review; this is called out explicitly rather than silently assumed
away, mirroring ``app.domains.dhcp.models.DhcpPool``'s own module
docstring precedent for documenting a real, unclosed gap plainly instead
of pretending it doesn't exist.

## VLAN: interface naming needs no invented identifier

``Vlan.vlan_id`` is already enforced unique per router by a real, partial
database index (``uq_vlans_router_id_vlan_id``) -- ``vlan{vlan_id}`` is
therefore a real, guaranteed-collision-free RouterOS interface name with
no fabricated suffix needed, unlike DHCP pool/server names (see
:func:`_dhcp_identifier`).

## Port Forwarding: ``BOTH`` maps to omitting ``protocol=``, not a literal value

RouterOS's ``/ip firewall nat`` rule matches every transport protocol when
``protocol=`` is omitted entirely -- there is no ``protocol=both`` value in
real RouterOS syntax. ``PortForwardingProtocol.BOTH`` is therefore rendered
by omitting the parameter, the actual honest equivalent, not a fabricated
keyword no real device would understand.

## Hotspot: user-profile + walled-garden only, not the server bind

Mirrors ``app.domains.hotspot.models.HotspotProfile``'s own module
docstring: only RouterOS's ``/ip hotspot user profile`` (session-timeout/
idle-timeout/rate-limit) and ``/ip hotspot walled-garden`` (allowed
hosts) are rendered -- never a full ``/ip hotspot add`` server bind,
which would need an interface/address-pool this table has no data for.
``rate-limit`` mirrors ``app.domains.queue_management.service
.format_mikrotik_rate_limit``'s own rx=upload/tx=download convention,
substituting ``0`` (RouterOS's own "unlimited" value) for whichever half
of the pair is unset.

## DNS: type inferred from the record itself, never a separate column

``DnsRecord.record_type`` already carries A/AAAA/CNAME -- ``/ip dns
static`` renders ``address=`` for A/AAAA records and ``cname=`` for CNAME,
matching RouterOS's own real, distinct parameter names for each shape
(there is no single parameter that means both).

## Firewall: rendered in ascending ``priority`` order

Mirrors ``app.domains.firewall.models.FirewallRule``'s own module
docstring: rule order is semantically significant in a real RouterOS
firewall filter, so ``service.py``'s own
``FirewallRepository.list_rules_for_router`` already returns rows sorted
by ``priority`` ascending -- this renderer trusts that ordering rather
than re-sorting, the same "sorting is the repository's job, rendering is
this function's job" split every other renderer here already follows.
``FirewallProtocol.ALL`` omits ``protocol=`` entirely, the identical
"omit the parameter, don't fabricate a value RouterOS wouldn't recognize"
convention ``PortForwardingProtocol.BOTH`` already establishes.

## QoS: marks traffic, never creates the paired queue

Mirrors ``app.domains.qos.models.QosTrafficRule``'s own module
docstring: only RouterOS's ``/ip firewall mangle`` packet-marking half of
real QoS is rendered here -- a real ``new-packet-mark`` derived from the
rule's own identifier, matched either by protocol/port range or by DSCP
value (never both, enforced at that domain's own service layer).
Pairing this mark with an actual ``/queue tree`` entry (the half that
would make the mark do anything) is real, separate device-side work,
deliberately left undone and documented rather than fabricated -- see
``docs/qos/FLOW.md`` §2.
"""

from __future__ import annotations

import ipaddress

from app.domains.dhcp.models import DhcpPool
from app.domains.dns.constants import DnsRecordType
from app.domains.dns.models import DnsRecord
from app.domains.firewall.constants import FirewallProtocol
from app.domains.firewall.models import FirewallRule
from app.domains.hotspot.models import HotspotProfile
from app.domains.port_forwarding.constants import PortForwardingProtocol
from app.domains.port_forwarding.models import PortForwardingRule
from app.domains.qos.models import QosTrafficRule
from app.domains.vlan.models import Vlan

from .constants import (
    DHCP_SECTION_HEADER,
    DNS_SECTION_HEADER,
    FIREWALL_SECTION_HEADER,
    HOTSPOT_SECTION_HEADER,
    PORT_FORWARDING_SECTION_HEADER,
    QOS_SECTION_HEADER,
    VLAN_SECTION_HEADER,
)


def _sanitize_identifier(name: str) -> str:
    """Lowercases and replaces every character that is not alphanumeric/
    ``-``/``_`` with ``-`` -- a real RouterOS identifier must not contain
    spaces or most punctuation."""
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in name)
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-") or "unnamed"


def _dhcp_identifier(pool: DhcpPool) -> str:
    """``DhcpPool.name`` carries no uniqueness constraint -- suffixing with
    the row's own real, guaranteed-unique primary key avoids a RouterOS
    name collision between two differently-configured pools that happen
    to share a display name."""
    return f"{_sanitize_identifier(pool.name)}-{str(pool.id)[:8]}"


def _hotspot_identifier(profile: HotspotProfile) -> str:
    """``HotspotProfile.name`` carries no uniqueness constraint -- same
    reasoning as :func:`_dhcp_identifier`."""
    return f"{_sanitize_identifier(profile.name)}-{str(profile.id)[:8]}"


def _qos_identifier(rule: QosTrafficRule) -> str:
    """``QosTrafficRule.name`` carries no uniqueness constraint -- same
    reasoning as :func:`_dhcp_identifier`."""
    return f"{_sanitize_identifier(rule.name)}-{str(rule.id)[:8]}"


def _smallest_enclosing_network(
    start: str, end: str
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """See module docstring's DHCP section: the smallest real CIDR block
    guaranteed to contain both bounds, computed exactly -- never a
    fabricated conventional mask."""
    start_ip = ipaddress.ip_address(start)
    end_ip = ipaddress.ip_address(end)
    for prefix_len in range(start_ip.max_prefixlen, -1, -1):
        candidate = ipaddress.ip_network(f"{start_ip}/{prefix_len}", strict=False)
        if start_ip in candidate and end_ip in candidate:
            return candidate
    return ipaddress.ip_network(f"{start_ip}/0", strict=False)


def render_dhcp_pool(pool: DhcpPool) -> list[str]:
    """Renders one enabled ``DhcpPool`` row -- see module docstring for
    the subnet-derivation caveat. Emits pool-only lines (no dhcp-server
    binding) when ``interface`` is unset, since RouterOS requires a real
    interface to bind a DHCP server to."""
    identifier = _dhcp_identifier(pool)
    lines = [
        f"/ip pool add name={identifier}-pool "
        f"ranges={pool.address_range_start}-{pool.address_range_end}"
    ]
    if pool.interface is None:
        lines.append(
            f"# {identifier}: no interface configured -- skipping "
            "dhcp-server binding, pool only"
        )
        return lines

    lines.append(
        f"/ip dhcp-server add name={identifier}-dhcp interface={pool.interface} "
        f"address-pool={identifier}-pool disabled=no"
    )
    network = _smallest_enclosing_network(
        pool.address_range_start, pool.address_range_end
    )
    network_parts = [f"/ip dhcp-server network add address={network}"]
    if pool.gateway_ip_address:
        network_parts.append(f"gateway={pool.gateway_ip_address}")
    dns_servers = [dns for dns in (pool.dns_primary, pool.dns_secondary) if dns]
    if dns_servers:
        network_parts.append(f"dns-server={','.join(dns_servers)}")
    network_parts.append(f"lease-time={pool.lease_time_seconds}s")
    lines.append(" ".join(network_parts))
    return lines


def render_vlan(vlan: Vlan) -> list[str]:
    """Renders one enabled ``Vlan`` row -- see module docstring for why
    ``vlan{vlan_id}`` needs no fabricated uniqueness suffix. Emits the
    tagged interface only (no ``/ip address``) when ``interface`` (the
    parent) is unset, since RouterOS requires a real parent interface to
    tag a VLAN onto."""
    vlan_interface = f"vlan{vlan.vlan_id}"
    if vlan.interface is None:
        return [
            f"# {vlan_interface}: no parent interface configured -- "
            "skipping, cannot tag a VLAN without one"
        ]
    lines = [
        f"/interface vlan add name={vlan_interface} vlan-id={vlan.vlan_id} "
        f"interface={vlan.interface}"
    ]
    if vlan.cidr:
        address = (
            f"{vlan.gateway_ip_address}/{vlan.cidr.split('/')[-1]}"
            if vlan.gateway_ip_address
            else vlan.cidr
        )
        lines.append(f"/ip address add address={address} interface={vlan_interface}")
    return lines


def render_port_forwarding_rule(rule: PortForwardingRule) -> list[str]:
    """Renders one enabled ``PortForwardingRule`` row -- see module
    docstring for why ``BOTH`` omits ``protocol=`` rather than emitting a
    fabricated ``protocol=both``."""
    parts = ["/ip firewall nat add chain=dstnat"]
    if rule.protocol != PortForwardingProtocol.BOTH:
        parts.append(f"protocol={rule.protocol}")
    if rule.destination_address:
        parts.append(f"dst-address={rule.destination_address}")
    parts.append(f"dst-port={rule.destination_port}")
    if rule.source_address:
        parts.append(f"src-address={rule.source_address}")
    parts.append("action=dst-nat")
    parts.append(f"to-addresses={rule.internal_address}")
    parts.append(f"to-ports={rule.internal_port}")
    parts.append(f'comment="{rule.name}"')
    return [" ".join(parts)]


def render_hotspot_profile(profile: HotspotProfile) -> list[str]:
    """Renders one enabled ``HotspotProfile`` row -- see module docstring
    for why only the user-profile/walled-garden slice is modeled."""
    identifier = _hotspot_identifier(profile)
    parts = [f"/ip hotspot user profile add name={identifier}"]
    if profile.session_timeout_minutes is not None:
        parts.append(f"session-timeout={profile.session_timeout_minutes}m")
    if profile.idle_timeout_minutes is not None:
        parts.append(f"idle-timeout={profile.idle_timeout_minutes}m")
    if profile.upload_limit_kbps is not None or profile.download_limit_kbps is not None:
        parts.append(
            f"rate-limit={profile.upload_limit_kbps or 0}k/"
            f"{profile.download_limit_kbps or 0}k"
        )
    lines = [" ".join(parts)]
    for host in profile.walled_garden_hosts:
        lines.append(
            f"/ip hotspot walled-garden add dst-host={host} action=allow "
            f'comment="{profile.name}"'
        )
    return lines


def render_qos_traffic_rule(rule: QosTrafficRule) -> list[str]:
    """Renders one enabled ``QosTrafficRule`` row -- see module docstring
    for why only the mangle mark half of real QoS is modeled. Matches by
    port range when both bounds are present, otherwise by ``dscp_value``
    (the two are mutually exclusive, enforced at
    ``app.domains.qos.validators.validate_traffic_match``)."""
    identifier = _qos_identifier(rule)
    parts = ["/ip firewall mangle add chain=prerouting"]
    if rule.port_range_start is not None and rule.port_range_end is not None:
        parts.append(f"protocol={rule.protocol}")
        parts.append(f"dst-port={rule.port_range_start}-{rule.port_range_end}")
    else:
        parts.append(f"dscp={rule.dscp_value}")
    parts.append("action=mark-packet")
    parts.append(f"new-packet-mark={identifier}")
    parts.append("passthrough=no")
    parts.append(f'comment="{rule.name} (priority={rule.priority})"')
    return [" ".join(parts)]


def render_dns_record(record: DnsRecord) -> list[str]:
    """Renders one enabled ``DnsRecord`` row -- see module docstring for
    why the RouterOS parameter name depends on ``record_type``."""
    parts = [f"/ip dns static add name={record.name} ttl={record.ttl_seconds}s"]
    if record.record_type == DnsRecordType.CNAME.value:
        parts.append(f"cname={record.address} type=CNAME")
    else:
        parts.append(f"address={record.address}")
    if record.comment:
        parts.append(f'comment="{record.comment}"')
    return [" ".join(parts)]


def render_firewall_rule(rule: FirewallRule) -> list[str]:
    """Renders one enabled ``FirewallRule`` row -- see module docstring
    for why ``ALL`` omits ``protocol=`` and why callers must already have
    sorted ``rule`` by ``priority`` ascending before calling this."""
    parts = [f"/ip firewall filter add chain={rule.chain}"]
    if rule.protocol != FirewallProtocol.ALL.value:
        parts.append(f"protocol={rule.protocol}")
    if rule.source_address:
        parts.append(f"src-address={rule.source_address}")
    if rule.destination_address:
        parts.append(f"dst-address={rule.destination_address}")
    if rule.source_port is not None:
        parts.append(f"src-port={rule.source_port}")
    if rule.destination_port is not None:
        parts.append(f"dst-port={rule.destination_port}")
    if rule.in_interface:
        parts.append(f"in-interface={rule.in_interface}")
    parts.append(f"action={rule.action}")
    comment = rule.comment or rule.name
    parts.append(f'comment="{comment} (priority={rule.priority})"')
    return [" ".join(parts)]


def render_network_config(
    *,
    dhcp_pools: list[DhcpPool],
    vlans: list[Vlan],
    port_forwarding_rules: list[PortForwardingRule],
    hotspot_profiles: list[HotspotProfile] | None = None,
    qos_traffic_rules: list[QosTrafficRule] | None = None,
    dns_records: list[DnsRecord] | None = None,
    firewall_rules: list[FirewallRule] | None = None,
) -> str:
    """Combines every enabled row across all five categories into one
    router-wide RouterOS script -- a full desired-state snapshot, mirroring
    how ``app.domains.router_provisioning.models.ConfigVersion`` already
    represents a router's *whole* config rather than an incremental diff.
    Returns an empty string if every input is empty -- callers
    (``service.py``) decide whether that is an error (a push) or a valid,
    informational result (a preview)."""
    sections: list[str] = []
    if dhcp_pools:
        sections.append(DHCP_SECTION_HEADER)
        for pool in dhcp_pools:
            sections.extend(render_dhcp_pool(pool))
    if vlans:
        sections.append(VLAN_SECTION_HEADER)
        for vlan in vlans:
            sections.extend(render_vlan(vlan))
    if port_forwarding_rules:
        sections.append(PORT_FORWARDING_SECTION_HEADER)
        for rule in port_forwarding_rules:
            sections.extend(render_port_forwarding_rule(rule))
    if hotspot_profiles:
        sections.append(HOTSPOT_SECTION_HEADER)
        for profile in hotspot_profiles:
            sections.extend(render_hotspot_profile(profile))
    if qos_traffic_rules:
        sections.append(QOS_SECTION_HEADER)
        for rule in qos_traffic_rules:
            sections.extend(render_qos_traffic_rule(rule))
    if dns_records:
        sections.append(DNS_SECTION_HEADER)
        for record in dns_records:
            sections.extend(render_dns_record(record))
    if firewall_rules:
        sections.append(FIREWALL_SECTION_HEADER)
        for rule in firewall_rules:
            sections.extend(render_firewall_rule(rule))
    return "\n".join(sections)


__all__ = [
    "render_dhcp_pool",
    "render_vlan",
    "render_port_forwarding_rule",
    "render_hotspot_profile",
    "render_qos_traffic_rule",
    "render_dns_record",
    "render_firewall_rule",
    "render_network_config",
]
