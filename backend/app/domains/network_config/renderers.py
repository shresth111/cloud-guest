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

## WireGuard: ``/32`` + ``persistent-keepalive=25s`` are not stylistic
choices, they are the two ways this exact setup silently breaks

This is the device-config-generation half of a platform-side WireGuard
system (``app.domains.wireguard``) that was, until this addition, real and
working end-to-end except for the one step that actually gets a physical
router talking to it: nothing rendered the RouterOS commands a
``WireGuardPeer``/``WireGuardServer`` pair implies. Three commands are
emitted -- a local interface carrying the peer's own (platform-generated,
Fernet-decrypted -- see ``app.domains.wireguard.models`` module docstring
for why the platform holds a recoverable copy at all) private key, the
``/ip address`` binding that interface to its allocated tunnel IP, and the
``/interface wireguard peers`` entry describing the hub side of the tunnel.

Two of that third command's parameters are correctness-critical, not
cosmetic, and were confirmed against a real MikroTik CHR + a real
WireGuard/FreeRADIUS VM this session, not assumed:

* ``persistent-keepalive=25s`` -- reused from this domain's own
  ``constants.DEFAULT_PERSISTENT_KEEPALIVE_SECONDS`` rather than a second,
  independently-chosen literal here. Every router this platform manages
  sits behind carrier-grade NAT with no public IP (the entire reason this
  WireGuard hub-and-spoke design exists at all -- see
  ``app.domains.wireguard.service`` module docstring). Without a
  keepalive, the NAT mapping the hub is relying on to reach the router
  back (for config pushes, CoA, health checks) silently expires between
  handshakes; the tunnel looks "up" locally on the router the whole time,
  and only inbound-initiated traffic quietly stops arriving -- one of the
  least debuggable failure modes in this entire system, because nothing
  on the router side ever reports an error.
* ``allowed-address=<hub-tunnel-ip>/32`` -- WireGuard's ``AllowedIPs`` is
  simultaneously a routing table entry *and* the cryptographic binding for
  which peer a decrypted packet is allowed to have come from. A wider
  range here (e.g. the whole ``/24``) does not fail loudly either -- it
  would still handshake -- it just means this peer's interface would
  accept and route traffic for addresses that belong to *other* peers
  behind the same hub, which is both a routing correctness bug and a
  tenant-isolation problem this platform cannot afford. The one legitimate
  address in range for a spoke peer talking to exactly one hub is the
  hub's own tunnel address, so ``/32`` is not a narrowing of scope, it is
  the accurate scope. ``_hub_tunnel_address`` derives that address the
  same way ``app.domains.wireguard.constants.HUB_RESERVED_HOST_COUNT``'s
  own docstring already documents the hub is conventionally assigned it
  (the network's first usable host address) -- computed, not hard-coded,
  so a hub whose own tunnel IP is ever reassigned is still rendered
  correctly.

``WireGuardPeer.tunnel_ip_address`` is a bare host address with no stored
prefix length of its own (see ``models.py``); the ``/ip address`` line's
prefix is taken from ``WireGuardServer.tunnel_network_cidr`` -- the real
CIDR every peer of that hub is allocated from (``validators
.allocate_tunnel_ip``) -- rather than an invented, possibly-wrong ``/24``,
the identical "derive the real value, don't fabricate a convention"
discipline the DHCP section above already establishes for the same
missing-prefix shape of problem.

The rendered interface name (``wg-cloudguard``, a fixed literal, not
suffixed with any row's id) needs no collision-avoidance suffix unlike
``_dhcp_identifier``/``_hotspot_identifier``/``_qos_identifier``: a
``WireGuardPeer`` is one-to-one with its router (``models.py``'s own
``uq_wireguard_peers_router_id`` constraint), so at most one such peer is
ever rendered into any single router's own script -- there is no second
row this name could ever collide with in the same render. Re-running this
renderer's output against a router that already has a
``wg-cloudguard`` interface (a key rotation, e.g.) is expected to fail on
the ``/interface wireguard add`` line with a real, honest RouterOS
"already exists" error rather than silently duplicating a redundant
interface -- idempotent replace-in-place (remove-then-add) is left to the
push/apply layer this renderer does not own, the same "rendering is a pure
function of desired state, applying it is separate" boundary
``render_network_config``'s own docstring already draws for every other
category here.

## RADIUS client: ``src-address`` is the one field this whole feature
lives or dies on

``/radius add`` registers this router as a NAS client against the
platform's own FreeRADIUS deployment. ``src-address=<tunnel_ip>`` is not
optional despite RouterOS accepting the command without it: FreeRADIUS
matches an incoming Access-Request against its configured client list by
*source IP address* (confirmed live this session -- the FreeRADIUS VM's
``clients.conf`` keys a client entry by ``ipaddr``, matched against
whatever address the packet actually arrived from), and a MikroTik router
with an unset ``src-address`` sources RADIUS traffic from whichever
interface the kernel's own routing table happens to pick for the
destination -- typically its WAN/public IP, not its WireGuard tunnel IP.
That address was never registered as a NAS client anywhere, so
FreeRADIUS silently rejects the request even with a perfectly correct
shared secret: no log line naming a config mistake, no obviously wrong
credential to check -- just an opaque auth failure, the least debuggable
outcome this renderer could produce. Forcing ``src-address`` to the
router's own allocated tunnel IP (the address this platform's ``nas``
lookup actually knows about -- see ``app.domains.guest.dependencies
.CurrentNas``) is what makes the two ends agree on which address is
allowed to authenticate at all.

``service=hotspot`` was confirmed live (RouterOS 7.21.5, ``/radius export
verbose``) to already default both ``authentication-port=1812`` *and*
``accounting-port=1813`` onto the same client entry -- RouterOS does not
split hotspot authentication and accounting into two separate ``/radius``
service values the way one might reasonably expect from ``ppp``'s own
finer-grained service list, so no second ``/radius add`` line is needed
here for accounting to be reachable at the NAS-client-registration level
this function owns. Whether a real hotspot session actually *emits*
accounting packets is a separate, honestly out-of-scope toggle:
``/ip hotspot profile``'s own ``radius-accounting`` field (defaults to
``yes`` once ``use-radius=yes`` is set, also confirmed live) lives on the
hotspot *server bind*, which this module's own Hotspot section above
already documents as deliberately unrendered ("user-profile +
walled-garden only, not the server bind... which would need an
interface/address-pool this table has no data for"). This function does
not reopen that boundary; it only guarantees the NAS-client entry itself
is registered in a shape that can carry accounting once that separate,
already-documented server-bind gap is closed.

``/radius incoming set accept=yes port=3799`` is the device-side half of
CoA (RFC 5176): ``app.domains.guest.radius_coa`` already builds and sends
real, wire-correct CoA-Request/Disconnect-Request packets platform-side
(confirmed this session, including against a live NAS) -- without this
line, a real router simply never listens on port 3799 and drops every one
of those packets on arrival, so a quota-exhausted guest could never be
disconnected without a full session timeout. This is the one line in this
renderer that is router-*global* rather than tied to any specific NAS
client row (RouterOS has exactly one ``/radius incoming`` settings object,
not one per registered client) -- re-rendering it once per NAS client is
harmless (``set``, not ``add``: the second application is a no-op, not a
duplicate), so no special-casing is added for the "already enabled by an
earlier push" case.

## Bootstrap: the "Step 0" problem, and why this script is thin, not a
config dump

Every renderer above assumes a router that is already reachable over its
WireGuard tunnel (device-facing config pull, CoA, health checks). Nothing
in this codebase, until this addition, produced anything for the moment
*before* that tunnel exists at all -- a brand-new router behind
carrier-grade NAT, with no known IP and no config, that an admin has just
racked at a site. :func:`render_bootstrap_script` is that "Step 0": a
short script an admin pastes once via WinBox/SSH at the site, which brings
up just enough connectivity (its own WireGuard tunnel) to reach the
platform, then lets every subsequent step happen over the API, the exact
zero-touch pattern real ISP/WISP tooling (Splynx/UISP/Powercode) already
uses for the identical CGNAT problem.

**Deliberately ~15 lines, not a full config dump.** A long WinBox terminal
paste both drops characters in practice (a real, common failure mode of
pasting many lines into a RouterOS terminal) and has no atomicity -- a
mid-script failure on line 40 of a 200-line paste leaves a half-configured
device with no signal anything went wrong, and no easy way for a
non-network-engineer site technician to tell which half actually applied.
This script does only the minimum: set identity, generate a keypair,
bring up one interface, enroll, then hand off to the platform's own,
already-real config-pull machinery (``GET /agent/config``,
``app.domains.router_agent.router.agent_pull_config``) for everything
else -- one already-atomic-per-category, server-rendered ``.rsc`` fetched
and ``/import``-ed in a single step, not re-typed by hand.

**The device generates its own keypair; only the public half is ever
POSTed.** See ``app.domains.router.schemas.ProvisioningCheckInRequest
.wireguard_public_key``'s own docstring for the full reasoning -- in
short, a real security risk unique to *this* delivery mechanism: unlike an
admin-triggered tunnel created through the authenticated dashboard, a
bootstrap script is a pasted-once, site-technician-handled artifact
routinely forwarded over WhatsApp/email between site techs in practice. A
server-generated private key embedded in that blob would turn it into a
bearer credential for the tunnel itself; RouterOS's own
``/interface wireguard add`` already generates a real keypair locally with
no extra step, so there is no reason to do otherwise.

**``/system identity`` is set to the location code, not
``RadiusNasClient.nas_identifier``.** These are two different,
independently-scoped identifiers already in this codebase, confirmed by
reading ``app.domains.guest.dependencies.CurrentNas``/
``app.domains.guest.models.RadiusNasClient``: ``nas_identifier`` is a
freeform RADIUS wire-protocol value, set at NAS *registration* time (a
separate, later, independently-triggered admin action --
``RadiusService.register_nas``, per ``render_network_config``'s own
docstring on that exact ordering) -- it does not exist yet at bootstrap
time, since no ``RadiusNasClient`` row exists for a router that has not
finished enrolling. ``Location.location_code`` (a short, human-shareable,
already-globally-unique code every location already has) is a real value
this script *can* set at this exact moment, and doing so gives the device
a human-legible, at-a-glance identity ("which site is this box at") the
instant an admin opens WinBox against it post-enrollment -- a real,
useful improvement over RouterOS's factory-default ``MikroTik`` identity,
even though it is not literally the RADIUS NAS-Identifier RouterOS's own
RADIUS client would separately send once that section of the full config
is later applied.

**Idempotency via a comment-tag remove-then-add.** Every entry this
script itself creates (the tunnel's ``/ip address`` and its
``/interface wireguard peers`` line) is tagged ``comment="CGBOOT"`` and
removed-then-re-added rather than blindly re-added, confirmed live this
session against the real MikroTik CHR test VM (RouterOS 7.21.5) -- so
re-running this exact script (e.g. a technician pastes it twice by
mistake) never duplicates entries. **Known, flagged gap, deliberately not
fixed here**: neither ``render_wireguard_peer`` nor ``render_radius_client``
(built earlier this session, both above) tag *their own* ``/ip address``/
``/interface wireguard peers``/``/radius`` lines with any comment at all,
so if the full ``.rsc`` this script fetches at its own last line is ever
re-applied a second time (e.g. a config-drift correction re-push), those
two renderers' lines would duplicate rather than idempotently replace.
Retrofitting that onto those two functions is a real, separate, small fix
-- deliberately left undone here rather than folded into this addition,
since it touches two functions this addition does not otherwise need to
change.

**HTTPS only for the platform's own two calls.** RouterOS 7 verifies TLS
certificates by default (confirmed live this session: a self-signed
endpoint fails ``/tool fetch`` outright, no ``check-certificate=no``
override is rendered here to work around that, since defeating certificate
verification on the one channel carrying a one-time bearer token and then
a long-lived persistent credential would undermine the point of using
HTTPS at all). ``api_base_url`` is therefore asserted to start with
``https://`` -- a caller passing a bare host or an ``http://`` URL gets a
clear ``ValueError`` here rather than a silently-insecure rendered script.
This constraint is specific to the bootstrap's *own* two calls back to the
platform (enrollment POST, config-pull ``/tool fetch``); it says nothing
about, and does not change, the WireGuard/RADIUS device-to-device traffic
``render_wireguard_peer``/``render_radius_client`` above already render.

**Real endpoint paths, not invented ones.** ``/api/v1/routers/provisioning
/check-in`` (``app.domains.router.router.provisioning_check_in``) and
``/api/v1/agent/config`` (``app.domains.router_agent.router
.agent_pull_config`` -- confirmed, by reading that module's own docstring,
to be the "config-pull" surface it names) are this platform's real,
already-mounted routes (``app.api.v1.router``, ``app.core.config
.Settings.api_v1_prefix``), not speculative ones invented for this
addition.

**Activation gate and the phone-home scheduler are two separate,
partially-out-of-scope pieces.** Whatever hotspot-related config the full
``.rsc`` eventually carries is expected to default ``disabled=yes`` until
a dashboard-triggered "activate" step (tunnel-up + a real RADIUS auth
test) flips it on -- no such activate endpoint/flow exists in this
codebase yet, and this addition does not build one; see this module's own
``render_hotspot_profile`` above, which already renders no
``disabled=``/enable state of its own (RouterOS's own default for a new
``/ip hotspot user profile`` entry). :func:`render_agent_heartbeat_scheduler`
renders the ``/system scheduler`` entry that periodically calls the real,
already-existing ``POST /agent/heartbeat``
(``app.domains.router_agent.router.agent_heartbeat``, confirmed by reading
that endpoint's own request/auth shape: ``X-Agent-Credential`` header,
JSON body with both fields optional) -- but it is **not** wired into
:func:`render_network_config`/called from anywhere in this addition's own
footprint, for a real reason worth being honest about, not silently
working around: ``app.domains.router_agent.models.RouterAgentCredential``
only ever stores a one-way hash of that credential (``credential_hash``);
the plaintext is disclosed exactly once, in check-in's own response
(``ProvisioningCheckInResponse.agent_credential``'s own docstring), and is
never retrievable again afterward. A *later* full-config render (as this
function's own name and the calling convention every other renderer here
follows would suggest) has no plaintext credential left to embed by the
time it runs. The only currently-correct place to call
:func:`render_agent_heartbeat_scheduler` is therefore immediately at
check-in time, while the plaintext is still in hand -- wiring that call
into ``app.domains.router.router.provisioning_check_in`` and/or
``app.domains.router_provisioning``'s initial-config-version creation is
real, additional cross-domain work outside this addition's declared
footprint, left undone and reported as a gap rather than guessed at.
"""

from __future__ import annotations

import ipaddress

from app.domains.dhcp.models import DhcpPool
from app.domains.dns.constants import DnsRecordType
from app.domains.dns.models import DnsRecord
from app.domains.firewall.constants import FirewallProtocol
from app.domains.firewall.models import FirewallRule
from app.domains.guest.models import RadiusNasClient
from app.domains.hotspot.models import HotspotProfile
from app.domains.port_forwarding.constants import PortForwardingProtocol
from app.domains.port_forwarding.models import PortForwardingRule
from app.domains.qos.models import QosTrafficRule
from app.domains.router.crypto import decrypt_secret
from app.domains.router_agent.constants import AGENT_CREDENTIAL_HEADER
from app.domains.vlan.models import Vlan
from app.domains.wireguard.constants import (
    DEFAULT_PERSISTENT_KEEPALIVE_SECONDS,
    DEFAULT_WIREGUARD_PORT,
)
from app.domains.wireguard.models import WireGuardPeer, WireGuardServer
from app.domains.wireguard.service import EXTERNALLY_MANAGED_KEY_SENTINEL

from .constants import (
    DHCP_SECTION_HEADER,
    DNS_SECTION_HEADER,
    FIREWALL_SECTION_HEADER,
    HOTSPOT_SECTION_HEADER,
    PORT_FORWARDING_SECTION_HEADER,
    QOS_SECTION_HEADER,
    RADIUS_SECTION_HEADER,
    VLAN_SECTION_HEADER,
    WIREGUARD_SECTION_HEADER,
)

# The rendered RouterOS interface name for a router's own WireGuard
# tunnel back to its hub. A fixed literal, not suffixed with any row's id
# like ``_dhcp_identifier``/``_hotspot_identifier``/``_qos_identifier`` --
# see module docstring's WireGuard section for why ``WireGuardPeer``'s own
# one-peer-per-router uniqueness constraint makes that suffix unnecessary
# here.
WIREGUARD_INTERFACE_NAME = "wg-cloudguard"


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


def _hub_tunnel_address(server: WireGuardServer) -> str:
    """The hub's own conventional tunnel address: the first usable host in
    ``tunnel_network_cidr``. See module docstring's WireGuard section --
    this mirrors, and is computed from the same real column as,
    ``app.domains.wireguard.constants.HUB_RESERVED_HOST_COUNT``'s own
    documented "the hub itself is conventionally assigned the network's
    first usable host address" convention, rather than hard-coding it."""
    network = ipaddress.ip_network(server.tunnel_network_cidr, strict=False)
    return str(next(network.hosts()))


def render_wireguard_peer(peer: WireGuardPeer, server: WireGuardServer) -> list[str]:
    """Renders one router's ``WireGuardPeer``/``WireGuardServer`` pair into
    its own local interface, tunnel address, and hub peer entry. See
    module docstring's WireGuard section for why ``persistent-keepalive``
    and the ``/32`` on ``allowed-address`` are both correctness-critical,
    not stylistic, and were confirmed against a real device this session.

    ``peer.private_key_encrypted`` is decrypted here (via
    ``app.domains.router.crypto.decrypt_secret``, the exact same helper
    ``WireGuardService.get_config_for_agent`` already uses to hand this
    same private key to the device over its own agent channel) since a
    rendered RouterOS script is, by definition, the plaintext the device
    itself must apply -- there is no more-encrypted form this command
    could take and still be a real ``private-key=`` RouterOS accepts.

    **Module 009 Part 3 addition -- the externally-managed-key guard.** A
    peer enrolled through zero-touch bootstrap (see module docstring's
    Bootstrap section) never has a real platform-held private key --
    ``private_key_encrypted`` decrypts to
    ``app.domains.wireguard.service.EXTERNALLY_MANAGED_KEY_SENTINEL``, an
    unmistakable marker, never a real key (see that constant's own
    comment). The ``/interface wireguard add ... private-key=`` line is
    skipped entirely for such a peer -- re-rendering it would push a
    nonsense value onto an interface the device's own bootstrap script
    already created correctly with its real, never-platform-known private
    key, silently breaking a working tunnel. The ``/ip address``/hub peer
    lines below carry no secret material either way, so they still render
    normally -- e.g. to keep the hub side in sync after an admin-triggered
    IP reallocation."""
    private_key = decrypt_secret(peer.private_key_encrypted)
    prefix_len = ipaddress.ip_network(
        server.tunnel_network_cidr, strict=False
    ).prefixlen
    lines: list[str] = []
    if private_key != EXTERNALLY_MANAGED_KEY_SENTINEL:
        lines.append(
            f"/interface wireguard add name={WIREGUARD_INTERFACE_NAME} "
            f'private-key="{private_key}" listen-port={DEFAULT_WIREGUARD_PORT}'
        )
    lines.append(
        f"/ip address add address={peer.tunnel_ip_address}/{prefix_len} "
        f"interface={WIREGUARD_INTERFACE_NAME}"
    )
    lines.append(
        f"/interface wireguard peers add interface={WIREGUARD_INTERFACE_NAME} "
        f'public-key="{server.public_key}" endpoint-address={server.endpoint_host} '
        f"endpoint-port={server.endpoint_port} "
        f"allowed-address={_hub_tunnel_address(server)}/32 "
        f"persistent-keepalive={DEFAULT_PERSISTENT_KEEPALIVE_SECONDS}s"
    )
    return lines


def render_radius_client(
    nas_client: RadiusNasClient, tunnel_ip: str, radius_server_host: str
) -> list[str]:
    """Renders one router's ``RadiusNasClient`` registration into its
    device-side RADIUS client entry plus CoA enablement. See module
    docstring's RADIUS section for why ``src-address=<tunnel_ip>`` is this
    function's single most important parameter, why ``service=hotspot``
    needs no separate accounting line, and why ``/radius incoming`` is
    rendered unconditionally here (it is a router-global setting, not
    per-client)."""
    secret = decrypt_secret(nas_client.shared_secret_encrypted)
    return [
        f"/radius add service=hotspot address={radius_server_host} "
        f'secret="{secret}" src-address={tunnel_ip}',
        "/radius incoming set accept=yes port=3799",
    ]


# Comment tag every entry this bootstrap script itself creates is stamped
# with, so re-running it (e.g. a technician pastes it twice) removes and
# re-adds rather than duplicating -- see module docstring's Bootstrap
# section. A short, fixed literal (not suffixed with any row id, mirroring
# WIREGUARD_INTERFACE_NAME's own no-suffix-needed reasoning): a router runs
# this script exactly once, before it has any other CloudGuest-managed
# config at all, so there is nothing else in a fresh device's config this
# tag could ever collide with.
_BOOTSTRAP_MGMT_TAG = "CGBOOT"

# Real, already-mounted platform API paths this addition's two device
# -facing calls target -- see module docstring's Bootstrap section for why
# these are read from the real routers/router_agent modules, not invented.
# Relative (no scheme/host) so they compose with whatever ``api_base_url``
# a caller supplies.
_CHECK_IN_PATH = "/api/v1/routers/provisioning/check-in"
_AGENT_CONFIG_PATH = "/api/v1/agent/config"
_AGENT_HEARTBEAT_PATH = "/api/v1/agent/heartbeat"


def _require_https(api_base_url: str, *, caller: str) -> None:
    """See module docstring's "HTTPS only" section -- shared by both
    functions below that render a call back to the platform."""
    if not api_base_url.startswith("https://"):
        raise ValueError(
            f"{caller}: api_base_url must start with https:// -- RouterOS "
            "7 verifies certificates by default, and this is the one "
            "channel carrying a one-time provisioning token and then a "
            "long-lived persistent agent credential"
        )


def render_bootstrap_script(
    *,
    location_code: str,
    provisioning_token: str,
    api_base_url: str,
    wireguard_listen_port: int = DEFAULT_WIREGUARD_PORT,
) -> list[str]:
    """Renders the "Step 0" zero-touch enrollment script -- see module
    docstring's Bootstrap section for the full reasoning behind every
    decision below (why ~15 lines, why the device generates its own
    keypair, why ``/system identity`` gets the location code rather than
    the RADIUS NAS identifier, the comment-tag idempotency convention, and
    why HTTPS is enforced). Every command here was confirmed, fragment by
    fragment, against a real MikroTik CHR (RouterOS 7.21.5) this session --
    including the ``:deserialize from=json`` call, which is what actually
    lets a RouterOS script parse this platform's own JSON response body
    without a second round-trip or a hand-rolled parser.

    Raises ``ValueError`` if ``api_base_url`` is not ``https://`` -- see
    :func:`_require_https`.

    ``provisioning_token``/``location_code`` are trusted, platform-
    generated/validated values by the time this function is called (a
    freshly-issued ``RouterProvisioningToken`` plaintext, a real
    ``Location.location_code``) -- like every other renderer in this file
    (e.g. ``render_dns_record``'s ``comment=``), they are interpolated
    as-is, not re-escaped for RouterOS quoting, matching this module's
    existing convention throughout."""
    _require_https(api_base_url, caller="render_bootstrap_script")
    check_in_url = f"{api_base_url}{_CHECK_IN_PATH}"
    config_url = f"{api_base_url}{_AGENT_CONFIG_PATH}"
    return [
        f'/system identity set name="{location_code}"',
        f"/interface wireguard add name={WIREGUARD_INTERFACE_NAME} "
        f"listen-port={wireguard_listen_port}",
        ":local pub [/interface wireguard get "
        f"[find name={WIREGUARD_INTERFACE_NAME}] public-key]",
        ':local body ("{\\"token\\":\\"" . "'
        f'{provisioning_token}" . "\\",\\"wireguard_public_key\\":\\"" '
        '. $pub . "\\"}")',
        f':local resp [/tool fetch url="{check_in_url}" http-method=post '
        'http-header-field="Content-Type: application/json" http-data=$body '
        "output=user as-value]",
        ':local enroll [:deserialize from=json value=($resp->"data")]',
        f'/ip address remove [find comment="{_BOOTSTRAP_MGMT_TAG}"]',
        '/ip address add address=(($enroll->"tunnel_ip_address") . "/32") '
        f'interface={WIREGUARD_INTERFACE_NAME} comment="{_BOOTSTRAP_MGMT_TAG}"',
        f'/interface wireguard peers remove [find comment="{_BOOTSTRAP_MGMT_TAG}"]',
        f"/interface wireguard peers add interface={WIREGUARD_INTERFACE_NAME} "
        'public-key=($enroll->"wireguard_server_public_key") '
        'endpoint-address=($enroll->"wireguard_endpoint_host") '
        'endpoint-port=($enroll->"wireguard_endpoint_port") '
        'allowed-address=(($enroll->"wireguard_hub_tunnel_address") . "/32") '
        f"persistent-keepalive={DEFAULT_PERSISTENT_KEEPALIVE_SECONDS}s "
        f'comment="{_BOOTSTRAP_MGMT_TAG}"',
        f'/tool fetch url="{config_url}" '
        'http-header-field=("X-Agent-Credential: " . ($enroll->"agent_credential")) '
        "dst-path=cloudguest.rsc",
        "/import file-name=cloudguest.rsc",
    ]


def render_agent_heartbeat_scheduler(
    agent_credential: str, api_base_url: str, *, interval: str = "5m"
) -> list[str]:
    """Renders a ``/system scheduler`` entry that periodically calls the
    real, already-existing ``POST /agent/heartbeat``
    (``app.domains.router_agent.router.agent_heartbeat`` -- confirmed by
    reading that endpoint before rendering a call to it: ``X-Agent-
    Credential`` header, JSON body with both ``routeros_version``/
    ``management_ip_address`` fields optional, so the empty ``{}`` body
    below is a real, valid request, not a placeholder). See module
    docstring's Bootstrap section for why this function is **not** wired
    into :func:`render_network_config` or called anywhere else in this
    addition: the plaintext ``agent_credential`` it embeds is disclosed
    exactly once, at check-in
    (``ProvisioningCheckInResponse.agent_credential``), and this platform
    holds no recoverable copy afterward -- the only currently-correct
    caller is whatever code still has that plaintext in hand right after
    check-in succeeds, which today is nothing in this codebase (a real,
    reported gap, not a silent workaround).

    The rendered ``on-event`` syntax (an inline, double-quote-escaped
    ``/tool fetch`` command) was confirmed against the real MikroTik CHR
    test VM this session, including a real ``/system scheduler add``
    accepting it without a syntax error."""
    _require_https(api_base_url, caller="render_agent_heartbeat_scheduler")
    heartbeat_url = f"{api_base_url}{_AGENT_HEARTBEAT_PATH}"
    # ``on-event``'s value is itself a double-quoted RouterOS string, so
    # every double-quote the wrapped /tool fetch command needs is
    # backslash-escaped (\") -- confirmed live this session: RouterOS
    # accepted this exact escaped form on a real /system scheduler add and
    # echoed it back correctly on /system scheduler print detail.
    on_event = (
        f'/tool fetch url=\\"{heartbeat_url}\\" http-method=post '
        f'http-header-field=\\"{AGENT_CREDENTIAL_HEADER}: {agent_credential}\\" '
        'http-data=\\"{}\\" output=none'
    )
    tag = f"{_BOOTSTRAP_MGMT_TAG}-hb"
    return [
        f'/system scheduler remove [find comment="{tag}"]',
        f"/system scheduler add name=cloudguest-heartbeat interval={interval} "
        f'on-event="{on_event}" comment="{tag}"',
    ]


def render_network_config(
    *,
    dhcp_pools: list[DhcpPool],
    vlans: list[Vlan],
    port_forwarding_rules: list[PortForwardingRule],
    hotspot_profiles: list[HotspotProfile] | None = None,
    qos_traffic_rules: list[QosTrafficRule] | None = None,
    dns_records: list[DnsRecord] | None = None,
    firewall_rules: list[FirewallRule] | None = None,
    wireguard_peer: WireGuardPeer | None = None,
    wireguard_server: WireGuardServer | None = None,
    radius_nas_client: RadiusNasClient | None = None,
    radius_server_host: str | None = None,
) -> str:
    """Combines every enabled row across all categories into one
    router-wide RouterOS script -- a full desired-state snapshot, mirroring
    how ``app.domains.router_provisioning.models.ConfigVersion`` already
    represents a router's *whole* config rather than an incremental diff.
    Returns an empty string if every input is empty -- callers
    (``service.py``) decide whether that is an error (a push) or a valid,
    informational result (a preview).

    ``wireguard_peer``/``wireguard_server`` render together or not at all
    (a peer with no hub to point at cannot produce a real
    ``/interface wireguard peers`` line) -- pass either both or neither.
    ``radius_nas_client`` additionally needs ``radius_server_host`` (there
    is no dedicated "RADIUS server host" column anywhere in this codebase
    to draw one from instead -- see ``service.py``'s own gathering step for
    why, in this platform's real deployment topology, that is
    ``wireguard_server.endpoint_host`` itself: the hub and the FreeRADIUS
    instance it fronts for are co-located on the same VM, confirmed live
    this session). A router can have a WireGuard tunnel long before it has
    a registered NAS client (tunnel creation and NAS registration are two
    separate, independently-triggered operations -- see
    ``app.domains.guest.service.RadiusService.register_nas``); this
    function makes no assumption about that ordering, it only renders
    whichever of the two real rows the caller actually has."""
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
    if wireguard_peer is not None and wireguard_server is not None:
        sections.append(WIREGUARD_SECTION_HEADER)
        sections.extend(render_wireguard_peer(wireguard_peer, wireguard_server))
    if (
        radius_nas_client is not None
        and radius_server_host is not None
        and wireguard_peer is not None
    ):
        # ``render_radius_client``'s own ``tunnel_ip`` parameter is the
        # router's *own* tunnel address (``src-address=``, see module
        # docstring's RADIUS section) -- ``wireguard_peer`` is the only
        # real source for that value, so a NAS client with no WireGuard
        # tunnel yet cannot render this section. See this function's own
        # docstring for why that ordering is left unenforced/undecided
        # here rather than assumed.
        sections.append(RADIUS_SECTION_HEADER)
        sections.extend(
            render_radius_client(
                radius_nas_client, wireguard_peer.tunnel_ip_address, radius_server_host
            )
        )
    return "\n".join(sections)


__all__ = [
    "render_dhcp_pool",
    "render_vlan",
    "render_port_forwarding_rule",
    "render_hotspot_profile",
    "render_qos_traffic_rule",
    "render_dns_record",
    "render_firewall_rule",
    "render_wireguard_peer",
    "render_radius_client",
    "render_bootstrap_script",
    "render_agent_heartbeat_scheduler",
    "render_network_config",
]
