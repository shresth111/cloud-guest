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
entry (which is what actually carries the gateway/DNS options out to
clients -- ``lease-time`` is a ``/ip dhcp-server`` server-object parameter,
not a network-object one; confirmed live against a real hEX lite, RouterOS
rejects it on ``network add`` with "expected end of command") needs a real
CIDR block, not a bare range. Rather than
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

## Hotspot dns-name: replacing the raw IP in the guest's address bar

RouterOS's ``/ip hotspot profile`` has a real, built-in ``dns-name`` field:
once set, RouterOS's own hotspot redirect (the ``302`` that sends a
newly-connected, not-yet-authenticated guest to the login page) uses that
name instead of the hotspot's raw IP in the URL it builds -- confirmed
against MikroTik's own published ``/ip hotspot profile`` reference. This is
what turns ``http://10.5.50.1/login`` in a guest's address bar into
``http://wifi.wyfyguest.com/login``, the exact UX complaint this
addition fixes.

**A real subdomain of the platform's own registered domain, not a
pseudo-TLD -- a deliberate, later choice (this constant originally used
``wyfy.portal``).** ``wyfyguest.com`` is already this platform's own real,
registered production domain (see ``app/main.py``'s CORS allowlist, which
already trusts ``wyfyguest.com``/``app.wyfyguest.com`` origins), so this
platform fully controls what, if anything, ``wifi.wyfyguest.com``
resolves to on the public internet -- there is no third party who could
ever legitimately hold or contest this exact name the way a truly
unrelated public domain could. It still never needs a public DNS record
for this feature to work (see below), and the org should be aware that
*if* ``wifi.wyfyguest.com`` is ever wanted for something else publicly
in the future, this per-router local override would fully shadow it for
any guest sitting on that router's own LAN -- worth a one-line note
wherever this platform's own DNS zone/domain inventory is tracked, not a
reason to avoid the name.

**``dns-name`` alone is not sufficient -- it changes the redirect URL, it
does not by itself make that hostname resolve.** MikroTik's own
documentation for this exact feature is explicit that a ``dns-name`` you
set must *separately* be made to resolve to the hotspot's own address, and
the standard way to do that for a name with no real public DNS record is a
plain ``/ip dns static`` entry pointing it at the hotspot's own address --
this is why ``_render_vlan_hotspot`` below emits both lines, never
``dns-name`` on its own. Guest devices already receive this router's own
address as their DNS server via the ``dns-server=`` option this same
function's ``/ip dhcp-server network add`` line has always set, and
``/ip dns set ... allow-remote-requests=yes`` (already rendered platform-
wide in the master-console bootstrap script) makes the router answer that
query -- no public DNS record is *needed* anywhere in this scheme, it is
resolved entirely locally, by each router, for its own guests, regardless
of whatever ``wifi.wyfyguest.com`` may or may not publicly resolve to.
(A public A record for ``wifi.wyfyguest.com`` was separately added in
the platform's own GoDaddy DNS zone as a belt-and-suspenders fallback for
the rare guest device that bypasses the router's own DNS server entirely
-- see this section's own "not independently confirmed" paragraph below
for why that fallback's precedence vs. the router's local answer isn't
verified, and note a public record cannot itself point at any individual
router's own private LAN IP, so it is not, and cannot be, a substitute for
the per-router ``/ip dns static`` line this function renders.)

**Not independently confirmed against a real device this session** (unlike
most of the rest of this file's decisions, which carry an explicit "live
this session" note): whether RouterOS's hotspot-specific DNS interception
path for an *unauthenticated* client takes precedence over, conflicts
with, or is simply additive to, a plain ``/ip dns static`` answer for the
same name is not something this addition verifies live. The
``/ip dns static`` record is the documented, standard-pattern fallback
regardless, so it is included rather than relying on ``dns-name``'s
redirect-only behavior alone -- but a real device test (connect an
unauthenticated guest, confirm the address bar shows the hostname *and*
the page actually loads, not an NXDOMAIN/timeout) is the one piece of
verification the module docstring's own "confirmed live" standard would
otherwise require, and is flagged here as genuinely outstanding rather
than assumed.

**Per-VLAN name, not one fixed global literal, to avoid a real collision
this function's own multi-VLAN-hotspot shape would otherwise create.**
``_render_vlan_hotspot`` can render more than one independent hotspot per
router (one per ``enable_hotspot`` VLAN, each with its own
``hotspot-address``) -- a single fixed ``dns-name``/static-DNS pair shared
by every one of them would leave the router's ``/ip dns static`` table
with either a name collision (RouterOS rejects a second ``add`` of the
same ``name=``) or, worse, multiple different addresses silently
round-robined under one name, sending some fraction of guests on VLAN A's
hotspot to VLAN B's gateway. ``{tag}.wifi.wyfyguest.com`` (``tag`` already being
this function's own real, ``vlan_id``-derived, guaranteed-unique-per-router
identifier) sidesteps that entirely, the same "derive a real, already-
unique value rather than fabricate a shared one" discipline
``_dhcp_identifier``/``_hotspot_identifier`` already establish for their
own name-collision problem above.

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

## QoS: marks traffic; the paired queue is now real too, just not rendered here

Only RouterOS's ``/ip firewall mangle`` packet-marking half of real QoS is
rendered by this module -- a real ``new-packet-mark`` derived from the
rule's own identifier (``app.domains.qos.identifiers
.qos_packet_mark_identifier`` -- the single source of truth this renderer
and the paired push below both use, see that function's own docstring for
why it lives in the ``qos`` domain, not here), matched either by
protocol/port range or by DSCP value (never both, enforced at that
domain's own service layer).

**Historical note, now resolved**: this section used to say pairing this
mark with an actual ``/queue tree`` entry was left undone. That gap is now
closed, but deliberately *not* in this renderer -- ``app.domains.qos.
device_adapters``/``service.push_rule_to_device`` create and maintain that
paired ``/queue tree`` entry via a direct device push (mirroring
``app.domains.queue_management``'s own device-push pattern), composing the
identical shared identifier this function emits into ``new-packet-mark=``.
This module's own concern stays exactly what it always was -- full-
desired-state script rendering for the categories with no urgency around
push latency -- while the queue-tree pairing, which only matters once a
rule is meant to actually prioritize live traffic, is pushed directly and
independently. See ``docs/qos/FLOW.md`` §2 for the full resolution
write-up and ``app.domains.qos.service.QosService.push_rule_to_device``'s
own docstring for the device-push mechanics.

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

## Content Filtering: DNS sinkhole + address-list/firewall-filter,
deliberately no Layer7, no web-proxy, no TLS interception

See ``app.domains.content_filtering``'s own module docstring for the full
scope write-up; this section documents only the rendering half.

``ContentFilterRule.value_type == "domain"`` renders **two**
``/ip dns static`` lines, not one: an exact-name match and a ``regexp=``
match for every subdomain. This mirrors ``render_dns_record``'s own real
RouterOS parameter shape (``address=`` for an A-type static entry) but
points every one at :data:`CONTENT_FILTER_SINKHOLE_ADDRESS`
(``127.0.0.1``, this platform's own loopback -- always exists, needs no
LAN host actually listening on it, and never ARPs a real device) instead
of a real destination -- a DNS sinkhole, the standard, honest way to make
a blocked domain simply fail to resolve for a device using this router as
its DNS server (guest DHCP already hands out this router's own address as
``dns-server=``, established by ``_render_vlan_hotspot``'s own DHCP
network line above). Two lines are needed because RouterOS's own
``/ip dns static`` treats ``name=`` (exact match) and ``regexp=``
(pattern match) as mutually exclusive per entry -- one entry can block
``facebook.com`` exactly, a second is needed to also catch
``www.facebook.com``/``m.facebook.com``/etc.

``ContentFilterRule.value_type == "ip_cidr"`` renders one
``/ip firewall address-list`` membership line per rule, **plus** one
shared, aggregate ``/ip firewall filter ... dst-address-list=<list>
action=drop`` line -- rendered exactly once per push
(:func:`render_content_filter_rules`), regardless of how many IP/CIDR
rules exist, since the DROP rule matches the whole address-list, not any
one member. Populating an address list with nothing that ever actually
drops traffic against it would be the exact "looks wired up but isn't"
gap this platform's own ``app.domains.mac_authorization`` module
docstring already called out and fixed for its own whitelist entries
before this addition existed -- this renderer does not repeat that gap.

**The one real, honest limitation, stated plainly:** a guest device that
manually configures a different DNS resolver (a public one, or DNS-over-
HTTPS/TLS) bypasses the sinkhole entirely -- this is a known, real
limitation of DNS-based content filtering everywhere it is deployed, not
unique to this renderer. This renderer deliberately does **not** also
emit a port-53-lockdown firewall rule to close that gap: forcing every
guest DNS query through the router is a general-purpose firewall policy
an admin can already build with ``app.domains.firewall``'s own existing
rule CRUD (``chain=forward protocol=udp dst-port=53 action=drop``,
excepting the router's own address) -- this domain does not duplicate a
capability that domain already fully owns.

Content filtering does not attempt Layer7 protocol matching (real, but
expensive per-packet regex matching -- not what this platform's actual
low-power test hardware, a MikroTik hEX lite, should spend its CPU
budget on for this feature) or a transparent web-proxy (which only sees
plaintext HTTP -- essentially none of the real sites a guest-WiFi content-
filtering customer wants blocked run unencrypted today), and never
attempts TLS interception (HTTPS MITM) under any circumstances -- a hard
scope boundary, not a judgment call.

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

**Deliberately ~25 lines, not a full config dump.** A long WinBox terminal
paste both drops characters in practice (a real, common failure mode of
pasting many lines into a RouterOS terminal) and has no atomicity -- a
mid-script failure on line 40 of a 200-line paste leaves a half-configured
device with no signal anything went wrong, and no easy way for a
non-network-engineer site technician to tell which half actually applied.
This script does only the minimum: set identity, clear any stale state a
previous run left behind, enroll, pull this peer's own key material, bring
up one interface, then *verify* what it just created and say so out loud.
Everything else (VLANs, hotspot, RADIUS -- the remaining wizard steps)
stays in the platform's own, already-real config machinery, never in this
paste.

**The platform generates the keypair; the private key is fetched at run
time, never embedded in the paste.** A bootstrap script is a pasted-once,
site-technician-handled artifact routinely forwarded over WhatsApp/email
between site techs in practice -- so no key material may appear in the
rendered text itself (the one embedded secret is the one-time, short-TTL
provisioning token, which check-in burns on first use). Instead the script
exchanges that token for the router's persistent agent credential
(``POST /routers/provisioning/check-in``, which allocates the tunnel and
a platform-held keypair), then immediately pulls ``peer_private_key`` over
HTTPS from ``GET /agent/wireguard-config``
(``app.domains.wireguard.router.agent_pull_wireguard_config``),
authenticated with that just-issued credential. The forwarded blob
therefore never becomes a bearer credential for the tunnel itself, and the
platform's ``WireGuardPeer`` row holds the real key both sides agree on --
which is also what makes a re-run rotate cleanly (see
``WireGuardService.ensure_tunnel_for_check_in``).

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

**Idempotency via comment-tagged cleanup-first, then verify.** Every
entry this script itself creates (the ``wg-cloudguard`` interface, the
tunnel's ``/ip address`` and its ``/interface wireguard peers`` line) is
tagged ``comment="CGBOOT"``, and the script *opens* by removing all three
-- the ``/ip address`` row **by comment, never by interface name**: when a
previous run's interface has been deleted, RouterOS keeps its orphaned
address row pointing at an internal id (a real production sighting:
``address=10.8.0.6/32 interface=*10 comment=CGBOOT``), which an
interface-name match can never find but which still blocks re-adding the
same address on the fresh interface. ``remove [find where ...]`` with no
matches is a no-op in RouterOS 7 (the committed pre-fix script already
relied on exactly that on first runs, confirmed live against the CHR test
VM, RouterOS 7.21.5), so no ``[:len ...]`` guards wrap the cleanup lines.
After creating, the script re-queries all three resources -- including
that the tunnel address is attached *specifically to* ``wg-cloudguard``,
not merely present -- and only that combined re-query prints the success
line, so a paste whose earlier line failed (RouterOS console executes a
paste line by line; ``:error`` aborts only its own line) can never end on
a false "successful". **Known, flagged gap, deliberately not
fixed here**: neither ``render_wireguard_peer`` nor ``render_radius_client``
(built earlier this session, both above) tag *their own* ``/ip address``/
``/interface wireguard peers``/``/radius`` lines with any comment at all,
so if the full ``.rsc`` the later wizard steps deliver is ever
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
platform (enrollment POST, wireguard-config ``/tool fetch``); it says nothing
about, and does not change, the WireGuard/RADIUS device-to-device traffic
``render_wireguard_peer``/``render_radius_client`` above already render.

**Real endpoint paths, not invented ones.** ``/api/v1/routers/provisioning
/check-in`` (``app.domains.router.router.provisioning_check_in``) and
``/api/v1/agent/wireguard-config`` (``app.domains.wireguard.router
.agent_pull_wireguard_config`` -- confirmed, by reading that module's own
docstring, to be the device-facing key-delivery surface) are this platform's real,
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

## Netwatch: real router-side detection, closed via a rotated agent credential

RouterOS's own ``/tool netwatch`` pings a target *from the router itself*
and runs a real, local ``up-script``/``down-script`` the instant that
target's status changes -- structurally faster than any server-initiated
poll (``app.domains.isp.service.run_health_check_sweep``, a 30-second
Celery Beat sweep) can be, since there is no round-trip to a central
server involved in the *detection* itself. :func:`render_isp_netwatch_entry`
renders one real ``/tool netwatch add host=<gateway> up-script=...
down-script=...`` entry per ``IspLink``, watching that link's own
already-known health-check target.

**Scope-limited to ``STATIC``-mode links with a known ``gateway_ip_address``,
honestly.** ``/tool netwatch``'s ``host=`` parameter needs a literal IP
address baked in at render/push time -- a ``DHCP``-mode link's target is
resolved *live*, at check time, by ``IspService.ping_link`` (its dynamic
default gateway can legitimately change between one push and the next),
and a ``PPPOE``-mode link has no IP-layer gateway/ping target at all (see
``app.domains.isp.constants.IspConnectionMode``'s own docstring). Rendering
a Netwatch entry against either would mean baking in a value already known
to go stale or fabricating one that was never real -- this function skips
both modes with an explanatory comment instead, the same "skip, don't
guess" discipline every other renderer in this file already follows.

**The credential problem this shares with, and solves differently than,
``render_agent_heartbeat_scheduler`` above.** A Netwatch ``up-script``/
``down-script`` needs to call back to this platform the instant the
router itself notices a change, authenticated the same way every other
device-facing call in this codebase is: ``X-Agent-Credential`` (see
``app.domains.router_agent.dependencies.CurrentAgent``). That credential's
plaintext is disclosed exactly once, in ``ProvisioningCheckInResponse``,
and this platform holds no recoverable copy afterward -- the exact gap
``render_agent_heartbeat_scheduler``'s own docstring documents and leaves
open (nothing in this codebase currently calls it). This function does
**not** inherit that gap silently: its caller,
``NetworkConfigService.push_isp_netwatch_config``, **rotates** the
router's agent credential (``RouterAgentService
.issue_credential_for_router`` already supports re-issuing in place, for
exactly the factory-reset/re-provision case) immediately before rendering,
so a real, currently-valid plaintext credential is always in hand at the
moment this function is called -- see that method's own docstring for the
full write-up, including the one honest caveat rotation carries.

**What actually gets reported back, and to where.** Each script's
``http-data`` body is a real, render-time-literal JSON payload
(``{"isp_link_id": "<uuid>", "status": "up"|"down", "host": "<ip>"}``) --
the *link id* is baked in, not resolved by the router, since the router
has no notion of this platform's own primary keys otherwise. It POSTs to
``POST /agent/netwatch-event``
(``app.domains.router_agent.router.agent_netwatch_event``), a genuine,
new, device-authenticated endpoint on that module's own existing
``CurrentAgent`` surface -- not a second, parallel credential scheme. That
endpoint feeds the exact same ``IspService.record_health_check_result``
pipeline the 30-second sweep already uses (a synthesized ``PingResult``,
0%/100% loss for up/down), so a Netwatch-detected change advances the
*same* ``consecutive_unhealthy_count``/failover machinery the sweep does,
rather than a second, parallel health signal.

**Self-idempotent by construction, not via ``_idempotent_lines``.**
Every other category in this file is wrapped in ``:do {...} on-error={}``
(``_idempotent_lines``), which silently *keeps* whatever is already on the
router if an "already have such entry" error is hit -- correct for a DHCP
pool or a VLAN, wrong here: since a fresh, rotated credential is embedded
in the script's own text on every push, silently keeping a stale existing
entry would mean the router goes on reporting with a credential this
platform already rotated away from (a real, silent breakage, not a
cosmetic one). :func:`render_isp_netwatch_entry` instead emits an explicit,
comment-tag-scoped ``/tool netwatch remove [find comment=...]`` immediately
before its own ``add`` -- the identical remove-then-add idempotency
convention ``render_bootstrap_script`` already establishes for its own
tagged entries, chosen deliberately over the wrap-and-suppress convention
for the reason above.

**Not confirmed against a real device this session** (unlike most of the
rendering decisions elsewhere in this file, several of which carry an
explicit "confirmed live" note) -- there was no live MikroTik reachable
for this addition to exercise ``/tool netwatch add ... up-script=...``
against. The command shape follows MikroTik's own published ``/tool
netwatch`` reference (curly-brace script-block syntax for
``up-script``/``down-script``, the same block-not-quoted-string form
RouterOS accepts for ``/system scheduler``'s own ``on-event``) plus this
file's own already-confirmed ``/tool fetch`` conventions
(``render_bootstrap_script``); still an honest, real gap worth a live
confirmation pass before this is exercised in production, not a silent
assumption.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from app.domains.content_filtering.constants import (
    CONTENT_FILTER_ADDRESS_LIST_NAME,
    CONTENT_FILTER_SINKHOLE_ADDRESS,
    ContentFilterValueType,
)
from app.domains.content_filtering.models import ContentFilterRule
from app.domains.dhcp.models import DhcpPool
from app.domains.dns.constants import DnsRecordType
from app.domains.dns.models import DnsRecord
from app.domains.firewall.constants import FirewallProtocol
from app.domains.firewall.models import FirewallRule
from app.domains.guest.models import RadiusNasClient
from app.domains.hotspot.models import HotspotProfile
from app.domains.isp.constants import IspConnectionMode
from app.domains.isp.models import IspLink
from app.domains.mac_authorization.models import MacAuthorizationEntry
from app.domains.network_config.wan.renderers import (
    DISCOVERED_NAT_COMMENT,
    DISCOVERED_WAN_LIST_COMMENT,
    _uplink_discovery_statements,
)
from app.domains.port_forwarding.constants import PortForwardingProtocol
from app.domains.port_forwarding.models import PortForwardingRule
from app.domains.qos.identifiers import qos_packet_mark_identifier
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
    CONTENT_FILTER_SECTION_HEADER,
    DHCP_SECTION_HEADER,
    DNS_SECTION_HEADER,
    FIREWALL_SECTION_HEADER,
    HOTSPOT_SECTION_HEADER,
    MAC_AUTHORIZATION_SECTION_HEADER,
    NETWATCH_SECTION_HEADER,
    PORT_FORWARDING_SECTION_HEADER,
    QOS_SECTION_HEADER,
    RADIUS_SECTION_HEADER,
    REMOTE_BOOTSTRAP_CONFIRM_ATTEMPTS,
    REMOTE_BOOTSTRAP_CONFIRM_DELAY_SECONDS,
    REMOTE_BOOTSTRAP_CUTOVER_DELAY_SECONDS,
    REMOTE_BOOTSTRAP_REVERT_WINDOW_MINUTES,
    VLAN_SECTION_HEADER,
    WIREGUARD_SECTION_HEADER,
    BootstrapMode,
)

# The rendered RouterOS interface name for a router's own WireGuard
# tunnel back to its hub. A fixed literal, not suffixed with any row's id
# like ``_dhcp_identifier``/``_hotspot_identifier``/``_qos_identifier`` --
# see module docstring's WireGuard section for why ``WireGuardPeer``'s own
# one-peer-per-router uniqueness constraint makes that suffix unnecessary
# here.
WIREGUARD_INTERFACE_NAME = "wg-cloudguard"

# The base ``dns-name`` used for the captive-portal redirect on every
# per-VLAN standalone hotspot ``_render_vlan_hotspot`` renders -- a real
# subdomain of this platform's own registered ``wyfyguest.com`` (already
# trusted by app.main's CORS allowlist), not a fabricated pseudo-TLD --
# see module docstring's "Hotspot dns-name" section for why that's safe
# (this platform, not a third party, controls the name), why a bare
# ``/ip dns static`` entry is rendered alongside ``dns-name`` rather than
# relying on it alone, why a public GoDaddy A record for this exact name
# is a belt-and-suspenders fallback rather than the thing this feature
# actually depends on, and why each VLAN's own hotspot gets a ``{tag}.``
# prefixed variant of this rather than this exact literal.
#
# ``wifi``, not ``portal``, since 2026-08-29: this constant said
# ``portal.wyfyguest.com`` while the routers in the field were already
# redirecting guests to ``wifi.wyfyguest.com``, set on the devices by hand
# rather than by this platform. The platform was therefore about to allow
# one name through the walled garden while guests were being sent to
# another -- the exact drift ``_portal_walled_garden_hosts`` documents its
# single-source-of-truth rule to prevent, present in production before that
# rule existed. Aligned onto the name the devices actually use, which is
# also the cheaper direction: the alternative is re-pointing every deployed
# router. ``wifi.wyfyguest.com`` was added to the platform's Let's Encrypt
# certificate the same day (it previously carried only app/auth/master/
# portal), so the name now terminates TLS correctly instead of failing
# validation and dropping guests onto plain HTTP.
HOTSPOT_DNS_NAME = "wifi.wyfyguest.com"

# RouterOS's ``/ip hotspot profile html-directory`` -- which uploaded page
# set a portal serves. Was a bare literal inside ``_render_vlan_hotspot``
# until ``app.domains.vlan.device_adapters`` had to push the same profile
# over the API: the script path and the direct-push path must name the same
# directory or a VLAN's portal serves different pages depending on which
# path last touched the router.
HOTSPOT_HTML_DIRECTORY = "cloudguest-hotspot"

# ---------------------------------------------------------------------------
# Markers and ports the paired device writers in
# ``wyfy_device_gateway.mikrotik_adapter`` already stamp on the rows they
# converge. These are duplicated here deliberately and must stay byte-equal:
# ``app.*`` cannot import the vendored gateway package, and a marker that
# disagrees is worse than no marker at all -- each path would then be unable
# to find the other's row, and would add a second one beside a working one.
# That is precisely the duplicate ``_ensure_radius_client_row`` exists to
# stop, reintroduced from the other side.
# ---------------------------------------------------------------------------

# Mirrors ``mikrotik_adapter._RADIUS_CLIENT_COMMENT``.
RADIUS_CLIENT_COMMENT = "WyfyGuest RADIUS NAS client"

# Mirrors ``mikrotik_adapter._ROGUE_DHCP_ALERT_COMMENT``.
ROGUE_DHCP_ALERT_COMMENT = "cloudguest-rogue-dhcp-watch"

# Mirrors ``mikrotik_adapter._CONTENT_FILTER_ENFORCEMENT_COMMENT``. Was an
# inline literal in ``render_content_filter_enforcement`` until that function
# had to *find* its own row again to reposition it.
CONTENT_FILTER_ENFORCEMENT_COMMENT = (
    "Wyfy Guest content filtering: block listed addresses"
)

# ``contract.RadiusClientConfig``'s own defaults. RouterOS defaults both onto
# a ``service=hotspot`` entry anyway (confirmed live on 7.21.5 -- see this
# module's RADIUS docstring section), but the writer sets them explicitly and
# a hand-made row this renderer now ADOPTS rather than duplicates may carry
# something else entirely.
RADIUS_AUTH_PORT = 1812
RADIUS_ACCT_PORT = 1813

# NOT RouterOS's own default (1700): the RFC 5176 assigned port. Finding 3799
# on a device is evidence this platform wrote it.
RADIUS_COA_PORT = 3799


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
    """Thin alias over ``app.domains.qos.identifiers
    .qos_packet_mark_identifier`` -- kept as a local name so every other
    renderer's own ``_*_identifier`` calling convention here doesn't need
    to change. The real implementation now lives in the ``qos`` domain
    itself (not here), since ``app.domains.qos.device_adapters`` (the
    paired ``/queue tree`` push this fix adds) must derive the exact same
    string independently and cannot import it back out of this module --
    see that function's own docstring for the full "why here, not there"
    write-up, including the import-cycle this avoids."""
    return qos_packet_mark_identifier(rule)


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
        f"address-pool={identifier}-pool lease-time={pool.lease_time_seconds}s "
        "disabled=no"
    )
    network = _smallest_enclosing_network(
        pool.address_range_start, pool.address_range_end
    )
    # ``lease-time`` is a ``/ip dhcp-server`` (the server object above)
    # parameter, not a ``/ip dhcp-server network`` one -- RouterOS rejects
    # it here with "expected end of command", confirmed live against the
    # real hEX lite this session.
    network_parts = [f"/ip dhcp-server network add address={network}"]
    if pool.gateway_ip_address:
        network_parts.append(f"gateway={pool.gateway_ip_address}")
    dns_servers = [dns for dns in (pool.dns_primary, pool.dns_secondary) if dns]
    if not dns_servers and pool.gateway_ip_address:
        # Falls back to the router itself, never to nothing. MikroTik
        # documents that an *omitted* ``dns-server`` makes the DHCP server
        # hand out the router's own *upstream* resolvers -- so a pool with
        # both DNS fields left blank (they are optional, and blank by
        # default on the customer's screen) points every guest straight
        # past this router's resolver. Everything that depends on that
        # resolver then silently stops working: Website Blocking realizes a
        # blocked domain as an ``/ip dns static`` entry, and a guest asking
        # 8.8.8.8 never sees it. Nobody touched a DNS setting to cause it.
        #
        # ``_render_vlan_hotspot`` below has always emitted
        # ``dns-server={gateway}`` for exactly this reason; this is the
        # same rule, applied to the path a plain DHCP pool takes.
        dns_servers = [pool.gateway_ip_address]
    if dns_servers:
        network_parts.append(f"dns-server={','.join(dns_servers)}")
    else:
        # No configured DNS and no gateway to fall back to. Rendering the
        # line without a value is not an option, so this states the
        # consequence rather than emitting a pool that quietly bypasses
        # the router -- the same "skip, don't guess" discipline every
        # other render_* function here follows.
        lines.append(
            f"# {identifier}: no dns-server and no gateway to fall back to "
            "-- guests will receive this router's upstream resolvers, and "
            "DNS-based content filtering will not apply to them"
        )
    lines.append(" ".join(network_parts))
    lines.extend(_render_rogue_dhcp_alert(pool.interface))
    return lines


def _render_rogue_dhcp_alert(interface: str) -> list[str]:
    """The ``/ip dhcp-server alert`` row that goes beside every pool this
    platform pushes -- the device's own watch for somebody else answering
    DHCP on the same segment.

    ## What it is for

    A guest plugs a home router into a venue port and it starts handing out
    leases. Guests land on its subnet, with a gateway that is not this
    router, and never reach the portal at all. The alert **logs**; it drops
    nothing and blocks nothing. That is the whole point -- it makes an event
    that is otherwise invisible show up somewhere an operator can find it.

    ``mikrotik_adapter.configure_rogue_dhcp_alerts`` writes this on the
    device-writer path. Nothing rendered it, so a router configured from a
    generated script served DHCP with nothing watching it, while a
    fleet-pushed router beside it was guarded.

    ## The trusted server is READ OFF THE DEVICE, never baked in

    ``valid-server`` is a MAC address, and the only correct value is this
    router's own MAC on this interface -- which is a fact about the
    hardware, not about any row in this platform's database, so a rendered
    literal is not available to us the way an address or a lease time is.
    ``app.domains.dhcp.device_adapters`` solves this by reading the
    interface's MAC from the device before it writes, and **refuses rather
    than defaults** when it cannot find one (``return None``): a guessed
    trusted server turns every legitimate lease into an alert, which is
    exactly how a genuine rogue then gets ignored.

    A script cannot do the read up front, so it does it at run time --
    ``[/interface get [find name=...] mac-address]``. If the interface does
    not resolve, that expression errors, :func:`_idempotent_lines`'
    ``on-error={}`` swallows it, and no alert row is written. Same refusal,
    same reason, reached differently: never a fabricated ``valid-server``.

    ## ``disabled=no`` is not decoration

    RouterOS creates an alert row **disabled by default**, so an ``add``
    that omits this leaves a row that reads as configured in an export and
    watches nothing. The writer's docstring calls this out and so does
    this line; it is also re-asserted on the ``set`` branch, because an
    operator (or an older build) may have left an existing row switched
    off.

    One row per interface -- that is RouterOS's own constraint, and it is
    why this is keyed on ``interface`` rather than on the platform comment
    the way most rows here are: a second ``add`` for the same interface
    would silently overwrite the first rather than sit beside it."""
    found = f'[/ip dhcp-server alert find where interface="{interface}"]'
    fields = (
        f'interface="{interface}" valid-server=$dhMac '
        f'comment="{ROGUE_DHCP_ALERT_COMMENT}" disabled=no'
    )
    return [
        f':local dhMac [/interface get [find name="{interface}"] mac-address]; '
        f":if ([:len {found}] = 0) "
        f"do={{ /ip dhcp-server alert add {fields} }} "
        f"else={{ /ip dhcp-server alert set {found} {fields} }}"
    ]


def _vlan_address_line(vlan: Vlan, bind_interface: str) -> str | None:
    if not vlan.cidr:
        return None
    address = (
        f"{vlan.gateway_ip_address}/{vlan.cidr.split('/')[-1]}"
        if vlan.gateway_ip_address
        else vlan.cidr
    )
    return f"/ip address add address={address} interface={bind_interface}"


def _render_vlan_hotspot(vlan: Vlan, bind_interface: str) -> list[str]:
    """Renders a standalone captive-portal hotspot (pool + dhcp-server +
    hotspot profile + hotspot server) bound to one VLAN's own interface --
    mirrors the exact command shape ``buildRouterSetupScript`` (frontend,
    ``RouterDetailTabs.tsx``) already proved live for the router's default
    ``hotspot1``, just re-targeted at this VLAN's own interface/subnet so
    it never touches ``hotspot1`` or the shared LAN bridge. Requires both
    ``cidr`` and ``gateway_ip_address`` (a hotspot needs a real pool to
    hand out) -- emits an explanatory skip comment otherwise, the same
    "skip, don't guess" discipline every other render_* function here
    already follows."""
    tag = f"vlan{vlan.vlan_id}"
    if not vlan.cidr or not vlan.gateway_ip_address:
        return [f"# {tag}-hotspot: needs both cidr and gateway_ip_address -- skipping"]
    network = ipaddress.ip_network(vlan.cidr, strict=False)
    usable = [str(h) for h in network.hosts() if str(h) != vlan.gateway_ip_address]
    if not usable:
        return [f"# {tag}-hotspot: no usable addresses left in {network} -- skipping"]
    pool_name = f"{tag}-hs-pool"
    profile_name = f"{tag}-hsprof"
    # See module docstring's "Hotspot dns-name" section: a per-VLAN
    # variant of the platform-wide default, not the bare literal, since
    # this function can render more than one independent hotspot per
    # router.
    dns_name = f"{tag}.{HOTSPOT_DNS_NAME}"
    return [
        f"/ip pool add name={pool_name} ranges={usable[0]}-{usable[-1]}",
        f"/ip dhcp-server add name={tag}-hs-dhcp interface={bind_interface} "
        f"address-pool={pool_name} disabled=no",
        f"/ip dhcp-server network add address={network} "
        f"gateway={vlan.gateway_ip_address} dns-server={vlan.gateway_ip_address}",
        # use-radius/login-by are not optional polish: a profile without
        # them defaults to `use-radius=no login-by=cookie,http-chap`, and
        # the portal then cannot check any credential against this
        # platform. Mirrors hsprof1, the working guest profile.
        f"/ip hotspot profile add name={profile_name} "
        f"hotspot-address={vlan.gateway_ip_address} "
        f"html-directory={HOTSPOT_HTML_DIRECTORY} "
        f"dns-name={dns_name} use-radius=yes login-by=http-pap",
        f"/ip dns static add name={dns_name} address={vlan.gateway_ip_address} "
        f'comment="{tag}-hotspot-dns-name"',
        f"/ip hotspot add name={tag}-hotspot interface={bind_interface} "
        f"address-pool={pool_name} profile={profile_name} disabled=no",
    ]


def _access_port_consent_guard(vlan: Vlan, physical: str, body: list[str]) -> list[str]:
    """Gate an access-mode VLAN's whole rendering on the port not already
    being a bridge member, for a VLAN whose operator never consented to
    taking it.

    ## The incident this mirrors

    An access VLAN on ``ether2`` pulled the port carrying a venue's access
    point out of the bridge the guest portal is bound to, and guest Wi-Fi
    across the site stopped serving. ``Vlan.previous_bridge`` made that
    reversible and the dashboard warned about it, but nothing *refused* --
    and a warning an operator can click past is not a decision they made.

    ``vlan.service.VlanService._check_takes_bridge_port`` closed that on the
    device-writer path: an access-mode push is refused outright unless
    ``Vlan.confirm_takes_port`` says the operator asked for exactly this.
    This renderer kept issuing an unconditional
    ``/interface bridge port remove``, and ``network_config.service
    ._gather_enabled_rows`` reads VLAN rows straight out of the lookup --
    the service's gate is not on this path at all. So the script reproduced
    the original incident on any router it was pushed to.

    ## Why a runtime guard rather than a render-time refusal

    The writer's rule is a fact about the *device*: it refuses only when the
    port is currently in a bridge, and returns early when the port's bridge
    is ``None`` (a real answer meaning it is in none, and there is nothing
    to take it out of). A renderer holds no device state, so the same
    condition is evaluated on the router instead -- which lands on the same
    rule rather than a stricter approximation of it.

    Each line is guarded individually because :func:`_idempotent_lines`
    wraps every command in its own ``:do {...} on-error={}`` block, so one
    ``:if`` cannot bracket the lines that follow it. Guarding only the
    ``bridge port remove`` would be worse than useless: the address and the
    hotspot would still land on a port that is still a bridge member, which
    is a half-configured VLAN rather than a refused one.

    ``:error`` is deliberately NOT used to abort. ``on-error={}`` would
    swallow it, so the refusal is a ``:log warning`` plus a ``:put`` an
    operator watching the paste can actually see.

    ## What this still cannot do

    ``previous_bridge`` is recorded by the writer at push time from the
    snapshot the refusal was based on, and is what lets a later delete put
    the port back. A rendered script has nowhere to write that fact back
    to, so a *confirmed* access VLAN taken by script is still not reversible
    the way one taken through ``VlanService`` is. Taking the port is gated
    now; giving it back remains device-writer-only, and that asymmetry is
    real rather than papered over here."""
    tag = f"vlan{vlan.vlan_id}"
    member = f"[:len [/interface bridge port find where interface={physical}]]"
    refusal = (
        f"{tag} (access): {physical} is a bridge member and this VLAN does "
        "not carry confirm_takes_port -- refusing to take the port"
    )
    return [
        f"# {tag} (access): confirm_takes_port is not set, so every line "
        f"below is gated on {physical} not already being a bridge member",
        f":if ({member} > 0) do={{ "
        f':log warning "cloudguest: {refusal}"; :put "{refusal}" }}',
        *[
            line
            if line.lstrip().startswith("#")
            else f":if ({member} = 0) do={{ {line} }}"
            for line in body
        ],
    ]


def render_vlan(vlan: Vlan) -> list[str]:
    """Renders one enabled ``Vlan`` row. Branches on ``port_mode``:

    ``"trunk"`` (default) -- ``interface`` is the parent trunk carrying
    802.1Q-tagged traffic; emits the tagged ``/interface vlan``
    sub-interface, the original, always-safe behavior (no bridge change).

    ``"access"`` -- ``interface`` is a dedicated *physical* port (e.g.
    ``ether3``); that port is pulled out of the shared LAN bridge and
    given this VLAN's subnet directly, untagged. Deliberately implemented
    as a dedicated port rather than bridge-wide ``vlan-filtering=yes`` +
    PVID -- see ``app.domains.vlan.models.Vlan.port_mode``'s own
    docstring for why: this way, enabling "access" mode can never disrupt
    the shared bridge's already-live traffic.

    Either mode additionally renders a standalone hotspot on this VLAN's
    own interface when ``enable_hotspot`` is set (see
    ``_render_vlan_hotspot``)."""
    vlan_interface = f"vlan{vlan.vlan_id}"

    if vlan.port_mode == "access":
        if vlan.interface is None:
            return [
                f"# vlan{vlan.vlan_id} (access): no physical port configured -- "
                "skipping, cannot dedicate an access port without one"
            ]
        physical = vlan.interface
        body = [f"/interface bridge port remove [find interface={physical}]"]
        address_line = _vlan_address_line(vlan, physical)
        if address_line:
            body.append(address_line)
        if vlan.enable_hotspot:
            body.extend(_render_vlan_hotspot(vlan, physical))
        if vlan.confirm_takes_port:
            return body
        return _access_port_consent_guard(vlan, physical, body)

    if vlan.interface is None:
        return [
            f"# {vlan_interface}: no parent interface configured -- "
            "skipping, cannot tag a VLAN without one"
        ]
    lines = [
        f"/interface vlan add name={vlan_interface} vlan-id={vlan.vlan_id} "
        f"interface={vlan.interface}"
    ]
    address_line = _vlan_address_line(vlan, vlan_interface)
    if address_line:
        lines.append(address_line)
    if vlan.enable_hotspot:
        lines.extend(_render_vlan_hotspot(vlan, vlan_interface))
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


def render_mac_authorization_entry(entry: MacAuthorizationEntry) -> list[str]:
    """Renders one currently-valid ``MacAuthorizationEntry`` -- the real
    device-config-generation seam this domain previously had no way to
    reach (see ``app.domains.mac_authorization.service`` module
    docstring's own "Device/router composition" section): until now, a
    whitelist entry was pure database bookkeeping with zero effect on
    the physical device. Rendered as a real ``/ip hotspot ip-binding
    type=bypassed`` -- the same mechanism (and RouterOS command shape)
    this platform's own device-agent heartbeat sync already uses for
    post-login authorized-MAC bypass (see
    ``app.domains.router_agent``'s ``/agent/authorized-macs`` consumer
    script), applied here to a MAC that should never need to log in
    through the captive portal at all."""
    identifier = f"mac-auth-{entry.id}"
    return [
        f"/ip hotspot ip-binding add mac-address={entry.mac_address} "
        f'type=bypassed comment="{identifier}"'
    ]


def _domain_subdomain_regex(domain: str) -> str:
    """The real RouterOS ``/ip dns static ... regexp=`` pattern matching
    every subdomain of ``domain`` (never ``domain`` itself -- see
    :func:`render_content_filter_rule`'s own docstring for why both an
    exact-name entry and this regexp entry are rendered together). A
    domain contains only alphanumerics/hyphens/dots -- the one character
    with real regex meaning is ``.``, escaped here; nothing else in a
    normalized (see ``app.domains.content_filtering.validators
    .normalize_domain``) hostname needs escaping."""
    escaped = domain.replace(".", r"\.")
    return f"^.*\\.{escaped}$"


def render_content_filter_rule(rule: ContentFilterRule) -> list[str]:
    """Renders one enabled ``ContentFilterRule`` row -- see module
    docstring's "Content Filtering" section for the full real-mechanism
    write-up. A ``DOMAIN`` rule renders a DNS-sinkhole pair (exact name +
    subdomain regexp); an ``IP_CIDR`` rule renders one address-list
    membership line only -- the aggregate DROP filter rule that actually
    makes IP/CIDR blocking take effect is rendered once per push by
    :func:`render_content_filter_enforcement`, not repeated here per
    rule."""
    label = f"{rule.category or 'custom'}: {rule.name}"
    if rule.value_type == ContentFilterValueType.IP_CIDR.value:
        return [
            f"/ip firewall address-list add list={CONTENT_FILTER_ADDRESS_LIST_NAME} "
            f'address={rule.value} comment="{label}"'
        ]
    domain = rule.value
    return [
        f"/ip dns static add name={domain} type=A "
        f'address={CONTENT_FILTER_SINKHOLE_ADDRESS} comment="{label}"',
        f'/ip dns static add regexp="{_domain_subdomain_regex(domain)}" type=A '
        f'address={CONTENT_FILTER_SINKHOLE_ADDRESS} comment="{label} (subdomains)"',
    ]


def render_content_filter_enforcement() -> list[str]:
    """The one, router-global ``/ip firewall filter`` DROP rule that makes
    every ``IP_CIDR``-type :class:`ContentFilterRule`'s address-list
    membership (rendered by :func:`render_content_filter_rule`) actually
    block traffic -- see module docstring's "Content Filtering" section
    for why this is rendered exactly once per push, not once per rule.

    ## Position is managed here too, not left to where RouterOS appends

    This used to be a bare ``add``, so the DROP landed at the *bottom* of
    ``forward`` -- below ``accept cloudguest-fw-fwd-established`` -- and a
    blocked destination was then only dropped on a *new* connection. A flow
    already established when the block was added kept flowing: the operator
    pressed Block, the dashboard said applied, and the guest's session
    carried on until it closed by itself.

    ``mikrotik_adapter._ensure_content_filter_enforcement_rule`` fixed
    exactly this on the device-writer path -- placing the rule immediately
    before the first ``accept`` in ``forward``, re-checked on every push --
    and left this half behind. This is that same convergence expressed as
    RouterOS script, so a router configured from a generated script blocks
    the same traffic as one an operator re-applied.

    See that method's docstring for the two device tests that make the
    placement buildable rather than guessed (**T1**: ``place-before`` takes
    a ``.id``, not an ordinal; **T2**: a static rule *can* sit above
    hotspot's own dynamic ``forward`` rules), and for why sitting above the
    accepts -- the dangerous direction in general -- is safe for *this* rule
    specifically: it matches ``dst-address-list=`` and nothing else, so it
    can only ever affect a destination the customer explicitly blocked,
    never the portal, the tunnel, or 8728.

    ## Why one line, and why add-then-remove rather than a position check

    :func:`_idempotent_lines` wraps every rendered command in its own
    ``:do {...} on-error={}``, and a RouterOS ``:local`` does not survive
    across two of those blocks -- so this must be ONE self-contained line,
    the same single-line discipline :func:`render_hotspot_walled_garden`
    and :func:`render_guest_data_path` already follow. Comparing positions
    inside a single line is possible and unreadable; re-adding at the right
    position and dropping the previous rows is neither, and converges to
    the identical end state.

    The ordering *inside* the line is the load-bearing part, and it matches
    the adapter's: the old rows are captured **before** the new one is
    added, and the ``add`` happens **before** any ``remove``, so the window
    holds two identical DROPs rather than none. A duplicated drop is
    harmless; a gap is a site briefly unblocked, and this is a control that
    must fail closed.

    That rewrite also fixes a second defect the bare ``add`` carried:
    ``/ip firewall filter`` has no unique key, so ``on-error={}`` caught
    nothing and **every push appended another DROP** at the bottom of the
    chain. This line leaves exactly one, however many times it is run."""
    rule = (
        "chain=forward "
        f"dst-address-list={CONTENT_FILTER_ADDRESS_LIST_NAME} action=drop "
        f'comment="{CONTENT_FILTER_ENFORCEMENT_COMMENT}"'
    )
    return [
        ":local cfOld [/ip firewall filter find where "
        f'comment="{CONTENT_FILTER_ENFORCEMENT_COMMENT}"]; '
        ":local cfAnchor [/ip firewall filter find where chain=forward "
        "action=accept]; "
        ":if ([:len $cfAnchor] > 0) "
        f"do={{ /ip firewall filter add {rule} "
        f"place-before=[:pick $cfAnchor 0] }} "
        f"else={{ /ip firewall filter add {rule} }}; "
        ":foreach cfR in=$cfOld do={ /ip firewall filter remove $cfR }"
    ]


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


# ============================================================================
# Guest data path -- the NAT rule without which an authenticated guest has
# nowhere to send a packet.
# ============================================================================

#: Header for the section emitted by :func:`render_guest_data_path`.
GUEST_DATA_PATH_SECTION_HEADER = "# --- Guest Data Path (CloudGuest-managed) ---"


def render_guest_data_path() -> list[str]:
    """Assert that guest traffic leaving this router gets source-NAT'd onto
    whatever interface is actually carrying the internet.

    ## Why this exists as its own, link-independent section

    Every piece of RouterOS below already existed. It lived inside
    ``app.domains.network_config.wan.renderers.render_wan_routing_section``,
    which ``wan.assembler.render_basic_wan_config`` short-circuits with
    ``if not ctx.links: return ""`` -- and ``ctx.links`` is built from
    *enabled ISP link rows*. So a router with no ISP link configured
    received no masquerade at all, and nothing anywhere said so.

    Confirmed live 2026-08-27/28, venue "huda city center", router
    21e13913: zero ``isp_links`` rows, zero ``provisioning_jobs``, one
    ``config_versions`` row still ``draft``, and no config push in 24h. The
    guest at ``10.5.50.250`` authenticated cleanly -- OTP verified, RADIUS
    ``authorized: true``, Accounting-Start received, WireGuard handshaking
    -- and had no internet, because nothing had ever told the router to NAT
    them. The ``bytes_uploaded``/``bytes_downloaded`` on that session were
    portal and walled-garden traffic, which is exactly why byte counters
    must never be read as proof that a guest reached the internet.

    The masquerade needs no ISP-link data whatsoever -- it derives its
    target from the device's own routing table -- so gating it on ISP links
    was never anything but an accident of where the code happened to sit.
    This function is that logic, reachable unconditionally.

    ## The interface is DISCOVERED, never assumed

    :func:`~app.domains.network_config.wan.renderers._uplink_discovery_statements`
    resolves the out-interface from the router's own active default route
    in the main routing table, verifies the result is a real interface, and
    degrades to ``""`` rather than to a plausible-looking wrong name. That
    matters more here than anywhere else it is used: this section ships to
    every enrolled router, and a masquerade pointed at the wrong
    out-interface on a venue that was working is a far worse outcome than
    no masquerade at all. If nothing resolves, this emits a warning and
    changes nothing.

    ## Why this cannot disturb the tunnel, RADIUS, or an operator's rules

    Three separate guarantees, none of them incidental:

    1. **Scoped by out-interface, not by source.** The rule matches
       ``out-interface=<the discovered uplink>``. Traffic to the WireGuard
       hub egresses ``wg-cloudguard``, never the uplink, so RADIUS
       continues to source from the router's tunnel address exactly as
       before. A source-scoped rule (``src-address=10.5.50.0/24``) would
       have needed an explicit tunnel exclusion to be equally safe; this
       one needs none, which is one fewer thing to get wrong.
    2. **Only ever touches its own marker.** Every read and every write is
       filtered on ``comment="cloudguest-nat-live"``. A venue's own
       masquerade, port forwards or hairpin rules carry no such comment and
       are therefore never counted, re-pointed, or removed. Nothing here
       removes anything at all.
    3. **Idempotent by count, not by hope.** Absent -> add; present ->
       re-point to the currently-live uplink inside ``:do {} on-error={}``.
       Re-running converges; it never duplicates.

    ## What this deliberately does NOT create

    No hotspot server, no address pool, no DHCP server -- despite those
    being part of the original brief. The evidence says they already work:
    the guest received ``10.5.50.250`` by DHCP and loaded the captive
    portal, which cannot happen without all three. They came from the
    enrollment ``.rsc``, not from a platform push, so the platform's
    ``hotspot_profiles`` table is empty while the device is correctly
    configured. Creating objects that already exist and are working, on a
    device this code cannot see, is the one change most likely to break a
    venue that is currently fine. The missing piece was NAT; this fixes
    NAT.
    """
    p = "cgDataPath"
    if_resolved = f'${p}If != ""'
    return [
        "; ".join(
            [
                *_uplink_discovery_statements(p),
                # Membership of the WAN interface list, so any
                # `in-interface-list=WAN` firewall rule this platform or the
                # operator relies on actually matches the live uplink.
                f":local {p}InList 0",
                f":if ({if_resolved}) do={{ :set {p}InList [:len [/interface list "
                f'member find where interface=${p}If list="WAN"]] }}',
                f":if ({if_resolved} && ${p}InList = 0) do={{ /interface list member "
                f'add list="WAN" interface=${p}If '
                f'comment="{DISCOVERED_WAN_LIST_COMMENT}" }}',
                # The masquerade itself.
                f":local {p}Nat [/ip firewall nat find where "
                f'comment="{DISCOVERED_NAT_COMMENT}"]',
                f":if ({if_resolved} && [:len ${p}Nat] = 0) do={{ /ip firewall nat add "
                f"chain=srcnat out-interface=${p}If action=masquerade "
                f'comment="{DISCOVERED_NAT_COMMENT}" }}',
                f":if ({if_resolved} && [:len ${p}Nat] > 0) do={{ :do {{ /ip firewall "
                f"nat set ${p}Nat chain=srcnat out-interface=${p}If "
                f"action=masquerade }} on-error={{ :log warning "
                f'("cloudguest: could not re-point the Wyfy-managed masquerade at " '
                f'. ${p}If . " -- guests may not get NAT over the live uplink") }} }}',
                f':if (!({if_resolved})) do={{ :log warning "cloudguest: no uplink '
                "interface resolved, so the Wyfy-managed WAN list membership and "
                'masquerade were left exactly as they are -- nothing was guessed" }',
            ]
        ),
    ]


def render_guest_data_path_verification() -> list[str]:
    """Fail loudly if the guest data path was not actually established.

    Separate from :func:`render_guest_data_path` because asserting and
    verifying are different claims, and this platform has just spent a day
    learning what happens when they are conflated. The bootstrap script's
    own success line has always been gated on re-queried WireGuard state
    for exactly this reason; this extends the same discipline to the half
    that was missing.

    ``:error`` rather than ``:log warning``: a router that finished
    enrollment without a NAT rule is a venue where every guest will
    authenticate successfully and then have no internet -- silently, with
    the platform reporting the router provisioned. Stopping the script with
    a named reason is strictly better than completing and being wrong,
    which is the exact failure this whole change exists to end."""
    return [
        f':if ([:len [/ip firewall nat find where comment="{DISCOVERED_NAT_COMMENT}"]] '
        "= 0) do={ :error "
        '"CloudGuest bootstrap verification failed: no guest NAT rule was '
        "established, so an authenticated guest would have no route to the "
        "internet. Usually this means no active default route was present "
        'when this script ran -- check the WAN uplink and re-run." }',
    ]


# ============================================================================
# Captive-portal walled garden -- what a guest may reach BEFORE they log in.
# ============================================================================

#: Header for the section emitted by :func:`render_hotspot_walled_garden`.
WALLED_GARDEN_SECTION_HEADER = (
    "# --- Captive Portal Walled Garden (CloudGuest-managed) ---"
)

#: ``comment=`` every walled-garden row this module owns carries. Same
#: ``cloudguest-<thing>-live`` shape as ``DISCOVERED_NAT_COMMENT`` and for
#: the same reason: the re-apply below must be able to find *its own* rows
#: without ever matching -- or removing -- one an operator added by hand.
MANAGED_WALLED_GARDEN_COMMENT = "cloudguest-walledgarden-live"


def _portal_walled_garden_hosts(api_url: str) -> list[str]:
    """The two hosts a not-yet-authenticated guest must be able to reach.

    ``api_url`` is any absolute URL on the platform's own API -- only its
    host is read, never its path -- which is what lets the bootstrap
    renderers pass the ``check_in_url`` they already hold instead of
    growing a second parameter carrying the same host twice.

    The API host is DERIVED from that URL rather than hardcoded so a
    staging deployment walls in its own API, not production's. The portal
    host is :data:`HOTSPOT_DNS_NAME`, the same constant
    ``_render_vlan_hotspot`` already puts in ``dns-name``/``/ip dns
    static`` -- one source of truth, so the name the guest is redirected to
    and the name they are permitted to reach can never drift apart.

    **The wildcard is not belt-and-braces, it is the entry that actually
    matches.** ``_render_vlan_hotspot`` does not redirect to the bare
    constant: it builds a per-VLAN ``{tag}.`` variant (``dns_name =
    f"{tag}.{HOTSPOT_DNS_NAME}"``) precisely so two hotspots on one router
    cannot collide. RouterOS's ``dst-host`` takes plain hostnames, IPs, or
    ``*``-prefixed wildcard domains (see ``hotspot.validators
    .validate_walled_garden_hosts``) -- a bare ``wifi.wyfyguest.com`` does
    not cover ``vlan100.wifi.wyfyguest.com``. Allowing only the bare name
    would therefore wall off the exact hostname every guest is sent to.
    Both forms are emitted because the wildcard conventionally does not
    match the bare name either, and a single-hotspot router bound straight
    to the constant is a real configuration.
    """
    api_host = urlsplit(api_url).hostname
    hosts = [HOTSPOT_DNS_NAME, f"*.{HOTSPOT_DNS_NAME}"]
    if api_host and api_host not in hosts:
        hosts.append(api_host)
    return hosts


def render_hotspot_walled_garden(*, api_url: str) -> list[str]:
    """Let an unauthenticated guest reach the platform's own portal and
    API -- and nothing else.

    ## Why this exists as its own, profile-independent section

    RouterOS's ``/ip hotspot walled-garden`` is what a captive portal uses
    to punch a hole for its own login page: until a guest authenticates,
    the hotspot intercepts *everything*, so the portal they are redirected
    to is itself unreachable unless it is explicitly allowed through.

    This platform already renders walled-garden rows -- in
    :func:`render_hotspot_profile`, from ``HotspotProfile
    .walled_garden_hosts``. That is an operator-configured list on an
    optional row, and it is the same structural mistake
    :func:`render_guest_data_path` was written to undo: something *every*
    router needs unconditionally was reachable only through a table that
    can legitimately be empty.

    Confirmed against production 2026-08-29: ``select name,
    walled_garden_hosts from hotspot_profiles where is_deleted=false``
    returned **zero rows**. Not "rows with an empty list" -- no profiles at
    all. So no router in the fleet has ever been sent a single
    walled-garden entry, and the portal has only ever been reachable
    because it is served from the router's own address, which the hotspot
    necessarily permits. The moment the portal moves to a real hostname --
    which is the entire point of ``dns-name``/``HOTSPOT_DNS_NAME`` -- that
    accident stops covering for the missing configuration.

    ## Rendered idempotently, and it never deletes

    Each host is guarded by a ``find where dst-host=... && comment=...``
    length check before its ``add``, the same self-guarding shape
    :func:`render_guest_data_path` uses, so re-running a bootstrap does not
    accumulate duplicate rows. Rows are only ever added, never removed:
    an operator's own walled-garden entries carry a different ``comment``
    (or none) and are untouched, and this function deliberately does not
    prune even its own stale rows -- withdrawing a host a live guest may be
    mid-request against is a worse failure than one extra allow rule.

    ## What this does NOT fix

    It does not stop the browser's "the information you're about to submit
    is not secure" warning. That warning comes from the router serving its
    own hotspot login page, with its own ``<form>``, over plain HTTP --
    ``dns-name`` changed the host in that URL, not its scheme. Removing the
    warning additionally requires the hotspot's ``html-directory``
    (``cloudguest-hotspot``, already set by ``_render_vlan_hotspot``) to
    hold a login page that carries no form of its own and merely redirects
    to the platform's real HTTPS portal. That needs a file on the device,
    so it needs either a ``/tool fetch`` of a page the API serves or a
    ``/file`` write -- neither of which is rendered here, and neither of
    which has been confirmed against a real device, which this module's own
    "confirmed live" standard requires before it ships. This section is the
    half that is safe to ship without a device: the HTTPS portal is
    unreachable pre-auth *without* it, so it is a prerequisite for that
    work rather than an alternative to it.
    """
    # One self-contained line per host, with the find inlined rather than
    # bound to a `:local` first: this rides on the bootstrap script, whose
    # own line-count cap (see tests) exists to keep it a thin paste, and a
    # temporary variable per host would double the footprint for no gain.
    return [
        f":if ([:len [/ip hotspot walled-garden find where "
        f'dst-host="{host}" && comment="{MANAGED_WALLED_GARDEN_COMMENT}"]] = 0) '
        f'do={{ /ip hotspot walled-garden add dst-host="{host}" action=allow '
        f'comment="{MANAGED_WALLED_GARDEN_COMMENT}" }}'
        for host in _portal_walled_garden_hosts(api_url)
    ]


def render_radius_client(
    nas_client: RadiusNasClient, tunnel_ip: str, radius_server_host: str
) -> list[str]:
    """Renders one router's ``RadiusNasClient`` registration into its
    device-side RADIUS client entry plus CoA enablement. See module
    docstring's RADIUS section for why ``src-address=<tunnel_ip>`` is this
    function's single most important parameter, why ``service=hotspot``
    needs no separate accounting line, and why ``/radius incoming`` is
    rendered unconditionally here (it is a router-global setting, not
    per-client).

    ## This converges; it used to append

    This emitted a bare ``/radius add`` with no read first, and
    :func:`_idempotent_lines`' ``on-error={}`` could not save it:
    ``/radius`` has no unique key, so the ``add`` never errored and every
    push left **another** NAS registration for the same server. After a
    secret rotation one of them is stale, and RouterOS consults them in
    order -- a router that authenticates guests intermittently, with a
    correct-looking configuration at both ends.

    ``mikrotik_adapter._ensure_radius_client_row`` fixed exactly this on
    the writer path, and its own docstring named this function as still
    carrying the defect. This is that same convergence: the ``add`` is
    guarded by a ``find where address=``, an existing row is adopted with
    a ``set`` rather than duplicated, and the row is stamped with
    :data:`RADIUS_CLIENT_COMMENT`.

    ``authentication-port``/``accounting-port`` are written explicitly even
    though ``service=hotspot`` already defaults both (module docstring,
    confirmed live on 7.21.5). The reason is the ``set`` branch rather than
    the ``add`` branch: a row this now *adopts* may be one a human created
    with different ports, and silently inheriting those is how a
    registration that reads as correct authenticates against nothing.

    Keyed on ``address`` alone rather than the writer's
    ``service`` + ``address`` pair: RouterOS stores ``service`` as a list,
    which does not survive a script-level ``=`` comparison the way it
    survives the adapter's Python one. One RADIUS server per router makes
    the address sufficient here."""
    secret = decrypt_secret(nas_client.shared_secret_encrypted)
    fields = (
        f"service=hotspot address={radius_server_host} "
        f'secret="{secret}" src-address={tunnel_ip} '
        f"authentication-port={RADIUS_AUTH_PORT} "
        f"accounting-port={RADIUS_ACCT_PORT} "
        f'comment="{RADIUS_CLIENT_COMMENT}" disabled=no'
    )
    found = f'[/radius find where address="{radius_server_host}"]'
    return [
        f":if ([:len {found}] = 0) do={{ /radius add {fields} }} "
        f"else={{ /radius set {found} {fields} }}",
        f"/radius incoming set accept=yes port={RADIUS_COA_PORT}",
    ]


# ============================================================================
# Netwatch -- see module docstring's own "Netwatch" section for the full
# design write-up.
# ============================================================================

# The real, already-mounted device-facing path
# app.domains.router_agent.router.agent_netwatch_event lives at -- not
# invented, mirrors _CHECK_IN_PATH/_AGENT_CONFIG_PATH/_AGENT_HEARTBEAT_PATH
# above exactly.
_AGENT_NETWATCH_EVENT_PATH = "/api/v1/agent/netwatch-event"

# RouterOS's own /tool netwatch polling cadence for each entry this
# function renders -- deliberately well under the 30-second server-side
# sweep interval (app.domains.isp.constants
# .ISP_HEALTH_CHECK_SWEEP_INTERVAL_SECONDS) so this is a genuinely faster,
# complementary detection path, not a cosmetic duplicate of it. A plain
# module constant, not a per-link tunable -- no real operational need for
# per-link Netwatch cadence has surfaced yet, the same "single honest
# default until a real need for tunability appears" posture
# app.domains.isp.constants documents for its own thresholds.
NETWATCH_CHECK_INTERVAL = "10s"


def _netwatch_payload(link_id: object, *, status: str, host: str) -> str:
    """The real, render-time-literal JSON body each Netwatch script's own
    ``/tool fetch http-data=`` carries -- escaped for embedding inside a
    RouterOS double-quoted string literal (``\\"``), the identical
    escaping convention :func:`render_agent_heartbeat_scheduler` already
    established for its own ``on-event`` string above."""
    return (
        '{\\"isp_link_id\\":\\"' + str(link_id) + '\\",'
        '\\"status\\":\\"' + status + '\\",'
        '\\"host\\":\\"' + host + '\\"}'
    )


def _netwatch_callback_script(
    *, event_url: str, agent_credential: str, link_id: object, host: str, status: str
) -> str:
    """One Netwatch ``up-script``/``down-script`` value -- a RouterOS
    curly-brace script block (not a quoted string, unlike
    :func:`render_agent_heartbeat_scheduler`'s own ``on-event`` -- both are
    real, valid RouterOS forms for this purpose; the block form needs no
    outer-quote escaping of its own, which keeps this one legible next to
    the already-escaped JSON body it carries) issuing one real ``/tool
    fetch`` POST to the real, already-mounted
    ``POST /agent/netwatch-event`` endpoint, authenticated the same way
    every other device-facing call in this codebase is
    (``X-Agent-Credential``, see ``app.domains.router_agent.constants
    .AGENT_CREDENTIAL_HEADER``)."""
    payload = _netwatch_payload(link_id, status=status, host=host)
    return (
        f'{{/tool fetch url="{event_url}" http-method=post '
        f'http-header-field="X-Agent-Credential: {agent_credential}" '
        f'http-data="{payload}" output=none}}'
    )


def render_isp_netwatch_entry(
    link: IspLink, *, api_base_url: str, agent_credential: str
) -> list[str]:
    """Renders one real ``/tool netwatch add host=<gateway> up-script=...
    down-script=...`` entry watching ``link``'s own already-known
    health-check target -- see module docstring's own "Netwatch" section
    for the full design write-up (scope limits, the credential-rotation
    seam, what gets reported back and to where, and why this is
    self-idempotent rather than wrapped by :func:`_idempotent_lines`).

    Raises ``ValueError`` if ``api_base_url`` is not ``https://`` -- see
    :func:`_require_https` (the identical guard
    :func:`render_bootstrap_script`/:func:`render_agent_heartbeat_scheduler`
    already enforce for their own calls back to this platform).
    """
    tag = f"isp-netwatch-{link.id}"
    if (
        link.connection_mode != IspConnectionMode.STATIC.value
        or not link.gateway_ip_address
    ):
        return [
            f"# {tag}: netwatch needs a STATIC-mode link with a known "
            "gateway_ip_address -- skipping (a DHCP link's target is "
            "resolved live at check time, never a fixed value; a PPPOE "
            "link has no IP-layer gateway/ping target at all -- see "
            "IspService.ping_link's own docstring)"
        ]
    _require_https(api_base_url, caller="render_isp_netwatch_entry")
    event_url = f"{api_base_url}{_AGENT_NETWATCH_EVENT_PATH}"
    up_script = _netwatch_callback_script(
        event_url=event_url,
        agent_credential=agent_credential,
        link_id=link.id,
        host=link.gateway_ip_address,
        status="up",
    )
    down_script = _netwatch_callback_script(
        event_url=event_url,
        agent_credential=agent_credential,
        link_id=link.id,
        host=link.gateway_ip_address,
        status="down",
    )
    return [
        f'/tool netwatch remove [find comment="{tag}"]',
        f"/tool netwatch add host={link.gateway_ip_address} "
        f"interval={NETWATCH_CHECK_INTERVAL} "
        f"up-script={up_script} down-script={down_script} "
        f'comment="{tag}"',
    ]


def render_isp_netwatch_config(
    links: list[IspLink], *, api_base_url: str, agent_credential: str
) -> str:
    """Combines every ``link`` in ``links`` into one standalone Netwatch
    script -- the pure-function assembler for
    ``NetworkConfigService.push_isp_netwatch_config``'s own push, mirroring
    :func:`render_network_config`'s own "combine every row into one script"
    shape, deliberately kept separate from it (see that method's own
    docstring for why: folding ISP/agent-credential plumbing into
    ``render_network_config``'s already-12-parameter signature would
    entangle a category no other one of its callers needs to know about).
    Returns an empty string for an empty ``links`` list -- the caller
    decides whether that is an error or a valid, informational result, the
    same split ``render_network_config`` itself already establishes."""
    if not links:
        return ""
    sections = [NETWATCH_SECTION_HEADER]
    for link in links:
        sections.extend(
            render_isp_netwatch_entry(
                link, api_base_url=api_base_url, agent_credential=agent_credential
            )
        )
    return "\n".join(sections)


# Comment tag every entry this bootstrap script itself creates is stamped
# with, so re-running it (e.g. a technician pastes it twice) removes and
# re-adds rather than duplicating -- see module docstring's Bootstrap
# section. A short, fixed literal (not suffixed with any row id, mirroring
# WIREGUARD_INTERFACE_NAME's own no-suffix-needed reasoning): a router runs
# this script exactly once, before it has any other CloudGuest-managed
# config at all, so there is nothing else in a fresh device's config this
# tag could ever collide with.
_BOOTSTRAP_MGMT_TAG = "CGBOOT"

# --- Clock / NTP -------------------------------------------------------
# Mirrors the Master console generator's own `Clock + NTP` chunk
# (`CLOCK_NTP_SERVERS`/`CLOCK_TIME_ZONE` in
# `cloudguest-foundation/src/components/routers/RouterDetailTabs.tsx`).
# The two generators are separate code in separate repos and had drifted:
# the console chunk has set the clock since 2026-08-23, this one never
# did, so a router enrolled through the Fleet Wizard got no NTP at all.
_BOOTSTRAP_NTP_SERVERS = ("216.239.35.0", "162.159.200.1")
_BOOTSTRAP_TIME_ZONE = "Asia/Kolkata"


def _render_clock_lines() -> list[str]:
    """Set the time zone, enable NTP, and REFUSE TO CONTINUE until the
    clock is actually synchronised.

    Why this belongs in the bootstrap script, before anything else runs:
    every subsequent line of this script talks to the platform over
    HTTPS (:func:`_require_https` guarantees it -- there are ten
    ``/tool fetch`` calls in this module and the bootstrap flow's
    check-in and key-pull are two of them). A MikroTik with no
    battery-backed real-time clock boots at the RouterOS build date, and
    TLS certificate validation fails closed against a wrong date. The
    fetch is then rejected *before it is sent*, with RouterOS's own
    generic failure text and nothing naming the clock as the cause.

    That is the exact production failure this closes: the router serves
    guests perfectly while never once checking in, so it shows OFFLINE
    in Master console forever and every diagnostic points at the network
    rather than the date. The Master console's own generator has emitted
    an equivalent chunk since 2026-08-23; this renderer -- the Fleet
    Wizard's path, and the only one used for zero-touch enrollment --
    never did, so wizard-provisioned routers were the ones that could
    still land in that state.

    ``:error`` rather than a printed warning, matching the rest of this
    module's fail-closed posture: the bootstrap script is delivered
    non-interactively (pasted whole, or pushed through the gateway), so
    a warning has no reader. Stopping here leaves a router with a
    correct identity and no tunnel, which is honestly incomplete and
    trivially retried; continuing produces one that looks enrolled and
    silently never reports.

    Single-line/``;``-join safe and free of ``#`` comments, per this
    module's contract. Each ``do={}``/``on-error={}`` body holds exactly
    one statement -- a multi-statement inline body is a confirmed live
    syntax error on this hardware.
    """
    servers = ",".join(_BOOTSTRAP_NTP_SERVERS)
    return [
        "/system clock set time-zone-autodetect=no "
        f"time-zone-name={_BOOTSTRAP_TIME_ZONE}",
        # RouterOS 7 spells the list `servers=`; RouterOS 6 has no such
        # property and wants `primary-ntp=`/`secondary-ntp=`. Try v7, fall
        # back to v6, and fail loudly if neither is accepted rather than
        # leaving the operator to infer it from the sync wait below.
        f"/system ntp client set enabled=yes servers={servers}",
        # Bounded wait: NTP needs a moment after being enabled, and the
        # very next thing this script does is an HTTPS fetch. 15 x 2s.
        ':local cgClk ""',
        ":local cgTries 0",
        (
            ':while ($cgClk != "synchronized" && $cgTries < 15) do={'
            " :do { :set cgClk [:tostr [/system ntp client get status]] }"
            ' on-error={ :set cgClk "unreadable" }; :set cgTries ($cgTries + 1);'
            " :delay 2s }"
        ),
        (
            ':if ($cgClk != "synchronized") do={ :error "CloudGuest bootstrap'
            " STOPPED: the clock is not NTP-synchronised (status=$cgClk). Every"
            " platform call in this script is HTTPS and will be rejected before"
            " it is sent, leaving this router permanently OFFLINE in Master"
            " console while its WiFi works. Check outbound UDP 123 is not"
            ' blocked at this venue, then re-run this script." }'
        ),
    ]


# Comment tags + fixed names for the two remote-mode ``/system scheduler``
# entries (the detached cutover and its timed revert safety net) --
# suffixed off the same base tag exactly like
# ``render_agent_heartbeat_scheduler``'s ``CGBOOT-hb``, and removed by
# comment (never by name) following that same established convention.
_BOOTSTRAP_CUTOVER_TAG = f"{_BOOTSTRAP_MGMT_TAG}-cutover"
_BOOTSTRAP_REVERT_TAG = f"{_BOOTSTRAP_MGMT_TAG}-revert"
_BOOTSTRAP_CUTOVER_SCHEDULER_NAME = "cloudguest-bootstrap-cutover"
_BOOTSTRAP_REVERT_SCHEDULER_NAME = "cloudguest-bootstrap-revert"

# Real, already-mounted platform API paths this addition's two device
# -facing calls target -- see module docstring's Bootstrap section for why
# these are read from the real routers/router_agent modules, not invented.
# Relative (no scheme/host) so they compose with whatever ``api_base_url``
# a caller supplies.
_CHECK_IN_PATH = "/api/v1/routers/provisioning/check-in"
_AGENT_CONFIG_PATH = "/api/v1/agent/config"
_AGENT_WIREGUARD_CONFIG_PATH = "/api/v1/agent/wireguard-config"
_AGENT_HEARTBEAT_PATH = "/api/v1/agent/heartbeat"

# Every check-in response field the bootstrap script dereferences -- each
# one gets its own presence check in the rendered script (a missing field
# must stop the run *naming that field*, not surface later as a cryptic
# RouterOS expression error), and ``ProvisioningCheckInResponse`` declares
# each one required so a platform regression fails loudly server-side
# before any router ever sees it.
_CHECK_IN_REQUIRED_FIELDS = (
    "agent_credential",
    "tunnel_ip_address",
    "wireguard_server_public_key",
    "wireguard_endpoint_host",
    "wireguard_endpoint_port",
    "wireguard_hub_tunnel_address",
)


def _render_json_field_check(var: str, field: str, source: str) -> str:
    """One RouterOS line asserting a deserialized JSON field is present.

    ``[:typeof ...]`` is ``"nothing"`` for a missing array member and
    ``"nil"`` for an explicit JSON ``null`` -- both mean the platform did
    not send a usable value, and the ``:error`` message names the exact
    field so the technician (and the founder reading over their shoulder)
    sees *which* contract broke, not a downstream expression error."""
    ref = f'(${var}->"{field}")'
    return (
        f':if ([:typeof {ref}] = "nothing" || [:typeof {ref}] = "nil") '
        f'do={{ :error "CloudGuest bootstrap: {source} response missing {field}" }}'
    )


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


def _embed_literal(text: str) -> str:
    """Escapes one literal RouterOS snippet for embedding inside a
    double-quoted RouterOS string (the remote mode's runtime-concatenated
    ``on-event`` values): ``"`` becomes ``\\"`` and ``$`` becomes ``\\$``
    -- both straight from RouterOS's own scripting escape table ("Insert
    double quote" / "Output $ character. Otherwise, $ is used to link the
    variable"), and the ``\\"`` form is the exact one
    :func:`render_agent_heartbeat_scheduler` already confirmed live
    against a real CHR. Backslashes never occur in the snippets this
    module embeds (asserted, so a future snippet containing one fails
    loudly here instead of silently rendering a broken escape)."""
    if "\\" in text:
        raise ValueError(
            "_embed_literal: snippet contains a backslash, which this "
            "escaper deliberately does not handle -- extend it consciously"
        )
    return text.replace('"', '\\"').replace("$", "\\$")


def _ros_string_expr(pieces: list[tuple[str, str]]) -> str:
    """Builds one RouterOS string-concatenation expression -- e.g.
    ``("lit" . ($enroll->"x") . "lit")`` -- from ``("lit", text)`` /
    ``("expr", routeros_expression)`` pieces. Literal pieces are escaped
    via :func:`_embed_literal` (they end up inside a double-quoted
    RouterOS string); expression pieces are runtime RouterOS code,
    evaluated at *staging* time so their values are baked into the stored
    scheduler ``on-event`` text. Adjacent literals are merged so the
    rendered expression stays readable -- the founder reads this text."""
    merged: list[tuple[str, str]] = []
    for kind, value in pieces:
        if kind == "lit" and merged and merged[-1][0] == "lit":
            merged[-1] = ("lit", merged[-1][1] + value)
        else:
            merged.append((kind, value))
    rendered = [
        f'"{_embed_literal(value)}"' if kind == "lit" else value
        for kind, value in merged
    ]
    return "(" + " . ".join(rendered) + ")"


def _join_embedded_commands(
    commands: list[list[tuple[str, str]]],
) -> list[tuple[str, str]]:
    """Joins per-command piece lists with ``"; "`` separators -- the
    embedded script executes as ONE detached scheduler job, where ``;``
    separates statements exactly as it does on a single console line."""
    joined: list[tuple[str, str]] = []
    for index, command in enumerate(commands):
        if index:
            joined.append(("lit", "; "))
        joined.extend(command)
    return joined


# Shared between both modes: the tunnel address handed back by check-in is
# a bare host IP; the /32 it carries on-interface is appended on-device.
_TUNNEL_ADDRESS_LOCAL_LINE = ':local tunaddr (($enroll->"tunnel_ip_address") . "/32")'


def _render_enrollment_lines(
    *, provisioning_token: str, check_in_url: str, wg_config_url: str
) -> list[str]:
    """The enrollment + key-delivery + full-validation block both modes
    share verbatim: one-time-token check-in (``:do {} on-error={}``
    wrapped, ``http-code`` guarded), per-field presence checks on every
    ``_CHECK_IN_REQUIRED_FIELDS`` member, the credentialed
    wireguard-config pull, and the missing/empty ``peer_private_key``
    checks. In on-site mode this block runs after the cleanup; in remote
    mode it runs *before anything is touched at all* -- that ordering
    difference lives entirely in the two callers, never in this block."""
    return [
        ':local body ("{\\"token\\":\\"" . "' + provisioning_token + '" . "\\"}")',
        ":local resp; :do { :set resp "
        f'[/tool fetch url="{check_in_url}" http-method=post '
        'http-header-field="Content-Type: application/json" http-data=$body '
        "output=user as-value] } on-error={ :error "
        '"CloudGuest bootstrap: check-in request failed -- the platform '
        "rejected the call or is unreachable; generate a fresh bootstrap "
        'script and re-run it" }',
        ':if (($resp->"http-code") != "200") do={ '
        ':error ("check-in failed: " . ($resp->"data")) }',
        ':local enroll [:deserialize from=json value=($resp->"data")]',
        *(
            _render_json_field_check("enroll", field, "check-in")
            for field in _CHECK_IN_REQUIRED_FIELDS
        ),
        ":local wgresp; :do { :set wgresp "
        f'[/tool fetch url="{wg_config_url}" '
        'http-header-field=("X-Agent-Credential: " . ($enroll->"agent_credential")) '
        "output=user as-value] } on-error={ :error "
        '"CloudGuest bootstrap: wireguard-config request failed -- the '
        'platform rejected the agent credential or is unreachable" }',
        ':if (($wgresp->"http-code") != "200") do={ '
        ':error ("wireguard-config failed: " . ($wgresp->"data")) }',
        ':local wgcfg [:deserialize from=json value=($wgresp->"data")]',
        _render_json_field_check("wgcfg", "peer_private_key", "wireguard-config"),
        ':if ([:len ($wgcfg->"peer_private_key")] = 0) do={ :error '
        '"CloudGuest bootstrap: wireguard-config response has an empty '
        'peer_private_key" }',
    ]


def render_bootstrap_script(
    *,
    location_code: str,
    provisioning_token: str,
    api_base_url: str,
    wireguard_listen_port: int = DEFAULT_WIREGUARD_PORT,
    mode: BootstrapMode = BootstrapMode.ONSITE,
) -> list[str]:
    """Renders the Step 1 enrollment script in one of two modes -- one
    generator, two orderings, shared blocks (identity line, the entire
    enrollment/validation block via :func:`_render_enrollment_lines`, the
    same create/verify command shapes).

    **ONSITE (default -- fresh enrollment, technician present).** Exactly
    the previously-shipped cleanup-first script: identity, tear down any
    stale CGBOOT-tagged state and the ``wg-cloudguard`` interface *before*
    contacting the platform, then check-in, key pull, create, verify,
    gated success line. Correct precisely because nothing valuable exists
    yet, the prior state is unknown, and the technician holds
    console/WinBox access if anything goes sideways. See this module's
    docstring Bootstrap section for every rationale (key handling, HTTPS
    enforcement, comment-tag idempotency, the orphaned ``interface=*10``
    address row, line-by-line console-paste semantics).

    **REMOTE (re-provision of a live, already-enrolled router).** On a
    provisioned router the WireGuard tunnel *is* the management path, so
    cleanup-first would saw off the branch being sat on. Two inversions:

    1. *Never destroy before you can replace.* Order: refuse unless the
       existing tunnel state is intact (interface + attached address + hub
       peer -- checked before the one-time token is ever spent), capture
       every value needed to restore it (``private-key`` is readable via
       ``get`` per the RouterOS WireGuard docs, marked sensitive --
       captured in-session under the delivering admin session's own
       policy), then run the shared enrollment/validation block. A
       stale/burned token, unreachable platform, or missing field
       ``:error``s out with the live tunnel completely untouched.
    2. *The script executes over the very tunnel it replaces.* When
       delivered through the gateway (``push_live_config`` /
       ``execute_live_command``), removing ``wg-cloudguard`` mid-script
       would kill the transport and orphan every remaining line. So the
       in-session part performs **no teardown at all**: it stages the
       whole cleanup -> create -> verify -> confirm sequence as a one-shot
       ``/system scheduler`` entry (RouterOS auto-stamps ``start-time`` at
       add time; an interval-only entry first fires one interval later and
       "will not run at startup" per the Scheduler docs), whose job is
       detached from any session, plus a second timed **revert** entry
       that restores the captured previous tunnel if the cutover has not
       confirmed itself. Scheduler jobs read their script text before
       executing, so the cutover's opening self-removal (the standard
       RouterOS run-once idiom) and the success path's revert-removal are
       ordinary comment-tag-scoped removes.

    Remote-mode choreography (all values baked at staging time via
    :func:`_ros_string_expr` -- reboot-safe, no reliance on globals):

    * ``cloudguest-bootstrap-revert`` (comment ``CGBOOT-revert``) is armed
      FIRST, ``interval={REMOTE_BOOTSTRAP_REVERT_WINDOW_MINUTES}m``.
    * ``cloudguest-bootstrap-cutover`` (comment ``CGBOOT-cutover``),
      ``interval={REMOTE_BOOTSTRAP_CUTOVER_DELAY_SECONDS}s``: self-removes,
      aborts unless the revert is still armed (so a cutover can never run
      after a revert has already restored the old tunnel), tears down both
      by-comment AND by-interface (a live router's rows may predate the
      CGBOOT tag -- ``render_wireguard_peer``'s documented untagged-rows
      gap), creates the replacement from the validated staged values,
      re-verifies all three resources (address attached specifically to
      ``wg-cloudguard``), then **confirms end-to-end** by pinging the
      hub's tunnel address (up to ``{REMOTE_BOOTSTRAP_CONFIRM_ATTEMPTS}``
      x ``{REMOTE_BOOTSTRAP_CONFIRM_DELAY_SECONDS}s`` -- decided well
      inside the revert window). Only a successful ping disarms the
      revert and logs success; local existence alone never does, because
      a locally-perfect config whose key the hub rejects is exactly the
      failure the revert exists for.
    * The revert entry restores the captured interface/address/peer,
      re-verifies, and only then disarms the (possibly never-run) cutover
      and itself -- so a *failed* revert stays scheduled and retries every
      window until it succeeds or a human intervenes; it never gives up
      silently.

    Verification provenance, stated honestly: ``\\"``/``\\$`` string
    escapes, ``:while``/``:delay``, ``[:pick <array> 0]``, and the
    WireGuard peer property names (``endpoint-address``,
    ``persistent-keepalive``, readable ``private-key``) were checked
    against MikroTik's current RouterOS 7 documentation this session;
    inline ``on-event`` script text and the scheduler comment-tag removal
    idiom were confirmed live on a real CHR by
    :func:`render_agent_heartbeat_scheduler`'s earlier work. Two
    constructs rest on long-established RouterOS behavior that the current
    docs do not spell out and that was NOT re-confirmed on a live 7.23.3
    device this session: ``[/ping <addr> count=N]`` returning the received
    count to a script, and a scheduler job surviving its own entry's
    removal. Both deserve a live pass on LOC-2026-000039's bench twin
    before first production use -- the same explicit "not confirmed live"
    discipline this module's Netwatch section already follows.

    Both modes: HTTPS-only (``ValueError`` otherwise), nothing hardcoded
    (every device-specific value dereferences the platform's JSON at run
    time), no ``#`` comment lines and no newline-dependent constructs
    (single-line ``;``-join safe), and every success line gated on real
    re-queries."""
    _require_https(api_base_url, caller="render_bootstrap_script")
    check_in_url = f"{api_base_url}{_CHECK_IN_PATH}"
    wg_config_url = f"{api_base_url}{_AGENT_WIREGUARD_CONFIG_PATH}"
    if mode is BootstrapMode.REMOTE:
        return _render_remote_bootstrap_lines(
            location_code=location_code,
            provisioning_token=provisioning_token,
            check_in_url=check_in_url,
            wg_config_url=wg_config_url,
            wireguard_listen_port=wireguard_listen_port,
        )
    return _render_onsite_bootstrap_lines(
        location_code=location_code,
        provisioning_token=provisioning_token,
        check_in_url=check_in_url,
        wg_config_url=wg_config_url,
        wireguard_listen_port=wireguard_listen_port,
    )


def _render_onsite_bootstrap_lines(
    *,
    location_code: str,
    provisioning_token: str,
    check_in_url: str,
    wg_config_url: str,
    wireguard_listen_port: int,
) -> list[str]:
    """The on-site (fresh-enrollment) rendering -- byte-identical to the
    pre-split script; see :func:`render_bootstrap_script`."""
    success_message = (
        "CloudGuest bootstrap successful: WireGuard tunnel and guest data path "
        "configured and verified"
    )
    # The three re-queries below back both the named verification lines and
    # the final success gate -- built once so the two can never drift.
    interface_exists = (
        f'[:len [/interface wireguard find where name="{WIREGUARD_INTERFACE_NAME}"]]'
    )
    address_attached = (
        "[:len [/ip address find where "
        f'interface="{WIREGUARD_INTERFACE_NAME}" && address=$tunaddr]]'
    )
    peer_exists = (
        "[:len [/interface wireguard peers find where "
        f'interface="{WIREGUARD_INTERFACE_NAME}" && comment="{_BOOTSTRAP_MGMT_TAG}"]]'
    )
    return [
        # -- identity (unchanged behavior) ---------------------------------
        f'/system identity set name="{location_code}"',
        # -- clock / NTP, BEFORE the first HTTPS call ----------------------
        # A fresh MikroTik has no battery-backed clock and boots at its
        # firmware build date, which fails TLS validation and so fails the
        # check-in fetch below before it is even sent. See
        # `_render_clock_lines`. This is the on-site path -- a genuinely
        # fresh box -- so it is exactly where an unset clock is guaranteed.
        *_render_clock_lines(),
        # -- stale-state cleanup, before anything else ---------------------
        # The /ip address row goes first and is matched BY COMMENT: after a
        # previous run's interface was deleted, its address row lingers
        # pointing at an internal id (interface=*10), unfindable by
        # interface name but still blocking the same address from being
        # re-added on the fresh interface. All three removes are first-run
        # no-ops (empty [find] -> nothing to remove).
        f'/ip address remove [find where comment="{_BOOTSTRAP_MGMT_TAG}"]',
        "/interface wireguard peers remove "
        f'[find where comment="{_BOOTSTRAP_MGMT_TAG}"]',
        f'/interface wireguard remove [find where name="{WIREGUARD_INTERFACE_NAME}"]',
        # -- enrollment + key delivery + validation (shared with remote) ---
        *_render_enrollment_lines(
            provisioning_token=provisioning_token,
            check_in_url=check_in_url,
            wg_config_url=wg_config_url,
        ),
        # -- create: interface, tunnel address, hub peer -------------------
        f"/interface wireguard add name={WIREGUARD_INTERFACE_NAME} "
        'private-key=($wgcfg->"peer_private_key") '
        f"listen-port={wireguard_listen_port} "
        f'comment="{_BOOTSTRAP_MGMT_TAG}"',
        _TUNNEL_ADDRESS_LOCAL_LINE,
        "/ip address add address=$tunaddr "
        f'interface={WIREGUARD_INTERFACE_NAME} comment="{_BOOTSTRAP_MGMT_TAG}"',
        f"/interface wireguard peers add interface={WIREGUARD_INTERFACE_NAME} "
        'public-key=($enroll->"wireguard_server_public_key") '
        'endpoint-address=($enroll->"wireguard_endpoint_host") '
        'endpoint-port=($enroll->"wireguard_endpoint_port") '
        'allowed-address=(($enroll->"wireguard_hub_tunnel_address") . "/32") '
        f"persistent-keepalive={DEFAULT_PERSISTENT_KEEPALIVE_SECONDS}s "
        f'comment="{_BOOTSTRAP_MGMT_TAG}"',
        # -- guest data path: NAT for the traffic this router is about to
        #    start authenticating. Emitted here, on the ONE path every
        #    enrolled router actually executes, because the platform's
        #    other route to a masquerade (the WAN chunk) is gated on
        #    enabled ISP link rows and a venue can be fully provisioned
        #    without any. Safe at this point in the script: the device has
        #    just completed several HTTPS calls, so it demonstrably has a
        #    working uplink and an active default route for
        #    render_guest_data_path to discover.
        *render_guest_data_path(),
        # -- walled garden: emitted here for exactly the reason the data
        #    path above is. Both are things every router needs and both
        #    were previously reachable only through an optional table --
        #    ISP links for the NAT rule, hotspot_profiles for these allow
        #    rules -- which production confirmed is empty fleet-wide.
        *render_hotspot_walled_garden(api_url=check_in_url),
        # -- verify what was actually created, then (and only then) declare
        #    success. The address check asserts attachment to the real
        #    interface, not mere existence -- the exact failure the orphaned
        #    interface=*10 row produced. The data-path check is the newest
        #    member and the reason the success line below no longer means
        #    only "the tunnel is up": a router that reaches this point
        #    without a NAT rule is a venue where every guest authenticates
        #    and none of them gets online.
        f":if ({interface_exists} = 0) do={{ :error "
        '"CloudGuest bootstrap verification failed: interface '
        f'{WIREGUARD_INTERFACE_NAME} does not exist" }}',
        f":if ({address_attached} = 0) do={{ :error "
        '"CloudGuest bootstrap verification failed: tunnel address is not '
        f'attached to {WIREGUARD_INTERFACE_NAME}" }}',
        f":if ({peer_exists} = 0) do={{ :error "
        '"CloudGuest bootstrap verification failed: hub peer is missing on '
        f'{WIREGUARD_INTERFACE_NAME}" }}',
        *render_guest_data_path_verification(),
        f":if ({interface_exists} > 0 && {address_attached} > 0 && "
        f"{peer_exists} > 0) do={{ "
        f':log info "{success_message}"; :put "{success_message}" }}',
    ]


def _render_remote_bootstrap_lines(
    *,
    location_code: str,
    provisioning_token: str,
    check_in_url: str,
    wg_config_url: str,
    wireguard_listen_port: int,
) -> list[str]:
    """The remote (live re-provision) rendering -- see
    :func:`render_bootstrap_script` for the full design write-up. Ordering
    invariant this function exists for: not one teardown command executes
    in-session; every removal lives inside the staged cutover/revert
    scheduler scripts, built only after the shared enrollment block has
    validated every replacement value."""
    iface = WIREGUARD_INTERFACE_NAME
    tag = _BOOTSTRAP_MGMT_TAG

    # Teardown shared by cutover and revert: by COMMENT for orphaned rows
    # (the interface=*10 sighting) AND by INTERFACE for live rows that
    # predate the CGBOOT tag (render_wireguard_peer's documented
    # untagged-rows gap) -- peers before the interface, so the
    # by-interface find still resolves.
    cleanup_commands: list[list[tuple[str, str]]] = [
        [("lit", f'/ip address remove [find where comment="{tag}"]')],
        [("lit", f'/ip address remove [find where interface="{iface}"]')],
        [("lit", f'/interface wireguard peers remove [find where comment="{tag}"]')],
        [
            (
                "lit",
                f'/interface wireguard peers remove [find where interface="{iface}"]',
            )
        ],
        [("lit", f'/interface wireguard remove [find where name="{iface}"]')],
    ]

    cutover_success = (
        "CloudGuest remote bootstrap successful: replacement tunnel verified "
        "against the hub"
    )
    cutover_commands: list[list[tuple[str, str]]] = [
        # Run-once: self-removal first (standard RouterOS idiom -- the job
        # already holds its script text), so a failed cutover never retries
        # blindly; recovery belongs to the revert entry alone.
        [
            (
                "lit",
                "/system scheduler remove "
                f'[find where comment="{_BOOTSTRAP_CUTOVER_TAG}"]',
            )
        ],
        # A cutover must never run after the revert has already fired and
        # restored the previous tunnel (e.g. both pending across a long
        # power loss): the revert disarms this entry, and this guard closes
        # the remaining ordering race.
        [
            (
                "lit",
                ":if ([:len [/system scheduler find where "
                f'comment="{_BOOTSTRAP_REVERT_TAG}"]] = 0) do={{ :error '
                '"CloudGuest remote bootstrap: revert window closed; '
                'aborting staged cutover" }',
            )
        ],
        *cleanup_commands,
        [
            ("lit", f'/interface wireguard add name={iface} private-key="'),
            ("expr", '($wgcfg->"peer_private_key")'),
            (
                "lit",
                f'" listen-port={wireguard_listen_port} comment="{tag}"',
            ),
        ],
        [
            ("lit", '/ip address add address="'),
            ("expr", "$tunaddr"),
            ("lit", f'" interface={iface} comment="{tag}"'),
        ],
        [
            ("lit", f'/interface wireguard peers add interface={iface} public-key="'),
            ("expr", '($enroll->"wireguard_server_public_key")'),
            ("lit", '" endpoint-address="'),
            ("expr", '($enroll->"wireguard_endpoint_host")'),
            ("lit", '" endpoint-port='),
            ("expr", '($enroll->"wireguard_endpoint_port")'),
            ("lit", ' allowed-address="'),
            ("expr", '($enroll->"wireguard_hub_tunnel_address")'),
            (
                "lit",
                f'/32" persistent-keepalive={DEFAULT_PERSISTENT_KEEPALIVE_SECONDS}s '
                f'comment="{tag}"',
            ),
        ],
        [
            (
                "lit",
                f':if ([:len [/interface wireguard find where name="{iface}"]] = 0) '
                "do={ :error "
                '"CloudGuest remote cutover failed: interface '
                f'{iface} does not exist" }}',
            )
        ],
        [
            (
                "lit",
                f':if ([:len [/ip address find where interface="{iface}" && '
                'address="',
            ),
            ("expr", "$tunaddr"),
            (
                "lit",
                '"]] = 0) do={ :error "CloudGuest remote cutover failed: '
                f'tunnel address is not attached to {iface}" }}',
            ),
        ],
        [
            (
                "lit",
                ":if ([:len [/interface wireguard peers find where "
                f'interface="{iface}" && comment="{tag}"]] = 0) do={{ :error '
                '"CloudGuest remote cutover failed: hub peer is missing on '
                f'{iface}" }}',
            )
        ],
        # End-to-end confirmation: only a real round-trip to the hub's
        # tunnel address proves the hub accepted the new key -- local
        # existence never disarms the revert.
        [("lit", ":local ok 0")],
        [("lit", ":local tries 0")],
        [
            (
                "lit",
                f":while ($ok = 0 && $tries < {REMOTE_BOOTSTRAP_CONFIRM_ATTEMPTS}) "
                f"do={{ :delay {REMOTE_BOOTSTRAP_CONFIRM_DELAY_SECONDS}s; "
                ':set tries ($tries + 1); :set ok [/ping "',
            ),
            ("expr", '($enroll->"wireguard_hub_tunnel_address")'),
            ("lit", '" count=2] }'),
        ],
        [
            (
                "lit",
                ":if ($ok > 0) do={ /system scheduler remove "
                f'[find where comment="{_BOOTSTRAP_REVERT_TAG}"]; '
                f':log info "{cutover_success}" }} else={{ :log error '
                '"CloudGuest remote bootstrap: hub unreachable over the '
                'replacement tunnel; automatic revert stays armed" }',
            )
        ],
    ]

    revert_restored = (
        "CloudGuest remote bootstrap: cutover was not confirmed in time -- "
        "previous tunnel configuration restored"
    )
    revert_commands: list[list[tuple[str, str]]] = [
        # Deliberately NO self-removal up front: a revert that fails midway
        # stays scheduled and retries every window (the whole sequence is
        # remove-then-add idempotent), disarming itself only after the
        # restored state re-verifies.
        *cleanup_commands,
        [
            ("lit", f'/interface wireguard add name={iface} private-key="'),
            ("expr", "$oldkey"),
            ("lit", '" listen-port='),
            ("expr", "$oldport"),
            ("lit", f' comment="{tag}"'),
        ],
        [
            ("lit", '/ip address add address="'),
            ("expr", "$oldaddr"),
            ("lit", f'" interface={iface} comment="{tag}"'),
        ],
        [
            ("lit", f'/interface wireguard peers add interface={iface} public-key="'),
            ("expr", "$oldpub"),
            ("lit", '" endpoint-address="'),
            ("expr", "$oldephost"),
            ("lit", '" endpoint-port='),
            ("expr", "$oldepport"),
            ("lit", ' allowed-address="'),
            ("expr", "$oldallowed"),
            ("lit", '" persistent-keepalive='),
            ("expr", "$oldka"),
            ("lit", f' comment="{tag}"'),
        ],
        [
            (
                "lit",
                f':if ([:len [/interface wireguard find where name="{iface}"]] = 0) '
                "do={ :error "
                '"CloudGuest remote revert failed: interface '
                f'{iface} does not exist" }}',
            )
        ],
        [
            (
                "lit",
                f':if ([:len [/ip address find where interface="{iface}" && '
                'address="',
            ),
            ("expr", "$oldaddr"),
            (
                "lit",
                '"]] = 0) do={ :error "CloudGuest remote revert failed: '
                f'previous tunnel address is not attached to {iface}" }}',
            ),
        ],
        [
            (
                "lit",
                ":if ([:len [/interface wireguard peers find where "
                f'interface="{iface}" && comment="{tag}"]] = 0) do={{ :error '
                '"CloudGuest remote revert failed: previous hub peer is '
                f'missing on {iface}" }}',
            )
        ],
        # Disarm the (possibly never-run) cutover FIRST, then self-disarm
        # -- after this line a cutover can never fire against the restored
        # tunnel.
        [
            (
                "lit",
                "/system scheduler remove "
                f'[find where comment="{_BOOTSTRAP_CUTOVER_TAG}"]',
            )
        ],
        [
            (
                "lit",
                "/system scheduler remove "
                f'[find where comment="{_BOOTSTRAP_REVERT_TAG}"]',
            )
        ],
        [("lit", f':log error "{revert_restored}"')],
    ]

    staged_message = (
        "CloudGuest remote bootstrap staged: cutover in "
        f"~{REMOTE_BOOTSTRAP_CUTOVER_DELAY_SECONDS}s, automatic revert armed "
        f"for {REMOTE_BOOTSTRAP_REVERT_WINDOW_MINUTES}m"
    )
    cutover_staged = (
        "[:len [/system scheduler find where " f'comment="{_BOOTSTRAP_CUTOVER_TAG}"]]'
    )
    revert_staged = (
        "[:len [/system scheduler find where " f'comment="{_BOOTSTRAP_REVERT_TAG}"]]'
    )
    return [
        # -- identity (same invariant as on-site) --------------------------
        f'/system identity set name="{location_code}"',
        # -- clock / NTP -----------------------------------------------------
        # Deliberately kept here too, even though a live re-provisioned
        # router has usually been up long enough to have synced: "usually"
        # is not an invariant, and this path's own fetches are HTTPS on the
        # same terms. Re-asserting an already-correct clock is a no-op, and
        # the bounded wait exits on the first poll when the status is
        # already `synchronized`. Placed before the tunnel-integrity
        # refusal below so that a wrong clock is reported as a wrong clock
        # rather than as an unreachable platform.
        *_render_clock_lines(),
        # -- refuse unless the live tunnel state is intact -- BEFORE the
        #    one-time token is spent, so a half-broken router never burns
        #    it. A router in this state needs the on-site script (and a
        #    human who can reach the device some other way).
        f':if ([:len [/interface wireguard find where name="{iface}"]] = 0) '
        "do={ :error "
        '"CloudGuest remote bootstrap: no existing '
        f"{iface} interface -- remote mode re-provisions a live tunnel; "
        'use the on-site script instead" }',
        f':if ([:len [/ip address find where interface="{iface}"]] = 0) '
        "do={ :error "
        '"CloudGuest remote bootstrap: no tunnel address attached to '
        f"{iface} -- existing tunnel state is incomplete; use the on-site "
        'script instead" }',
        ":if ([:len [/interface wireguard peers find where "
        f'interface="{iface}"]] = 0) do={{ :error '
        '"CloudGuest remote bootstrap: no hub peer on '
        f"{iface} -- existing tunnel state is incomplete; use the on-site "
        'script instead" }',
        # -- capture everything the revert needs, still touching nothing --
        f':local wgid [:pick [/interface wireguard find where name="{iface}"] 0]',
        ":local oldkey [/interface wireguard get $wgid private-key]",
        ":local oldport [/interface wireguard get $wgid listen-port]",
        ":local oldaddr [/ip address get "
        f'[:pick [/ip address find where interface="{iface}"] 0] address]',
        ":local peerid [:pick [/interface wireguard peers find where "
        f'interface="{iface}"] 0]',
        ":local oldpub [/interface wireguard peers get $peerid public-key]",
        ":local oldephost [/interface wireguard peers get $peerid endpoint-address]",
        ":local oldepport [/interface wireguard peers get $peerid endpoint-port]",
        ":local oldallowed [/interface wireguard peers get $peerid allowed-address]",
        ":local oldka [/interface wireguard peers get $peerid persistent-keepalive]",
        # -- enrollment + key delivery + validation (shared with on-site);
        #    any failure from here back means the tunnel was never touched -
        *_render_enrollment_lines(
            provisioning_token=provisioning_token,
            check_in_url=check_in_url,
            wg_config_url=wg_config_url,
        ),
        _TUNNEL_ADDRESS_LOCAL_LINE,
        # -- guest data path, asserted inline and WITHOUT a hard failure ---
        #    Safe here: it only ever adds or re-points its own
        #    comment-tagged NAT rule and WAN list member, touches nothing
        #    belonging to the tunnel being re-provisioned, and removes
        #    nothing at all. Deliberately NOT paired with
        #    render_guest_data_path_verification(): this is a live,
        #    already-serving router, and aborting a re-provision over a
        #    missing NAT rule would be a worse outcome than the missing
        #    rule. The on-site path -- a fresh box, technician present --
        #    is where failing loudly is the right call.
        *render_guest_data_path(),
        # -- walled garden, same add-only, never-remove shape. Safe on a
        #    live re-provision for the same reason the data path above is:
        #    it only ever adds its own comment-tagged allow rules and takes
        #    nothing away from a router that is already serving guests.
        *render_hotspot_walled_garden(api_url=check_in_url),
        # -- stage: bake validated values into the two detached scripts ----
        f":local cut {_ros_string_expr(_join_embedded_commands(cutover_commands))}",
        f":local rvt {_ros_string_expr(_join_embedded_commands(revert_commands))}",
        "/system scheduler remove " f'[find where comment="{_BOOTSTRAP_CUTOVER_TAG}"]',
        "/system scheduler remove " f'[find where comment="{_BOOTSTRAP_REVERT_TAG}"]',
        # Revert is armed BEFORE the cutover exists -- there is no instant
        # at which the cutover could fire unprotected.
        f"/system scheduler add name={_BOOTSTRAP_REVERT_SCHEDULER_NAME} "
        f"interval={REMOTE_BOOTSTRAP_REVERT_WINDOW_MINUTES}m on-event=$rvt "
        f'comment="{_BOOTSTRAP_REVERT_TAG}"',
        f"/system scheduler add name={_BOOTSTRAP_CUTOVER_SCHEDULER_NAME} "
        f"interval={REMOTE_BOOTSTRAP_CUTOVER_DELAY_SECONDS}s on-event=$cut "
        f'comment="{_BOOTSTRAP_CUTOVER_TAG}"',
        f":if ({cutover_staged} > 0 && {revert_staged} > 0) do={{ "
        f':log info "{staged_message}"; :put "{staged_message}" }}',
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
    mac_authorization_entries: list[MacAuthorizationEntry] | None = None,
    content_filter_rules: list[ContentFilterRule] | None = None,
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
            sections.extend(_idempotent_lines(render_dhcp_pool(pool)))
    if vlans:
        sections.append(VLAN_SECTION_HEADER)
        for vlan in vlans:
            sections.extend(_idempotent_lines(render_vlan(vlan)))
    if port_forwarding_rules:
        sections.append(PORT_FORWARDING_SECTION_HEADER)
        for rule in port_forwarding_rules:
            sections.extend(_idempotent_lines(render_port_forwarding_rule(rule)))
    if hotspot_profiles:
        sections.append(HOTSPOT_SECTION_HEADER)
        for profile in hotspot_profiles:
            sections.extend(_idempotent_lines(render_hotspot_profile(profile)))
    if qos_traffic_rules:
        sections.append(QOS_SECTION_HEADER)
        for rule in qos_traffic_rules:
            sections.extend(_idempotent_lines(render_qos_traffic_rule(rule)))
    if dns_records:
        sections.append(DNS_SECTION_HEADER)
        for record in dns_records:
            sections.extend(_idempotent_lines(render_dns_record(record)))
    if firewall_rules:
        sections.append(FIREWALL_SECTION_HEADER)
        for rule in firewall_rules:
            sections.extend(_idempotent_lines(render_firewall_rule(rule)))
    if mac_authorization_entries:
        sections.append(MAC_AUTHORIZATION_SECTION_HEADER)
        for entry in mac_authorization_entries:
            sections.extend(_idempotent_lines(render_mac_authorization_entry(entry)))
    if content_filter_rules:
        sections.append(CONTENT_FILTER_SECTION_HEADER)
        for rule in content_filter_rules:
            sections.extend(_idempotent_lines(render_content_filter_rule(rule)))
        if any(
            rule.value_type == ContentFilterValueType.IP_CIDR.value
            for rule in content_filter_rules
        ):
            sections.extend(_idempotent_lines(render_content_filter_enforcement()))
    if wireguard_peer is not None and wireguard_server is not None:
        sections.append(WIREGUARD_SECTION_HEADER)
        sections.extend(
            _idempotent_lines(render_wireguard_peer(wireguard_peer, wireguard_server))
        )
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
            _idempotent_lines(
                render_radius_client(
                    radius_nas_client,
                    wireguard_peer.tunnel_ip_address,
                    radius_server_host,
                )
            )
        )
    # THE GUEST DATA PATH RIDES ALONG WITH ANY REAL PUSH, but does not by
    # itself make an empty push non-empty.
    #
    # Appended after the emptiness decision above deliberately. Emitting it
    # unconditionally would mean `render_network_config` never returns "",
    # which would silently retire `push_config`'s EmptyNetworkConfigError
    # guard -- "you asked to push a configuration that configures nothing"
    # is a real thing to tell an operator, and turning it into a no-op to
    # smuggle in one NAT rule trades one honest signal for another.
    #
    # Nothing is lost by that restraint: the path that every enrolled
    # router actually executes is the bootstrap script, and
    # `render_guest_data_path` is unconditional THERE (see
    # `_render_onsite_bootstrap_lines`). A router with zero enabled rows is
    # not one anybody pushes to; a router with any real configuration gets
    # the NAT assertion carried along with it, idempotently, on every push.
    if sections:
        sections.append(GUEST_DATA_PATH_SECTION_HEADER)
        sections.extend(_idempotent_lines(render_guest_data_path()))
    return "\n".join(sections)


def _idempotent_lines(lines: list[str]) -> list[str]:
    """Wraps each real RouterOS command in ``:do {...} on-error={}`` so a
    full-desired-state push (this function re-renders *every* enabled row,
    not just new ones -- see this module's own docstring) can safely
    re-apply an object that's already present on the device instead of
    aborting the whole script on the first "already have such X" error.
    Comment lines (``# ...``, emitted by a render_* function for a row it
    deliberately skipped, e.g. a VLAN with no parent interface) pass
    through unwrapped -- there is nothing to retry-guard there."""
    return [
        line if line.lstrip().startswith("#") else f":do {{ {line} }} on-error={{}}"
        for line in lines
    ]


__all__ = [
    "HOTSPOT_DNS_NAME",
    "HOTSPOT_HTML_DIRECTORY",
    "MANAGED_WALLED_GARDEN_COMMENT",
    "WALLED_GARDEN_SECTION_HEADER",
    "render_dhcp_pool",
    "render_vlan",
    "render_port_forwarding_rule",
    "render_hotspot_profile",
    "render_hotspot_walled_garden",
    "render_qos_traffic_rule",
    "render_dns_record",
    "render_firewall_rule",
    "render_mac_authorization_entry",
    "render_content_filter_rule",
    "render_content_filter_enforcement",
    "render_wireguard_peer",
    "render_radius_client",
    "render_bootstrap_script",
    "BootstrapMode",
    "render_agent_heartbeat_scheduler",
    "render_network_config",
    "NETWATCH_CHECK_INTERVAL",
    "render_isp_netwatch_entry",
    "render_isp_netwatch_config",
]
