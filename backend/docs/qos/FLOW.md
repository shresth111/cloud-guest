# QoS & VOIP Priority -- Design Notes

## 0. Research: `queue_management` already IS "bandwidth/QoS" -- don't duplicate it

Before writing any code, research confirmed `app.domains
.queue_management.service`'s own module docstring calls itself *"the
vendor-agnostic bandwidth/QoS orchestrator"* -- it already has
`QueueProfile.priority` (a real RouterOS `/queue simple`/`/queue tree`
priority, 1-8 -- `queue_management/constants.py`'s own
`MIN_QUEUE_PRIORITY`/`MAX_QUEUE_PRIORITY`), rate limits, burst fields, and
a real device push via its own `device_adapters.py`
(`MikroTikQueueAdapter`, real `librouteros` calls). None of that is
duplicated here.

What is missing everywhere in this codebase is traffic
**classification**: matching packets by protocol/port (SIP signaling,
RTP media) or DSCP value. A full-tree grep for `voip|sip|dscp`
(case-insensitive) found exactly one hit outside this domain --
`app.domains.policy.schemas.QoSPolicyRules.dscp_marking`, a validated but
currently **uncomposed** JSONB shape (`queue_management`'s own
`service.py` only resolves `PolicyType.BANDWIDTH`, never `PolicyType
.QOS`). This domain does not wire that policy type either -- doing so
would be a reasonable future extension, but is not required for the real
scope here (a plain per-router rule table, matching every other "config
resource" domain's own shape).

## 1. Scope: classification only, `queue_management`'s priority reused, not redefined

`QosTrafficRule.priority` reuses `app.domains.queue_management
.constants.MIN_QUEUE_PRIORITY`/`MAX_QUEUE_PRIORITY`/
`DEFAULT_QUEUE_PRIORITY` directly (re-exported under this domain's own
`constants.py` names, not redeclared) -- the same real RouterOS 1-8
range, so the two domains can never independently drift to different
bounds. This domain creates no `QueueProfile`, no queue assignment, and
has no device_adapters.py of its own -- it only decides "traffic matching
X should be treated at priority N," never "how much bandwidth priority N
actually gets" (that remains entirely `queue_management`'s concern).

## 2. `/ip firewall mangle` only marks; pairing with a real queue is documented, not automated

RouterOS realizes QoS as two independent steps: (1) **mark** matching
traffic (`/ip firewall mangle ... action=mark-packet`), and (2) a
`/queue tree`/`/queue simple` entry that **references** that same mark to
actually apply bandwidth/priority treatment. Research confirmed
`queue_management`'s own `device_adapters.py` already accepts a
`packet_mark` parameter on `create_queue_tree` — but nothing anywhere
creates the matching mark, and `QueueAssignment`'s own polymorphic target
model (organization/location/router/guest_team/guest/voucher/device/
session) has no "packet-mark" target type today.

This domain's own `app.domains.network_config` rendering (see that
domain's `FLOW.md` §6) produces only the mangle mark half of that pair.
**Pairing the resulting packet-mark with an actual `/queue tree` entry
is real, separate device-side work, left undone in this pass** -- an
honest, explicitly documented gap (mirroring `app.domains.dhcp`'s own
subnet-mask-gap precedent and `app.domains.hotspot`'s own "no server
bind" precedent) rather than a fabricated end-to-end automation. Closing
it would mean extending `QueueAssignment`'s target-type model, a real,
larger change to an already-complete domain that was deliberately kept
out of this domain's own scope (confirmed with the user before starting
this build).

## 3. RBAC: a genuinely new permission module, no unclaimed fit

Unlike `PermissionModule.HOTSPOT` (pre-seeded, unclaimed, waiting for
`app.domains.hotspot`), research confirmed **no** pre-existing,
unclaimed `PermissionModule` fits QoS -- every module in the 45-entry
enum is either already claimed by a built domain or belongs to an
unrelated concern. `PermissionModule.QOS` was minted fresh, following
`PermissionModule.NETWORK_CONFIG`'s own identical "grep `rbac/enums.py`
first, mint only if nothing fits" discipline. Action shape mirrors
`PermissionModule.DHCP`/`VLAN`'s identical "plain CRUD, no `EXECUTE`"
posture (`CREATE`/`READ`/`UPDATE`/`DELETE`/`MANAGE`), `ScopeType.ROUTER`.
The pre-existing "Network Administrator" role gains a `FULL` override.

## 4. Traffic match: exactly one kind per rule, real DSCP/port bounds

A rule matches by **either** a port range (`protocol` + both
`port_range_start`/`port_range_end`) **or** a `dscp_value` -- never both,
never neither (`validators.validate_traffic_match`). `protocol` has no
`BOTH` wildcard value (unlike `app.domains.port_forwarding
.constants.PortForwardingProtocol`) since a real RouterOS mangle rule
matching `dst-port` requires an explicit `protocol=tcp`/`udp` -- matching
both transports needs two separate mangle rules, not one rule with an
omitted protocol. DSCP bounds (0-63) are the IETF standard's own 6-bit
field width (RFC 2474), not this codebase's own choice.
