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

## 2. `/ip firewall mangle` marks; the paired queue is now real too (RESOLVED)

RouterOS realizes QoS as two independent steps: (1) **mark** matching
traffic (`/ip firewall mangle ... action=mark-packet`), and (2) a
`/queue tree` entry that **references** that same mark to actually apply
priority treatment. This section originally documented step (2) as a
deliberate, unclosed gap: nothing anywhere created the matching queue,
so a pushed mangle mark had zero device effect on its own.

**This is now closed**, without extending `QueueAssignment`'s polymorphic
target model (the larger change this section originally floated and
explicitly deferred) -- that route would have made `queue_management` own
QoS's own classification rules, duplicating this domain's own scope
rather than composing with it. Instead:

* `app.domains.qos.identifiers.qos_packet_mark_identifier` is now the
  single source of truth for a rule's own packet-mark string, used by
  both `network_config.renderers.render_qos_traffic_rule` (the mangle
  mark) and this domain's own new `device_adapters.py` (the queue tree),
  so the two halves can never reference different marks.
* `app.domains.qos.device_adapters` is a new, narrow adapter (mirrors
  `queue_management.device_adapters`'s own shape) exposing exactly the
  three real `wyfy_device_gateway` operations this domain needs:
  `create_queue_tree` (via `create_priority_queue`), `set_priority`, and
  `remove_queue` (via `remove_priority_queue`) -- never `/queue simple`,
  never PCQ, both of which remain entirely `queue_management`'s concern.
* `QosService.push_rule_to_device` (new, `POST /qos-rules/{rule_id}/push`,
  gated by the new `qos.execute` permission action) is the real, explicit
  device push -- deliberately not auto-fired on create/update (see that
  method's own module-docstring "why a separate, explicit push endpoint"
  section), mirroring every other domain's own "CRUD is pure DB writes,
  a real device push is a separate action" convention.
  `QosTrafficRule` gained `device_queue_id`/`device_packet_mark`/
  `device_push_status`/`device_push_error`/`device_pushed_at` (migration
  `0078_add_qos_traffic_rule_device_push`) to track that push's real,
  current device state, mirroring `QueueAssignment`'s own identical
  columns.
* `delete_rule` now also removes the live device queue tree first when
  one exists, so a deleted rule never leaves an orphaned `/queue tree`
  entry referencing a mark nothing will set again.

**Still out of scope, honestly**: the `/queue tree`'s own `max-limit` is
fixed at "unlimited" (`0`, RouterOS's own real convention -- see
`constants.QOS_QUEUE_UNLIMITED_MAX_LIMIT_KBPS`'s own docstring) and
`parent` is fixed at RouterOS's built-in `"global"` pseudo-interface
(`constants.QOS_QUEUE_TREE_PARENT`'s own docstring) since
`QosTrafficRule` has no bandwidth-ceiling or interface column of its own
to derive either from -- neither choice was confirmed against a real
device this session (no live MikroTik hardware in this environment, see
`app.domains.qos.device_adapters`'s own module docstring), flagged
honestly per this file's own standard rather than assumed.

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
