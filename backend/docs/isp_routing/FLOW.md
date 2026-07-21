# ISP Routing -- Design Write-Up

## 1. One `rule_type`, one match field each -- not a polymorphic `target_id`

`app.domains.queue_management.constants.QueueTargetType` is a polymorphic
discriminator over a single, uniformly-UUID-keyed `target_id` column --
every member's target is "some row's id", so one nullable UUID column
suffices. `IspRoutingRuleType` (VLAN/USER/IP/SOURCE/INTERFACE/POLICY) has
no such uniform shape: a VLAN match is an integer ID, a user match is a
MAC address string, an IP match is an address string, a source match is a
CIDR string, an interface match is a name string, and a policy match is a
real UUID FK. Rather than force these into one polymorphic column (and
lose type safety/indexability for five of the six), each `rule_type` gets
its own concrete, real column (`vlan_id`/`source_mac_address`/
`ip_address`/`source_cidr`/`interface_name`/`policy_id`), with exactly one
populated per row -- enforced by `validators.validate_match_fields`, not a
database `CHECK` constraint (mirrors every other domain's own "type
discriminator + service-level validation, not a DB-level invariant"
convention for conditionally-required fields).

`validate_match_fields` rejects both under- and over-population: the one
field `rule_type` names must be set, and every other match field must be
`None`. A rule with two populated match fields is ambiguous about what it
actually matches -- never silently resolved by picking one. This runs on
both `create_rule` and `update_rule`; an update that changes `rule_type`
without also supplying the newly-required match field is rejected, not
silently left pointing at a now-irrelevant old field.

## 2. No live device push in this pass

Real MikroTik RouterOS policy routing needs three constructs working
together:

* `/ip firewall mangle` -- a `new-routing-mark` action, matching on
  `src-address`/`dst-address`/`in-interface`/address-lists, applied in
  `prerouting` (or `output` for router-originated traffic) to tag
  packets/connections with a named routing mark.
* `/routing table` (RouterOS v7) or a legacy `/ip route` with a
  `routing-mark`/`table` parameter -- a separate routing table per mark,
  each holding a default route out a specific WAN gateway/interface.
* `/ip route` entries -- one route per table, pointing at the target
  `IspLink`'s own gateway/interface, with `check-gateway` for failover
  awareness.

Generating and pushing all of that live is real, meaningful device work --
but it is scoped to the not-yet-built Network Configuration Management
domain (roadmap item #11), which explicitly owns "Support Versioning/
Backup/Restore/Rollback" across DHCP/VLAN/Port Forwarding/QoS/ISP
Routing/Hotspot Settings behind one provisioning-integration mechanism.
Building a second, one-off push path here (independent of that future
mechanism) would either duplicate it or be thrown away once it exists.
This domain therefore mirrors `app.domains.policy`'s own identical
"priority + enable/disable, realized onto a device later" precedent: a
pure rules/inventory table, no `device_adapters.py`, no Celery task.

## 3. `router_id`/`isp_link_id` consistency, not a database constraint

A rule's `isp_link_id` must belong to the same `router_id` the rule
itself is scoped to -- a routing rule can only steer traffic onto an
uplink physically present on its own router. This can't be a foreign-key-
level constraint (there is no single-column FK expressing "this UUID's
row also has this other column equal to X"), so `IspRoutingService`
resolves both the router (`RouterLookupProtocol.get_router`) and the ISP
link (`IspLinkLookupProtocol.get_link`, composing
`app.domains.isp.service.IspService.get_link` directly -- never
re-implemented) and compares `link.router_id == router.id` itself,
raising `IspRoutingLinkRouterMismatchError` if they disagree. The same
check re-runs in `update_rule` whenever `isp_link_id` changes.

## 4. `priority`: lower tried first, mirrors `IspLink`, not `PolicyAssignment`

Two "priority" conventions coexist in this codebase:
`PolicyAssignment.priority` is "higher wins" (a tie-breaker among matching
assignments at the same scope); `IspLink.priority` is "lower tried first"
(which enabled `BACKUP` link `trigger_failover` picks first). This domain
follows `IspLink`'s convention, since it is the sibling domain this one
composes with directly and shares the same "several rules could plausibly
apply, evaluate in ascending priority order" framing a future provisioning
pass will need.

## 5. No history table

Unlike `app.domains.isp`'s `IspLink`/`IspHealthCheck` split, there is no
"current state + history" concern here -- a rule's own row *is* its
current state, and there is no live device push in this pass to produce a
history of. If/when Network Configuration Management adds real
provisioning for this domain, that history belongs to *its* own
versioning mechanism (shared across every domain it provisions), not a
second, isp_routing-specific history table.

## 6. RBAC: a brand-new, additive module, no `EXECUTE` action

`PermissionModule.ISP_ROUTING` gets `CREATE`/`READ`/`UPDATE`/`DELETE`/
`MANAGE` -- deliberately no `EXECUTE`, unlike `PermissionModule.ISP`'s own
manual health-check/failover/failback triggers, since this domain has no
device-facing action to execute in this pass. `MODULE_NARROWEST_SCOPE` is
`ScopeType.ROUTER` (a routing rule is scoped to one router's own uplinks),
and the existing "Network Administrator" system role's own `_M.ISP:
_L.FULL` override gained an identical `_M.ISP_ROUTING: _L.FULL` entry. No
migration is needed for any of this -- `permission_groups`/`permissions`/
`permission_scopes`/`role_permissions` rows are all seeded idempotently at
application/CLI startup by `seed_rbac`.
