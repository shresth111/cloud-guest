# DHCP Pool Management -- Design Write-Up

## 1. Range-overlap conflict detection: a service-layer check, not a DB constraint

Unlike `app.domains.vlan.models.Vlan`'s own `vlan_id` uniqueness (a plain
equality check a partial unique b-tree index can enforce directly), "do
these two IP ranges overlap" is not expressible as a simple
column-equality index -- real support for it would need a PostgreSQL
range type (`int4range`/`inet`-adjacent) plus a GiST exclusion constraint,
infrastructure this codebase has never introduced for any domain.
Conflict detection is therefore a service-layer check only
(`service.DhcpService._check_range_conflict`): on both create and update,
every other non-deleted pool on the *same router and interface* is
fetched and checked for overlap via the standard interval-overlap test
(`validators.ranges_overlap`: `start_a <= end_b and start_b <= end_a`,
compared as integers via `ipaddress`). This is a real, honest gap
(documented in `models.py`'s own module docstring), not silently assumed
away -- a genuine race between two concurrent creates could still slip
past it, exactly as it would for any service-layer-only invariant in this
codebase.

## 2. No live device push in this pass

Provisioning a real DHCP pool onto a MikroTik router needs at minimum an
`/ip pool` entry (the address range itself) plus an `/ip dhcp-server`
entry bound to the target interface (referencing that pool, plus
lease-time/gateway/DNS options via `/ip dhcp-server network`). That is
real, meaningful device work -- but it is scoped to the not-yet-built
Network Configuration Management domain (roadmap item #11), which
explicitly owns "Support Versioning/Backup/Restore/Rollback" across
DHCP/VLAN/Port Forwarding/QoS/ISP Routing/Hotspot Settings behind one
provisioning-integration mechanism. This domain therefore mirrors
`app.domains.vlan`/`app.domains.isp_routing`/`app.domains.policy`'s own
identical "config resource + enable/disable, realized onto a device
later" precedent: a pure rules/inventory table, no `device_adapters.py`,
no Celery task.

## 3. Why conflict scope is (router, interface), not just router

Two different interfaces on the same router are different L2 broadcast
domains -- a `192.168.1.0/24` pool on `ether2` and an identical
`192.168.1.0/24` pool on `vlan10` do not actually collide on the wire,
the same way `app.domains.vlan`'s own `vlan_id` uniqueness is scoped per
router (not platform-wide) because different routers are different
devices. Two pools with `interface=None` are still compared against each
other (`None == None`), since an un-scoped pool has no way to be known
safe from another un-scoped pool on the same router.

## 4. RBAC: reusing an already-seeded module, not minting a new one

Unlike `app.domains.isp`/`app.domains.isp_routing`/`app.domains.vlan`
(each of which minted a brand-new `PermissionModule`), `PermissionModule
.DHCP` **already existed** in `rbac/enums.py` before this domain --
seeded ahead of any real domain, the identical posture
`PermissionModule.BANDWIDTH` had before `app.domains.queue_management`
filled it in. This build discovered the collision while wiring RBAC
(attempting to mint a second `DHCP = "dhcp"` member raised a real
`TypeError` at class-definition time), removed the duplicate, and instead
reused the existing `MODULE_ACTIONS[PermissionModule.DHCP]` entry as-is
(its shape, `CREATE`/`READ`/`UPDATE`/`DELETE`/`MANAGE`, already matched
what this domain needs) and upgraded its display name from the generic
placeholder `"DHCP"` to `"DHCP Pool Management"`. No new `PermissionModule`
member, no migration -- `permission_groups`/`permissions`/
`permission_scopes`/`role_permissions` rows are all seeded idempotently at
application/CLI startup by `seed_rbac`.

## 5. No history table

Like `app.domains.vlan`/`app.domains.isp_routing`, there is no "current
state + history" concern here -- a pool's own row *is* its current state,
and there is no live device push in this pass to produce a history of.
