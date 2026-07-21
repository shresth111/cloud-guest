# VLAN Management -- Design Write-Up

## 1. `vlan_id` uniqueness: a partial unique index, not a service-only check

A router may not hold two non-deleted `Vlan` rows with the same
`vlan_id` (RouterOS itself would reject configuring the same VLAN tag
twice on one device). This is enforced at **both** layers: `VlanService`
checks `get_vlan_by_router_and_tag` before create/update (for a real,
translatable `VlanIdAlreadyExistsError` rather than a raw database
integrity error reaching the API layer), and a partial unique database
index (`uq_vlans_router_id_vlan_id` on `(router_id, vlan_id)`,
`postgresql_where=text("is_deleted = false")`) backstops it against races
and enforces "reusable after soft-delete" -- mirrors
`app.domains.isp.models.IspLink`'s own identical partial-unique-index
precedent for "logically unique among non-deleted rows."

The same `vlan_id` is perfectly valid across *different* routers -- the
uniqueness constraint is scoped to `router_id`, not platform-wide.

## 2. No live device push in this pass

Provisioning a real VLAN onto a MikroTik router needs at minimum: a
`/interface vlan` entry (the VLAN interface itself, tagged onto a parent
interface) and an `/ip address` entry (binding the gateway/CIDR to that
new interface). That is real, meaningful device work -- but it is scoped
to the not-yet-built Network Configuration Management domain (roadmap
item #11), which explicitly owns "Support Versioning/Backup/Restore/
Rollback" across DHCP/VLAN/Port Forwarding/QoS/ISP Routing/Hotspot
Settings behind one provisioning-integration mechanism. Building a
second, one-off push path here would either duplicate that future
mechanism or be thrown away once it exists. This domain therefore mirrors
`app.domains.isp_routing`/`app.domains.policy`'s own identical "priority/
config + enable/disable, realized onto a device later" precedent: a pure
rules/inventory table, no `device_adapters.py`, no Celery task.

## 3. Validation: real, not cosmetic

`cidr`/`gateway_ip_address` are validated via Python's own `ipaddress`
module (`ip_network(cidr, strict=False)` / `ip_address(...)`) rather than
a regex or left unchecked -- a malformed value here would silently produce
a broken RouterOS config once Network Configuration Management's own
provisioning pass eventually consumes this row, so catching it at
create/update time (`InvalidCidrError`/`InvalidGatewayIpAddressError`) is
strictly better than discovering it at provisioning time. `vlan_id` is
similarly validated against IEEE 802.1Q's real 1-4094 usable range
(`InvalidVlanIdError`) -- VLAN 0 ("priority-tagged, no VLAN") and 4095
("reserved for implementation use") are real protocol reservations, not
arbitrary bounds.

## 4. No history table

Like `app.domains.isp_routing`, there is no "current state + history"
concern here -- a VLAN's own row *is* its current state, and there is no
live device push in this pass to produce a history of. If/when Network
Configuration Management adds real provisioning for this domain, that
history belongs to *its* own versioning mechanism (shared across every
domain it provisions), not a second, vlan-specific history table.

## 5. RBAC: a brand-new, additive module, no `EXECUTE` action

`PermissionModule.VLAN` gets `CREATE`/`READ`/`UPDATE`/`DELETE`/`MANAGE` --
deliberately no `EXECUTE`, since this domain has no device-facing action
to execute in this pass (identical to `PermissionModule.ISP_ROUTING`'s own
action set). `MODULE_NARROWEST_SCOPE` is `ScopeType.ROUTER` (a VLAN is a
router's own interface-level construct), and the existing "Network
Administrator" system role's own `_M.ISP_ROUTING: _L.FULL` override
gained an identical `_M.VLAN: _L.FULL` entry. No migration is needed for
any of this -- `permission_groups`/`permissions`/`permission_scopes`/
`role_permissions` rows are all seeded idempotently at application/CLI
startup by `seed_rbac`.
