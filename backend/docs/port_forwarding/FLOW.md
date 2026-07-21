# Port Forwarding Management -- Design Write-Up

## 1. Conflict detection: a service-layer check, not a DB constraint

Mirrors `app.domains.dhcp.models.DhcpPool`'s own identical reasoning: "do
these two rules both claim the same external protocol/destination-
address/destination-port" is not expressible as a simple column-equality
index, since `protocol="both"` and `destination_address=None` ("any
address") must each be treated as overlapping *every* other value, not
compared by plain equality. Conflict detection is therefore a
service-layer check only (`service.PortForwardingService._check_conflict`):
on both create and update, every other non-deleted rule on the *same
router* is fetched and checked via `validators.protocols_overlap`/
`addresses_overlap` plus a plain `destination_port` equality. This is a
real, honest gap (documented in `models.py`'s own module docstring), not
silently assumed away.

## 2. No live device push in this pass

Provisioning a real port-forwarding rule onto a MikroTik router is a
single `/ip firewall nat` entry (`chain=dstnat`, matching
`protocol`/`dst-address`/`dst-port`/`src-address`, with
`action=dst-nat` pointing at `to-addresses`/`to-ports`). That is real,
meaningful device work -- but it is scoped to the not-yet-built Network
Configuration Management domain (roadmap item #11), which explicitly owns
"Support Versioning/Backup/Restore/Rollback" across DHCP/VLAN/Port
Forwarding/QoS/ISP Routing/Hotspot Settings behind one
provisioning-integration mechanism. This domain therefore mirrors
`app.domains.dhcp`/`app.domains.vlan`/`app.domains.isp_routing`'s own
identical "config resource + enable/disable, realized onto a device
later" precedent: a pure rules/inventory table, no `device_adapters.py`,
no Celery task.

## 3. `internal_address`: single-host only, never a CIDR

A DSTNAT rule's own `to-addresses` target is always exactly one host --
RouterOS itself would never forward one external port to an entire
subnet. `validate_ip_address` (strict `ipaddress.ip_address`, no CIDR
tolerance) enforces this, distinct from `validate_address`'s CIDR-or-IP
tolerance for `source_address`/`destination_address` (both of which are
real *match* fields, where a CIDR restriction is meaningful -- "only
allow forwarding to originate from this /24").

## 4. RBAC: reusing an already-seeded module, not minting a new one

Like `app.domains.dhcp` discovered for `PermissionModule.DHCP`,
`PermissionModule.FIREWALL` already existed in `rbac/enums.py` before
this domain -- seeded ahead of any real domain, the identical posture
`PermissionModule.BANDWIDTH` had before `app.domains.queue_management`
filled it in. Having learned from that DHCP experience, this build
checked `rbac/enums.py` for a pre-existing `FIREWALL`/`PORT_FORWARDING`
member *before* wiring RBAC (rather than discovering a collision after
the fact) -- port forwarding is a real RouterOS `/ip firewall nat`
concept, so `PermissionModule.FIREWALL` was the obvious semantic fit.
Its existing action tuple (`CREATE`/`READ`/`UPDATE`/`DELETE`/`EXECUTE`/
`MANAGE`), `ScopeType.ROUTER` narrowest scope, and the "Network
Administrator" system role's own `_M.FIREWALL: _L.FULL` grant were all
already correct and required **no changes at all** -- this domain's only
edit to `app.domains.rbac` is additive `AuditAction` enum values
(`PORT_FORWARDING_RULE_CREATED`/`_UPDATED`/`_DELETED`). The pre-existing
`EXECUTE` action is simply unused by this domain's own routes (no manual
trigger exists in this pass) -- an unused-but-available action on a
shared module is not a problem, the same way `PermissionModule.FIREWALL`
will likely host real firewall filter rules later without needing a
third `PermissionModule`.

## 5. No history table

Like `app.domains.dhcp`/`app.domains.vlan`/`app.domains.isp_routing`,
there is no "current state + history" concern here -- a rule's own row
*is* its current state, and there is no live device push in this pass to
produce a history of.
