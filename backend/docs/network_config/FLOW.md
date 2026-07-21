# Network Configuration Management -- Design Notes

## 0. Not greenfield: two real mechanisms already exist

Before writing any code, research confirmed the real device-I/O and
config-versioning machinery this domain needs already exists, split
across two already-built domains:

* `app.domains.router_provisioning` -- real `ConfigTemplate`/
  `ConfigVariable`/`ConfigProfile`/`ConfigVersion` rendering, diffing,
  apply/rollback, a durable Postgres+Redis provisioning queue.
* `app.domains.router_agent` -- the real, device-side poll/complete
  consumer of that queue (`GET /agent/actions` / reports completion via
  `complete_provisioning_job`), closing `router_provisioning`'s own
  long-documented "a future `app.domains.router_agent` module is expected
  to call `complete_provisioning_job`" seam.

`app.domains.provisioning_engine` also has real device I/O
(`librouteros`/`asyncssh`) but always runs a full 7-step onboarding
pipeline (Discover -> Validate -> Generate Config -> Push Config ->
Verify -> Health Check -> Register Monitoring) -- a mismatch for "the
admin edited one DHCP pool, push the delta," which doesn't need
rediscovery/revalidation of a router that's already onboarded.
`router_provisioning`'s own pull-model queue (consumed by a real
router-side agent) is the mechanism the original architecture doc
(`docs/ARCHITECTURE_DESIGN.md` §6.2) itself named: "network_tools... each
a config template pushed through the existing router_provisioning/
router_agent push pipeline (reused, not duplicated)."

## 1. The three small additions this domain needed elsewhere

`app.domains.dhcp`/`app.domains.port_forwarding` already had an
unpaginated, repository-level `list_pools_for_router`/
`list_rules_for_router` (used internally for their own conflict checks)
but no public, org-validating service-level wrapper. `app.domains.vlan`
had neither. Three small, real additions were made, each mirroring the
pattern the other two already partially established:

* `DhcpService.list_pools_for_router(router_id, *,
  requesting_organization_id)` -- validates the router via
  `router_lookup.get_router` (raising `RouterNotFoundError` for a
  cross-organization router, identical to every other org-scoped read in
  this codebase), then returns every non-deleted pool.
* `PortForwardingService.list_rules_for_router(...)` -- identical shape.
* `VlanRepository.list_vlans_for_router`/`VlanService
  .list_vlans_for_router(...)` -- VLAN had no repository-level
  equivalent at all; both the repository and service methods were added
  together.

None of these filter `is_enabled` -- that filtering happens in
`NetworkConfigService._gather_enabled_rows`, since "which rows count as
enabled" is this domain's own rendering concern, not a generic listing
concern the owning domains should bake in.

## 2. `create_version_from_content`: why not `assign_profile`

`RouterProvisioningService.assign_profile` is designed around one
router having *one* assigned `ConfigTemplate` at a time
(`ConfigProfile.router_id` is unique) -- reusing it here would mean
minting a new, throwaway `ConfigTemplate` row on every single push (since
the rendered content changes every time a DHCP pool/VLAN/rule changes)
and would silently overwrite whatever real, admin-assigned template
profile the router already has. `create_version_from_content` was added
to `RouterProvisioningService` instead: it reuses every real, tested
mechanism `assign_profile` itself uses -- sequential version numbering
(`get_next_version_number`), the `DRAFT` starting status, the
`CONFIG_VERSION_DRAFTED` event -- while leaving `profile_id` `NULL` and
never touching the `ConfigProfile`/`ConfigTemplate` tables at all. A
router with both an admin-assigned template profile *and* NCM-pushed
network config ends up with one shared `ConfigVersion` history
containing both kinds of entries (profile-linked and `profile_id IS
NULL`) -- a real, honest shared timeline, not two competing histories.

## 3. What a "push" renders, and the subnet-mask gap

See `renderers.py`'s own module docstring for the full per-category
detail. The headline honesty call: `DhcpPool` has no subnet-mask/CIDR
column, only a start/end range and an optional gateway -- RouterOS's own
`/ip dhcp-server network` entry needs a real CIDR block to carry
gateway/DNS/lease-time options to clients. Rather than fabricate a
conventional `/24` that could be flatly wrong, the renderer computes the
mathematically smallest real CIDR block guaranteed to contain the
configured range (searching prefix lengths from `/32` downward). This is
an honest, exact answer to "what block *at minimum* must this subnet
be" -- if the real LAN subnet is wider (a legitimate, common setup: a
pool `.100-.200` inside a `/24`), the resulting entry will be narrower
than reality and should be widened by the admin after review. This is
called out explicitly in code, mirroring `app.domains.dhcp.models
.DhcpPool`'s own module docstring precedent for documenting a real gap
plainly rather than pretending it away.

`PortForwardingProtocol.BOTH` renders by omitting RouterOS's
`protocol=` parameter entirely (which matches every transport) rather
than emitting a fabricated `protocol=both` literal no real device
understands -- the actual honest equivalent.

`Vlan.vlan_id`'s own real, partial-unique-per-router database index
means `vlan{vlan_id}` needs no invented uniqueness suffix, unlike DHCP
pool/dhcp-server names (`DhcpPool.name` has no uniqueness constraint at
all, so those get a real-primary-key suffix to avoid a RouterOS name
collision between two same-named pools).

## 4. Preview vs. push: why an empty result means different things

`preview_config` returns an empty `rendered_content` (with zeroed
counts) for a router with nothing enabled -- a valid, informational
answer to "what would be pushed right now." `push_config` raises
`EmptyNetworkConfigError` for the identical empty case, since creating a
real, durable, permanently-empty `ConfigVersion` row and queuing a real
`ProvisioningJob` for a device-side no-op would be a genuinely wasted
write, not a useful one.

## 5. Version history/diff/rollback: pure delegation, no NCM-owned table

Per the chosen scope ("thin renderer, delegate history" -- the
alternative considered and rejected was a `DeviceSyncRun`-style push-run
history table, which would have sat alongside `router_provisioning`'s
own `ConfigVersion` history with real overlap risk), `list_versions`/
`get_version`/`diff_versions`/`rollback_and_apply` are pure pass-throughs
to `RouterProvisioningLookupProtocol`. `router.py` reuses
`app.domains.router_provisioning.schemas`'s own `ConfigVersionResponse`/
`ConfigVersionListResponse`/`ConfigVersionDiffResponse`/
`ConfigVersionApplyResponse` directly rather than redefining an identical
shape -- the only schema this domain owns is `NetworkConfigPreviewResponse`,
which has no analog anywhere else in the codebase.

## 6. Hotspot: added as a fourth category in the same pass, not deferred

Unlike DHCP/VLAN/Port Forwarding (each built independently, before this
domain existed, each deferring real device provisioning to "the
not-yet-built Network Configuration Management domain"), Hotspot
Settings (`app.domains.hotspot.models.HotspotProfile`) was composed into
this pipeline the moment it was built: `HotspotLookupProtocol`
(`list_profiles_for_router`) is the fourth composed read, and
`render_hotspot_profile` renders RouterOS `/ip hotspot user profile` +
`/ip hotspot walled-garden` entries (see `renderers.py`'s own module
docstring for why the server bind itself is out of scope, mirroring the
DHCP subnet-mask gap's identical "document the real limit, don't
fabricate a binding this table has no data for" posture). `rate-limit`
mirrors `app.domains.queue_management.service
.format_mikrotik_rate_limit`'s own rx=upload/tx=download convention.

## 7. QoS: a fifth category, marking only, no paired queue created

`QosLookupProtocol` (`list_rules_for_router`) is the fifth composed
read. `render_qos_traffic_rule` renders a single RouterOS
`/ip firewall mangle` entry per rule -- `action=mark-packet` matched
either by `protocol`/`dst-port` (a port range) or by `dscp` (mutually
exclusive, enforced at `app.domains.qos.validators
.validate_traffic_match`). This only marks traffic; it never creates the
paired `/queue tree` entry that would make the mark do anything --
see `docs/qos/FLOW.md` §2 for why that pairing is real, separate,
currently-manual device-side work, deliberately left undone and
documented rather than fabricated as automatic. The rule's own
`priority` is embedded in the mangle rule's `comment` field only
(informational -- `app.domains.queue_management` remains the sole real
consumer of an actual priority value, via whatever `/queue tree` entry
an admin later pairs with this mark).
