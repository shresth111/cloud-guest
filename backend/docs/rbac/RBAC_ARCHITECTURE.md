# RBAC Architecture

This document is the record of *every* design decision Module 004 made where
the spec left room for judgment, plus the mechanics of the authorization
engine. Read this before modifying `app/domains/rbac/`.

## 1. The hierarchy and the scope model

The platform's tenancy hierarchy is:

```text
CloudGuest (platform)
  -> MSP                (future domain; modeled as a UUID column only)
    -> Organization      (future domain; modeled as a UUID column only)
      -> Location         (future domain; modeled as a UUID column only)
        -> Router           (future domain; modeled as a UUID column only)
          -> Guest
```

`ScopeType` (`app/domains/rbac/enums.py`) enumerates the levels RBAC actually
reasons about: `GLOBAL`, `ORGANIZATION`, `LOCATION`, `ROUTER`, `DEVICE`
(future, unused today). **There is no `MSP` scope type.** The Organization,
Location, Router (and MSP) domains don't exist yet in this codebase (see the
module's scope boundary), so `organization_id` / `location_id` / `router_id`
/ `msp_id` are plain nullable `UUID` columns with no `ForeignKey` -- a real FK
constraint gets added in a follow-up migration once those domains land.

### Why MSP has no scope type of its own

MSP-flavoured roles (MSP Owner, MSP Admin) are seeded at `ORGANIZATION`
scope, not a dedicated `MSP` level. Reasoning: once the Organization domain
exists, an MSP is naturally modeled as an Organization row flagged as an MSP
"container" (an organization that owns other organizations), not as a
structurally distinct entity. Rather than invent a scope level for a domain
concept that doesn't exist yet and guess at its shape, MSP roles use the
closest existing scope (`ORGANIZATION`) today. `msp_id` is still carried as a
column on `roles` -- wait, actually only on `user_roles` and is referenced by
`ScopeContext`/`GrantScope` -- as a forward-compatible hook: when the MSP
domain lands, `ScopeType.MSP` can be added to the enum and `msp_id`
already has a place to live on `user_roles`/`permission_overrides` without a
second migration.

## 2. Database design

All 11 tables extend `app.database.base.BaseModel` (UUID PK, timestamps,
soft-delete, audit, version columns) -- no exceptions, per the module's
convention. Table-by-table:

| Table | Purpose |
|---|---|
| `permission_groups` | One row per `PermissionModule` (Dashboard, Users, Roles, ...). |
| `permissions` | One row per (module, action) pair actually applicable to that module (see `MODULE_ACTIONS`). Never hardcoded in authorization logic -- resolved by key at runtime. |
| `permission_scopes` | Which `ScopeType`s a permission is valid at (see "Permission-scope constraints" below). |
| `roles` | Name/slug/description, `is_system_role`, `is_template`, `is_active`, `scope_type`, `organization_id` (nullable -- org-scoped custom roles), `parent_role_id` (self-FK -- cloning provenance + inheritance). |
| `role_scopes` | Extra scope types a role may be *assigned at* beyond its own natural `scope_type` (empty for all 15 seeded system roles; exists for custom roles that need that flexibility). |
| `role_permissions` | Role -> permission, **allow-only** (see "Allow-only role grants" below). |
| `user_roles` | User -> role, at a specific scope (`scope_type` + `organization_id`/`location_id`/`router_id`/`msp_id`), with `granted_at`/`granted_by`/`expires_at`/`is_active`. A user can hold the same role at multiple distinct scopes (separate rows) and multiple distinct roles at the same scope. |
| `permission_overrides` | Per-user allow/deny on a specific permission, at its own scope context, layered on top of role-derived grants. |
| `organization_roles` | Per-organization role configuration: which roles are enabled for this org, and which is the default for new members. See "organization_roles / location_roles" below. |
| `location_roles` | Same idea, narrower: per-location role configuration. |
| `audit_log_entries` | Generic audit trail (`actor_user_id`, `action`, `entity_type`, `entity_id`, `metadata` JSONB, `organization_id`/`location_id`). Scoped to what RBAC needs, but column-named generically enough for other domains to reuse later. |

### Allow-only role grants (no role-level deny)

`role_permissions` only supports granting. There is no "deny" concept at the
role level. Deny semantics exist exclusively at the user level, via
`permission_overrides`. Reasoning:

- A role can then never make a user's access *worse* than not holding it --
  roles are purely additive, which is much easier to reason about when a
  user holds several roles simultaneously (the effective set is a simple
  union, no need to resolve deny-vs-allow conflicts *between roles*).
- Deny-as-an-override captures the actual real-world need ("this specific
  person, who otherwise has the org-admin role, should not be able to
  delete guest data") without complicating every role's authoring model.

### `organization_roles` / `location_roles`

These aren't placeholders. `organization_roles` answers two concrete
operational questions: "is role X even available for use within organization
Y" (`is_enabled`) and "what role does a brand-new member of organization Y
get by default" (`is_default_for_new_members`). `location_roles` answers the
same two questions one level down. Neither table grants permissions by
itself -- they configure which of the already-seeded/custom roles are
in-play for a given tenant, and RBACService exposes
`set_organization_role_config` as the write path (a `location_roles`
equivalent would follow the same `upsert_location_role` repository method
once a Location-scoped admin UI needs it).

### `role_scopes` and "invalid scope assignment" prevention

A role's assignable scopes are `{role.scope_type} | {rows in role_scopes for
that role}`. All 15 seeded system roles have zero `role_scopes` rows -- they
are only assignable at their own natural scope. This table exists for custom
roles that legitimately need extra flexibility (e.g. a location-templated
role an organization also wants to be able to assign org-wide). Assigning a
role at a scope not in this permitted set raises
`InvalidScopeAssignmentError` (`RBACService._validate_scope_assignment`).

### Permission-scope constraints (and why `GLOBAL` is always allowed)

`permission_scopes` records, per module, the **narrowest** scope its
permissions are meaningful at (`MODULE_NARROWEST_SCOPE` in `seed.py`) --
e.g. `System Settings` only makes sense at `GLOBAL`; `Guest Users` is
meaningful all the way down to `LOCATION`. A permission is seeded as valid at
its narrowest scope *and every broader scope* (`allowed_scope_types_for_module`
walks `SCOPE_HIERARCHY_ORDER` from `GLOBAL` down to the narrowest,
inclusive).

This directionality is deliberate and load-bearing: **`Super Admin` is a
`GLOBAL`-scoped role granted every permission in the system (`FULL` on every
module)**. If `permission_scopes` expressed a *ceiling* instead (e.g. "Guest
Users permissions only apply at LOCATION scope, full stop"), seeding Super
Admin would immediately raise `InvalidScopeAssignmentError` the moment it
tried to hold a location-level permission. Expressing it as a *floor*
("valid from here up to GLOBAL") means `GLOBAL` is unconditionally in every
module's allowed set, so a global role can always hold any permission,
while a narrower custom role is still correctly blocked from holding a
permission whose narrowest scope is broader than the role's own scope (e.g.
an `ORGANIZATION`-scoped custom role cannot be granted anything under
`System Settings`, whose narrowest scope is `GLOBAL`). This exact
invariant is asserted by `tests/unit/test_rbac.py::TestSeedDataConsistency`
and is what caught the "Read Only"/"Auditor" roles (`ORGANIZATION` scope,
`READ` default across every module) initially trying to hold
`system_settings.read` during design -- fixed by explicitly overriding
`SYSTEM_SETTINGS` to `GrantLevel.NONE` for both.

## 3. The authorization engine (`authorization.py`)

Four components, composed top-down. **Nothing here ever branches on a
role's name or slug.** Every decision reads permission keys and scope data
from the database (or the cache warmed from it) -- this is the "Dynamic
Permission Evaluation" / "100% data-driven" requirement.

### RoleResolver

`get_active_assignments(user_id)` returns active, non-expired `user_roles`
rows whose `Role` is *also* active and not soft-deleted. A deactivated role
grants nothing even if the assignment row itself is still `is_active=True`
-- this is the "deactivated roles' assignments should not grant access"
requirement, enforced at the resolver, not the API layer.

### PermissionResolver

`resolve(user_id)` returns an `EffectiveGrants` (an `allow` tuple and a
`deny` tuple of `EffectiveGrant`s). For each active assignment:

1. Its role's own permissions, plus (recursively, see below) its parent
   chain's permissions, are unioned into the assignment's grant scope.
2. All of the user's active, non-expired `permission_overrides` are then
   layered in as either `allow` or `deny` grants at *their own* scope.

**Inheritance is recursive, not single-level.** `resolve_role_permission_keys`
walks `parent_role_id` all the way up the chain (via
`repository.get_parent_chain`), bounded by `Settings.rbac_max_parent_role_depth`
(default 10) as a defensive backstop against any cycle that slips past the
service-layer cycle check. Recursive was chosen over single-level because
role cloning is expected to chain -- a role cloned from a role that was
itself cloned from a system role should still see the *whole* lineage's
grants, not just its immediate parent's. The service-layer
`_assert_no_cycle` check (walking the *proposed* parent's chain before
accepting a new `parent_role_id`) is what keeps this recursion from ever
actually looping in practice; the depth cap is belt-and-suspenders.

### ScopeResolver

`satisfies(grant_scope, requested_scope_type, requested_context)` answers
"does this grant cover this check?", implementing the stated hierarchy
rule: a `GLOBAL` grant satisfies everything; an `ORGANIZATION` grant
satisfies an organization-level check *or narrower* (location/router) as
long as the requested context's `organization_id` matches; a grant can
never satisfy a check at a *broader* level than itself (a location-scoped
grant cannot authorize an organization-level action).

**Known limitation, called out explicitly:** because the Location/Router
domains don't exist yet, `ScopeResolver` cannot look up "which organization
does this location belong to" from a location id alone. It relies entirely
on the caller supplying `organization_id` *alongside*
`location_id`/`router_id` in the requested `ScopeContext` (this is exactly
what `CurrentOrganization`/`CurrentLocation` do via headers -- see below).
When the Location domain exists, the natural follow-up is for
`CurrentLocation` to resolve a location's parent organization from the DB
and populate `ScopeContext.organization_id` automatically, rather than
trusting the caller's header.

### AccessValidator

Ties it together: `has_permission(user_id, key, scope_type, scope_context)`
checks `deny` grants first (any matching deny wins outright), then `allow`
grants. `check(...)` is the raising form: on denial it logs a warning,
writes a `Permission Denied` `audit_log_entries` row, and raises
`PermissionDeniedError`. `get_effective_grants` is cache-aware (see below).

## 4. Permission overrides: precedence and escalation

**Precedence: a deny override always wins.** If a user has both a role-
granted `allow` and a `permission_overrides` `deny` for the same permission
at an overlapping scope, the check fails. An `allow` override grants a
permission the user doesn't otherwise hold via any role, at its own scope.
This is exactly "the override wins over role-derived permissions when
present" from the spec, made precise: *deny* always overrides *allow*
(role- or override-derived); an *allow* override only adds, it never
removes a deny.

### Privilege escalation via overrides

An `ALLOW` override cannot be used to hand out (to yourself or anyone else)
a permission you don't already effectively hold, **unless** the granter
holds `permissions.manage` at `GLOBAL` scope (`RBACService.
grant_permission_override`). This is a deliberate substitute for "unless
you're a Super Admin" that stays 100% data-driven: nothing checks the
granter's role name. `permissions.manage` happens to be one of the
permissions the seeded Super Admin role holds (along with everything
else), so Super Admins get the bypass naturally, as a *consequence* of
their permission set -- not because anything special-cases their identity.
Any future role granted `permissions.manage` at `GLOBAL` scope gets the
same bypass, which is the correct, generalizable behavior. `DENY` overrides
carry no escalation risk (they only restrict), so granting one only
requires the general `permissions.assign` permission at a covering scope.

## 5. Role escalation prevention (assigning roles to users)

`RBACService.assign_role_to_user` enforces, in order:

1. The target role must be active (`RoleInactiveError` otherwise).
2. Cross-tenant: an explicit `organization_id` on the assignment must match
   the caller's `requesting_organization_id` when both are present
   (`CrossTenantAccessError`).
3. Scope validity: `scope_type` must be the role's own scope or one of its
   `role_scopes` entries, and the corresponding id (`organization_id` /
   `location_id` / `router_id`) must be supplied (`InvalidScopeAssignmentError`).
4. The assigner must hold `roles.assign` at the assignment's scope
   (`PermissionDeniedError` via `AccessValidator.check`, which also audits
   the denial).
5. **Escalation check:** the assigner's own effective permission set must
   already cover, at the assignment's scope, *every* permission the target
   role grants (own + inherited). If the role grants a permission the
   assigner doesn't hold there, `RoleEscalationError`. This is a real,
   generalizable rule ("you cannot deputize someone with more power than
   you have") derived purely from permission-set comparison -- again, no
   role-name special-casing. It falls out naturally that a Super Admin
   (who holds every permission) can assign any role, and a narrowly scoped
   role can only assign roles that are subsets of its own grants.

## 6. Cross-tenant isolation

`RBACService._enforce_role_tenant_access` is the single choke point: a role
with a non-null `organization_id` is only visible/mutable when the caller's
`requesting_organization_id` matches it exactly; `organization_id IS NULL`
(global) roles are visible to everyone. `list_roles` filters the same way
at the repository level (`organization_id == requesting_org OR
organization_id IS NULL`). Every role read/write path
(`get_role`/`update_role`/`delete_role`/`clone_role`/`assign_permission_to_role`)
routes through `get_role`, so this check cannot be bypassed by calling a
different entrypoint.

## 7. `CurrentOrganization` / `CurrentLocation`: the interim design

There is no Organization/Location domain to query "what org does this user
belong to" against. Rather than fabricate one, `CurrentOrganization` /
`CurrentLocation` / `CurrentRouter` (`dependencies.py`) read explicit
`X-Organization-Id` / `X-Location-Id` / `X-Router-Id` request headers,
validated as UUIDs (`InvalidScopeHeaderError` on malformed input). This is a
deliberate, temporary trust-the-caller design: once the Organization/Location
domains exist, these three dependencies are the *only* place that needs to
change (to resolve/validate against real membership data instead of trusting
a header), because every other RBAC component consumes `ScopeContext`
objects, not headers, directly.

`RequirePermission(key, scope=None)` infers the narrowest scope implied by
whichever headers were actually supplied when `scope=` isn't given
explicitly (`_infer_scope_type`), so a plain `RequirePermission("x.read")`
naturally checks at `ROUTER` scope if `X-Router-Id` was sent, `LOCATION` if
only `X-Location-Id` was sent, and so on, falling back to `GLOBAL`.

## 8. Cache design (`cache.py`)

`PermissionCache` stores the JSON-serialized `EffectiveGrants` (see
`EffectiveGrant.to_json`/`from_json`) under `rbac:effective_permissions:
{user_id}`, TTL from `Settings.rbac_permission_cache_ttl_seconds` (default
300s). **This is a real, invalidated cache, not a TTL-only one.** Every
mutation that can change a user's effective permissions calls
`RBACService._invalidate_users` or `_invalidate_role_holders` immediately:

| Mutation | Invalidates |
|---|---|
| Role assigned / revoked | The one target user |
| Permission override granted / revoked | The one target user |
| Permission assigned to / removed from a role | Every user currently holding that role (`get_user_ids_with_role`) |
| Role activated / deactivated | Every user currently holding that role |
| Role updated (any field) | Every user currently holding that role |
| Role deleted | Every user who held it (looked up *before* the soft delete) |

The TTL exists purely as a backstop against a missed invalidation path (e.g.
a future direct-SQL admin fix), not as the primary consistency mechanism.

## 9. Audit logging

`RBACService._audit` writes an `audit_log_entries` row for every action
listed in the spec (`AuditAction` enum): role created/updated/deleted/cloned/
activated/deactivated, permission assigned/removed, role assigned/revoked,
permission override granted/revoked, and permission denied (written by
`AccessValidator.check` itself, not the service, since a denial can happen
without ever reaching a service method). This is wired directly into the
service/validator methods that perform each mutation, not bolted on
separately.

## 10. Role cloning and templates

`RBACService.clone_role` requires the source to be `is_system_role=True`
**or** `is_template=True` (`RoleNotCloneableError` otherwise) -- matching
"system roles or explicitly marked template roles usable as a cloning
source". The clone gets `parent_role_id = source.id` (both for audit
provenance and for inheritance, per §3), copies the source's `role_scopes`
and `role_permissions` rows, and is always created as a non-system,
non-template role (`is_system_role=False`, `is_template=False`) -- a clone
doesn't retain the "cannot be renamed/deleted" protection of its source
(that protection is a property of the specific row, not the lineage), and
isn't itself immediately clonable unless the org explicitly marks it as a
template later via `update_role`.

## 11. Custom roles vs. "custom permission groups"

The spec lists "custom roles / custom permission groups" as one feature.
Custom **roles** are fully supported: any authenticated caller with
`roles.create` can create an org-scoped role (`RBACService.create_role`
with `organization_id` set) with an arbitrary subset of existing
permissions. Custom **permission groups**, however, are *not* modeled as a
separate per-organization concept -- `permission_groups` remains a single,
shared, platform-wide taxonomy (the 36 `PermissionModule` values). Adding a
genuinely org-specific *module* would mean an organization inventing new
permission keys nothing in the platform code checks for, which doesn't fit
this system's "permissions are dynamically resolved but their *shape* is
platform-defined" design. If a future need for org-specific permission
namespacing emerges, the natural extension is an optional `organization_id`
column on `permission_groups` (currently absent) -- deliberately deferred
rather than spec'd speculatively.

## 12. Scope-type choices for the 15 seeded system roles

| Role | `scope_type` | Why |
|---|---|---|
| Super Admin, Platform Admin, Platform Support, Billing Manager | `GLOBAL` | Platform-wide operations spanning every tenant. |
| MSP Owner, MSP Admin | `ORGANIZATION` | No `MSP` scope type exists (see §1); closest fit until the MSP/Organization domains exist. |
| Organization Owner, Organization Admin | `ORGANIZATION` | Manage a single tenant. |
| Network Administrator, Location Manager, Reception Staff, Helpdesk, Guest Operator | `LOCATION` | Day-to-day, site-level operational roles. |
| Read Only, Auditor | `ORGANIZATION` | The common "tenant-wide visibility" need; either can be cloned to `GLOBAL` for a platform-wide variant if needed. |

Each role's actual grants are expressed as a *default grant level per
module, with per-module overrides* (`GrantLevel`: `NONE`/`READ`/`OPERATE`/
`FULL`) rather than a literal permission list -- see `SYSTEM_ROLES` in
`seed.py` and the generated `PERMISSION_MATRIX.md`.

## 13. Testing strategy

`tests/unit/test_rbac.py` mirrors `test_auth.py`'s approach: a
`FakeRBACRepository` (in-memory, implements `RBACRepositoryProtocol`) and a
`FakeRedis` stand in for Postgres/Redis, since neither is available in this
environment. Coverage: role CRUD (including duplicate-slug and system-role-
immutability rejections), permission CRUD, `PermissionResolver` (direct and
recursive-inherited grants, deactivated-role and expired-assignment
exclusion), `ScopeResolver` hierarchy rules, `AccessValidator` end-to-end
(allow, deny-override-wins, allow-override-grants, denial audit logging),
role assignment (success, invalid-scope rejection, escalation rejection,
missing-permission rejection, revocation), cross-tenant isolation
(cross-org read rejection, list filtering, global-role visibility),
permission-override escalation (rejection and the `permissions.manage`
bypass), cache hit/miss (a `CountingRepository` asserts the underlying
resolver is only invoked once across two cached reads), and cache
invalidation on both role-assignment and role-permission changes. A
`TestSeedDataConsistency` class also guards the seed data's own internal
invariants (every module mapped, every role's grants a subset of that
module's applicable actions, `GLOBAL` always in every module's allowed
scope set, every role's own scope type compatible with every module it's
granted) purely from the data structures, without touching a database.
