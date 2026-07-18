# Location Architecture

This document records every design decision Module 006 made where the brief
left room for judgment. Read this before modifying
`app/domains/location/` or the targeted RBAC seams it touches
(`location_id` FK follow-up, `CurrentLocation` hardening).

## 1. Where Location sits in the hierarchy

CloudGuest's modeled hierarchy is Organization -> Location -> Router ->
Guest. A `Location` is a physical site (an office, a retail branch, a
campus building) belonging to **exactly one** organization
(`organization_id`, real FK, `NOT NULL`) -- unlike `Organization`, which can
recursively own other organizations (MSP hierarchy), a location has no
children of its own kind. The Router domain does not exist yet (a future
module); `Location` deliberately does not reference or model routers in any
way -- no `router_count` column, no relationship, nothing that would need
revisiting once Router lands.

## 2. `LocationStatus`: not a copy of `OrganizationStatus`

`OrganizationStatus` is `trial` / `active` / `suspended` / `archived`.
`LocationStatus` (`app/domains/location/enums.py`) is `active` / `inactive`
/ `suspended` / `archived` -- deliberately **not** the same four states with
`trial` swapped for `inactive`, but a genuinely different semantic set for a
genuinely different entity:

* **No `trial` state.** Billing/subscription state is exclusively an
  organization-level concept in this codebase's boundary (see
  `docs/organization/ORGANIZATION_ARCHITECTURE.md` §4) -- a location has no
  subscription of its own, so a location-level "trial" would be meaningless.
* **`inactive`** replaces it: the location record exists (address, contact,
  timezone already on file) but is not currently operational -- e.g. a site
  being onboarded before its routers are provisioned, a seasonal location
  closed for part of the year, or a site temporarily taken offline for
  maintenance. This is a normal, expected, non-administrative state a
  location can sit in for a while.
* **`suspended`** is administrative and independent of the organization's
  own status -- an organization can remain `active` while one specific
  location is `suspended` (e.g. a compliance incident, a safety issue, or a
  billing dispute scoped to that single site). This is the precise
  difference from organization-level suspension, which takes down the
  entire tenant; location-level suspension takes down exactly one site.
  Only the dedicated `suspend`/`activate` endpoints transition a location
  into or out of this state.
* **`archived`** mirrors `OrganizationStatus.ARCHIVED` exactly: soft-deleted
  via `BaseModel`'s mixin, permanent (the site closed for good), only ever
  set by `LocationService.archive_location`.

One behavioral note carried over unmodified from `OrganizationService`
(intentionally, for consistency, not because it was independently
rediscovered as ideal): `LocationService.get_location` resolves with
`include_deleted=False` by default, so a location archived through the real
`archive_location` path (which also soft-deletes it) will read back as
`LocationNotFoundError` on a subsequent `update`/`suspend`/`activate` call,
not `LocationArchivedError` -- the `LocationArchivedError` branch only fires
for a location whose `status` column says `archived` while `is_deleted` is
still `False` (e.g. a row created directly with that status, as
`test_organization.py`'s own `test_update_archived_organization_raises`
does for organizations). This is exactly `OrganizationService`'s existing
behavior, reproduced here for parity rather than "fixed", since diverging
would make the two domains inconsistent for no functional gain -- a caller
can't reach an archived-and-soft-deleted row through the API either way.

## 3. No separate `LocationMember` table -- no gap was found

The brief asked to introduce one only if a genuine gap in RBAC's coverage
were found. None was: a user's relationship to a location is fully
expressed by RBAC's existing `user_roles` table scoped to `location_id`
(`scope_type = location`). Unlike `Organization`, which needed
`OrganizationMember` because *tenant membership* ("does this user belong to
this org at all, independent of what they can do") is meaningfully distinct
from *authorization* ("what can this user do") -- an invited-but-not-yet-
accepted member has zero roles, a state `user_roles` alone cannot express --
a location has no analogous "invited but not yet a resident" concept. There
is no location-level onboarding/acceptance flow to model, no "does this user
belong to this location" question distinct from "does this user hold a role
scoped to this location". Every legitimate location-level relationship
(network administrator at Location X, reception staff at Location Y) is
already exactly what a `user_roles` row scoped to `location_id` expresses,
and RBAC's `LocationRole` table (per-location role curation/defaults,
already built in Module 004) covers the analogous "which roles are enabled
here, what's the default" configuration surface `OrganizationRole` covers
for organizations. Introducing `LocationMember` would duplicate `user_roles`
with no new information captured.

## 4. Hierarchy validation: composed with `OrganizationService`, not duplicated

`LocationService` never queries the `organizations` table directly. It
depends on a narrow, duck-typed `OrganizationLookupProtocol` (just
`get_organization`) -- the same cross-domain-composition-not-duplication
pattern `OrganizationService` itself already uses for RBAC's audit log
(`AuditLogWriter`). In practice this is satisfied by the real
`OrganizationService` (wired in `app/domains/location/dependencies.py`), so
"does this organization exist" / "is it archived" is answered by the exact
same code path `app/domains/organization/router.py` itself uses -- there is
exactly one implementation of "what does an archived organization mean" in
the codebase.

* **Creating** a location: `OrganizationLookupProtocol.get_organization`
  raises `OrganizationNotFoundError` (propagated, unmodified) if the
  organization doesn't exist; `LocationService` then checks
  `organization.status == OrganizationStatus.ARCHIVED` and raises
  `OrganizationArchivedError` (reused directly from
  `app.domains.organization.exceptions`, not re-implemented) if so.
* **Updating** a location never re-validates the parent organization,
  because `organization_id` cannot change post-creation (see §5) -- there is
  nothing new to validate.

## 5. `organization_id` is immutable after creation

**Decision: a location's `organization_id` cannot be changed once set.**
`LocationUpdateRequest` (`app/domains/location/schemas.py`) simply does not
expose the field at all -- there is no "reassign to a different
organization" code path anywhere in the service or API surface.

Reasoning: a `Location` models a physical building. "Moving" a building to a
different tenant is not a real-world operation an update endpoint should
pretend to support cheaply -- unlike, say, renaming a location or fixing its
address, reassigning `organization_id` would silently invalidate every
`user_roles`/`location_roles`/`permission_overrides` row currently scoped to
that location (all of which are keyed by `location_id`, which wouldn't
change, but whose *meaning* -- "location X in organization A" -- would
suddenly become "location X in organization B" out from under every existing
role assignment). If a location genuinely needs to change tenant ownership
(e.g. a franchise site sold from one operator to another), the correct
operation is to archive the old `Location` row and create a fresh one under
the new organization, with RBAC role assignments deliberately re-created
rather than silently carried over -- a real administrative decision, not an
incidental side effect of a `PUT`. `LocationService.update_location`
defensively strips an `organization_id` key from its input `dict` if one is
ever present (belt-and-suspenders against a future caller constructing the
update payload by hand, e.g. from a script, rather than via the schema),
documented directly in the service's docstring; this is verified by
`test_location.py::test_update_location_ignores_organization_id_if_present`.

## 6. Tenant scoping (list/read/write access)

Mirrors `OrganizationService`'s own `_enforce_tenant_access` pattern exactly,
for consistency across domains, extended one level down the hierarchy:

* A caller with no `requesting_organization_id` (resolved from
  `X-Organization-Id` via RBAC's `CurrentOrganization`) is a platform-level,
  `GLOBAL`-scoped caller and may act on any location.
* A caller acting within organization A (`requesting_organization_id == A`)
  may read/mutate a location only if the location's `organization_id == A`,
  or if the location's organization's `parent_organization_id == A` (i.e. A
  is an MSP and the location belongs to one of A's child organizations) --
  `CrossOrganizationLocationAccessError` (403) otherwise.
* This check runs on every read/write path that resolves a location by id
  (`get_location`, and therefore `update_location`/`archive_location`/
  `suspend_location`/`activate_location`, which all call `get_location`
  internally first) and on the two collection endpoints scoped by a path
  `organization_id` (`list_locations`, `create_location`), via a second
  helper (`_assert_organization_accessible`) that checks the path
  `organization_id` itself against `requesting_organization_id` before ever
  touching a specific location row.

This exists because RBAC's `RequirePermission` only answers "does this
caller hold `locations.create`/etc at the resolved scope" -- it has no
opinion on *which* organization's data a path parameter names. Without this
service-layer check, a caller holding an `ORGANIZATION`-scoped role for
organization A could set `X-Organization-Id: A` (satisfying the permission
check at A's scope) while pointing the URL path at organization B's `id`,
creating or reading organization B's locations despite never having been
authorized for B. This mirrors exactly the reasoning
`docs/organization/ORGANIZATION_ARCHITECTURE.md` §2 gives for
`OrganizationService._enforce_tenant_access`, applied one level down.

## 7. RBAC `location_id` FK follow-up

Per the module brief, `app/domains/rbac/models.py`'s `location_id` columns
now carry a real `ForeignKey("locations.id")`:

| Model | `ondelete` | Why |
|---|---|---|
| `UserRole.location_id` | `SET NULL` | A role assignment losing its location context is safer than being destroyed outright -- mirrors `UserRole.organization_id`'s own `SET NULL` reasoning from migration `0004`. |
| `PermissionOverride.location_id` | `SET NULL` | Same reasoning as `UserRole`. |
| `LocationRole.location_id` | `CASCADE` | This column was already `NOT NULL` (unlike `UserRole`/`PermissionOverride`'s nullable `location_id`) -- it is a strict per-location config row (mirrors `OrganizationRole`) with no meaning once its location is gone, the same reasoning `OrganizationRole.organization_id` used for its own `CASCADE`. |
| `AuditLogEntry.location_id` | `SET NULL` | Preserve audit history even if the location row is later removed -- audit trails should outlive the entities they describe (mirrors `AuditLogEntry.organization_id`). |

`router_id` (on `UserRole`/`PermissionOverride`) and the future `msp_id`
remain plain, FK-less `UUID` columns -- the Router (and future MSP) domains
still do not exist, per the module brief's explicit scope boundary. `Role`
and `OrganizationRole` carry no `location_id` column at all and were not
touched. `PermissionScope` carries no scope columns at all and was
similarly left alone.

This was implemented as:

1. A targeted edit to `app/domains/rbac/models.py` (only the four
   `location_id` column definitions gained a `ForeignKey`, plus the module
   docstring was updated to describe the new state) -- no other RBAC logic,
   index, or column touched. `router_id` columns were verified (both by
   reading the model and via
   `test_location.py::TestRbacLocationFkFollowUp::test_router_id_columns_remain_fk_less`)
   to remain untouched.
2. A new Alembic migration, `0006_add_location_fk_to_rbac_tables.py` (after
   `0005_create_location_tables.py`), that adds the constraints via
   `op.create_foreign_key`/`op.drop_constraint` -- a pure ALTER-TABLE
   follow-up, exactly mirroring `0004_add_organization_fk_to_rbac_tables.py`'s
   shape; it does not redo `0002`/`0004`'s already-applied definitions.
3. `AuditAction` (RBAC's enum) gained five new `location_*` values, used
   exclusively by `LocationService`, additive only -- no existing value was
   renamed or removed.

**Verification:** the full pre-existing `tests/unit/test_rbac.py` suite (38
tests) and `tests/unit/test_organization.py` suite (36 tests) both pass
unmodified after this change, plus
`test_location.py::TestRbacLocationFkFollowUp` directly asserts (at the
SQLAlchemy model/metadata level) that the four columns now declare a
`ForeignKey` targeting `locations.id`, that `LocationRole.location_id` is
still `NOT NULL`, and that `router_id` still carries no FK.

## 8. `CurrentLocation`: from trusted header to validated, org-consistent location

RBAC's own docs (`docs/rbac/RBAC_ARCHITECTURE.md`, and
`docs/organization/ORGANIZATION_ARCHITECTURE.md` §5 for the analogous prior
change) predicted this seam would need hardening once Location existed. The
change made (`app/domains/rbac/dependencies.py::CurrentLocation`):

* No `X-Location-Id` header -> returns `None`, no DB lookup at all
  (unaffected callers acting without a location context, e.g. an
  organization-level operation, are unaffected).
* Header present -> looks up the location
  (`LocationNotFoundError` if it doesn't exist -- and, since
  `GenericRepository.get_by_id` defaults to excluding soft-deleted rows the
  same way `CurrentOrganization`'s lookup does for organizations, an
  archived location also reads as "not found" here, not as a distinct
  "archived" error) and, **if** an organization context was already resolved
  via `CurrentOrganization` (i.e. `X-Organization-Id` was present and
  passed its own validation), checks that the location's `organization_id`
  matches it -- `LocationOrganizationMismatchError` (403) otherwise. This is
  a real cross-tenant boundary check: a location belonging to a different
  organization than the one named by `X-Organization-Id` must be rejected,
  not silently trusted, exactly as the module brief specified.
* If `X-Location-Id` is present but `X-Organization-Id` is not, the
  mismatch check is skipped (there is nothing to compare against) -- the
  location's own existence/not-archived check still applies regardless.

This reuses `LocationNotFoundError`/`LocationOrganizationMismatchError` from
`app.domains.location.exceptions` and `Location` from
`app.domains.location.models` rather than reinventing location-validation
logic inside RBAC -- the same reuse posture `CurrentOrganization` already
established for the Organization domain. This introduces a one-directional
import from `app.domains.rbac.dependencies` into
`app.domains.location.models`/`exceptions` only (not `location.service`/
`repository`/`dependencies`), so there is no import cycle:
`location.dependencies -> rbac.dependencies -> location.models`, and
`location.models` imports nothing from `rbac`. `CurrentRouter` is unchanged,
for the reason above (no Router domain yet).

## 9. Slug uniqueness, normalization, and country/email handling

Location slugs are unique **per organization**
(`UniqueConstraint("organization_id", "slug")`, migration `0005`), not
globally -- two different organizations may each have their own
"downtown-branch" location; only one location within the *same*
organization may hold that slug. This mirrors `Organization.slug`'s own
validation/normalization posture (`^[a-z0-9]+(?:-[a-z0-9]+)*$`, lowercased)
but scoped one level narrower. `LocationService` re-normalizes (lowercase)
defensively at write time regardless of caller, the same defense-in-depth
posture `OrganizationService` takes for its own slug. `country` is validated
as a 2-letter ISO 3166-1 alpha-2 code at the schema layer and re-normalized
to uppercase defensively in the service, mirroring the slug/email
normalization pattern. `contact_email` (an optional on-site contact, not a
login identity) is lowercased before storage the same way
`Organization.contact_email` is, but is not required to be unique --
multiple locations, even within the same organization, may legitimately
share an on-site contact person.

## 10. What this module deliberately does not do

* No Router/User/Monitoring/Billing domains -- out of scope per the module
  brief.
* No `LocationMember` table -- see §3.
* No hard delete of locations from the API -- `DELETE` always archives
  (`status=archived` + `BaseModel` soft-delete), never removes the row.
* No `organization_id` reassignment after creation -- see §5.
* No native PostgreSQL enum types for `status` -- a plain `String` column
  with a Python `StrEnum`, mirroring `app.domains.organization.enums`'s
  documented convention, so a new value never requires an `ALTER TYPE`
  migration.
* No modeling of router counts, guest WiFi configuration, or any
  Router-domain concept on `Location` itself -- the Router domain does not
  exist yet, and `Location` is deliberately kept forward-compatible with it
  rather than anticipating its shape.
