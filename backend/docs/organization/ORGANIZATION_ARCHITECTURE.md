# Organization Architecture

This document records every design decision Module 005 made where the brief
left room for judgment. Read this before modifying
`app/domains/organization/` or the targeted RBAC seam it touches.

## 1. MSP modeling: no separate MSP table

Per `docs/rbac/RBAC_ARCHITECTURE.md`'s own note ("an MSP is modeled, once the
Organization domain exists, as an Organization row flagged as an MSP
container"), this module does **not** introduce a separate MSP entity.
`Organization.org_type` (`OrganizationType`: `STANDARD` | `MSP`) is the sole
discriminator. An MSP is just an `Organization` row with `org_type == MSP`
that owns other `Organization` rows via `parent_organization_id`.

Invariants enforced in `OrganizationService`:

* Only an MSP-type organization may be pointed at by another organization's
  `parent_organization_id` (`NotAnMspOrganizationError` otherwise) --
  checked on both `create_organization` and `update_organization`.
* Circular hierarchies are rejected the same way RBAC rejects circular
  `parent_role_id` chains: `_assert_valid_parent` walks the *proposed*
  parent's ancestry (`OrganizationRepository.get_parent_chain`, bounded by a
  50-hop defensive depth cap) and raises `CircularOrganizationHierarchyError`
  if the organization being reparented appears in that chain (this also
  catches the trivial self-parent case).
* An MSP-type organization with existing children cannot be changed to
  `STANDARD` (`MspDowngradeWithChildrenError`) -- its children would be left
  pointing at a parent that can no longer legally have children.

Nested MSPs (an MSP owned by another MSP) are permitted rather than
forbidden: the invariant only checks that the *parent* is MSP-type, not that
the child isn't. This is deliberately permissive for MSP-reseller scenarios;
typical usage has MSPs at the top level (`parent_organization_id = NULL`)
and standard organizations as their children.

## 2. Tenant scoping (list/read/write access)

Mirrors `RBACService`'s own `_enforce_role_tenant_access`/`list_roles`
pattern exactly, for consistency across domains:

* A caller with no `requesting_organization_id` (resolved from
  `X-Organization-Id` via RBAC's `CurrentOrganization`) is a platform-level,
  `GLOBAL`-scoped caller (e.g. Super Admin, Platform Admin) and may act on
  any organization. `GET /organizations` returns every organization.
* A caller acting within organization A (`requesting_organization_id == A`)
  may only read/mutate A itself or A's children (if A is an MSP) --
  `CrossOrganizationAccessError` otherwise. `GET /organizations` is filtered
  to `id == A OR parent_organization_id == A` at the repository level (an
  `OR` query, the same shape as RBAC's `list_roles`).

This is exactly what the brief asked for ("platform-level roles see all,
org-scoped roles see only their own + children if MSP") expressed without
ever branching on a role's name -- it falls out of whether
`requesting_organization_id` is present and what it is, both already
resolved by RBAC's existing scope-header machinery.

## 3. Membership vs. RBAC role assignment

`OrganizationMember` deliberately does **not** touch `user_roles`. RBAC
answers "what can this user do"; membership answers "does this user belong
to this organization at all". An invited member has zero permissions --
membership and authorization are two independent axes:

* A user can be an active member with no roles (can't do anything yet,
  but is "in" the org for billing/seat-count/directory purposes).
* Conversely nothing stops assigning a `user_roles` row scoped to an
  organization the user isn't a member of today (RBAC has no dependency on
  Organization) -- though in practice the natural flow is invite -> accept
  -> assign a role, in that order, which the router layer is responsible
  for sequencing, not this service.

`OrganizationService` never calls into `RBACService`. Wiring "what role
does a new member get by default" (RBAC's own `organization_roles` table
already models "default role for new members") is left to the caller
(e.g. the router or a future onboarding flow), not automated here -- this
keeps the two domains' write paths independently testable and avoids a
hard service-to-service dependency in either direction.

### Invite/accept flow shape

`POST /organizations/{id}/members` (invite, gated by `organizations.manage`)
creates an `OrganizationMember` row with `status=invited`, `joined_at=NULL`.
`POST /organizations/{id}/members/{member_id}/accept` is **not** gated by
any `organizations.*` permission -- deliberately, since an invited user by
definition holds no permissions in that organization yet, so requiring one
would make every invite unacceptable. The only check is that the caller
*is* the invited user (`OrganizationService.accept_invite` compares
`member.user_id` to the caller's id, raising `OrganizationMembershipNotFoundError`
-- not a 403 -- to avoid confirming a given member-id/org-id pair exists to
an unrelated caller). `GET /me/organizations` is the self-service listing
counterpart (any status, so an invitee can see their own pending invites).
This shape was chosen over a bespoke "list my pending invites" endpoint
because `GET /me/organizations?membership_status=invited` already covers it
via the existing query parameter.

### Membership state machine and the "no unauthorized reactivation" rule

`MembershipStatus`: `invited -> active -> (suspended | removed)`, with
`suspended -> active` only via the explicit `change_member_status` service
method (not exposed as its own endpoint today, but present at the service
layer per the brief -- see `OrganizationService.change_member_status`), and
`removed -> invited` only via a brand-new `invite_member` call (a genuine
re-invite, a new row, not a resurrection of the removed one). Concretely,
`invite_member` inspects the most recent existing membership row for the
(organization, user) pair:

| Existing status | `invite_member` behavior |
|---|---|
| `active` or `invited` | `DuplicateMembershipError` -- already a member or already invited |
| `suspended` | `MembershipSuspendedError` -- must be explicitly reactivated by an admin (`change_member_status`), not re-invited |
| `removed` (or no row at all) | A new `invited` row is created |

This is exactly the brief's "a removed/suspended member should not be
resolvable as active without a real re-invite flow" requirement, made
precise: suspended requires an explicit reactivation action (distinguishing
"paused" from "gone"); removed requires a genuinely fresh invite (preserving
history as multiple rows rather than mutating the old one in place).

### Uniqueness: one active membership per (organization, user)

Enforced at the database level by a **partial unique index** (Postgres-only,
`postgresql_where="status = 'active'"` -- see migration `0003`) on
`(organization_id, user_id)`, not a plain unique constraint. A plain unique
constraint would prevent ever re-inviting a removed member (a second row for
the same pair would violate it even though the first is `removed`); the
partial index allows unlimited historical rows while still making it
impossible for two rows to be simultaneously `active` for the same pair.

### Last-active-member protection

`remove_member` (and `change_member_status` when transitioning to
`removed`) counts current active members via
`OrganizationRepository.count_active_members` and raises
`LastActiveMemberError` if the member being removed is the only active one.
**Decision: this rule is enforced.** Reasoning: an organization with zero
active members is unreachable by anyone through the membership system (no
one could invite a new member into it, since inviting doesn't itself
require existing membership, but nothing would ever surface the org as
"yours" to any user, and no in-app actor would exist to manage it) --
essentially the same rationale as "can't delete the last owner" in most
SaaS products. A platform-level (`GLOBAL`-scoped) administrator can still
archive the whole organization (`DELETE /organizations/{id}`) regardless of
its member count, since archival doesn't go through membership removal at
all.

## 4. `settings` JSONB: the extension point, and the billing boundary

`Organization.settings` (JSONB, default `{}`) is the single, intentional
escape hatch for per-organization configuration that doesn't warrant its own
column -- feature flags, branding/notification preferences, and similar. It
is **not** meant to become a dumping ground for structured, frequently
queried data; anything that needs indexing, foreign keys, or validation
belongs in a real column or a related table instead.

**Billing boundary, explicitly not crossed:** this domain does not model
subscription plans, invoices, payment methods, or entitlement/quota logic.
`PermissionModule.BILLING` / `INVOICES` / `SUBSCRIPTIONS` are already-seeded,
separate permission modules in `app/domains/rbac/seed.py` reserved for a
future Billing domain. The only nod to billing here is
`Organization.subscription_tier`, a nullable, free-form label
(e.g. `"starter"`, `"enterprise"`) with zero pricing/entitlement logic of
its own -- a future Billing domain can key its own plan/entitlement
resolution off of it, but Organization neither validates its values against
a known plan list nor enforces anything based on it. This keeps Module 005
from having to anticipate an unbuilt domain's shape.

## 5. `CurrentOrganization`: from trusted header to validated membership

RBAC's own docs (`docs/rbac/RBAC_ARCHITECTURE.md` §7) called this out as
"the single place to change" once Organization exists. The change made
(`app/domains/rbac/dependencies.py::CurrentOrganization`):

* No `X-Organization-Id` header -> returns `None`, no DB lookup at all
  (platform-level callers acting without an org context, e.g. creating the
  very first organization, are unaffected).
* Header present -> looks up the organization
  (`OrganizationNotFoundError` if it doesn't exist) and checks the current
  user holds an **active** `OrganizationMember` row for it
  (`OrganizationMembershipRequiredError` otherwise, 403).

This is a real behavior change (previously any authenticated caller could
set any `X-Organization-Id` and have it trusted at face value), scoped to
exactly the one dependency RBAC's own documentation predicted would need it,
reusing `OrganizationNotFoundError`/`OrganizationMembershipRequiredError`
from `app.domains.organization.exceptions` and
`Organization`/`OrganizationMember` from `app.domains.organization.models`
rather than re-implementing membership-checking logic inside RBAC. This
does introduce a one-directional import from `app.domains.rbac.dependencies`
into `app.domains.organization.models`/`enums`/`exceptions` -- deliberately
the *models* module only, not `organization.service`/`repository`/
`dependencies`, so there is no import cycle:
`organization.dependencies -> rbac.dependencies -> organization.models`,
and `organization.models` imports nothing from `rbac`.

`CurrentLocation`/`CurrentRouter` are unchanged (still trust their headers)
because the Location/Router domains still do not exist -- exactly the
scope boundary RBAC's own docs already drew.

## 6. RBAC `organization_id` FK follow-up

Per the module brief, `app/domains/rbac/models.py`'s `organization_id`
columns now carry a real `ForeignKey("organizations.id")`:

| Model | `ondelete` | Why |
|---|---|---|
| `Role.organization_id` | `SET NULL` | A global/custom role should not vanish if its owning organization is later hard-deleted (normal lifecycle is soft-delete/archive, not hard delete, but the constraint should degrade gracefully if it ever happens). |
| `UserRole.organization_id` | `SET NULL` | Same reasoning; a role assignment losing its org context is safer than being destroyed outright. |
| `OrganizationRole.organization_id` | `CASCADE` | This column was already `NOT NULL` -- it is a strict per-organization config row with no meaning once its organization is gone. |
| `PermissionOverride.organization_id` | `SET NULL` | Same as `UserRole`. |
| `AuditLogEntry.organization_id` | `SET NULL` | Preserve audit history even if the organization row is later removed -- audit trails should outlive the entities they describe. |

**`PermissionScope` was checked and intentionally left untouched** -- it
has no `organization_id` column at all (only `permission_id`/`scope_type`),
so the brief's instruction to "add a real ForeignKey... on: Role, UserRole,
OrganizationRole, PermissionScope" does not apply to it as written; this
was verified by reading the model definition rather than assumed.

This was implemented as:

1. A targeted edit to `app/domains/rbac/models.py` (only the five
   `organization_id` column definitions gained a `ForeignKey`, plus the
   module docstring was updated to stop claiming `organization_id` is
   FK-less) -- no other RBAC logic, tests, or column touched.
2. A new Alembic migration, `0004_add_organization_fk_to_rbac_tables.py`
   (after `0003_create_organization_tables.py`), that adds the constraints
   via `op.create_foreign_key`/`op.drop_constraint` -- it does not redo
   `0002_create_rbac_tables`'s already-applied table/column/index
   definitions, it is a pure ALTER-TABLE follow-up.
3. `AuditAction` (RBAC's enum) gained nine new `organization_*` values,
   used exclusively by `OrganizationService`, additive only -- no existing
   value was renamed or removed.

**Verification:** the full pre-existing `tests/unit/test_rbac.py` suite (38
tests) passes unmodified after this change, plus
`test_organization.py::TestRbacOrganizationFkFollowUp` directly asserts (at
the SQLAlchemy model/metadata level) that the five columns now declare a
`ForeignKey` targeting `organizations.id`, and that `PermissionScope` still
does not have an `organization_id` column at all.

## 7. Slug and email normalization

Organization slugs are validated (schema-level, `OrganizationCreateRequest`/
`OrganizationUpdateRequest`) against `^[a-z0-9]+(?:-[a-z0-9]+)*$` and
lowercased, mirroring `RegisterRequest.validate_username`'s pattern in the
auth domain. `OrganizationService` re-normalizes (lowercase) defensively at
write time regardless of caller, the same defense-in-depth posture
`AuthRepository.create_user`/`get_user_by_email` take for email/username.
`contact_email` is likewise lowercased before storage/uniqueness checks
(slugs are unique platform-wide via a real DB `UniqueConstraint`; contact
email is not required to be unique across organizations, since the same
person can legitimately be the contact for more than one organization, e.g.
an MSP's own staff).

## 8. What this module deliberately does not do

* No Location/Router/User/Monitoring/Billing domains -- out of scope per
  the module brief.
* No automatic RBAC role assignment on invite/accept -- see §3.
* No hard delete of organizations from the API -- `DELETE` always archives
  (`status=archived` + `BaseModel` soft-delete), never removes the row.
* No native PostgreSQL enum types for `org_type`/`status`/membership
  `status` -- plain `String` columns with a Python `StrEnum`, mirroring
  `app.domains.auth.models`'s (`User.status`) and
  `app.domains.rbac.enums`'s documented convention, so a new value never
  requires an `ALTER TYPE` migration.
