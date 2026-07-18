# User Domain Architecture

This document records every design decision Module 007 made where the
brief left room for judgment. Read this before modifying
`app/domains/user/` or the targeted, additive extensions it required in
`app.domains.auth`/`app.domains.rbac`.

## 1. No owned model, no `repository.py` -- a pure orchestration layer

Every other domain in this codebase (`location`, `organization`, `rbac`)
has a `models.py` (SQLAlchemy ORM classes) and a `repository.py`
(`XRepositoryProtocol` + `GenericRepository`-backed `XRepository`) because
each of them owns at least one persisted table. `app.domains.user` owns
**none**. It exists entirely to compose three domains that already model
everything a "user" needs:

* **Identity** (`first_name`, `last_name`, `email`, `username`, `phone`,
  `password_hash`, `profile_photo`, `designation`, `department`,
  `employee_id`, `timezone`, `language`, `status`, `is_active`,
  `is_verified`, login/lockout tracking) -- `auth.models.User` (Module 003).
* **Membership** ("does this user belong to this organization at all") --
  `organization.models.OrganizationMember` (Module 005).
* **Authorization** ("what can this user do") -- RBAC's `user_roles` +
  `PermissionResolver`/`RoleResolver` (Module 004).

Given that, `app/domains/user/service.py` composes narrow, duck-typed
Protocols over each of those three domains' real services (the same
compose-not-duplicate pattern `LocationService` established for
`OrganizationLookupProtocol` in Module 006), rather than defining its own
`repository.py` around a table that doesn't exist. This is a deliberate
divergence from the file-layout template in the module brief -- there is
no `models.py`/`repository.py` in this domain, and that absence is itself
the design decision, not an oversight.

## 2. No new table or column was added

The brief explicitly permitted adding **one** small, clearly-justified
table or nullable column (e.g. a per-user "default/primary organization"
preference) if genuinely needed for a good `GET /api/v1/me` experience.
**None was added.** Reasoning:

* A "default organization" preference would only matter if the API needed
  to silently pick *which* organization's context to act within when a
  multi-org user's request carries no explicit scope. This codebase
  already has an established, working mechanism for that: the caller
  states its scope explicitly per-request via the `X-Organization-Id`
  header (`app.domains.rbac.dependencies.CurrentOrganization`), the same
  way every other multi-tenant-aware endpoint (`organizations`,
  `locations`) already works. There is no code path anywhere in this
  module (or the ones it composes) that needs to *infer* an organization
  from stored user state instead of being told one -- `GET /api/v1/me`
  simply returns identity + **all** of the caller's memberships +
  **all** of their active roles across every scope, with no "current org"
  concept to default.
* `OrganizationMember.is_primary_contact` (Module 005) already exists and
  answers a closely related but distinct question ("is this member the
  designated point of contact *for this specific organization*") -- adding
  a second, overlapping "default org for this user" concept would create
  two competing notions of "primary" with no clear precedence rule between
  them.
* Nothing in the required endpoint list (`GET/POST /users`,
  `GET/PUT /users/{id}`, `POST /users/{id}/deactivate`/`activate`,
  `GET/PUT /me`) needs any state that doesn't already exist on `auth.User`,
  `OrganizationMember`, or RBAC's tables. Adding a column "just in case" was
  judged to be exactly the "add more columns by default" anti-pattern the
  brief warned against.

Consequently, **no Alembic migration (`0007_...`) was created** -- there is
no schema change for it to carry. `alembic/env.py` was left untouched.

## 3. What was added to `app.domains.auth`, and why

Per the brief's explicit boundary decision, this module must not duplicate
`auth.models.User`. The only genuinely new capability the auth domain
needed was **search + pagination over `User`**, which didn't exist at all
before this module (auth's own login/register/session flows never needed
to list users). One method was added, additively, to
`AuthRepositoryProtocol`/`AuthRepository`:

```python
async def list_users(
    self, *, page: int, page_size: int, search: str | None = None,
    is_active: bool | None = None, user_ids: list[uuid.UUID] | None = None,
) -> tuple[list[User], PaginationMeta]: ...
```

This is a hand-written query (not expressible via `GenericRepository`'s
equality/IN-only filter convention) for the same reason
`OrganizationRepository.list_organizations`/`LocationRepository
.list_locations` are hand-written: an OR-across-columns `ilike` search.
The `user_ids` parameter is what lets **one** method serve both
platform-wide listing (`UserService` calls it with `user_ids=None`) and
organization-scoped listing (called with the `user_id`s of that
organization's active members, resolved by composing
`OrganizationService`) -- see §6.

**Deliberately not added:** `create_user_by_admin`, `deactivate_user`,
`reactivate_user`, or any other wrapper method the brief's own phrasing
suggested as an example. The already-existing, fully generic
`create_user(**fields)`/`update_user(user, **fields)` cover every one of
those use cases verbatim -- an admin-created account and a deactivation are
both just a `User` row created/updated with a particular set of fields. The
*business rule* of which fields those are (e.g. `is_active=True,
is_verified=True` at admin-creation time; `is_active=False,
status="inactive"` at deactivation time) lives in `UserService`, exactly
where business rules belong -- not duplicated as a same-shaped wrapper one
layer down in the repository. Adding those wrappers would have been
indirection without new capability.

No other auth file (`service.py`, `jwt.py`, `password.py`, `security.py`,
`dependencies.py`, `router.py`) was modified. In particular,
`auth.dependencies.get_current_user`'s existing `if user is None or not
user.is_active: raise HTTPException(401, ...)` check was **read, not
changed** -- see §7.

## 4. Duplicate-email/username rejection: reused, not reinvented

Per the brief ("delegate to auth's existing uniqueness constraint/error
handling, don't reinvent"), `UserService.create_user` raises
`app.domains.auth.service.EmailAlreadyExistsError`/
`UsernameAlreadyExistsError` directly -- the exact same exception classes
(and therefore the exact same HTTP 409 shape) `AuthService.register` raises
for the identical condition. `app/domains/user/exceptions.py` re-exports
them from one place for convenient importing, but does not subclass or
wrap them into a parallel `user`-domain error type. The uniqueness check
itself (`get_user_by_email`/`get_user_by_username` then raise) is a
two-line, read-then-raise pattern duplicated at the *call site* the same
way `AuthService.register` does it inline -- there was no shared "check
uniqueness" method to extract without adding a new auth method purely for
a one-call-site convenience.

## 5. Admin-created organization membership: invited vs. active

**Decision: when an admin creates a user directly into an organization
(`organization_id` set on `POST /api/v1/users`), the resulting
`OrganizationMember` row is created as `ACTIVE`, not `INVITED`.**

This required no change to `OrganizationService` at all (per the module's
"do not modify Organization domain internals" constraint). `UserService
.create_user` composes **two** of `OrganizationService`'s existing public
methods in sequence:

```python
invite = await self.organization_lookup.invite_member(
    actor_user_id=actor_user_id, organization_id=organization_id, user_id=user.id,
)
await self.organization_lookup.accept_invite(
    user_id=user.id, organization_id=organization_id, member_id=invite.id,
)
```

`invite_member` creates the row `INVITED` (with its own duplicate-
membership/suspended-membership checks and `ORGANIZATION_MEMBER_INVITED`
audit entry, all for free), and `accept_invite` immediately transitions it
to `ACTIVE` with `joined_at` set (with its own `ORGANIZATION_MEMBER_ACCEPTED`
audit entry). The net effect is an `ACTIVE` membership, but the audit trail
honestly records both steps -- because that *is* honestly what happened:
this is functionally an admin performing an invite-and-immediately-accept-
on-the-user's-behalf, not a bypass of `OrganizationService`'s own state
machine.

**Why active, not left invited:** the entire premise of `POST
/api/v1/users` is that an *administrator* is directly provisioning the
account (setting a temporary password, vouching for the person) -- unlike
`OrganizationService.invite_member`'s own primary use case (inviting an
*existing* user who must independently accept), there is no second party
here who needs to consent to something they didn't already know about. The
person didn't request access and doesn't need to "accept" an invite to an
organization an administrator just placed them in with full knowledge; an
`INVITED`-and-never-accepted membership would leave the new account unable
to act within that organization until some other, unspecified step
happened, with no endpoint in this module's scope to trigger it. This
mirrors common enterprise "admin-invited user" UX conventions, where an
administrator-created account is usable immediately.

This also means `UserService` never constructs an `OrganizationMember` row
directly (no raw dict/model manipulation bypassing `OrganizationService`'s
own validation) -- every membership-lifecycle rule `OrganizationService`
already enforces (duplicate/suspended-membership rejection, audit logging)
still applies on the admin-creation path, for free.

## 6. Tenant scoping for list/detail (mirrors Organization/Location)

`UserService._member_user_ids_in_scope(organization_id)` computes "the
active-member user ids visible to a caller acting within
`organization_id`" as: that organization's own active members, plus (if it
is an MSP) the active members of every child organization it owns --
composed entirely from `OrganizationService.get_organization`/
`list_children`/`list_members`, the exact same "self or child" shape
`OrganizationService.list_organizations`/`LocationService`'s tenant checks
already use.

* **`list_users`**: `requesting_organization_id is None` (a platform-level,
  `GLOBAL`-scoped caller) sees every user
  (`AuthRepository.list_users(user_ids=None)`); otherwise the caller sees
  only users whose id is in `_member_user_ids_in_scope(...)`.
* **`get_user_detail`**/**`update_user`**/**`deactivate_user`**/
  **`reactivate_user`**: the same helper backs
  `_enforce_user_tenant_access`, which raises
  `CrossOrganizationUserAccessError` (403) if the target user's id is not
  in scope for a non-platform caller.
* **`create_user`** (when `organization_id` is supplied): a distinct helper,
  `_assert_organization_in_scope`, checks the *target* `organization_id`
  itself against the caller's scope (self or MSP-child) before ever
  creating anything -- the same two-helper split (one for an existing
  resolved entity, one for a path/payload-named target) `LocationService`
  uses for `_enforce_organization_scope` vs. `_assert_organization_accessible`.
* **`get_me`**/**self-update**: never tenant-scoped -- a user can always see
  and edit their own profile regardless of any `X-Organization-Id` context
  on the request. There is no "which tenant am I allowed to see myself
  under" question to ask.

This exists for the same reason `LOCATION_ARCHITECTURE.md` §6 gives:
`RequirePermission` only answers "does this caller hold `users.read`/etc at
the resolved scope" -- it has no opinion on *which* user a path parameter
names. Without this service-layer check, a caller holding an
`ORGANIZATION`-scoped `users.read` for organization A could point
`GET /users/{id}` at a user who belongs only to organization B and read
their profile despite never having been authorized for B.

## 7. Deactivation needs no separate session-revocation step

`auth.dependencies.get_current_user` (Module 003, read but **not**
modified by this module) already contains:

```python
user = await repository.get_user_by_id(uuid.UUID(str(payload["sub"])))
if user is None or not user.is_active:
    raise HTTPException(status_code=401, detail="User is not active")
```

`UserService.deactivate_user` sets `is_active=False` (plus
`status="inactive"`, via `UserAccountStatus.INACTIVE`). Because
`get_current_user` re-fetches the user row from the database on **every**
authenticated request (it does not trust a cached/stale claim baked into
the JWT), a deactivated user's existing, still-cryptographically-valid
access token is rejected on their very next request with no extra work --
confirmed directly in `test_user.py
::TestDeactivateReactivate::test_deactivated_user_fails_get_current_user_active_check`,
which deactivates a user, mints a real access token via
`JWTManager.create_access_token`, and asserts `get_current_user` raises a
401. `reactivate_user` additionally clears `failed_login_attempts`/
`locked_until` (so a reactivated account isn't immediately re-locked by
stale brute-force-protection state from before it was deactivated) and sets
`status="active"`.

An administrator cannot deactivate their own account through
`POST /users/{id}/deactivate` (`SelfDeactivationNotAllowedError`, 400) --
this prevents an admin from locking themselves out via this endpoint; if
self-deactivation is genuinely intended, it is out of this module's scope
(auth's own session-management endpoints are the right seam for a user
choosing to end their own access).

## 8. Admin vs. self editable profile fields

Three separate request schemas, not one schema reused with
`exclude_unset`-based filtering alone -- the *set* of fields each one even
allows a caller to *submit* is itself part of the security boundary:

| Field | Admin (`PUT /users/{id}`) | Self (`PUT /me`) |
|---|---|---|
| `first_name` / `last_name` | Yes | Yes |
| `phone` | Yes | Yes |
| `profile_photo` | Yes | Yes |
| `timezone` / `language` | Yes | Yes |
| `designation` / `department` / `employee_id` | Yes | **No** |
| `is_verified` | Yes | **No** |
| `email` / `username` | **No** | **No** |
| `is_active` / `status` | **No** | **No** |

* `designation`/`department`/`employee_id` are organization-/HR-managed
  attributes -- a user should not be able to unilaterally declare their own
  job title or employee id; these are admin-only.
* `is_verified` must never be self-settable -- a user promoting their own
  verification status would defeat whatever verification process exists.
  Admins may set it (e.g. to manually mark an account verified without the
  (currently unimplemented) email-delivery step -- see §9).
* `email`/`username` are excluded from **both** schemas. Changing a login
  identifier is a sensitive auth-domain operation (uniqueness re-check,
  likely re-verification, user notification) that this aggregation layer's
  endpoints deliberately do not take on -- it is out of scope here, and
  would belong to a future dedicated `auth`-domain endpoint if ever needed.
* `is_active`/`status` are excluded from **both** update schemas -- they
  are owned exclusively by the dedicated `deactivate`/`activate` endpoints,
  the same "one way to do it" convention `LocationUpdateRequest` uses for
  `status` (never settable via `PUT`, only via `suspend`/`activate`/
  `DELETE`).

Both `UserService.update_user`/`update_self` additionally filter the
incoming `data` dict against `ADMIN_EDITABLE_FIELDS`/`SELF_EDITABLE_FIELDS`
at the **service** layer, not just by relying on the request schema not
exposing a field -- the same defense-in-depth posture
`LocationService.update_location` uses for defensively stripping
`organization_id` regardless of whether the schema exposes it. This means
behavior can never silently diverge from this table even if a future
caller constructs the `data` dict by hand (verified directly by
`test_user.py::TestProfileUpdate::test_admin_update_ignores_email_and_status_fields`
and `test_self_update_allows_only_self_editable_fields`).

## 9. Admin-created accounts are active and verified immediately

Self-service `AuthService.register` creates a user with
`is_verified=False` and issues a Redis-cached verification token (intended
to be emailed, though no actual email-delivery infrastructure exists in
this codebase yet -- `AuthService.resend_verification`/`verify_email`
already document this same gap). `UserService.create_user` instead creates
admin-provisioned accounts with `is_active=True, is_verified=True`
immediately. Reasoning:

* There is no verification-email-delivery infrastructure in this codebase
  today. Creating an admin-provisioned account as unverified would leave
  it permanently unable to log in (`AuthService.login` raises
  `EmailNotVerifiedError` for `is_verified=False`) with no way to complete
  verification, since nothing sends the email.
* An administrator directly creating an account (setting a temporary
  password, presumably after some out-of-band identity check of their own)
  is a materially stronger identity assertion than an anonymous
  self-service signup -- mirroring common enterprise "admin-provisioned"/
  SSO-invited-user conventions, where the account is usable immediately
  because the administrator already vouched for it.
* The `temporary_password` field name and its schema description
  ("the user should change it on first login") document the expectation
  that the admin-set password is provisional, without this module
  reimplementing a forced-password-change-on-next-login flow (which would
  require new state on `auth.User` this module deliberately avoided adding
  -- see §2 -- and is judged out of scope for this aggregation layer).

## 10. Initial role assignment at creation time: convenience only, `ORGANIZATION` scope only

`POST /api/v1/users` accepts an optional `initial_role_id`, requiring
`organization_id` to also be set (`InitialRoleRequiresOrganizationError`,
400, otherwise). When both are present, `UserService.create_user` calls
`RBACService.assign_role_to_user(..., scope_type=ScopeType.ORGANIZATION,
organization_id=organization_id)` directly -- reusing RBAC's own
escalation checks (`RoleEscalationError`), scope validation
(`InvalidScopeAssignmentError`), and `ROLE_ASSIGNED` audit entry verbatim.

This is deliberately narrow: only an `ORGANIZATION`-scoped assignment
against the same organization the user was just added to is supported as a
creation-time convenience. A `GLOBAL`/`LOCATION`/`ROUTER`-scoped initial
role, or a role assignment made without also creating a membership, is
**not** supported here -- the caller should use RBAC's own
`POST /api/v1/users/{id}/roles` endpoint afterward for anything beyond the
single common case this convenience covers. This module never
re-implements RBAC's role-assignment/removal endpoints (`POST`/`DELETE
/users/{id}/roles`, `GET /users/{id}/permissions`, `GET /me/permissions`)
-- all continue to be owned exclusively by
`app/domains/rbac/router.py`.

## 11. The aggregated user-detail view is read-composition, not a model

`UserService.UserAggregate` (`user: User`, `memberships:
list[OrganizationMembershipView]`, `roles: list[Role]`) and
`OrganizationMembershipView` (an `OrganizationMember` paired with its
organization's display name) are plain `@dataclass(frozen=True, slots=True)`
value objects assembled fresh on every call to `get_user_detail`/`get_me` --
never persisted, never cached beyond the request. Roles are resolved via
`RoleResolver.get_active_roles(user_id)` (RBAC's own existing role-lookup
logic, unmodified) rather than a raw query against `user_roles`, so this
domain never re-derives "is this assignment active and non-expired" itself.
Memberships are resolved via `OrganizationService.list_user_organizations`
plus one `get_organization` call per membership (to embed
`organization_name` without a second client round trip) -- acceptable
for a single-user detail view; the list endpoint deliberately does **not**
do this per-row (see §6 -- listing only needs user ids to filter on, not
per-user membership details), avoiding an N+1 pattern at list scale.

## 12. What this module deliberately does not do

* No `UserProfile`/second `User` table, no new column -- see §2.
* No `repository.py`/`models.py` -- see §1.
* No re-implementation of RBAC's role-assignment/removal or
  permission-listing endpoints (`POST/DELETE /users/{id}/roles`,
  `GET /users/{id}/permissions`, `GET /me/permissions`) -- all remain
  RBAC's alone; this module only *reads* active roles for the aggregated
  view and *optionally* assigns exactly one initial role at creation time
  through RBAC's own service method.
* No modification of `app.domains.organization`/`app.domains.location`
  internals -- only their existing public service methods are composed.
* No modification of `app.domains.auth`'s login/register/token/session
  logic -- only one additive repository method
  (`AuthRepositoryProtocol.list_users`) was added.
* No hard delete of users from the API -- deactivation flips `is_active`/
  `status`; `auth.models.User`'s own soft-delete columns
  (`is_deleted`/`deleted_at`, inherited from `BaseModel`) are never touched
  by this module, since outright account deletion is a materially more
  consequential, still out-of-scope operation.
* No forced-password-change-on-first-login mechanism -- see §9.
* No email-delivery integration for admin-created accounts -- see §9 (the
  same known gap `AuthService.register`'s own verification-email flow
  already has).
