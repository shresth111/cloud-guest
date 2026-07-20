# Policy -- Design Write-Up

This document covers every non-obvious design decision made while building
Policy, and the reasoning behind each -- see `README.md` for the folder/API
surface overview and `DATABASE.md` for the schema.

## 1. What "Policy" is, and why it is a leaf module

Policy is a single source of truth for per-organization/location-
configurable rules -- session limits, authentication rate limits, and,
structurally, bandwidth/FUP/business-hours/access/VLAN/QoS/routing policies
-- their assignment to a scope, and their versioning. It follows the design
already written and merged into this codebase in
`docs/ARCHITECTURE_DESIGN.md` §6.1/§13, authored by the same effort that
built `app.domains.guest_access` (a concurrently-developed module,
independently verified and reconciled with this session's own Guest Teams
work before either was pushed).

`policy` depends only on `app.domains.organization`/`app.domains.location`
(tenant/hierarchy lookups, via narrow Protocols) and `app.domains.rbac`
(audit logging, and reusing `ScopeType` for assignment scoping) -- both
foundational Identity & Access modules, not feature domains. It has **zero**
import of `app.domains.guest`/`app.domains.guest_access`/
`app.domains.voucher`/etc. Those modules would depend on `policy`, never the
reverse, so `policy` can never be part of an import cycle as more consumers
are added -- the single load-bearing architectural constraint this entire
module is built around.

## 2. Versioning: append-only, current-pointer-based rollback

`PolicyVersion` rows are immutable once created. Editing a policy's rules
never mutates an existing version -- `create_version` always inserts a new
`DRAFT` row. `Policy.current_version_id` is a single, explicit pointer at
whichever version is "live"; `publish_version` moves it forward,
`rollback` moves it back to any earlier *already-published* version.

Two alternatives were considered and rejected:

* **Delete every version after the rollback target.** This would destroy
  the append-only audit trail the architecture design calls for -- a
  `PolicyVersion` being append-only is what lets a past decision always be
  traced back to the exact version that produced it.
* **Duplicate the target version's `rules` into a brand-new version.** This
  would create two versions with identical `rules` and no way to tell, from
  the version history alone, that one was a rollback rather than an
  independent edit that happened to match the old value.

Re-pointing `current_version_id` is the simplest operation that is both
correct and fully traceable: `PolicyRolledBack`'s own event records both the
`from_version_id` and `to_version_id`, so the rollback itself is legible in
the event/audit log even though no new version row was created.

`rollback` only accepts a target that is itself already `PUBLISHED` (never a
`DRAFT`) -- rolling back to an unreviewed draft would silently activate
rules nobody ever published, and only accepts a target that actually
belongs to the policy being rolled back (`PolicyRollbackTargetMismatchError`
otherwise) -- both real, tested rejections
(`test_rollback_to_unpublished_version_raises`,
`test_rollback_to_version_of_another_policy_raises`).

## 3. Rules validation: a real per-`PolicyType` schema registry

`schemas.POLICY_RULE_SCHEMAS` maps every `PolicyType` to a Pydantic model.
`validators.validate_rules` validates (and normalizes) every
`create_version` call's `rules` payload against it before persisting,
raising `PolicyRulesValidationError` on any shape mismatch. Only `SESSION`
(`SessionPolicyRules`) and `AUTHN` (`AuthNPolicyRules`) have a concrete
schema, because this module's own gap analysis (see `README.md`'s table)
found real, already-hardcoded platform constants for exactly those two
types. Every other type (`BANDWIDTH`/`FUP`/`BUSINESS_HOURS`/`ACCESS`/`VLAN`/
`QOS`/`ROUTING`) maps to `GenericPolicyRules` -- accepts any JSON object,
no further shape validation -- honestly reflecting that no existing
hardcoded constant in this codebase justifies a specific schema for those
types yet. This mirrors the same "real check without a fake opinion"
discipline this codebase already applies elsewhere (e.g. Celery health's
`UNKNOWN` status before a worker was ever wired in) -- a `Policy`/
`PolicyVersion` of any of the generic types is fully functional (can be
created, versioned, published, assigned, resolved) today; it simply has no
seeded default and no stronger validation than "is this JSON" until a real
consumer's own constants justify one.

## 4. Resolution: scope specificity, then priority, then platform default

`PolicyResolver.resolve` is pure (no I/O) -- it takes an already-fetched
list of candidate `PolicyAssignment` rows and picks the winner by
`(scope_specificity, priority)`, both descending:

* **Scope specificity**: `LOCATION` (2) > `ORGANIZATION` (1) > `GLOBAL` (0).
  Mirrors `app.domains.rbac.enums.SCOPE_HIERARCHY_ORDER`'s identical
  broad-to-narrow ordering, just resolved narrow-first instead of
  broad-first (`rbac`'s own ordering answers "which scope authorizes a
  broader action"; this module's ordering answers "which scope's policy is
  more specific and should win").
* **Priority**: a plain tie-breaker for two assignments at the *same* scope
  (e.g. two different organization-level assignments of different
  policies for the same `policy_type` -- an edge case the schema permits
  since there is no uniqueness constraint on
  `(policy_id, scope_type, scope_id)`, see `DATABASE.md`).

`PolicyService.resolve_effective_policy` does the actual repository fetch
(`PolicyRepository.list_candidate_assignments` -- a single query joining
`policy_assignments` to `policies`, filtering for `is_active`, an active
policy of the requested type, and a scope match against `global`/this
organization/this location) and hands the results to the resolver. If no
assignment matches at all, it falls back to
`constants.PLATFORM_DEFAULT_RULES` -- the safety net that lets every
organization get a sane, real answer to "what session policy applies to me"
even before anyone has ever configured one, mirroring
`app.domains.guest.constants.DEFAULT_SESSION_TIMEOUT_MINUTES`'s own
previous role as *the* answer before this module existed. `ResolvedPolicy
.source` always says which tier won (`"location:<id>"`,
`"organization:<id>"`, `"global:<policy_id>"`, or the literal
`"platform_default"`), so a caller can always tell *why* a given rule set
was returned, not just what it is.

## 5. Assignment scope validation

`PolicyAssignment.scope_type` reuses `app.domains.rbac.enums.ScopeType`
directly (validated via `ScopeType(scope_type)`, raising
`InvalidPolicyAssignmentScopeTypeError` on an unrecognized string) rather
than inventing a parallel enum -- `rbac` is a foundational module `policy`
is already allowed to depend on (see §1), and "global/organization/location"
is exactly the same three-tier scope shape `rbac`'s own role assignments
already model. `scope_id` must be `NULL` for `global` and non-`NULL` for
every other scope type (`PolicyAssignmentScopeIdNotAllowedError`/
`PolicyAssignmentScopeIdRequiredError`) -- see `DATABASE.md` for why
`scope_id` cannot be a real, single-table foreign key.

A policy may only be assigned once it has at least one `PUBLISHED` version
(`PolicyAssignmentRequiresPublishedVersionError` otherwise) -- an
unpublished policy has no rules a resolver could honestly return.

## 6. RBAC permission-module decision: new, additive `POLICY`

`docs/ARCHITECTURE_DESIGN.md` §2/§14 already named `policy` as one of the
modules needing a new, additive `PermissionModule` value (alongside
`guest_access`/`identity`/`guest_teams`/etc.) rather than reusing an
existing one -- confirmed correct by this module's own review: Policy
governs a genuinely distinct administrative concern (defining/versioning/
assigning session-timeout, rate-limit, and (eventually) network-policy
rules) with no existing module whose action vocabulary would honestly cover
it.

**What was added** (see `app/domains/rbac/enums.py`/`seed.py`):

* `PermissionModule.POLICY = "policy"` (additive enum value).
* `MODULE_ACTIONS[POLICY] = (CREATE, READ, UPDATE, DELETE, EXECUTE,
  MANAGE)` -- `DELETE` is reserved (not currently wired to any endpoint,
  mirroring `GUEST_USERS`'s/`GUEST_TEAMS`'s own unused reserved actions) for
  a possible future hard-delete-a-policy admin action; `EXECUTE` is what
  `router.py` actually gates deactivate/publish/rollback/
  assignment-deactivation behind (lifecycle, punitive-shaped actions,
  mirroring `GUEST_SESSIONS`'s/`GUEST_TEAMS`'s own `.execute` choice for
  disconnect/terminate/revoke); `UPDATE` gates creating a new draft version
  (an edit to the policy's own configuration, not a lifecycle transition).
* `MODULE_DISPLAY_NAMES[POLICY] = "Policy"`.
* `MODULE_NARROWEST_SCOPE[POLICY] = ScopeType.LOCATION` -- same as
  `GUEST_USERS`/`GUEST_SESSIONS`/`GUEST_TEAMS` (a policy assignment may be
  global/org-wide/location-specific; `LOCATION` is the narrowest meaningful
  scope, and broader scopes remain allowed per
  `allowed_scope_types_for_module`'s existing "narrowest and everything
  broader" rule).
* `SYSTEM_ROLES` overrides added for exactly three roles whose existing
  profile plausibly covers policy configuration:
  * **Network Administrator** (`OPERATE`) -- Policy covers `BANDWIDTH`/
    `VLAN`/`QOS`/`ROUTING` rule types, squarely this role's own domain
    (it already holds `BANDWIDTH: FULL`).
  * **Location Manager** (`OPERATE`) -- day-to-day session/authN policy at
    their own location is a plausible extension of a role that already
    operates `GUEST_TEAMS`/`GUEST_SESSIONS`/`GUEST_ACCESS`.
  * **Helpdesk** (`READ`) -- first-line support can see what policy applies
    when diagnosing a guest issue, mirroring its own `GUEST_TEAMS: READ`/
    `GUEST_USERS: READ` choices, but cannot mutate it.

  Every role whose *default* grant level already covers every module
  automatically (`Super Admin`/`Platform Admin`: `FULL`; `MSP Owner`/`MSP
  Admin`: `OPERATE`; `Organization Owner`: `FULL`; `Organization Admin`:
  `OPERATE`; `Platform Support`/`Read Only`/`Auditor`: `READ`) needed no
  explicit override. `Billing Manager`, `Reception Staff`, `Guest Operator`
  intentionally received **no** override -- none has a plausible need to
  configure session-timeout/rate-limit/network policy, mirroring their own
  existing `NONE`-by-default restraint for comparably administrative
  modules.

No `docs/rbac/PERMISSION_MATRIX.md` regeneration was performed as part of
this change -- that file is regenerated by a manual command outside this
feature's directory-rule boundary, exactly as every other domain's own
additive RBAC change has left it.

## 7. Route ordering: `/policies/resolve` before `/policies/{policy_id}`

FastAPI/Starlette match routes in registration order. `GET /policies/resolve`
is registered before `GET /policies/{policy_id}` in `router.py` -- if the
`{policy_id}` route were registered first, a request for `/policies/resolve`
would be captured by it instead (and fail `uuid.UUID` path-parameter
parsing) rather than ever reaching the resolve handler. This ordering is
load-bearing, not cosmetic, and is called out explicitly in `router.py`'s
own module docstring.

## 8. Platform-wide policies: readable by everyone, mutable only by a
## platform-level caller

`Policy.organization_id` is nullable: `NULL` means a platform-wide policy
definition, available as a resolution candidate to every organization
(mirrors `notification_templates.organization_id`'s identical "nullable FK
signals platform default" convention already named in
`docs/ARCHITECTURE_DESIGN.md` §15). Any caller (including one scoped to a
specific organization) may **read** a platform-wide policy --
`_enforce_read_scope` only rejects cross-organization access when the
policy's own `organization_id` is non-`NULL` and differs from the
requester's. Only a platform-level caller (one with no
`requesting_organization_id` at all, mirroring `ScopeType.GLOBAL`) may
**create** a platform-wide policy -- an organization-scoped caller
attempting to pass `organization_id=None` is rejected with
`CrossOrganizationPolicyAccessError`
(`test_org_caller_cannot_create_platform_wide_policy`).

## 9. Gap analysis: what has a seeded default, and what does not

This module's default ruleset (`constants.PLATFORM_DEFAULT_RULES`) mirrors
real, already-hardcoded platform constants found by grepping
`app.domains.guest.constants` and `app.domains.voucher.constants` for
genuine per-organization-configurability candidates -- see `README.md`'s own
table for the exact mapping. `app.domains.guest.constants
.DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST`'s own docstring already named
"the Policy Engine's job" as this constant's intended successor before this
module was ever built, which is the strongest possible confirmation this gap
analysis targeted the right candidates.

`app.domains.otp`'s `Settings.otp_expiry_seconds` was considered and
excluded: it lives in `app.core.config.Settings` (deployment/environment
configuration), not a domain-local business-rule constant like the four
`guest`/two `voucher` constants above, and this module's own scope is
per-organization *business policy*, not infrastructure configuration.
`app.domains.guest_access`'s `ACCESS_RULE_TYPE_PRECEDENCE` (VIP > TEMPORARY
> BLOCKLIST > WHITELIST > default-allow) was also considered: it is
ordering logic, not a tunable quantity, and
`docs/ARCHITECTURE_DESIGN.md` §5.2 itself already earmarks this as future
work ("`policy` (Phase 2) can subsume precedence ordering as a configured
`AccessPolicy`") rather than something this module's initial build should
force into a JSONB rule shape prematurely.

## 10. What this module does not do yet

No consumer (`guest`, `guest_access`, `voucher`) has been rewired to
actually call `PolicyService.resolve_effective_policy` in place of its own
hardcoded constant. `docs/ARCHITECTURE_DESIGN.md` §13 itself anticipates
this staging: "Until Phase 2 ships, Phase 1 modules (`guest`, `guest_teams`)
use their nullable FK/local default and simply have no policy source to
resolve -- no blocking dependency, no stub module needed." This build *is*
Phase 2 shipping -- the leaf itself, real and fully functional end to end
(create, version, publish, assign, resolve, roll back) -- but rewiring an
existing domain's own enforcement path to read from it is a separate,
later change, deliberately out of this module's own directory boundary (its
own build instructions authorized building `app/domains/policy/` plus
targeted, additive edits to `app/api/v1/router.py` and RBAC -- not rewriting
`guest`/`guest_access`/`voucher`'s internals). This is an honest scope
boundary: every piece inside `app.domains.policy` itself is real, not a
placeholder.
