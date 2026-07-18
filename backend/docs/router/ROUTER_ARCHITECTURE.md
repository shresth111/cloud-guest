# Router Architecture

This document records every design decision Module 008 made where the
brief left room for judgment. Read this before modifying
`app/domains/router/` or the targeted RBAC seam it touches (the `router_id`
FK follow-up).

## 1. Where Router sits in the hierarchy, and the `organization_id` denormalization

CloudGuest's modeled hierarchy is Organization -> Location -> Router ->
Guest. A `Router` is a physical/virtual MikroTik RouterOS device deployed at
**exactly one** location (`location_id`, real FK, `NOT NULL`, `ON DELETE
CASCADE`).

**Decision: `Router` also carries `organization_id` directly** (real FK,
`NOT NULL`, `ON DELETE CASCADE`), denormalized from `location.organization_id`
at creation time, rather than being derived solely via a join through
`locations` on every query.

Location itself faced an analogous question one level up ("does a child
need its own copy of the parent's tenant id") and answered it by *not*
denormalizing anything from Organization onto Location beyond the direct
FK it already needs (`organization_id` -- Location's *direct* parent, not a
grandparent). Router's situation is different in kind: Router's direct
parent is Location, and Organization is a *grandparent* two hops up. Two
things tipped the decision toward denormalizing here rather than following
Location's letter (if not its spirit):

* **Precedent already exists in this exact shape.** RBAC's own scope
  columns (`UserRole`, `PermissionOverride`) already carry *both*
  `organization_id` and `location_id` on the same row, not just the
  narrowest one with the other derived via a join -- multi-level tenant
  scope columns living side by side on one row is already this codebase's
  established pattern, not a new one being introduced here.
* **Direct tenant-scoped queries without a join.** Routers are the entity a
  network-operations dashboard/device-list view queries most heavily,
  typically scoped by organization directly (e.g. "all routers this MSP's
  child organizations own," "all routers in org X regardless of which
  location"). Requiring a join through `locations` for every such query
  (and, transitively, in `RouterService._enforce_organization_scope`, which
  runs on every read/write resolved by router id) would be strictly more
  expensive for no benefit, given the value can never drift (see below).

**Both `location_id` and `organization_id` are immutable after creation**,
mirroring `Location.organization_id`'s own immutability decision (see
`docs/location/LOCATION_ARCHITECTURE.md` §5) for the identical reason: a
router "moving" to a different location/organization is not a real-world
operation an update endpoint should pretend to support cheaply. If a
physical device is genuinely redeployed to a different site, the correct
operation is to decommission the old `Router` row and register a fresh one
at the new location, with RBAC role assignments/provisioning credentials
deliberately re-created rather than silently carried over.
`RouterUpdateRequest` simply never exposes `location_id`/`organization_id`;
`RouterService.update_router` defensively strips both keys from its input
`dict` regardless (belt-and-suspenders against a future caller constructing
the payload by hand), mirroring `LocationService.update_location`'s own
convention. Because the value is fixed at creation and never re-derived,
there is no "the denormalized copy might drift from the source of truth"
failure mode to defend against later.

## 2. `RouterStatus`: state machine and transition graph

`RouterStatus` (`app/domains/router/enums.py`) is **not** a copy of
`OrganizationStatus`/`LocationStatus` (`active`/`suspended`/`archived`) -- a
physical device has a materially different lifecycle: it must be
provisioned before it is ever "active," and its online/offline state is a
connectivity signal, not an administrative toggle.

```text
PENDING_PROVISIONING --(device presents provisioning token)--> PROVISIONING
PENDING_PROVISIONING --(admin cancels before device ever connects)--> DECOMMISSIONED

PROVISIONING --(first heartbeat after initial config succeeds)--> ONLINE
PROVISIONING --(admin cancels a stuck/failed provisioning)--> DECOMMISSIONED

ONLINE --(missed heartbeat)--> OFFLINE
ONLINE --(admin suspends)--> SUSPENDED
ONLINE --(admin decommissions)--> DECOMMISSIONED

OFFLINE --(heartbeat resumes)--> ONLINE
OFFLINE --(admin suspends)--> SUSPENDED
OFFLINE --(admin decommissions)--> DECOMMISSIONED

SUSPENDED --(admin reinstates)--> OFFLINE   [not ONLINE -- see below]
SUSPENDED --(admin decommissions)--> DECOMMISSIONED

DECOMMISSIONED --(terminal, no outgoing edges at all, not even to itself)
```

The exhaustive graph lives in exactly one place,
`ROUTER_STATUS_TRANSITIONS` (`app/domains/router/enums.py`), and every
status-changing service method (`_set_status`, `decommission_router`,
`heartbeat`) consults it via `RouterService._validate_transition` before
writing a new status -- there is no second, ad hoc place a status change is
permitted. `_validate_transition` deliberately has **no** "same status is a
no-op" shortcut: calling decommission on an already-`DECOMMISSIONED` router
raises `InvalidRouterStatusTransitionError` (that state has no outgoing
edges, including to itself), the same for suspending an already-`SUSPENDED`
router. This was caught by a test written against the intended behavior
(`test_decommission_from_decommissioned_raises`) during development -- an
earlier draft of `_validate_transition` had exactly this shortcut and
silently allowed it, which the test suite caught immediately.

Two edges deserve specific justification:

* **`PROVISIONING -> ONLINE` is a direct, explicit edge, not "any heartbeat
  moves it forward."** The only way to reach `ONLINE` from `PROVISIONING`
  is a heartbeat call (see §5's "no separate complete-provisioning endpoint"
  discussion) -- there is no automatic timer or background process in this
  module that promotes a provisioning router to online on its own.
* **`SUSPENDED -> (reinstate)` lands on `OFFLINE`, not `ONLINE`.** This is
  the one asymmetry in the graph relative to what might seem intuitive
  ("un-suspend restores whatever it was before"). The reasoning: only a
  heartbeat/check-in may ever assert "currently reachable" -- an
  administrative `reinstate` action is a statement of *permission* ("this
  router is allowed to operate again"), not a statement of *fact*
  ("this router is definitely online right now"). Whether the device is
  actually reachable again is something only the device itself can report,
  via the next heartbeat. Landing on `OFFLINE` keeps that distinction
  honest instead of optimistically asserting connectivity the platform
  hasn't actually observed.

There is **no separate "complete-provisioning" endpoint** in this module's
API surface, even though the original module brief's endpoint sketch did
not list one either (its own point 5 lists `check-in` and `heartbeat` as the
only two provisioning-adjacent endpoints, with heartbeat's relationship to
check-in explicitly left as "your call, document it" -- this is that
documentation). The resolution: `RouterService.heartbeat`, called while a
router is `PROVISIONING`, *is* the completion signal -- the first heartbeat
after initial device configuration both confirms reachability and completes
provisioning in one call (`PROVISIONING -> ONLINE`). This was chosen over
inventing an unlisted tenth endpoint because it cleanly reuses the exact
liveness-reporting mechanism that exists anyway for ongoing operation,
rather than adding a redundant "I'm done configuring" signal distinct from
"I'm alive" -- for a router that just finished its very first configuration
pass, those two facts are the same fact.

## 3. Credential encryption: interim design and key-management boundary

Router API credentials (a RouterOS API username plus a password or API key)
must be **decryptable**, not just verifiable -- unlike a user's login
password (one-way Argon2id, `app.domains.auth.password.PasswordManager`),
this platform must open a live RouterOS API connection to the physical
device, which requires the plaintext secret back out again.

**Decision: `cryptography`'s `Fernet`** (AES-128-CBC + HMAC-SHA256,
authenticated symmetric encryption), added as a genuinely new dependency
(`requirements.txt`/`pyproject.toml`) -- no encryption utility of any kind
existed in this codebase before this module, only one-way hashing.
`app.domains.router.crypto.encrypt_secret`/`decrypt_secret` wrap a single
application-level key read from `Settings.router_encryption_key`
(`app/core/config.py`, following `jwt_secret_key`'s exact pattern: a
`min_length`-validated field with an insecure-but-functional local-dev
default, documented as required-override-in-production). `Router.api_username`
is stored in the clear (a connection identifier, not a secret by itself --
the same posture this codebase already takes for e.g.
`Organization.contact_email`); the password/API key is Fernet-encrypted
before ever reaching `Router.api_credentials_encrypted` (a `Text` column
holding the opaque, urlsafe-base64 ciphertext). No response schema
(`RouterResponse`) ever echoes either the ciphertext or a decrypted secret
back to a caller -- only a `has_api_credentials: bool` flag.

**This is explicitly an interim design**, not a claim that it is
production-grade secrets management:

* The key lives in application configuration (an env var in every real
  deployment), not a dedicated key-management service. There is no key
  rotation, no per-tenant/per-router data-key envelope encryption, no access
  auditing of who decrypted what and when.
* Rotating `router_encryption_key` today is a manual, single-key,
  single-environment operation (re-encrypt every existing row under the new
  key) -- nothing in this module automates that.
* A production hardening pass should replace `crypto.py`'s implementation
  with a real KMS integration (AWS KMS, HashiCorp Vault, GCP Secret
  Manager, etc.), most likely issuing per-router or per-tenant data keys
  rather than one global application secret. The `encrypt_secret`/
  `decrypt_secret` function boundary in `crypto.py` is deliberately the only
  place `RouterService` touches this concern, so that swap should not
  require touching `service.py`, `models.py`, or the API layer at all.

This mirrors the same honest-boundary posture this codebase already takes
elsewhere for deliberately deferred infrastructure (e.g. Organization's
`subscription_tier` being a label only, with real billing logic explicitly
out of scope pending a future Billing domain).

## 4. Health signal: minimal, not a metrics system

`Router.health_status` (nullable `String`, `RouterHealthStatus` enum:
`healthy`/`unhealthy`) and `last_health_check_at` exist to answer exactly
one question for the device-list view: "is this router currently
reachable" -- not to build a metrics/telemetry/alerting system. That is the
separate, already-seeded `Monitoring`/`Alerts` permission modules' job, a
future domain this module deliberately does not anticipate the shape of.
`health_status` is `None` until the first health check ever runs
("unknown" is not itself a stored enum value -- absence of a value already
expresses it, so there is no third enum member to keep in sync with "has
this router ever reported in"). In this module, `RouterService.heartbeat`
is the only code path that ever sets `health_status`/`last_health_check_at`
(always to `"healthy"`/now on a successful heartbeat) -- there is no
separate active health-probing mechanism (e.g. the platform proactively
pinging the device's RouterOS API) built here; that would be exactly the
kind of "full monitoring/alerting system" the brief called out as
out-of-scope for this module.

## 5. Zero-touch provisioning: token design, flow, and the device-auth scheme

**Token storage.** `RouterProvisioningToken.token_hash` stores a **SHA-256
hex digest** of the plaintext bearer token
(`secrets.token_urlsafe(32)`, 256 bits of entropy), not an Argon2id hash.
This is a deliberate departure from `PasswordManager`'s hashing choice, for
a specific reason: Argon2id's slow, memory-hard design exists to defend
*low-entropy, human-chosen* secrets (a person's password) against offline
brute-force guessing. A 256-bit randomly-generated token has no such
weakness to defend against -- guessing it is infeasible regardless of hash
speed -- so a fast cryptographic hash (SHA-256) is the correct, standard
choice for this kind of credential (the same reasoning real-world API-key
systems generally use), and avoids paying Argon2id's deliberate CPU/memory
cost on every device check-in for no security benefit. The plaintext token
is generated once (`RouterService.generate_provisioning_token`), returned
in the API response exactly once, and never persisted or retrievable
again -- the same "shown once" UX convention this codebase already uses
conceptually for e.g. a temporary password.

**Token generation is approval-gated.** `router_provisioning` is the only
permission module in the entire seeded set (`app/domains/rbac/seed.py`)
that includes an `approve` action alongside `create` -- `routers` itself
has no `approve` action at all. That asymmetry is a strong, deliberate
signal in the existing seed data that `approve` exists specifically to gate
*this* action: issuing a bearer credential that lets a physical device join
the network is treated as security-sensitive enough to warrant a
"someone approved this" step distinct from ordinary create permission.
`POST /routers/{id}/provisioning-token` therefore requires **both**
`router_provisioning.create` and `router_provisioning.approve` (two
`RequirePermission` dependencies on the same route). A token may only be
generated while the router is `PENDING_PROVISIONING`
(`ProvisioningTokenGenerationNotAllowedError` otherwise) -- generating a
provisioning credential for a router that has already provisioned or gone
online makes no sense.

**The check-in/heartbeat endpoint split**, and why check-in is not a normal
authenticated-user endpoint:

* `POST /routers/provisioning/check-in` -- presented by the **physical
  device**, which has no platform user identity, no JWT, no concept of
  `X-Organization-Id`/`X-Location-Id` scope headers. Its only credential is
  the provisioning token itself, submitted in the request body
  (`ProvisioningCheckInRequest.token`). This route carries no
  `RequirePermission`/`CurrentUser` dependency at all -- auth is entirely
  `RouterService.check_in`'s job: hash the presented token, look it up,
  reject if unknown/expired/already-used
  (`ProvisioningTokenNotFoundError`/`ProvisioningTokenExpiredError`/
  `ProvisioningTokenAlreadyUsedError`), reject if the router it belongs to
  isn't `PENDING_PROVISIONING` anymore
  (`ProvisioningTokenRouterStateError` -- looked up with
  `include_deleted=True` deliberately, so a decommissioned router's stale
  token gives this specific, informative error rather than a misleading
  `RouterNotFoundError`), then mark the token used and transition
  `PENDING_PROVISIONING -> PROVISIONING`. Its response is a deliberately
  minimal, non-`ApiResponse`-envelope shape
  (`ProvisioningCheckInResponse`, just `router_id`/`status`) -- documented
  here as the one endpoint in this codebase that departs from the standard
  envelope, since the calling device is not expected to parse a rich,
  user-facing API contract.
* A bespoke bearer-header auth scheme (e.g. `Authorization: Bearer
  <provisioning-token>`) was considered and rejected in favor of a
  token-in-body request: this keeps the device's one and only interaction
  with the platform's auth surface fully self-contained in
  `RouterService.check_in`/a single Pydantic request schema, rather than
  requiring a new header-parsing branch in shared middleware/dependency code
  that every other (JWT-based) endpoint would need to keep not colliding
  with. It also avoids ever needing to explain "there are now two different
  kinds of Bearer token accepted by this API" in the same header.
* `POST /routers/{id}/heartbeat` -- **not** device-token-authenticated.
  Sized to the honest constraint that designing an ongoing (post-
  provisioning) device-identity/token-issuance-and-rotation system was
  explicitly out of this module's scope (the brief's own endpoint list
  and RBAC's seeded permissions have no such concept), and building one
  prematurely would be speculative scope creep the brief's discipline
  section warns against. Instead, heartbeat is an ordinary
  `RequirePermission("routers.manage")`-gated platform endpoint,
  representing a monitoring relay/agent or administrator confirming
  liveness on the router's behalf -- consistent with this module's stated
  boundary that a *real* monitoring/telemetry integration is a separate,
  already-seeded future domain (`Monitoring`/`Alerts`). If/when a real
  device-originated heartbeat channel is built, it should very likely reuse
  the same hash-compare-token pattern `check_in` already establishes here
  (e.g. a longer-lived, renewable device token distinct from the single-use
  provisioning token), rather than inventing a third auth scheme.
* Heartbeats are **never audited** (`AuditAction` gained no
  `ROUTER_HEARTBEAT_RECORDED` value) -- they are frequent device telemetry,
  not an admin-driven event, and logging every one to `audit_log_entries`
  would flood a table meant for accountable, human-attributable actions.
  Each heartbeat is still recorded via `logger.info("router_heartbeat", ...)`
  for operational visibility.

## 6. Audit logging

Reuses RBAC's existing `audit_log_entries` table via the same narrow,
duck-typed `AuditLogWriter` protocol shape `OrganizationService`/
`LocationService`/`UserService` all use -- no new audit mechanism.
`AuditAction` gained seven new, additive `router_*` values
(`app/domains/rbac/enums.py`): `router_created`, `router_updated`,
`router_decommissioned`, `router_suspended`, `router_reinstated`,
`router_provisioning_token_generated`, `router_provisioned`. The check-in
flow's audit entry (`router_provisioned`) is written with
`actor_user_id=None` -- the device that checked in has no platform user
identity to attribute the action to (see §5); this is not a bug, it
correctly reflects that this specific event was not performed by any
authenticated platform user. As noted in §5, heartbeats are deliberately
excluded from this list.

## 7. No `RouterRole` table -- no gap was found

The brief asked to confirm RBAC has no dedicated router-level role-scoped
config table (there is only `OrganizationRole`/`LocationRole`) and to add
one only if a genuine gap were found. None was. `OrganizationRole`/
`LocationRole` exist to answer two questions at their respective scope:
"which (system or custom) roles are actually enabled/usable here" and
"what role does a brand-new member at this scope get by default." Neither
question has a meaningful router-level analogue that isn't already fully
answered by `LocationRole` one level up:

* There is no router-level "member" concept distinct from a location-level
  one that would need its own default-role assignment -- a person's
  relationship to network infrastructure at a given site is already fully
  expressed by `user_roles` scoped to `location_id` (or, narrower still, to
  a specific `router_id` via `ScopeType.ROUTER`, which RBAC already
  supports and this module uses unmodified for router-scoped `UserRole`/
  `PermissionOverride` rows).
  `LocationRole` already covers "which roles are enabled at this site" at
  the natural granularity administrators actually want to curate (per
  site, not per device within a site) -- adding a second, redundant
  curation table one level narrower, with no distinct question it would
  answer, would duplicate `LocationRole` for no new information captured,
  the same reasoning `docs/location/LOCATION_ARCHITECTURE.md` §3 gives for
  why no `LocationMember` table was added either.
* Nothing in this module's design surfaced a "per-router default role"
  need -- a router is a device record, not an entity people are "added to"
  the way they join an organization or get staffed at a location.

`ScopeType.ROUTER` and `router_id`-scoped `UserRole`/`PermissionOverride`
rows (now carrying a real FK, see §8) remain the only router-scoped RBAC
surface. This was an intentional scope decision made explicit in
`app/domains/rbac/models.py`'s module docstring, not an oversight -- revisit
only if a genuine per-router role-curation need is identified in a future
module (e.g. if a future Monitoring/Alerts domain needs router-level
role-based access distinct from what `user_roles` scoped to `router_id`
already expresses).

## 8. RBAC `router_id` FK follow-up

Per the module brief, `app/domains/rbac/models.py`'s `router_id` columns
now carry a real `ForeignKey("routers.id")`:

| Model | `ondelete` | Why |
|---|---|---|
| `UserRole.router_id` | `SET NULL` | A role assignment losing its router context is safer than being destroyed outright -- mirrors `UserRole.location_id`'s own `SET NULL` reasoning from migration `0006`. |
| `PermissionOverride.router_id` | `SET NULL` | Same reasoning as `UserRole`. |

`AuditLogEntry` carries **no** `router_id` column at all (only
`organization_id`/`location_id` -- confirmed by reading the model directly
before making any change, and asserted directly by
`tests/unit/test_router.py::TestRbacRouterFkFollowUp
::test_audit_log_entry_has_no_router_id_column`), so there was nothing to
add a constraint to there. There is no `RouterRole` table (see §7), so
unlike the two prior FK follow-ups (`0004` for `organization_id`, `0006`
for `location_id`), there is no analogous `CASCADE`-owning per-scope
config table to update alongside the `SET NULL` ones. `msp_id` remains
FK-less -- the MSP domain still does not exist, per the module brief's
explicit scope boundary; `Role`/`OrganizationRole`/`LocationRole` carry no
`router_id` column at all and were not touched; `PermissionScope` carries
no scope columns at all and was similarly left alone.

This was implemented as:

1. A targeted edit to `app/domains/rbac/models.py` (only the two
   `router_id` column definitions on `UserRole`/`PermissionOverride`
   gained a `ForeignKey`, plus the module docstring was updated to
   describe the new state and explain the no-`RouterRole`-table decision)
   -- no other RBAC logic, index, or column touched.
2. A new Alembic migration, `0008_add_router_fk_to_rbac_tables.py` (after
   `0007_create_router_tables.py`), that adds the constraints via
   `op.create_foreign_key`/`op.drop_constraint` -- a pure ALTER-TABLE
   follow-up, exactly mirroring `0004_add_organization_fk_to_rbac_tables.py`/
   `0006_add_location_fk_to_rbac_tables.py`'s shape.
3. `AuditAction` (RBAC's enum) gained seven new `router_*` values, used
   exclusively by `RouterService`, additive only -- no existing value was
   renamed or removed.
4. `tests/unit/test_location.py`'s own
   `TestRbacLocationFkFollowUp::test_router_id_columns_remain_fk_less` --
   which, at the time Module 006 landed, correctly asserted `router_id` was
   still FK-less, since the Router domain did not exist yet -- was updated
   in place (renamed to `test_router_id_columns_now_carry_fk_per_module_008`)
   to assert the new, current state, with a docstring explaining exactly
   why: this is the anticipated event that test's own original comment
   predicted ("A real FK constraint for `router_id` gets added in a
   follow-up migration once that domain lands, the same way
   `organization_id` and `location_id` just were"). This is the one
   pre-existing test this module touched, and it was a required update
   (not an optional cleanup) -- leaving it unmodified would mean the test
   suite asserts a fact this module's own explicit task makes false.

**Migration numbering note:** Module 007 (`app.domains.user`) added no
migration of its own -- it is a pure aggregation/composition layer over
`auth`/`organization`/`rbac` with no persisted model of its own. The next
available migration number after `0006_add_location_fk_to_rbac_tables` is
therefore `0007`, not `0008` -- this module's two migrations are
`0007_create_router_tables.py` and `0008_add_router_fk_to_rbac_tables.py`.

**Verification:** the full pre-existing `tests/unit/test_rbac.py` suite
passes unmodified after this change, plus
`tests/unit/test_router.py::TestRbacRouterFkFollowUp` directly asserts (at
the SQLAlchemy model/metadata level) that the two columns now declare a
`ForeignKey` targeting `routers.id`, that `AuditLogEntry` has no
`router_id` column, and that `msp_id` still carries no FK.

## 9. Serial number / MAC address handling

`serial_number` and `mac_address` are **globally** unique (hardware
identifiers assigned by the manufacturer, not scoped to a tenant -- unlike
`Location.slug`, which is deliberately unique only per organization). MAC
addresses are normalized to uppercase, colon-separated form
(`AA:BB:CC:DD:EE:FF`) both at the schema layer (`_validate_mac` in
`schemas.py`) and defensively again in the service layer
(`_normalize_mac`), the same defense-in-depth posture
`LocationService`/`OrganizationService` take for their own
slug/email/country normalization. Duplicate checks
(`DuplicateSerialNumberError`/`DuplicateMacAddressError`) run on both create
and update (excluding the router's own current row on update), consistent
with how `LocationService.update_location` excludes the current location
when re-checking slug uniqueness.

## 10. What this module deliberately does not do

* No Captive Portal/Guest WiFi/Guest Users/Guest Sessions/Radius/
  WireGuard/Firewall/DHCP/DNS/Hotspot/Bandwidth/Monitoring/Alerts domains --
  out of scope per the module brief; this module is the device record and
  its provisioning lifecycle only.
* No `RouterRole` table -- see §7.
* No real KMS/secrets-manager integration for credential encryption -- see
  §3's interim-design note.
* No hard delete of routers from the API -- `DELETE` always decommissions
  (`status=decommissioned` + `BaseModel` soft-delete), never removes the
  row.
* No `location_id`/`organization_id` reassignment after creation -- see §1.
* No active health-probing/metrics/alerting system -- see §4.
* No ongoing device-identity/token-issuance system for heartbeats beyond
  the single-use provisioning token -- see §5's heartbeat-auth discussion.
* No native PostgreSQL enum types for `status`/`health_status` -- plain
  `String` columns with Python `StrEnum`s, mirroring every other domain's
  documented convention, so a new value never requires an `ALTER TYPE`
  migration.
