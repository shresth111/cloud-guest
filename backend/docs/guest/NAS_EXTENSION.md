# NAS Extension -- Design Write-Up

This document covers the extension of `RadiusNasClient` (originally a bare
`router_id`/`nas_identifier`/`shared_secret_encrypted`/`is_active` row from
BE-010 Part 4) into a real, managed NAS entity: a human-readable code,
denormalized tenant scope, a status lifecycle, and full admin CRUD/
lifecycle endpoints. See `README.md`/`DATABASE.md` for the folder/API
surface overview and schema, and `FLOW.md` for the original RADIUS
`rlm_rest` integration this extension builds on top of.

## Why an extension, not a new module

A module brief for this work assumed a fresh "NAS module" atop an
"Industry" module and a Router module with no NAS concept yet -- neither
matches this actual repository: this codebase has no `industry` domain, and
`RadiusNasClient` already existed, fully wired into a real FreeRADIUS
`rlm_rest` integration (`authenticate_nas`/`authorize`/`accounting_*`).
Building a second, parallel NAS entity would duplicate that real,
already-tested integration rather than extend it. Every change here lives
inside `app.domains.guest` (where `RadiusNasClient` already lived), composes
`RadiusService`'s own existing methods, and touches no other domain's
internals beyond additive RBAC/router registration.

## 1. `nas_code`: human-readable, real-data-derived, not backfilled

The brief's own examples (`NAS-HOTEL001-0001`) assumed a short per-site
mnemonic (`"HOTEL001"`) that does not exist in this codebase.
`Location.location_code` (from Smart Location Provisioning) is the real,
closest equivalent -- but it is itself shaped `"LOC-2026-000001"`, not a
short site code. `nas_number_generator.generate_nas_code` embeds this real
value verbatim (`"NAS-LOC-2026-000001-0001"`) rather than inventing a second,
fictional short-code concept with no real data behind it -- see that
module's own docstring for the full reasoning, including the
`location_id`-prefix fallback for locations with no `location_code` (that
column is nullable -- only locations provisioned through Smart Location
Provisioning have one).

The sequence is real and atomic: `RadiusNasCodeCounter`
(`radius_nas_code_counters` table) mirrors `LocationCodeCounter` exactly --
a single atomic `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` per
`counter_key` (here, `"nas:<location_id>"` -- one counter per location, so
the sequence numbers the Nth NAS at *that* location, matching the brief's
own "resets per site" examples).

`nas_code` is **nullable** on the model, and pre-existing rows (registered
before this extension) are never retroactively backfilled with a generated
value -- mirrors `Location.location_code`'s own identical migration
decision (see migration `0026`), for the identical reason: a real sequence
number cannot be honestly invented after the fact without risking gaps or
collisions with rows generated going forward.

## 2. Shared secret: real auto-generation, shown once

Before this extension, `register_nas` required the caller to supply a
plaintext secret. This extension makes it optional:
`nas_number_generator.generate_shared_secret` produces a real,
cryptographically-random (`secrets.token_urlsafe`, the OS CSPRNG) string
when none is supplied. Either way, the plaintext is returned to the caller
exactly once, via `RadiusNasRegistrationResult.shared_secret`/
`RadiusNasSecretRegenerationResult.shared_secret` -- the standard
"show a secret once at issuance, never again" posture any real secret/
API-key system needs, since the stored value is Fernet-encrypted
(`encrypt_secret`, reused from `app.domains.router.crypto`, unchanged from
before this extension) and never logged or persisted in plaintext.

`POST /radius/nas/{id}/regenerate-secret` invalidates the old secret
immediately and returns the new one the same way -- it does not require or
change the NAS's own `status`, since rotating a compromised secret on a
currently-disabled NAS is a legitimate, independent action.

## 3. Status lifecycle: real graph, `ACTIVE`-by-default registration

`constants.NasStatus` (`PENDING`/`ACTIVE`/`DISABLED`/`SUSPENDED`/`DELETED`)
replaces the previous bare `is_active` boolean's limited semantics, with an
explicit, exhaustive transition graph
(`constants.NAS_STATUS_TRANSITIONS`) mirroring
`GUEST_SESSION_STATUS_TRANSITIONS`'s/`VOUCHER_BATCH_STATUS_TRANSITIONS`'s
identical "terminal states have no outgoing edges, not even to themselves"
discipline. `is_active` is kept (never dropped -- no destructive migration
changes an existing column) as a derived, synced mirror of
`status == ACTIVE`, updated by every status-mutating method alongside
`status` itself, so any external reader still keyed on the original boolean
keeps working; `authenticate_nas` itself now checks `status`, the real
source of truth.

**Registration defaults to `ACTIVE`, not `PENDING`.** Unlike `Router`'s own
`PENDING_PROVISIONING` (a real multi-step hardware provisioning gate), a NAS
registration's only prerequisite -- correct credentials -- already exists at
the moment of registration; there is no genuine intermediate state to
default-stage behind. `PENDING` remains a real, valid, reachable status
(`register_nas(..., initial_status=NasStatus.PENDING)`) for a future caller
(e.g. an automated router-provisioning flow wanting to stage a NAS ahead of
its router finishing provisioning) -- this extension keeps the mechanism
real without forcing every caller through an artificial staging step that
serves no purpose for the caller that exists today (the admin registration
endpoint).

`SUSPENDED` is modeled as a real, validated status with its own legal
transitions (reachable from `ACTIVE`, exits back to `ACTIVE` or to
`DELETED`), for structural completeness, but this build exposes no
dedicated `POST .../suspend` endpoint -- only `activate`/`disable`/
`regenerate-secret` were named in this extension's own scope. This is an
honest scope boundary (the status value and its transitions are fully real
and tested), not a placeholder.

`DELETED` is terminal and is reached only through `delete_nas`, which sets
**both** `status=DELETED` **and** the row's ordinary `BaseModel` soft-delete
fields (`is_deleted`/`deleted_at`) -- so a deleted NAS disappears from every
normal listing the same way every other domain's soft-deleted rows already
do, and (consistent with `guest_teams`'/`policy`'s own identical
`get_by_id` convention) becomes unreachable via `get_nas_client` afterward,
not just status-flagged.

## 4. Denormalized `organization_id`/`location_id`

The original four-column table had neither -- every tenant check required a
join through `Router`. This extension denormalizes both from the resolved
`Router` at registration time, closing that gap and bringing this table in
line with `docs/ARCHITECTURE_DESIGN.md` §15's "denormalize onto every child
table at write time" convention every other domain's table already follows.
Migration `0030` backfills both for pre-existing rows via a single
deterministic `UPDATE ... FROM routers` join (unlike `nas_code`, this data
already exists and needs no generation, so a full backfill -- and `NOT
NULL` afterward -- is both possible and correct).

## 5. Vendor, not device_type

`vendor` (default `"MikroTik"`) is a real, true default -- every `Router` in
this codebase is a MikroTik RouterOS device today (see that model's own
docstring) -- and a genuine extensibility seam for whenever multi-vendor
support is added, not a fabricated placeholder. It is deliberately **not**
paired with a separate `device_type` column: `Router.model` (reachable via
`router_id`) already serves that exact purpose; duplicating it onto `NAS`
would create a second, driftable source of truth for the same fact.

## 6. RBAC: additive `EXECUTE` action, no new module

`PermissionModule.RADIUS` already existed (seeded actions: create/read/
update/delete/manage, narrowest scope `ScopeType.ROUTER`) -- this extension
adds `EXECUTE` to its action tuple (gating `activate`/`disable`/
`regenerate-secret`, mirroring `GUEST_SESSIONS`'/`GUEST_TEAMS`'/`POLICY`'s
own `.execute` choice for lifecycle-ending/-mutating actions), rather than
inventing a new `PermissionModule` -- NAS management is squarely a RADIUS
concern, not a genuinely distinct one. Because `expand_grant_level`'s
`OPERATE` bucket already includes every action except `MANAGE`/`DELETE`, no
`SYSTEM_ROLES` override needed changing: `Network Administrator`'s existing
`RADIUS: FULL` (and every `FULL`/`OPERATE`-by-default role) picks up
`radius.execute` automatically the moment the action exists.

New `AuditAction` values (`RADIUS_NAS_ACTIVATED`/`RADIUS_NAS_DISABLED`/
`RADIUS_NAS_SECRET_REGENERATED`/`RADIUS_NAS_UPDATED`/`RADIUS_NAS_DELETED`)
follow `RADIUS_NAS_REGISTERED`'s own "always audited, low-volume,
admin-driven infrastructure change" profile -- written through the same
shared `audit_log_entries` table every other domain uses, never a
dedicated per-domain audit table (a "NASAudit"/"NASHistory" table was
named in the original module brief but would duplicate this codebase's
own, already-proven, single-shared-audit-table convention every one of its
17+ domains already follows -- an actively worse design in this codebase's
context, not a missing feature).

## 7. Route organization

Admin CRUD/lifecycle moved to a dedicated `nas_router`
(`prefix="/radius/nas"`), separate from the pre-existing `radius_router`
(now holding only the pure `rlm_rest` wire-protocol endpoints,
`/radius/authorize`/`/radius/accounting`, unauthenticated via `CurrentNas`).
Two cross-reference lookups (`GET /locations/{location_id}/nas`,
`GET /routers/{router_id}/nas`) live on their own router
(`nas_cross_reference_router`) since neither prefix nests under
`/radius/nas`. `GET /routers/{router_id}/nas` returns a single object, not
a list, despite its route shape -- `RadiusNasClient.router_id` is unique
(one-to-one), so a router has at most one NAS.

## 8. What this extension does not do

* No RADIUS wire-protocol change -- `authorize`/`accounting_start`/
  `accounting_interim_update`/`accounting_stop` are untouched.
* No change to `authenticate_nas`'s external contract -- only its internal
  check (`status` instead of `is_active`).
* No `router_provisioning` integration -- `register_nas` still has exactly
  one caller (the admin registration endpoint); wiring an automated
  provisioning flow to call it (using `initial_status=PENDING`) is a
  plausible future change, not part of this extension.
