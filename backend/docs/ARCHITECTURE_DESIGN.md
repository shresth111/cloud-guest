# CloudGuest Backend — Architecture Design Document (ADD)

**Scope:** Phase 1 – Phase 5 of the roadmap, built on the existing CloudGuest codebase.
**Status:** Design only. No implementation code. Awaiting approval.
**Author role:** Lead Software Architect (continuation engagement)

---

## 0. Grounding — Conventions Carried Forward From the Existing Codebase

This design does not introduce a new architecture. It extends the one already running in
production, confirmed by direct inspection of `app/domains/*`:

| Convention | What it actually is |
|---|---|
| Module shape | Flat folder per domain: `models.py`, `repository.py`, `service.py`, `router.py`, `schemas.py`, `dependencies.py`, `constants.py`, `exceptions.py`, `validators.py`, `events.py`. No `domain/application/infrastructure/presentation` sub-layers. |
| Data access | One generic `GenericRepository[ModelT]` (CRUD, soft-delete, pagination, filter, sort, search, optimistic `version`) composed inside each domain's own `Protocol` + concrete `Repository` class. Hand-written SQL only for what the generic layer can't express. |
| Cross-domain calls | Narrow `Protocol` interfaces (e.g. `OrganizationLookupProtocol`), satisfied structurally by the real service — no adapters, no service locator. |
| Base model | `BaseModel` mixins: UUID PK, `created_at/updated_at`, `is_deleted/deleted_at`, `created_by/updated_by`, optimistic `version`. Every new table gets all of these. |
| Tenancy | `organization_id` (and often `location_id`) **denormalized onto child tables** at write time, not derived by join, purely so tenant-scoped queries stay single-table. |
| API envelope | `ApiResponse[T]` (`success`, `message`, `data`, `request_id`) via `build_response`. Deviations (raw file downloads) are explicit and documented. |
| AuthZ | `RequirePermission("<module>.<action>")` FastAPI dependency, checked against a pre-seeded `PermissionModule` enum + `MODULE_ACTIONS` grant-level table in `rbac/seed.py`. |
| Events | Plain frozen `dataclass` events per domain, constructed and logged **synchronously, in-process**, by that domain's own service. No event bus, no pub/sub registry. Explicitly a subset of what reaches `audit_log_entries`. |
| Migrations | Flat, numbered, additive (`0001_...` → `0026_...` today). No per-branch migration trees. |
| Enums | `StrEnum`, stored as `String` columns — never native Postgres enums — so new values are additive, no migration needed to add a status. |

**Key discovery that shapes this design:** `PermissionModule` already reserves keys for
`CAMPAIGNS`, `GUEST_SESSIONS`, `RADIUS`, `FIREWALL`, `DHCP`, `DNS`, `HOTSPOT`, `BANDWIDTH`,
`NOTIFICATIONS`, `WHITE_LABEL`, `AUDIT_LOGS`, `SYSTEM_SETTINGS`, `INVOICES`, `SUBSCRIPTIONS` —
none of which have domains yet. And `app/domains/guest/models.py` **already contains**
`GuestSession`, `GuestDevice`, `GuestLoginHistory`, `GuestConsent`. This design treats those as
existing aggregates to extend, not entities to recreate — the single most important
duplicate-prevention decision in this document.

---

## 1. Final Bounded Contexts

| Bounded Context | Existing modules inside it | New/extended modules added by this design |
|---|---|---|
| **Identity & Access** | `auth`, `rbac`, `user`, `organization`, `location` | — |
| **Guest Platform** | `guest`, `voucher`, `captive_portal`, `otp` | `guest` (extended: session engine), `identity` (new), `guest_access` (new), `guest_teams` (new) |
| **Policy** | — | `policy` (new, Phase 2) |
| **Network Platform** | `router`, `router_provisioning`, `router_agent`, `wireguard` | `network_device` (new), `network_wan` (new), `network_tools` (new), `monitoring` (extended: health scoring) |
| **Enterprise Platform** | `rbac` (audit_log_entries table) | `notification` (new), `audit` (extends rbac's audit log), `compliance` (extends `guest.GuestConsent`), `license` (new), `white_label` (new) |
| **Operations** | `analytics`, `monitoring` | `timeline` (new), `analytics` (extended: advanced dashboard), `monitoring`/`network_tools` (extended: diagnostics) |
| **Billing** | `billing` | — |

A bounded context here is a grouping for reasoning about ownership and RBAC `PermissionModule`
families — it is **not** a folder. Folders stay one-per-domain, flat, as today.

---

## 2. Final Module Hierarchy

| Phase | Module (folder name) | Status | Notes |
|---|---|---|---|
| 0 (existing) | `auth`, `rbac`, `organization`, `location`, `user`, `router`, `router_provisioning`, `router_agent`, `wireguard`, `otp`, `voucher`, `captive_portal`, `guest`, `monitoring`, `analytics`, `billing` | EXISTING | Do not recreate. |
| 1 | `guest` | **EXTEND** | Session lifecycle: concurrent-session limits, idle/session timeout enforcement, force logout, disconnect reasons — additive service methods + admin router endpoints on the existing module. `GuestSession`/`GuestDevice`/`GuestLoginHistory` are reused as-is. |
| 1 | `guest_access` | NEW | Guest whitelist/blocklist, device whitelist/blocklist, temporary access, VIP access. |
| 1 | `identity` | NEW | Smart Identity: configurable, per-organization login method registry (mobile/email/passport/aadhaar/employee_id/room_number/voucher/SSO/custom). |
| 1 | `guest_teams` | NEW | Teams, members, shared users; policy references are FK placeholders until `policy` (Phase 2) exists. |
| 1 | `voucher` | **EXTEND** | Voucher Plan, Voucher Series as new tables in the existing module; Voucher Analytics implemented as new read-only views/service methods inside `analytics` (reusing `voucher`'s repository via its Protocol), not a duplicate analytics stack. |
| 2 | `policy` | NEW | Unified Policy Engine — authN/session/bandwidth/FUP/business-hours/access/VLAN/QoS/routing policies, assignment, versioning. Central module consumed by `guest`, `guest_access`, `identity`, `router_provisioning`. |
| 3 | `network_device` | NEW | NAC — device identity/compliance registry (distinct from `guest_access`'s device allow/deny decision layer). |
| 3 | `network_wan` | NEW | ISP & WAN circuit inventory, failover, usage. |
| 3 | `network_tools` | NEW | DHCP / VLAN / QoS / DNS / Firewall config templates, pushed via existing `router_provisioning`/`router_agent`. |
| 3 | `monitoring` | **EXTEND** | Network health scoring on top of existing monitoring tables. |
| 4 | `notification` | NEW | Notification Center — channels, templates, delivery. First real candidate for an outbox/dispatch pattern (see §12). |
| 4 | `audit` | **EXTEND** | Query/export/retention surface over RBAC's existing `audit_log_entries`; widens which domain events get audited. |
| 4 | `compliance` | **EXTEND** | Retention & erasure workflows over the existing `guest.GuestConsent`. |
| 4 | `license` | NEW | Entitlement/license engine, keyed off `Organization.subscription_tier` and `billing`'s plan data. |
| 4 | `white_label` | NEW | Branding config per organization/location, feeding `captive_portal`'s existing portal config. |
| 5 | `timeline` | NEW | Cross-domain activity read-model (mostly query, minimal own writes). |
| 5 | `analytics` | **EXTEND** | Advanced Dashboard APIs on the existing `dashboard_service.py`. |
| 5 | `monitoring` / `network_tools` | **EXTEND** | Diagnostics APIs. |

**7 new folders total** (`guest_access`, `identity`, `guest_teams`, `policy`, `network_device`,
`network_wan`, `network_tools`, `notification`, `license`, `white_label`, `timeline` — 11, corrected
count below in §21), the rest are extensions of existing modules. This is the direct application
of "never duplicate entities/services" to the brief's phase list.

---

## 3. Folder Structure

Every new module follows the existing flat template exactly:

```
app/domains/<module_name>/
    __init__.py
    models.py          # SQLAlchemy ORM, extends BaseModel
    constants.py        # StrEnum status/type values
    exceptions.py        # Domain-specific exceptions
    schemas.py           # Pydantic v2 request/response DTOs
    repository.py        # Protocol + GenericRepository-backed impl
    service.py            # Application service, orchestration + business rules
    validators.py          # Pure validation helpers
    events.py               # Frozen dataclass domain events (in-process, logged)
    dependencies.py           # FastAPI Depends() wiring
    router.py                  # APIRouter, RBAC-gated
```

Example — `app/domains/guest_access/`:

```
app/domains/guest_access/
    __init__.py
    models.py        # GuestAccessRule, DeviceAccessRule
    constants.py      # AccessRuleType (WHITELIST/BLOCKLIST), AccessScope
    exceptions.py
    schemas.py
    repository.py
    service.py
    validators.py
    events.py
    dependencies.py
    router.py
```

Migrations stay flat in `alembic/versions/`, continuing the existing numbering
(next is `0027_...`). Tests mirror under `tests/unit/domains/<module_name>/`.

No module gets nested `domain/`, `application/`, `infrastructure/`, `presentation/`
subfolders — that would make it the one structurally inconsistent domain in the codebase.

---

## 4. Domain Dependencies

Dependencies are expressed the existing way: a module's `dependencies.py` imports another
module's `get_<x>_service`/`get_<x>_repository` functions, or defines a narrow `Protocol` the
other module's service already satisfies.

| Module | Depends on (via Protocol/service composition) |
|---|---|
| `guest` (extended) | `location`, `router`, `voucher`, `rbac` (audit), **`policy`** (Phase 2+, session/idle-timeout policy lookup) |
| `guest_access` | `guest`, `location`, `organization`, `rbac` |
| `identity` | `organization`, `rbac`; optionally `otp` (for OTP-based methods), `voucher` (voucher-as-login) |
| `guest_teams` | `guest`, `organization`, `rbac`, **`policy`** (Phase 2+) |
| `policy` | `organization`, `location`, `rbac` — consumed BY `guest`, `guest_access`, `identity`, `router_provisioning`, `network_tools` |
| `network_device` | `router`, `location`, `rbac`, `guest_access` (compliance-driven block decisions) |
| `network_wan` | `router`, `location`, `monitoring` |
| `network_tools` | `router_provisioning`, `router_agent`, `policy` |
| `notification` | `rbac` (recipients/permissions), every domain that raises events it wants delivered (via each domain's own service calling `notification`'s service — never the reverse) |
| `audit` | `rbac` (owns the table), read-only consumers: `timeline`, `compliance` |
| `compliance` | `guest` (GuestConsent), `audit` |
| `license` | `organization`, `billing` |
| `white_label` | `organization`, `location`, `captive_portal` |
| `timeline` | `audit`, `guest`, `voucher`, `billing`, `monitoring` — read-only aggregator, writes nothing to other domains |

Rule preserved from the existing codebase: **dependencies point inward toward
Identity & Access and outward-but-never-circularly toward feature domains.** `policy` and
`notification` are the only two modules many other domains depend on — both stay dependency-free
of feature domains themselves (they take primitives — org id, event payloads — not domain objects).

---

## 5–10. Module Profiles

*(Aggregate Roots, Entities, Value Objects, Domain Services, Application Services, and Repository
Interfaces are given together per module — this matches how the existing codebase actually reads:
one `models.py` + one `service.py` + one `repository.py` per module, not six separate global lists.)*

### 5.1 `guest` (EXTEND)

- **Responsibility:** Own the guest identity, device, and session lifecycle end to end, including
  enforcement (concurrent sessions, idle/session timeout, forced disconnect).
- **Dependencies:** `location`, `router`, `voucher`, `rbac`, `policy` (Phase 2+).
- **Aggregate roots:** `Guest` (existing), `GuestSession` (existing — extended with enforcement
  behavior, not new columns unless a gap analysis proves otherwise).
- **Entities:** `GuestDevice`, `GuestLoginHistory`, `GuestConsent` (all existing).
- **New Value Objects:** `SessionWindow` (started_at/ended_at/idle_deadline, computed, not
  persisted), `ConcurrentSessionLimit` (int + scope).
- **New Domain Service:** `SessionLifecycleEvaluator` — pure function(s): given a session +
  policy/limits, decide idle-expired / session-expired / over-concurrent-limit. No I/O.
- **Application Service additions:** `GuestService.force_logout()`, `.disconnect_session()`,
  `.enforce_idle_timeouts()` (invoked by a scheduled job), `.count_active_sessions()`.
- **Repository additions:** `GuestRepositoryProtocol.list_active_sessions_for_guest()`,
  `.bulk_expire_idle_sessions()` (single `UPDATE ... WHERE`, mirrors `voucher`'s
  `bulk_revoke_vouchers_for_batch` pattern).
- **Public API additions:** `POST /guest-sessions/{id}/force-logout`,
  `GET /guest-sessions/live`, `GET /guest-sessions/history`.
- **Future extensibility:** Accounting (bytes/duration) already captured on `GuestSession`;
  RADIUS interim-accounting updates plug into `.record_accounting()` without schema change.

### 5.2 `guest_access` (NEW)

- **Responsibility:** Allow/deny decisions for guests and devices, independent of session state —
  whitelist, blocklist, temporary access windows, VIP tier.
- **Dependencies:** `guest`, `location`, `organization`, `rbac`.
- **Aggregate roots:** `GuestAccessRule` (guest-level allow/deny), `DeviceAccessRule` (MAC-level
  allow/deny).
- **Entities:** none beyond the two roots (each rule is self-contained).
- **Value Objects:** `MacAddress` (validated format), `AccessWindow` (start/end, for temporary
  access), `AccessDecision` (ALLOW/DENY/VIP + reason, returned by the domain service, never
  persisted directly).
- **Domain Service:** `AccessDecisionResolver` — given guest_id/device_mac + scope, returns the
  highest-precedence `AccessDecision` (VIP > temporary > blocklist > whitelist > default-allow).
  Pure logic, called synchronously from `guest`'s login flow.
- **Application Service:** `GuestAccessService` — CRUD over rules, delegates decisions to the
  resolver, audit-logs every deny.
- **Repository:** `GuestAccessRepositoryProtocol` — one `GenericRepository` per table + a
  `find_active_rule(guest_id | mac, scope)` hand-written lookup.
- **Public API:** `POST/GET/DELETE /guest-access/rules`, `GET /guest-access/rules/{id}/check`.
- **Future extensibility:** `policy` (Phase 2) can subsume precedence ordering as a configured
  `AccessPolicy` — this module keeps the mechanism, Phase 2 can externalize the ordering.

### 5.3 `identity` (NEW)

- **Responsibility:** Configurable login-method registry per organization/location — which of
  mobile/email/passport/aadhaar/employee_id/room_number/voucher/SSO/custom are enabled, and their
  field/validation config.
- **Dependencies:** `organization`, `rbac`; loosely `otp`, `voucher` (existing modules already own
  the actual credential verification — `identity` owns *which methods are offered*, not their
  verification logic, to avoid duplicating `otp`/`voucher`).
- **Aggregate root:** `IdentityMethodConfig` (one row per org/location + method type).
- **Value Objects:** `IdentityFieldSchema` (JSON-described required fields per method, e.g.
  passport needs `passport_number` + `nationality`), `CustomMethodDefinition`.
- **Domain Service:** `IdentityMethodValidator` — validates a login payload's shape against the
  configured `IdentityFieldSchema` before handing off to the method's real verifier
  (`otp.OtpService`, `voucher.VoucherService`, or a new lightweight verifier for
  passport/aadhaar/employee_id/room_number, which are simple format+lookup checks, not full
  domains).
- **Application Service:** `IdentityService` — `get_enabled_methods(org_id, location_id)`,
  `validate_and_route(method, payload)` → delegates to the right existing service.
- **Repository:** `IdentityRepositoryProtocol` — thin, one table.
- **Public API:** `GET /identity/methods` (guest-facing, portal reads this to render the login
  form), `PUT /identity/methods` (admin config).
- **Future extensibility:** SSO is the one method needing a real external protocol (SAML/OIDC) —
  scoped as its own verifier behind the same `IdentityMethodValidator` seam, added later without
  touching other methods.

### 5.4 `guest_teams` (NEW)

- **Responsibility:** Group guests into teams with shared policy/session limits and named
  membership (e.g. a corporate account's traveling staff).
- **Dependencies:** `guest`, `organization`, `rbac`, `policy` (Phase 2+, optional FK until then).
- **Aggregate root:** `GuestTeam`.
- **Entities:** `GuestTeamMember` (join of `GuestTeam` ↔ `Guest`), `GuestTeamSharedUser`
  (non-guest identities, e.g. a shared front-desk login, granted team access).
- **Value Objects:** `TeamRole` (OWNER/MEMBER), `TeamPolicyRef` (nullable FK to `policy.Policy`
  once Phase 2 lands; `NULL` = inherit org default).
- **Domain Service:** none beyond simple membership invariants (max team size, one owner).
- **Application Service:** `GuestTeamService`.
- **Repository:** `GuestTeamRepositoryProtocol`.
- **Public API:** `POST/GET/PUT/DELETE /guest-teams`, `POST /guest-teams/{id}/members`.
- **Future extensibility:** `TeamPolicyRef` is the seam Phase 2 fills in — no migration needed
  when `policy` ships, just start writing non-null values.

### 5.5 `voucher` (EXTEND) — Voucher Plan / Series / Analytics

- **Responsibility addition:** Template-ize voucher creation (`VoucherPlan` = reusable
  quota/duration/price template) and give batches a `VoucherSeries` grouping (e.g. this month's
  print run), on top of the existing `VoucherBatch`/`Voucher`.
- **New aggregate roots:** `VoucherPlan`, `VoucherSeries`.
- **Value Objects:** `QuotaDefinition` (data/time/device limits — currently inline on
  `VoucherBatch`, promoted to a reusable VO embedded in `VoucherPlan`).
- **Domain Service:** none new — plan/series are configuration, not behavior.
- **Application Service:** `VoucherService` gains `create_from_plan()`, `list_series()`.
- **Voucher Analytics — placed in `analytics`, not `voucher`:** new read-only
  `VoucherAnalyticsService` methods inside the existing `analytics` module, consuming
  `VoucherRepositoryProtocol` (already exists) for redemption-rate, plan-performance,
  series-performance queries. This avoids `analytics` and `voucher` both owning aggregation logic.
- **Public API:** `POST/GET /voucher-plans`, `GET /voucher-series`,
  `GET /analytics/vouchers/*` (in `analytics`'s router, not `voucher`'s).

### 6.1 `policy` (NEW, Phase 2) — Unified Policy Engine

- **Responsibility:** Single source of truth for every policy type (authN, session, bandwidth,
  FUP, business-hours, access, VLAN, QoS, routing), their assignment to org/location/team/guest
  scopes, and versioning.
- **Dependencies:** `organization`, `location`, `rbac`. Deliberately **zero** dependency on
  `guest`/`network_*` — those modules depend on `policy`, not the reverse, so `policy` stays a
  leaf that can't create cycles as more consumers are added.
- **Aggregate root:** `Policy` (one row per policy, `policy_type` discriminator +
  JSONB `rules` payload — mirrors the existing codebase's comfort with JSONB config columns, seen
  already on `Organization`).
- **Entities:** `PolicyVersion` (immutable snapshot on every edit — append-only, like
  `GuestSession`'s own "sessions are append-only" precedent), `PolicyAssignment` (scope_type +
  scope_id + policy_id + priority).
- **Value Objects:** `PolicyRule` (typed per `policy_type`: `SessionPolicyRule`,
  `BandwidthPolicyRule`, `FUPPolicyRule`, `BusinessHoursPolicyRule`, `VLANPolicyRule`,
  `QoSPolicyRule`, `RoutingPolicyRule` — validated Pydantic models stored as the `rules` JSONB,
  not separate tables per type, so adding a new policy type is additive config, not a migration).
- **Domain Service:** `PolicyResolver` — given scope chain (guest → team → location →
  organization) + policy_type, returns the highest-priority active `PolicyVersion`. Pure,
  cacheable, no I/O beyond the resolved read.
- **Application Service:** `PolicyService` — CRUD, versioning (`create_version`,
  `publish_version`, `rollback`), assignment management.
- **Repository:** `PolicyRepositoryProtocol`.
- **Public API:** `POST/GET/PUT /policies`, `POST /policies/{id}/versions`,
  `POST /policy-assignments`, `GET /policy-assignments/resolve?scope=...`.
- **Future extensibility:** New policy types are a new `PolicyRule` Pydantic variant + a new
  `PolicyType` enum value — no new table, no new migration.

### 6.2 Phase 3 — `network_device`, `network_wan`, `network_tools`, `monitoring` (extend)

- **`network_device` (NAC):** Aggregate root `NetworkDevice` (identity/compliance registry —
  vendor, OS fingerprint, compliance status). Distinct from `guest_access.DeviceAccessRule`
  (that's an allow/deny decision; this is device *identity*). Depends on `router`, `location`,
  feeds `guest_access` as an input signal, never the reverse.
- **`network_wan`:** Aggregate root `WanCircuit` (ISP, bandwidth, failover priority). Domain
  service `FailoverEvaluator`. Depends on `router`, `monitoring`.
- **`network_tools`:** Aggregate roots `DhcpConfig`, `VlanConfig`, `QosConfig`, `DnsConfig`,
  `FirewallRule` — each a config template pushed through the **existing**
  `router_provisioning`/`router_agent` push pipeline (reused, not duplicated). Depends on
  `policy` for QoS/bandwidth rule sourcing.
- **`monitoring` (EXTEND):** new `HealthScoreService` computing a composite score from existing
  monitoring tables + `network_wan` uptime — no new aggregate root, a read/compute service only.

### 6.3 Phase 4 — `notification`, `audit`, `compliance`, `license`, `white_label`

- **`notification`:** Aggregate roots `NotificationTemplate`, `NotificationChannel`
  (email/SMS/webhook/in-app config), `NotificationDelivery` (append-only log, mirrors `voucher`
  events' "logged, not queried as business state" posture). Application service
  `NotificationService.send(event_type, payload, recipients)`. **This is the one module where an
  outbox/at-least-once delivery pattern is justified** — see §12.
- **`audit` (EXTEND rbac):** No new table — `audit_log_entries` already exists under `rbac`. This
  module adds a dedicated `service.py`/`router.py` for query/filter/export/retention over that
  table, and a `AuditWriterProtocol` other domains can depend on generically (several already
  informally depend on `rbac`'s audit repository directly — this formalizes that seam).
- **`compliance` (EXTEND guest):** No new consent table — `GuestConsent` already exists. Adds
  `RetentionPolicy` (new, small table: per-org data-retention window) and
  `ErasureRequest` (new: right-to-erasure workflow state machine). Domain service
  `ErasureExecutor` — orchestrates soft/hard delete across `guest`, `voucher`, `analytics` via
  each module's existing repository, never touching another domain's tables directly.
- **`license`:** Aggregate root `LicenseGrant` (org_id, tier, feature flags, expiry) — reads
  `Organization.subscription_tier` as its seed value, reconciled against `billing`'s plan data.
  Domain service `EntitlementChecker` (pure, cacheable) — the thing every module's router *could*
  eventually call to gate a premium feature, but Phase 4 only builds the checker, not the gating
  everywhere.
- **`white_label`:** Aggregate root `BrandingConfig` (org/location scoped — logo, colors, domain).
  Feeds `captive_portal`'s existing `CaptivePortalConfig` at render time via a `Protocol`, not by
  writing into `captive_portal`'s table.

### 6.4 Phase 5 — `timeline`, `analytics` (extend), diagnostics (extend)

- **`timeline`:** No aggregate root of its own — a **read-model** module. Application service
  `TimelineService.get_activity(scope, filters)` fans out to `audit`, `guest` (login history),
  `voucher` (redemptions), `billing` (invoices/payments) via their existing repositories/Protocols
  and merges chronologically. Zero new tables unless a materialized denormalized feed is later
  needed for scale — start without one.
- **`analytics` (EXTEND):** Advanced Dashboard APIs are new `router.py` endpoints + `service.py`
  methods on the existing `dashboard_service.py`/`dashboard_aggregation.py` — no new module.
- **Diagnostics APIs (EXTEND `monitoring`/`network_tools`):** New endpoints only; diagnostics run
  through the existing `router_agent` command-dispatch path.

---

## 11. Database Relationships

Every new table extends `BaseModel` (UUID PK + timestamps + soft-delete + audit + version) and
follows the existing FK-naming convention (`fk_<table>_<column>_<referred_table>`).

Key new relationships (existing tables in *italics*):

```
policies (1) ──< policy_versions (append-only)
policies (1) ──< policy_assignments >── scope: organizations | locations | guest_teams | guests

guest_access_rules >── guests (FK, nullable — org/location-level rules have no guest_id)
device_access_rules >── (mac_address, no FK — devices aren't a first-class table pre-Phase-3)

network_devices >── routers (FK), locations (FK)
                 <── referenced by guest_access_rules' future device_id (Phase 3 backfill target)

identity_method_configs >── organizations (FK), locations (FK, nullable = org-wide default)

guest_teams >── organizations (FK)
guest_team_members >── guest_teams (FK), guests (FK)
guest_team_shared_users >── guest_teams (FK), users (FK)

voucher_plans >── organizations (FK)
voucher_series >── voucher_plans (FK)
voucher_batches (existing) >── voucher_series (FK, nullable — legacy batches predate series)

notification_templates >── organizations (FK, nullable = platform default)
notification_deliveries >── notification_templates (FK)

retention_policies >── organizations (FK)
erasure_requests >── guests (FK)

license_grants >── organizations (FK, unique — one active grant per org)

branding_configs >── organizations (FK), locations (FK, nullable)

wan_circuits >── routers (FK) or locations (FK, for multi-router sites)
dhcp_configs / vlan_configs / qos_configs / dns_configs / firewall_rules >── routers (FK) or locations (FK)
```

`GuestSession`, `GuestDevice`, `GuestLoginHistory`, `GuestConsent`, `Voucher`, `VoucherBatch` are
**reused unmodified** unless the Phase 1 gap analysis (still pending — see prior message) proves a
specific column is missing.

---

## 12. Event Flow

The existing pattern — frozen dataclass events, constructed and logged synchronously by the
owning service, no bus — is **kept as the default** for every new module. Reasons to keep it:
every existing domain does it this way, it's simple, and it's already proven at 16 domains'
scale.

**One deliberate exception: `notification`.** Fan-out to email/SMS/webhook is I/O-bound,
retryable, and needs at-least-once delivery — the synchronous in-process pattern would block the
triggering request on a third-party API call. `notification` introduces:

- `NotificationDelivery` rows written **synchronously** (fast, local) as a durable outbox record
  with `status=PENDING`.
- Actual dispatch happens via the **existing** Celery app (`app/core/celery_app.py` already
  exists and is used by `billing`/`analytics`'s `tasks.py` files) — a `notification/tasks.py`
  worker task, following the exact convention `billing.tasks`/`analytics.tasks` already
  establish. Not a new async framework, not a new bus — reuse of what's already running.
- Other domains call `NotificationService.enqueue(event_type, payload)` synchronously (cheap
  write), same call shape as every other cross-domain `Protocol` call in this codebase.

No other new module needs this — everything else stays synchronous/in-process, matching existing
`voucher`/`otp`/`wireguard` events.

---

## 13. Policy Engine Integration

`policy` is a leaf module (§4) — it depends on nothing feature-specific and is depended on by
`guest`, `guest_access`, `identity`, `guest_teams`, `network_tools`. Integration shape, consistent
with the rest of the codebase's Protocol pattern:

- Each consumer defines its own narrow `PolicyLookupProtocol` (e.g. `guest` only needs
  `resolve(scope, "session")` and `resolve(scope, "bandwidth")`), satisfied structurally by
  `policy.PolicyService`.
- Resolution order is fixed: **guest-specific → team → location → organization → platform
  default**, implemented once in `policy.PolicyResolver` and never duplicated per consumer.
- Consumers **read** resolved policy at decision time (session start, access check, provisioning
  push) — they do not cache policy long-term in their own tables, avoiding drift between a policy
  edit and its effect. `PolicyVersion` being append-only means a decision can always be traced
  back to the exact version that produced it (store `policy_version_id` on the decision record,
  e.g. `GuestSession.applied_session_policy_version_id` — additive nullable column).
- Until Phase 2 ships, Phase 1 modules (`guest`, `guest_teams`) use their nullable FK/local default
  and simply have no policy source to resolve — no blocking dependency, no stub module needed.

---

## 14. RBAC Integration

No changes to `rbac` itself. Every new module:

- Defines its `PermissionModule` values by **reusing already-seeded enum members where they
  exist** (`GUEST_SESSIONS`, `CAMPAIGNS`, `NOTIFICATIONS`, `WHITE_LABEL`, `AUDIT_LOGS` are already
  in the enum — confirmed in §2 of the prior report) and adding new members only for genuinely new
  nouns (`guest_access`, `identity`, `guest_teams`, `policy`, `network_device`, `network_wan`,
  `network_tools`, `license`).
- Adds its actions to `rbac/seed.py`'s `MODULE_ACTIONS` table, following the existing
  `create/read/update/delete/manage/approve/...` action vocabulary and `expand_grant_level`
  bucketing (`VIEW`/`OPERATE`/`MANAGE`) rather than inventing new grant levels.
- Every admin router endpoint gets `RequirePermission("<module>.<action>")`, exactly like every
  existing router.
- Guest-facing endpoints (identity method listing, access decision checks triggered by login)
  follow `voucher`/`otp`'s precedent: no `RequirePermission`/`CurrentUser`, protected by
  rate-limiting instead, since there's no platform identity to authorize.

---

## 15. Multi-Tenant Strategy

Unchanged from the existing pattern, applied to every new table:

- `organization_id` (and `location_id` where applicable) is a **denormalized, immutable-after-create
  column** on every new aggregate root — not derived via join — matching `GuestSession`'s
  documented rationale (tenant-scoped queries stay single-table).
- Every new service method that lists/searches takes `requesting_organization_id` from
  `CurrentOrganization` and filters on it, exactly like every existing service.
- Cross-organization data (e.g. `license.LicenseGrant`, `identity` platform-default configs) is
  the explicit exception, and is marked as such in that module's docstring, mirroring how
  `notification_templates.organization_id` being nullable already signals "platform default" in
  this design.
- MSP hierarchy (`Organization.parent_organization_id`, already existing) is respected by new
  modules the same way `organization`/`rbac` already do: an MSP-scoped grant/policy/license can
  optionally cascade to child organizations — implemented as a resolver check
  (`policy.PolicyResolver`, `license.EntitlementChecker`), not duplicated storage.

---

## 16. API Structure

- All new routers mount under `/api/v1/...`, added to `app/api/v1/router.py`'s existing
  `include_router` list — one line per module, same as today.
- `ApiResponse[T]` envelope for every endpoint, no exceptions anticipated in Phases 1–5 (unlike
  `voucher`'s CSV export precedent — none of these modules produce raw file downloads by design,
  though `audit`'s export endpoint should be reviewed against that precedent when built).
- Route naming follows existing plural-resource convention: `/guest-access/rules`,
  `/policies`, `/policy-assignments`, `/voucher-plans`, `/notification-templates`, etc.
- Guest-facing (unauthenticated) endpoints are the exception, not the rule, and are called out
  explicitly per module above (`identity`'s method listing, `guest_access`'s login-time check if
  exposed directly rather than only used internally by `guest`).

---

## 17. Naming Conventions

Matches existing codebase exactly:

- Modules: `snake_case`, singular-domain-noun (`guest_access`, not `guest_accesses`).
- Models: `PascalCase`, tables auto-derived to `snake_case` plural via `BaseModel`'s
  `__tablename__` `declared_attr` (already implemented — new models get this for free by
  inheriting `BaseModel`).
- Enums: `StrEnum`, `PascalCase` class, `UPPER_SNAKE` members, stored as their `.value` string.
- Protocols: `<Module>RepositoryProtocol`, `<Concern>Protocol` for narrow cross-domain shapes.
- Services: `<Module>Service` (application), free-standing `PascalCase` classes for domain
  services with no module prefix requirement (`PolicyResolver`, `AccessDecisionResolver`,
  `SessionLifecycleEvaluator`) — matches how `voucher`'s `VoucherRedemptionRateLimiter` is named
  today (domain-service-shaped, not suffixed `...Service`).
- Events: `<Aggregate><PastTenseVerb>` (`PolicyVersionPublished`, `GuestAccessRuleCreated`).
- Permission keys: `<module>.<action>`, action vocabulary reused from `rbac/seed.py`.

---

## 18. Dependency Injection Strategy

No new DI framework. Every new module's `dependencies.py` follows the exact existing chain:

```
get_db_session
  → get_<module>_repository(db) -> <Module>RepositoryProtocol
    → get_<module>_service(repository, <other services via their get_<x>_service>) -> <Module>Service
```

Cross-module composition passes already-constructed services as constructor args (as `voucher`'s
`get_voucher_service` does with `organization_service`/`location_service`/`audit_repository`
today) — no service locator, no container, no reflection-based injection introduced.

---

## 19. Migration Strategy

- Continue the existing flat, numbered, additive Alembic sequence — next migration is
  `0027_create_guest_access_tables.py`, then one file per logical table group, matching the
  existing "one migration per domain-slice" granularity seen in `0007`–`0018`.
- Every new table: UUID PK via `UUIDMixin`, timestamps/soft-delete/audit/version via the shared
  mixins, naming-convention-derived constraint names — no manual constraint naming.
- Additive-only changes to existing tables (e.g. `GuestSession.applied_session_policy_version_id`
  in Phase 2) are separate, small, nullable-column migrations — mirrors `0019`/`0020`'s existing
  precedent of narrow, additive columns on `guest_sessions`.
- No destructive migrations against existing tables in any phase covered by this document.
- Phase ordering in §2 double as migration ordering: Phase 1 migrations land before Phase 2's
  `policy_version_id` column addition to `guest_sessions`, etc.

---

## 20. Testing Strategy

Mirrors `tests/unit/`'s existing per-domain structure:

- `tests/unit/domains/<module_name>/` — one test module per new folder, same layout as existing
  domains' tests.
- Repository tests against a real (test) Postgres via the existing async session fixture —
  `GenericRepository` behavior is already covered generically; new repository tests focus on the
  hand-written queries only (mirrors `voucher/repository.py`'s own doc comment about why its two
  hand-written methods exist and need dedicated coverage).
- Service tests mock repositories via their `Protocol` (no real DB needed for pure orchestration
  logic) — `PolicyResolver`, `AccessDecisionResolver`, `SessionLifecycleEvaluator` are pure
  functions and get plain unit tests with no fixtures at all.
- Router tests use the existing FastAPI `TestClient`/RBAC-bypass test fixtures already present for
  every existing domain's router tests.
- New: `notification`'s Celery task gets a task-level test asserting delivery status transitions
  (`PENDING → SENT/FAILED`), following `billing/tasks.py`'s existing test pattern.
- Cross-module integration tests (e.g. "does a `policy` edit actually change `guest` session
  behavior") live at the boundary, calling both modules' public services — not inside either
  module's own test folder, matching how existing cross-domain behavior (voucher redemption →
  guest session creation) is tested today.

---

## 21. Full Module Dependency Graph

```
                                   ┌─────────────┐
                                   │   auth      │
                                   └──────┬──────┘
                                          │
                                   ┌──────▼──────┐
                    ┌─────────────┤    rbac      ├─────────────┐
                    │              └──────┬──────┘              │
                    │                     │                     │
             ┌──────▼──────┐      ┌───────▼───────┐     ┌───────▼──────┐
             │organization │◄─────┤     user       │     │    audit     │(extends rbac)
             └──────┬──────┘      └────────────────┘     └───────▲──────┘
                    │                                            │
             ┌──────▼──────┐                                     │
             │  location   │                                     │
             └──────┬──────┘                                     │
                    │                                            │
   ┌────────────────┼─────────────────────┬──────────────────────┤
   │                │                     │                      │
┌──▼───┐      ┌─────▼─────┐        ┌──────▼──────┐        ┌──────┴──────┐
│router│      │  billing  │        │   POLICY    │◄───────┤   license   │
└──┬───┘      └─────┬─────┘        │   (leaf)    │        └─────────────┘
   │                │              └──────┬──────┘
   ├──router_provisioning                 │  (consumed by, never depends on ↓)
   ├──router_agent                        │
   ├──wireguard                    ┌──────┼───────────────┬───────────────┐
   │                               │      │               │               │
┌──▼──────────┐             ┌──────▼───┐ ┌▼────────────┐ ┌▼─────────────┐ │
│network_device│            │  guest   │ │guest_access │ │  identity    │ │
│network_wan   │            │(extended)│◄┤             │ │              │ │
│network_tools │            └────┬─────┘ └─────────────┘ └──────────────┘ │
└──────────────┘                 │                                        │
                                  ├── otp                                  │
                                  ├── voucher ──► analytics (voucher stats)│
                                  ├── captive_portal ◄── white_label       │
                                  └── guest_teams ─────────────────────────┘
                                       │
                                ┌──────▼──────┐
                                │ compliance  │ (extends guest.GuestConsent)
                                └─────────────┘

                    monitoring ──► network_wan (health scoring)
                    monitoring/network_tools ──► diagnostics (Phase 5, extension)

  notification  ◄── called by every domain above (one-directional, never called TO)
  timeline      ◄── reads from audit, guest, voucher, billing, monitoring (read-only fan-in)
  analytics     ◄── reads from guest, voucher, monitoring, billing (existing pattern, extended)
```

**Reading the graph:** arrows point from dependent → dependency (same direction as an import).
`policy` and `notification` are intentionally the only two "everyone can call this" leaves — both
take primitive inputs (scope IDs, event payloads), never domain objects, so they can never create
an import cycle back into a feature domain. `timeline` and `analytics` are the only two
"read-only fan-in" modules — they depend on everything but nothing depends on them.

---

## Summary of New Folders (11 total)

`guest_access`, `identity`, `guest_teams`, `policy`, `network_device`, `network_wan`,
`network_tools`, `notification`, `compliance` *(if not folded into `guest`)*, `license`,
`white_label`, `timeline`.

## Summary of Extended Existing Modules (5 total)

`guest` (session engine), `voucher` (plan/series), `analytics` (voucher analytics, advanced
dashboard), `monitoring` (health scoring, diagnostics), `rbac`/`audit` (query surface only, no
schema change).

---

**This document is a design artifact only. No migrations, models, services, or routers have been
created. Awaiting your approval before implementation begins, module by module, per the existing
workflow (review → integration strategy → files → DB changes → implement → migrate → test).**
