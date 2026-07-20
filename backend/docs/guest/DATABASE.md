# Guest: Database Schema

Migration: `alembic/versions/0015_create_guest_tables.py` (revises
`0014_create_captive_portal_tables`). Six new tables, all extending
`app.database.base.BaseModel` (`id`, `created_at`, `updated_at`,
`deleted_at`/`is_deleted`, `created_by`/`updated_by`, `version`) -- no
changes to any existing table's columns.

## `guests`

A returning-guest identity, recognized across visits by `identifier` (the
same phone/email value presented to `app.domains.otp`/`app.domains
.voucher`).

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable | A guest always belongs to a tenant |
| `location_id` | UUID, FK `locations.id` (`SET NULL`), nullable | "Home" location -- where first seen; a guest may visit other locations under the same org over time, sessions are never constrained to only this location |
| `identifier` | String(255) | Phone or email -- same value used with otp/voucher |
| `display_name` | String(200), nullable | Optional self-reported name |
| `first_seen_at` / `last_seen_at` | DateTime(tz) | |
| `total_visit_count` | Integer, default `0` | Incremented on every successful login/reconnect |
| `is_blocked` | Boolean, default `false` | Admin-set ban |
| `blocked_reason` | Text, nullable | |

Unique index: `uq_guests_organization_id_identifier` on
`(organization_id, identifier)` -- see `FLOW.md` for why identity is scoped
per tenant, not globally.

## `guest_devices`

A physical device (by MAC address) seen logging in as some `Guest`.

| Column | Type | Notes |
|---|---|---|
| `guest_id` | UUID, FK `guests.id` (`CASCADE`) | Current "owner" -- reassignable, see `FLOW.md` §10 |
| `mac_address` | String(17), **globally unique** | Not scoped per guest -- see `FLOW.md` §10 |
| `device_name` | String(200), nullable | |
| `first_seen_at` / `last_seen_at` | DateTime(tz) | |

## `guest_sessions`

One continuous guest WiFi connection interval on one router (the RADIUS
NAS). Append-only -- see `FLOW.md` §3.

| Column | Type | Notes |
|---|---|---|
| `guest_id` | UUID, FK `guests.id` (`CASCADE`), not nullable | |
| `device_id` | UUID, FK `guest_devices.id` (`SET NULL`), nullable | Absent if the guest presented no MAC |
| `router_id` | UUID, FK `routers.id` (`CASCADE`), not nullable | The NAS this session is on |
| `location_id` | UUID, FK `locations.id` (`CASCADE`), not nullable | |
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable | Denormalized from `location_id` at session-start time -- mirrors `Router.organization_id`'s identical rationale (avoids a join on every tenant-scoped analytics query); immutable after creation |
| `auth_method` | String(30) | `constants.GuestAuthMethod` -- `otp_sms`/`otp_email`/`voucher`/`username_password` |
| `voucher_id` | UUID, FK `vouchers.id` (`SET NULL`), nullable | Set only when `auth_method="voucher"` |
| `status` | String(20), default `active` | `constants.GuestSessionStatus` -- see transition graph below |
| `started_at` | DateTime(tz), not nullable | |
| `ended_at` | DateTime(tz), nullable | Set when the session leaves `ACTIVE` |
| `last_activity_at` | DateTime(tz), not nullable | Bumped by `record_usage`; drives timeout detection |
| `ip_address` | String(45), nullable | |
| `bytes_uploaded` / `bytes_downloaded` | BigInteger, default `0` | |
| `data_limit_mb` | Integer, nullable | Copied from the voucher batch (or left `None`) at session start -- never a live reference, see `FLOW.md` §7 |
| `session_timeout_minutes` | Integer, nullable | Same "copied, not referenced" reasoning |
| `disconnect_reason` | String(255), nullable | e.g. `"inactivity_timeout"`, `"data_limit_exceeded"`, `"radius_accounting_stop"` |

Status transition graph (`constants.GUEST_SESSION_STATUS_TRANSITIONS`),
extended for Phase 1 BhaiFi-parity with `PAUSED` (see `FLOW.md` §11 for the
full Pause/Resume/Extend write-up -- `PAUSED` is the sole status with an
outgoing edge back to `ACTIVE`; every other status remains terminal):

```text
ACTIVE  -> DISCONNECTED | EXPIRED | TERMINATED | PAUSED
PAUSED  -> ACTIVE | DISCONNECTED | TERMINATED
DISCONNECTED, EXPIRED, TERMINATED -> (terminal, no outgoing edges)
```

## `guest_login_history`

Every login attempt, success or failure -- see `FLOW.md` §9 for the
`guest_id`-nullability reasoning.

| Column | Type | Notes |
|---|---|---|
| `guest_id` | UUID, FK `guests.id` (`SET NULL`), **nullable** | Populated only when a `Guest` row already exists for the identifier; never force-created on failure |
| `organization_id` / `location_id` | UUID, FK (`SET NULL`), nullable | Additive beyond the minimal spec -- mirrors `OtpRequest`'s own scope columns, lets analytics filter without joining through the nullable `guest_id` |
| `identifier` | String(255), not nullable | Always present, even when `guest_id` is null |
| `auth_method` | String(30) | |
| `success` | Boolean | |
| `failure_reason` | String(255), nullable | e.g. the failing exception's class name |
| `attempted_at` | DateTime(tz) | |
| `ip_address` | String(45), nullable | |

## `guest_consents`

A record of a guest accepting a captive portal's terms and conditions.

| Column | Type | Notes |
|---|---|---|
| `guest_id` | UUID, FK `guests.id` (`CASCADE`), not nullable | |
| `captive_portal_config_id` | UUID, FK `captive_portal_configs.id` (`SET NULL`), nullable | |
| `consented_at` | DateTime(tz) | |
| `terms_version` | String(50), nullable | Which version of the T&C was agreed to |
| `ip_address` | String(45), nullable | |

## `radius_nas_clients`

A router's registered FreeRADIUS NAS identity -- a router *is* a RADIUS
NAS, one-to-one. Extended by migration `0030` -- see `NAS_EXTENSION.md` for
the full design write-up behind every column below the original four
(`router_id`/`nas_identifier`/`shared_secret_encrypted`/`is_active`).

| Column | Type | Notes |
|---|---|---|
| `router_id` | UUID, FK `routers.id` (`CASCADE`), **unique** | One-to-one with `routers` |
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable | Denormalized from `router.organization_id` at registration time; backfilled for pre-existing rows |
| `location_id` | UUID, FK `locations.id` (`CASCADE`), not nullable | Denormalized from `router.location_id`; backfilled for pre-existing rows |
| `nas_code` | String(80), nullable, **partial unique** (`WHERE nas_code IS NOT NULL`) | Human-readable, e.g. `"NAS-LOC-2026-000001-0001"`. Nullable and never backfilled for pre-existing rows -- mirrors `Location.location_code`'s identical convention |
| `nas_identifier` | String(255), **unique** | The identifier FreeRADIUS's `rlm_rest` presents |
| `shared_secret_encrypted` | Text, not nullable | Fernet-encrypted via `app.domains.router.crypto.encrypt_secret` -- reused, not a new encryption mechanism; recoverable (not hashed), since a live comparison needs the plaintext back |
| `status` | String(20), default `active` | `pending`/`active`/`disabled`/`suspended`/`deleted` -- see `constants.NasStatus`. Backfilled from `is_active` for pre-existing rows |
| `is_active` | Boolean, default `true` | Kept as a synced, derived mirror of `status == active` -- `status` is the real source of truth as of this extension |
| `name` | String(200), nullable | Admin-facing label, distinct from `router.name` |
| `description` | Text, nullable | |
| `ip_address` | String(45), nullable | The RADIUS NAS-IP-Address value; defaults from `router.public_ip_address`/`management_ip_address` at registration, its own column thereafter |
| `vendor` | String(50), default `MikroTik` | A real, true default (every `Router` today is MikroTik) -- an extensibility seam, not a fabricated value |

## `guest_quota_usages` (new table -- Phase 1 BhaiFi-parity)

Migration `0034_create_guest_quota_usage_table.py` (revises
`0033_create_queue_management_tables`). Cumulative Fair Usage Policy (FUP)
data/time counters for one guest, one recurring period (daily/weekly/
monthly) at a time -- the guest-level aggregate `guest_sessions`' own
per-session `bytes_uploaded`/`bytes_downloaded` cannot answer on its own.
See `FLOW.md` §12 for the full read/bump/rollover write-up.

| Column | Type | Notes |
|---|---|---|
| `guest_id` | UUID, FK `guests.id` (`CASCADE`), not nullable | |
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), not nullable | Denormalized from `guests.organization_id` -- avoids a join to resolve `PolicyType.FUP`/`Organization.timezone` |
| `period_type` | String(20), not nullable | `constants.QuotaPeriodType` -- `daily`/`weekly`/`monthly` |
| `period_start` | DateTime(tz), not nullable | This row's current period boundary, computed from the guest's org's own `Organization.timezone` (`validators.compute_period_start`) |
| `bytes_used` | BigInteger, default `0` | Bumped on every RADIUS Interim-Update (`GuestService.record_usage`) |
| `minutes_used` | Integer, default `0` | Guest-level wall-clock connected time -- **not** summed across concurrent sessions; accrued by a periodic sweep (`tasks.run_fup_time_accrual_sweep`), not per-request |
| `last_accrued_at` | DateTime(tz), nullable | Last time the accrual sweep touched `minutes_used`; `NULL` until the first tick (or immediately after a reset) |

Unique index: `uq_guest_quota_usages_guest_id_period_type` on
`(guest_id, period_type)` -- one row per guest per period type.

## `radius_nas_code_counters` (new table)

The dedicated, atomic counter table backing `nas_code` generation --
structurally identical to `location_code_counters`.

| Column | Type | Notes |
|---|---|---|
| `counter_key` | String(80), **unique** | `"nas:<location_id>"` -- one row per location |
| `last_value` | Integer, default `0` | Incremented via a single atomic `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` |

## Facts genuinely new vs. reused from elsewhere

* **New** (no existing column anywhere): every column on all six original
  tables -- nothing elsewhere in this codebase models a guest identity,
  device, session, login history, consent, or RADIUS NAS client. Phase 1
  BhaiFi-parity adds a seventh table (`guest_quota_usages`) plus
  `PAUSED` (a new `guest_sessions.status` value, no column change).
* **Reused, not duplicated**: `organizations.id`/`locations.id`/
  `routers.id`/`vouchers.id`/`captive_portal_configs.id` as FK targets (no
  schema change to any of them); `audit_log_entries` (RBAC) as the audit
  sink, via additive `AuditAction` values (5 original +
  `GUEST_SESSION_PAUSED`/`_RESUMED`/`_EXTENDED` for Phase 1) -- no new
  audit table; `app.domains.router.crypto` for
  `RadiusNasClient.shared_secret_encrypted` -- no new encryption
  mechanism.

## Entity-relationship summary

```text
organizations --< guests (organization_id, NOT NULL)
locations     --< guests (location_id, nullable)
guests        --< guest_devices (guest_id, NOT NULL, reassignable)
guests        --< guest_sessions (guest_id, NOT NULL)
guest_devices --< guest_sessions (device_id, nullable)
routers       --< guest_sessions (router_id, NOT NULL)
locations     --< guest_sessions (location_id, NOT NULL)
organizations --< guest_sessions (organization_id, NOT NULL, denormalized)
vouchers      --< guest_sessions (voucher_id, nullable)
guests        --< guest_login_history (guest_id, nullable)
organizations --< guest_login_history (organization_id, nullable)
locations     --< guest_login_history (location_id, nullable)
guests        --< guest_consents (guest_id, NOT NULL)
captive_portal_configs --< guest_consents (captive_portal_config_id, nullable)
routers       --- radius_nas_clients (router_id, UNIQUE -- one-to-one)
organizations --< radius_nas_clients (organization_id, NOT NULL, denormalized)
locations     --< radius_nas_clients (location_id, NOT NULL, denormalized)
guests        --< guest_quota_usages (guest_id, NOT NULL)
organizations --< guest_quota_usages (organization_id, NOT NULL, denormalized)
```

No other existing table gained a new column or FK for the original six
tables -- like Module 010 Parts 1-3, none of them are referenced by any
RBAC scope column, so no RBAC follow-up migration was needed there. Phase 1
BhaiFi-parity's `guest_quota_usages` addition is likewise additive-only
(a new table, no existing column touched) and needs no RBAC schema change
of its own -- it has no dedicated admin CRUD endpoints (read/written
entirely by `GuestService`'s login-time enforcement, RADIUS accounting
bump, and the two new Celery Beat sweeps).
