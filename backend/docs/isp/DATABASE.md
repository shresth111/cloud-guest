# ISP Management Domain -- Database Schema

Migration: `alembic/versions/0036_create_isp_management_tables.py`. See
`FLOW.md` for the full design reasoning behind each decision below.

## `isp_links` (new table)

One row per WAN uplink a router carries -- holds both its static
admin-assigned priority (`role`/`priority`) and its *current* health
snapshot directly as columns (see `FLOW.md` §2 for the "current state +
history" split).

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `router_id` | `UUID` | No | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Denormalized from the owning `Router` at creation time, immutable after. |
| `location_id` | `UUID` | No | FK -> `locations.id`, `ondelete="CASCADE"`. Same denormalization convention. |
| `provider_name` | `VARCHAR(200)` | No | |
| `link_type` | `VARCHAR(20)` | No | `server_default 'other'` -- one of `constants.IspLinkType`'s values (fiber/dsl/cable/wireless_4g/wireless_5g/satellite/leased_line/other). Informational only. |
| `role` | `VARCHAR(10)` | No | One of `constants.IspLinkRole`'s values (`primary`/`backup`). Exactly one `PRIMARY` row per router, enforced at the service layer. |
| `is_active_uplink` | `BOOLEAN` | No | `server_default false`. Which link is *currently* carrying traffic -- see `FLOW.md` §2. |
| `auto_failback` | `BOOLEAN` | No | `server_default true`. Only meaningful on the `PRIMARY` row. |
| `is_enabled` | `BOOLEAN` | No | `server_default true`. An admin's own reversible "take this link out of service" toggle -- distinct from `health_status`. |
| `priority` | `INTEGER` | No | `server_default 0`. Lower value tried first among a router's own `BACKUP` links during failover. |
| `interface` | `VARCHAR(100)` | Yes | The router's own WAN-facing interface name (e.g. `"ether1"`). Informational only. |
| `gateway_ip_address` | `VARCHAR(45)` | Yes | Health-check ping target; falls back to the router's own management/public IP if unset. |
| `dns_primary` / `dns_secondary` | `VARCHAR(45)` | Yes | |
| `download_bandwidth_mbps` / `upload_bandwidth_mbps` | `INTEGER` | Yes | |
| `health_status` | `VARCHAR(20)` | No | `server_default 'unknown'` -- one of `constants.HealthStatus`'s values. `UNKNOWN` until the first real health check ever runs (never defaulted to `HEALTHY`). |
| `latency_ms` | `FLOAT` | Yes | Most recent `avg-rtt` reading. |
| `packet_loss_percentage` | `FLOAT` | Yes | Most recent reading. |
| `last_checked_at` | `TIMESTAMPTZ` | Yes | |
| `consecutive_unhealthy_count` | `INTEGER` | No | `server_default 0`. Reset to 0 the moment a check comes back `HEALTHY` or `DEGRADED`. Drives `constants.DEFAULT_CONSECUTIVE_FAILURES_BEFORE_FAILOVER`. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_isp_links_router_id`, `ix_isp_links_organization_id`,
`ix_isp_links_location_id`, `ix_isp_links_role`,
`ix_isp_links_health_status`, `ix_isp_links_is_enabled`, plus the partial
unique index enforcing "at most one active uplink per router":

```sql
CREATE UNIQUE INDEX uq_isp_links_router_id_active_uplink
  ON isp_links (router_id)
  WHERE is_active_uplink = true AND is_deleted = false;
```

## `isp_health_checks` (new table)

An append-only time-series log of every real health-check execution
against an `isp_links` row's own `gateway_ip_address`, mirroring
`monitoring.models.HealthCheck`'s identical shape.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `isp_link_id` | `UUID` | No | FK -> `isp_links.id`, `ondelete="CASCADE"`. |
| `checked_at` | `TIMESTAMPTZ` | No | |
| `status` | `VARCHAR(20)` | No | One of `constants.HealthStatus`'s values -- the classification result for this one check. |
| `latency_ms` | `FLOAT` | Yes | |
| `packet_loss_percentage` | `FLOAT` | Yes | |
| `error_message` | `TEXT` | Yes | |

Plus the standard `BaseModel` columns.

Indexes: `ix_isp_health_checks_isp_link_id`,
`ix_isp_health_checks_checked_at`.

No circular/deferred foreign keys are needed -- every FK here is
one-directional and declared inline at table-creation time, mirroring
migration `0033`'s identical note.

## No RBAC schema change beyond a brand-new, additive module

This feature's only edit to `app.domains.rbac` is a brand-new, additive
`PermissionModule.ISP` seeded module (`enums.py`/`seed.py`) plus additive
`AuditAction` enum values (`ISP_LINK_CREATED`/`ISP_LINK_UPDATED`/
`ISP_LINK_DELETED`/`ISP_FAILOVER_TRIGGERED`/`ISP_FAILBACK_TRIGGERED`) --
no migration needed for any of those (`permission_groups`/`permissions`/
`permission_scopes`/`role_permissions` rows are all seeded idempotently at
application/CLI startup by `seed_rbac`, never by a migration, per this
codebase's own established convention -- see e.g. migration `0033`'s
identical note).
