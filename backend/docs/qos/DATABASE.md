# QoS & VOIP Priority Domain -- Database Schema

Migration: `alembic/versions/0045_create_qos_tables.py`. See `FLOW.md`
for the full design reasoning behind each decision below.

## `qos_traffic_rules` (new table)

One row per traffic-classification rule a router applies. A row's own
state *is* its current state -- there is no history table; real device
provisioning is composed via `app.domains.network_config`, not tracked
here.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `router_id` | `UUID` | No | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Denormalized from the owning `Router` at creation time, immutable after. |
| `location_id` | `UUID` | No | FK -> `locations.id`, `ondelete="CASCADE"`. Same denormalization convention. |
| `name` | `VARCHAR(200)` | No | Admin-facing label. No uniqueness constraint -- mirrors `dhcp_pools.name`/`hotspot_profiles.name`'s own identical posture. |
| `protocol` | `VARCHAR(10)` | Yes | `"tcp"`/`"udp"` (see `constants.QosProtocol`) -- required together with a port range, `NULL` for a DSCP-only rule. |
| `port_range_start` / `port_range_end` | `INTEGER` | Yes | Both required together for a port-range match (1-65535, start <= end); both `NULL` for a DSCP-only rule. |
| `dscp_value` | `INTEGER` | Yes | 0-63 (IETF RFC 2474's 6-bit field). `NULL` for a port-range rule. |
| `priority` | `INTEGER` | No | `server_default 8` -- reuses `app.domains.queue_management`'s own real RouterOS 1-8 range; validated at the service layer, not a database `CHECK` constraint. |
| `is_enabled` | `BOOLEAN` | No | `server_default true`. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_qos_traffic_rules_router_id`,
`ix_qos_traffic_rules_organization_id`,
`ix_qos_traffic_rules_location_id`, `ix_qos_traffic_rules_is_enabled`.

No database-level constraint enforcing "exactly one match kind" (port
range vs. DSCP) -- see `FLOW.md` §4 for why this is a service-layer
check only (`validators.validate_traffic_match`), not a SQL `CHECK`.

No circular/deferred foreign keys are needed -- every FK here is
one-directional and declared inline at table-creation time, mirroring
migration `0044`'s identical note.

## RBAC schema change: a genuinely new permission module

Unlike `PermissionModule.HOTSPOT` (already pre-seeded before its domain
was built), `PermissionModule.QOS` (`rbac/enums.py`) is a brand-new,
additive enum member -- no pre-existing, unclaimed module fit this
domain's own scope (see `FLOW.md` §3). Three additive `AuditAction` enum
values (`QOS_TRAFFIC_RULE_CREATED`/`_UPDATED`/`_DELETED`) were also
added. No migration needed for any of this, since `permission_groups`/
`permissions`/`permission_scopes`/`role_permissions` rows are all seeded
idempotently at application/CLI startup by `seed_rbac`, never by a
migration (see migration `0039`'s identical note).
