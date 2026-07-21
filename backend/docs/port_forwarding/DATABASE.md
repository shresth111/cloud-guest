# Port Forwarding Management Domain -- Database Schema

Migration: `alembic/versions/0040_create_port_forwarding_tables.py`. See
`FLOW.md` for the full design reasoning behind each decision below.

## `port_forwarding_rules` (new table)

One row per port-forwarding (NAT DSTNAT) rule a router carries. A row's
own state *is* its current state -- see `FLOW.md` §5 for why there is no
history table.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `router_id` | `UUID` | No | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Denormalized from the owning `Router` at creation time, immutable after. |
| `location_id` | `UUID` | No | FK -> `locations.id`, `ondelete="CASCADE"`. Same denormalization convention. |
| `name` | `VARCHAR(200)` | No | Admin-facing label. |
| `protocol` | `VARCHAR(10)` | No | `server_default 'both'` -- one of `constants.PortForwardingProtocol`'s values (tcp/udp/both). |
| `source_address` | `VARCHAR(64)` | Yes | An IP or CIDR restricting which originating source may use this rule. `NULL` means "any source". Validated at the service layer via `ipaddress.ip_network`. |
| `destination_address` | `VARCHAR(64)` | Yes | An IP or CIDR matching the router's own WAN address this rule applies to. `NULL` means "any of this router's own addresses". Same validation. |
| `destination_port` | `INTEGER` | No | The external port, 1-65535. |
| `internal_address` | `VARCHAR(45)` | No | The internal forwarding target -- always a single host, never a CIDR (see `FLOW.md` §3). Validated at the service layer via `ipaddress.ip_address`. |
| `internal_port` | `INTEGER` | No | The internal target port, 1-65535. |
| `description` | `TEXT` | Yes | |
| `is_enabled` | `BOOLEAN` | No | `server_default true`. |

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_port_forwarding_rules_router_id`,
`ix_port_forwarding_rules_organization_id`,
`ix_port_forwarding_rules_location_id`,
`ix_port_forwarding_rules_destination_port`,
`ix_port_forwarding_rules_is_enabled`.

No conflict-detection database constraint -- see `FLOW.md` §1 for why
this is a service-layer check only (`PortForwardingConflictError`), not a
database `EXCLUDE` constraint.

No circular/deferred foreign keys are needed -- every FK here is
one-directional and declared inline at table-creation time, mirroring
migration `0039`'s identical note.

## No RBAC schema change beyond reusing an already-seeded module

This feature's only edit to `app.domains.rbac` is additive `AuditAction`
enum values (`PORT_FORWARDING_RULE_CREATED`/`PORT_FORWARDING_RULE_UPDATED`/
`PORT_FORWARDING_RULE_DELETED`) -- `PermissionModule.FIREWALL`, its action
tuple, its `ScopeType.ROUTER` narrowest scope, and the "Network
Administrator" system role's own grant all already existed and required
no changes (see `FLOW.md` §4). No migration is needed for any RBAC data
-- `permission_groups`/`permissions`/`permission_scopes`/
`role_permissions` rows are all seeded idempotently at application/CLI
startup by `seed_rbac`, never by a migration, per this codebase's own
established convention -- see e.g. migration `0039`'s identical note.
