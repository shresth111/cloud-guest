# ISP Routing Domain -- Database Schema

Migration: `alembic/versions/0037_create_isp_routing_tables.py`. See
`FLOW.md` for the full design reasoning behind each decision below.

## `isp_routing_rules` (new table)

One row per traffic-steering rule. A rule's own row *is* its current state
-- see `FLOW.md` §5 for why there is no history table.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `router_id` | `UUID` | No | FK -> `routers.id`, `ondelete="CASCADE"`. |
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. Denormalized from the owning `Router` at creation time, immutable after. |
| `location_id` | `UUID` | No | FK -> `locations.id`, `ondelete="CASCADE"`. Same denormalization convention. |
| `isp_link_id` | `UUID` | No | FK -> `isp_links.id`, `ondelete="CASCADE"`. Must belong to the same `router_id` -- enforced at the service layer, see `FLOW.md` §3. |
| `rule_type` | `VARCHAR(20)` | No | One of `constants.IspRoutingRuleType`'s values (vlan/user/ip/source/interface/policy). |
| `name` | `VARCHAR(200)` | No | Admin-facing label. |
| `description` | `TEXT` | Yes | |
| `priority` | `INTEGER` | No | `server_default 0`. Lower value tried first -- mirrors `IspLink.priority`'s own convention, see `FLOW.md` §4. |
| `is_enabled` | `BOOLEAN` | No | `server_default true`. |
| `vlan_id` | `INTEGER` | Yes | Populated iff `rule_type == "vlan"`. |
| `source_mac_address` | `VARCHAR(17)` | Yes | Populated iff `rule_type == "user"`. |
| `ip_address` | `VARCHAR(45)` | Yes | Populated iff `rule_type == "ip"`. |
| `source_cidr` | `VARCHAR(64)` | Yes | Populated iff `rule_type == "source"`. |
| `interface_name` | `VARCHAR(100)` | Yes | Populated iff `rule_type == "interface"`. |
| `policy_id` | `UUID` | Yes | FK -> `policies.id`, `ondelete="SET NULL"`. Populated iff `rule_type == "policy"`. |

Exactly one of the six match columns above is populated per row, enforced
at the service layer (`validators.validate_match_fields`), not a database
`CHECK` constraint -- see `FLOW.md` §1.

Plus the standard `BaseModel` columns (`id`, `created_at`, `updated_at`,
`deleted_at`, `is_deleted`, `created_by`, `updated_by`, `version`).

Indexes: `ix_isp_routing_rules_router_id`,
`ix_isp_routing_rules_organization_id`,
`ix_isp_routing_rules_location_id`, `ix_isp_routing_rules_isp_link_id`,
`ix_isp_routing_rules_rule_type`, `ix_isp_routing_rules_is_enabled`.

No circular/deferred foreign keys are needed -- every FK here is
one-directional and declared inline at table-creation time, mirroring
migration `0036`'s identical note.

## No RBAC schema change beyond a brand-new, additive module

This feature's only edit to `app.domains.rbac` is a brand-new, additive
`PermissionModule.ISP_ROUTING` seeded module (`enums.py`/`seed.py`) plus
additive `AuditAction` enum values (`ISP_ROUTING_RULE_CREATED`/
`ISP_ROUTING_RULE_UPDATED`/`ISP_ROUTING_RULE_DELETED`) -- no migration
needed for any of those (`permission_groups`/`permissions`/
`permission_scopes`/`role_permissions` rows are all seeded idempotently at
application/CLI startup by `seed_rbac`, never by a migration, per this
codebase's own established convention -- see e.g. migration `0036`'s
identical note).
