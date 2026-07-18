# Router Agent: Database Schema

Migration: `alembic/versions/0010_create_router_agent_tables.py` (revises
`0009_create_router_provisioning_tables`). One new table, extending
`app.database.base.BaseModel` (`id`, `created_at`, `updated_at`,
`deleted_at`/`is_deleted`, `created_by`/`updated_by`, `version`) -- no
changes to any existing table's columns.

## `router_agent_credentials`

A persistent, hashed bearer credential authenticating every ongoing
device-facing call this module exposes -- distinct from, and issued only
after, BE-008's one-time `RouterProvisioningToken` has already been
consumed at check-in. See `FLOW.md` §2 for the full issuance-timing
reasoning.

| Column | Type | Notes |
|---|---|---|
| `router_id` | UUID, FK `routers.id` (`CASCADE`), **unique** | One credential per router; a reissue rotates this same row |
| `credential_hash` | String(128), **unique** | SHA-256 hex digest -- plaintext is never stored, only returned once, in BE-008's check-in response |
| `issued_at` | DateTime | Refreshed on every rotation |
| `expires_at` | DateTime | `issued_at + credential_ttl_days` (constructor-configurable, default `constants.AGENT_CREDENTIAL_TTL_DAYS` = 365) |
| `last_used_at` | DateTime, nullable | Updated on every successful `CurrentAgent` resolution |
| `revoked_at` | DateTime, nullable | Cleared (`NULL`) on a subsequent reissue/rotation |
| `rotation_count` | Integer | Incremented on every reissue (0 at first issuance) |
| `agent_software_version` | String(100), nullable | The agent software's own version, e.g. `"cloudguest-agent 1.2.0"` -- distinct from `routers.routeros_version` |
| `capabilities` | JSONB | Model detection / supported features / interface list -- whatever a real RouterOS device reports |
| `license_key` | String(255), nullable | |
| `license_status` | String(20) | `constants.AgentLicenseStatus` (`valid`/`invalid`/`expired`/`unknown`) |
| `last_status_report_at` | DateTime, nullable | Set on every `POST /agent/status` call |

Constraints: `UNIQUE (router_id)`, `UNIQUE (credential_hash)`. Indexes:
`router_id` (unique), `credential_hash` (unique), `expires_at`,
`revoked_at`.

## Why one table, not two

This row plays two roles for the same router, both strictly one-to-one with
it: (1) the persistent device-identity credential itself (`credential_hash`/
`issued_at`/`expires_at`/`revoked_at`/`rotation_count`), and (2) the agent's
most-recently-self-reported status (`agent_software_version`/
`capabilities`/`license_key`/`license_status`/`last_status_report_at`). A
genuine second table (e.g. `RouterAgentStatus`) was considered and
rejected: both halves share the exact same cardinality (`router_id` unique,
one row per router) and the exact same lifecycle (created once at
credential issuance, then updated in place on every subsequent call) --
splitting them would only add a mandatory one-to-one join for no distinct
query need, the identical "don't split what has no independent lifecycle"
reasoning `app.domains.router_provisioning.models.ConfigVersion.is_backup`
documents for why a backup is a tagged `ConfigVersion` rather than a
separate `RouterBackup` table.

## Facts genuinely new vs. reused from elsewhere

* **New** (no existing column anywhere): `agent_software_version`,
  `capabilities`, `license_key`, `license_status`. Nothing in
  BE-008/Module 009 Part 1 tracks the agent software's own version, its
  reported capabilities, or license state.
* **Reused, not duplicated**: `routeros_version` already lives on
  `routers.routeros_version` (BE-008) -- `POST /agent/status` updates it via
  `RouterService.update_router`, this table never carries a second copy of
  it. The router's current configuration lives on Module 009 Part 1's own
  `config_versions`/`config_profiles` -- this table never stores rendered
  config text.

## Entity-relationship summary

```text
routers --< router_agent_credentials (router_id, unique -- one per router)
```

No other table gained a new column or FK for this module -- the two
optional fields added to `ProvisioningCheckInResponse`
(`agent_credential`/`agent_credential_expires_at`) are a Pydantic schema
change only, not a database column.
