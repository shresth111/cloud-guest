# WireGuard: Database Schema

Migration: `alembic/versions/0011_create_wireguard_tables.py` (revises
`0010_create_router_agent_tables`). Two new tables, both extending
`app.database.base.BaseModel` (`id`, `created_at`, `updated_at`,
`deleted_at`/`is_deleted`, `created_by`/`updated_by`, `version`) -- no
changes to any existing table's columns.

## `wireguard_servers`

A platform-operated WireGuard concentrator ("hub"). Every
`WireGuardPeer` tunnels back to exactly one hub, identified by `server_id`.

| Column | Type | Notes |
|---|---|---|
| `name` | String(150) | |
| `endpoint_host` | String(255) | Public hostname/IP a router dials to reach this hub |
| `endpoint_port` | Integer | Default `51820` (`constants.DEFAULT_WIREGUARD_PORT`) |
| `public_key` | String(64), **unique** | Base64-encoded 32-byte X25519 public key |
| `private_key_encrypted` | Text | Fernet ciphertext (`app.domains.router.crypto`) -- never leaves the platform, still encrypted at rest for defense-in-depth |
| `tunnel_network_cidr` | String(64) | e.g. `"10.100.0.0/16"` -- the address space peer tunnel IPs are allocated from |
| `is_active` | Boolean | See "single-hub simplification" in `FLOW.md` §3 -- no schema-level singleton constraint |

Constraints: `UNIQUE (public_key)`. Indexes: `is_active`, `public_key`
(unique), plus the standard `BaseModel` indexes.

## `wireguard_peers`

One router's WireGuard tunnel/peer registration.

| Column | Type | Notes |
|---|---|---|
| `router_id` | UUID, FK `routers.id` (`CASCADE`), **unique** | One peer per router, ever; re-creation after revocation reuses this same row (see `FLOW.md` §5) |
| `server_id` | UUID, FK `wireguard_servers.id` (`RESTRICT`) | Which hub this peer tunnels to |
| `tunnel_ip_address` | String(45) | Allocated from the hub's `tunnel_network_cidr` by `validators.allocate_tunnel_ip` |
| `public_key` | String(64), **unique** | Base64-encoded 32-byte X25519 public key -- platform-generated |
| `private_key_encrypted` | Text | Fernet ciphertext -- the peer's own private key, delivered to the device via `GET /agent/wireguard-config` |
| `status` | String(20) | `constants.PeerStatus` (`pending`/`active`/`revoked`) -- see `constants.PEER_STATUS_TRANSITIONS` |
| `rotation_count` | Integer | Incremented on every key rotation and every revoke-then-recreate cycle (0 at first creation) |
| `last_handshake_at` | DateTime, nullable | Device-reported liveness signal; `NULL` means "unknown" (never `None`-as-its-own-enum-value, mirrors `Router.health_status`) |
| `revoked_at` | DateTime, nullable | Set when `status` transitions to `revoked`; cleared on a subsequent revoke-then-recreate |

Constraints: `UNIQUE (router_id)`, `UNIQUE (public_key)`,
`UNIQUE (server_id, tunnel_ip_address)` -- the last one is the real
race-safety net for tunnel-IP allocation (see `FLOW.md` §4). Indexes:
`router_id` (unique), `server_id`, `status`, `tunnel_ip_address`, plus the
standard `BaseModel` indexes.

`health_status` is **not** a column -- it is computed at read time by
`WireGuardService.compute_health_status` from `last_handshake_at` against
`Settings.wireguard_handshake_stale_after_minutes` (see `FLOW.md` §7), so
it can never drift stale between reads.

## Why one `WireGuardPeer` row per router, not append-only history

Unlike `app.domains.router_provisioning.models.ConfigVersion` (where every
past rendered config is independently meaningful audit trail, so
apply/rollback always creates a *new* row and marks the old one
superseded), a router's *previous* WireGuard keypair/tunnel IP has no
standalone value once superseded -- it is dead key material pointing at an
address no longer routed to that peer. `rotation_count`, this module's
`TunnelRotated`/`TunnelRevoked` domain events (`events.py`, logged
synchronously), and the `audit_log_entries` row every mutation writes are
what preserve *that* a rotation/revocation happened and when, without a
second table duplicating three columns (router, actor, timestamp) already
captured twice over -- the identical "don't add a table for data already
captured" discipline `app.domains.router_provisioning.models`'s own module
docstring documents for why it has no `RouterSecretRotationLog`. This
mirrors `app.domains.router_agent.models.RouterAgentCredential`'s own
unique-FK-plus-in-place-rotation design far more closely than
`ConfigVersion`'s append-only one.

## Facts genuinely new vs. reused from elsewhere

* **New** (no existing column anywhere): every column on both tables --
  nothing elsewhere in this codebase models a WireGuard hub or a router's
  tunnel/peer registration.
* **Reused, not duplicated**: encryption (`app.domains.router.crypto`),
  tenant scoping/router-eligibility (BE-008's `RouterService`), and device
  authentication (`app.domains.router_agent`'s `CurrentAgent`) -- none of
  these needed a new column anywhere, only composition at the service
  layer (see `README.md`'s "Reused, Not Reused" section).

## Entity-relationship summary

```text
wireguard_servers --< wireguard_peers (server_id)
routers           --< wireguard_peers (router_id, unique -- one per router)
```

No other existing table gained a new column or FK for this module -- unlike
BE-008/Module 009 Part 2's own follow-up migrations (0004/0006/0008 added
FKs to RBAC's scope tables), neither `wireguard_servers` nor
`wireguard_peers` is referenced by any RBAC scope column, so no RBAC
follow-up migration is needed here.
