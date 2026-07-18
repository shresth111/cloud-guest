# Module 009 Part 3: WireGuard

The WireGuard domain (`app.domains.wireguard`) gives the platform a stable
way to reach a router's management interface even when the physical device
sits behind carrier-grade NAT with no public IP -- common for guest-WiFi
deployments. The platform runs a WireGuard "hub" (`WireGuardServer`); each
router is a "peer" (`WireGuardPeer`) tunnelled back to it. Once the tunnel
is up, the router has a stable, always-reachable tunnel-internal IP,
regardless of what NAT sits in front of its real WAN connection.

This is BE-009's third and final part, alongside Part 1
(`app.domains.router_provisioning`: config engine/queue/enrollment) and
Part 2 (`app.domains.router_agent`: device credential + heartbeat/
config-pull/status-push/action-queue).

See `FLOW.md` for the full tunnel lifecycle and every non-obvious design
decision, and `DATABASE.md` for the two new tables and their relationships.

## Cloud-Managed WireGuard, In One Paragraph

Unlike a normal, self-managed WireGuard deployment (where each peer
generates its own keypair and only ever hands the hub its *public* key),
this platform's cloud-managed model has **the platform generate both
sides' keypairs**, including the router-peer's. That is the only way this
works for a device the platform cannot always reach directly to run a
self-service setup wizard on: zero-touch provisioning (BE-009 Parts 1/2)
already establishes the pattern of the platform deciding a device's
configuration and pushing it down wholesale, and this module extends that
same posture to WireGuard key material. The consequence: a peer's private
key must be recoverable by the platform (so it can ever be handed to the
device), so it is stored Fernet-encrypted via the exact same
`app.domains.router.crypto.encrypt_secret`/`decrypt_secret` helpers BE-008
already established for `Router.api_credentials_encrypted` -- see
`FLOW.md` §1 for why this is the right reuse, not a new mechanism.

## What This Module Does NOT Do

* **It does not run a real WireGuard daemon.** There is no live `wg show`
  integration anywhere in this sandbox. Tunnel health
  (`GET /routers/{id}/wireguard-peer`'s `health_status` field) is a
  DB-tracked, device-*reported* signal derived from
  `WireGuardPeer.last_handshake_at` against a configurable staleness
  threshold (`Settings.wireguard_handshake_stale_after_minutes`) -- the
  same honest "interim design" posture BE-008's own `Router.health_status`
  and BE-009's simulated provisioning already establish. A production
  hardening pass would replace this with real `wg show`/kernel-interface
  polling on the hub side.
* **It does not support multiple active hubs / multi-region routing.**
  Exactly one active `WireGuardServer` is assumed for this platform's
  current scale -- a deliberate simplification, not a schema limitation
  (see `models.WireGuardServer`'s own docstring and `FLOW.md` §7). The
  table supports more than one row; nothing prevents a future
  region-aware hub-selection strategy from being implemented purely inside
  `WireGuardRepository.get_active_server`, with no migration required.
* **It does not build a second encryption mechanism.** Every
  Fernet-encrypted secret in this module reuses
  `app.domains.router.crypto` exactly as-is.
* **It does not build a second device-credential scheme.** The
  device-facing endpoints in this module depend on
  `app.domains.router_agent.dependencies.CurrentAgent` -- the same
  persistent, hashed bearer credential (`X-Agent-Credential` header) every
  other device-facing endpoint in this codebase already uses. See `FLOW.md`
  §5 for the exact composition.
* **It does not expose hub (`WireGuardServer`) CRUD over HTTP.** Hub
  management is a service-layer capability in this iteration (tested
  directly, see `tests/unit/test_wireguard.py::TestHubCrud`) -- bootstrapping
  a single hub is an operational/seed concern today, not a per-tenant one,
  consistent with the module brief's own deliberately narrow, five-endpoint
  admin-facing surface. A future admin UI/endpoint for multi-hub management
  is out of scope here.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0011_create_wireguard_tables.py
  app/
    domains/
      wireguard/
        __init__.py
        constants.py      # PeerStatus, HealthStatus, key/IP/keepalive constants
        models.py          # WireGuardServer, WireGuardPeer (see DATABASE.md)
        exceptions.py       # WireGuardError subclasses (CloudGuestError)
        events.py            # Plain dataclasses, logged synchronously by service.py
        validators.py          # Pure business-rule checks + IP allocator (no I/O)
        repository.py           # WireGuardRepositoryProtocol + repo
        service.py               # WireGuardService: the whole domain's business logic
        schemas.py                # Pydantic request/response DTOs
        dependencies.py            # FastAPI dependency wiring (reuses router_agent's CurrentAgent)
        router.py                   # FastAPI routes
      rbac/
        enums.py                    # AuditAction gained 3 additive WIREGUARD_* values
    core/
      config.py                     # Settings gained wireguard_handshake_stale_after_minutes
    api/
      v1/
        router.py                   # wireguard_router registered
  docs/
    wireguard/
      README.md
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_wireguard.py
```

## API Surface

Admin-facing endpoints (registered under `/api/v1`, see `app/api/v1/router.py`)
use the standard `ApiResponse`/`build_response` envelope and are gated by
RBAC's `RequirePermission` against the already-seeded `wireguard.*`
permission keys:

```text
GET    /api/v1/routers/{router_id}/wireguard-peer          wireguard.read
POST   /api/v1/routers/{router_id}/wireguard-peer          wireguard.create
DELETE /api/v1/routers/{router_id}/wireguard-peer          wireguard.delete
POST   /api/v1/routers/{router_id}/wireguard-peer/rotate   wireguard.execute
```

Device-facing endpoints are authenticated by
`app.domains.router_agent.dependencies.CurrentAgent` (the
`X-Agent-Credential` header), not RBAC, and do not use the `ApiResponse`
envelope -- mirroring `app.domains.router_agent.router`'s own device-facing
endpoints exactly:

```text
GET  /api/v1/agent/wireguard-config
POST /api/v1/agent/wireguard-config/handshake
```

`POST /agent/wireguard-config/handshake` is one additive endpoint beyond
the module brief's literal five -- see `FLOW.md` §6 for why.

## Reused, Not Duplicated

* `GenericRepository` (Module 002).
* `app.domains.router.crypto.encrypt_secret`/`decrypt_secret` (BE-008) --
  both the hub's and every peer's private key are encrypted through this
  exact helper. No new cryptographic mechanism.
* `cryptography`'s `X25519PrivateKey`/`X25519PublicKey` (already a
  transitive capability of the `cryptography` package this codebase depends
  on for Fernet) for WireGuard keypair generation -- no new dependency.
  Confirmed present and usable in the pinned `cryptography==44.0.0`.
* Python's stdlib `ipaddress` module for tunnel-IP allocation -- no new
  dependency.
* `RouterService.get_router` (BE-008) -- composed through a narrow
  `RouterLookupProtocol`, giving this module tenant isolation and
  router-eligibility (`decommissioned`/`suspended`) enforcement for free.
* `app.domains.router_agent.dependencies.CurrentAgent`/`AgentIdentity` --
  imported and reused as-is for both device-facing endpoints, never
  reimplemented.
* RBAC's `audit_log_entries` (via the same narrow `AuditLogWriter` protocol
  shape every other domain's service uses) with 3 additive `AuditAction`
  values.
* `CloudGuestError` (Module 001).

## New, Not Reused (Genuine Additions)

* `WireGuardServer`/`WireGuardPeer` -- genuinely new tables; nothing
  elsewhere models a WireGuard hub or a router's tunnel/peer registration.
* `validators.allocate_tunnel_ip` -- a from-scratch, stdlib-`ipaddress`
  -based next-free-address allocator; no existing IP-allocation logic
  anywhere in this codebase to reuse.
* `PeerStatus`/`HealthStatus` -- genuinely new lifecycle/health concepts
  specific to a WireGuard tunnel.
* `Settings.wireguard_handshake_stale_after_minutes` -- a new, additive
  config field following the exact pattern of every other domain-specific
  `Settings` field already in `app/core/config.py`.

## Testing

`tests/unit/test_wireguard.py` exercises `WireGuardService` against a
**real** `RouterService` instance (itself wired against small in-memory
fakes, mirroring `test_router_agent.py`'s own `make_services` setup) rather
than a hand-rolled fake for it. Coverage: hub CRUD, tunnel-IP allocation
(collision-skipping, pool exhaustion, and a simulated concurrent-allocation
race exercising the retry-then-succeed / retry-exhausted paths), automatic
tunnel creation (keypair generation, encrypted storage, decrypt
round-trip), peer revoke + re-create (row reuse, IP freed for reuse), key/
tunnel rotation (same IP, new keys, status reset), device-facing config
pull composed through the real `CurrentAgent` dependency (with and without
a valid credential), handshake reporting, health-status staleness
threshold logic, and tenant isolation. All 272 previously-passing tests
continue to pass unmodified, plus 45 new tests here (317 total).
