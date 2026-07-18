# WireGuard: Flows and Design Decisions

This document records every design decision this module made where the
brief left room for judgment, plus the end-to-end tunnel lifecycle. Read
this before modifying `app/domains/wireguard/`.

## 1. Why the peer's private key is Fernet-encrypted via BE-008's crypto helper

**Decision: reuse `app.domains.router.crypto.encrypt_secret`/
`decrypt_secret` exactly as-is. No second encryption mechanism.**

Every existing *hashed* secret in this codebase
(`RouterProvisioningToken.token_hash`, `RouterAgentCredential
.credential_hash`) is one-way by design: the platform only ever needs to
compare a device-presented bearer credential, never recover it. A
WireGuard peer's private key is a fundamentally different kind of secret --
in this platform's cloud-managed model, **the platform generates it**, not
the device, which means the platform must be able to decrypt it back to
plaintext in order to ever hand it to the device at all. That is exactly
the problem `app.domains.router.crypto` was already built to solve for
`Router.api_credentials_encrypted` (a RouterOS API password the platform
must also recover to open a live API connection). Reusing it here -- and
for the hub's own private key, which never leaves the platform but is
still encrypted at rest for defense-in-depth -- means this module adds
zero new cryptographic surface area to audit, and inherits that helper's
own documented caveats as-is (a single application-level key, not a real
KMS integration; see `app.domains.router.crypto`'s own module docstring).

## 2. WireGuard key generation: `cryptography`'s X25519 classes, no new dependency

WireGuard uses Curve25519 (X25519) keypairs: a 32-byte private scalar, a
32-byte public point, both conventionally base64-encoded (exactly what
`wg genkey`/`wg pubkey` produce). Before writing any code, the pinned
`cryptography==44.0.0` package (already a dependency, for Fernet) was
checked directly:

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
priv = X25519PrivateKey.generate()
pub = priv.public_key()
priv.private_bytes_raw()   # -> 32 raw bytes
pub.public_bytes_raw()     # -> 32 raw bytes
```

Both raw-bytes accessors are present and produce exactly the 32-byte shape
needed. `service.generate_wireguard_keypair` therefore only adds stdlib
`base64` encoding on top -- no new dependency was added for key generation.

## 3. Single-hub simplification, not a schema limitation

**Decision: exactly one active `WireGuardServer` for this platform's
current scale, but the schema itself supports more than one row.**

`WireGuardServer` carries no `UNIQUE`/`CHECK` constraint limiting
`is_active=true` to a single row. `WireGuardRepository.get_active_server`
resolves "the" hub via a query (`WHERE is_active = true LIMIT 1`), which is
free to be reinterpreted later (e.g. "the nearest active hub to this
router's region", or a load-balancing strategy across several active hubs)
without any migration. Multi-region hub support is explicitly out of scope
for this iteration and left as documented future work.

## 4. Tunnel-IP allocation

**Algorithm.** `validators.allocate_tunnel_ip(cidr, occupied)` uses stdlib
`ipaddress.ip_network(cidr).hosts()` (already excludes the network/
broadcast addresses), skips the hub's own reserved leading address
(`constants.HUB_RESERVED_HOST_COUNT = 1` -- the hub conventionally takes
the first usable host address, e.g. `10.100.0.1` for `10.100.0.0/16`), and
returns the first candidate not already in `occupied`. `occupied` is
computed from every **non-revoked** peer of that hub
(`WireGuardRepository.list_occupied_tunnel_ips`) -- a revoked peer's
address is deliberately excluded, i.e. "freed for reuse" (see §5).

**Complexity.** Linear scan, first-fit. Fast for the common case (a
mostly-empty pool); worst case (a nearly-exhausted pool) is O(pool size).
Acceptable for this platform's expected per-hub peer counts and this
sandbox's synchronous test usage. A very large CIDR with heavy allocation/
revocation churn would eventually want a dedicated free-list/bitmap
instead of a linear scan -- not implemented here.

**Concurrency.** `allocate_tunnel_ip` itself has no notion of "in
progress" allocations -- it is a pure function of whatever the caller
currently considers occupied. Real race-safety comes from the database:
`WireGuardPeer`'s `UNIQUE (server_id, tunnel_ip_address)` constraint
guarantees two concurrent requests can never both commit the same address,
even if both independently computed it as "next free" from a stale read.
`WireGuardService._allocate_and_persist` catches the resulting
`DuplicateRecordError` and retries allocation up to
`_MAX_ALLOCATION_ATTEMPTS` (3) times with a fresh occupancy read before
surfacing `TunnelIPAllocationConflictError` (409, "please retry") to the
caller. `tests/unit/test_wireguard.py::TestAllocationConflictRetry`
exercises both the retry-then-succeed and retry-exhausted paths directly,
using a fake repository that simulates a stale occupancy read. No explicit
row lock (`SELECT ... FOR UPDATE` on the hub) is taken; that would be the
natural next step for a higher-contention production deployment.

## 5. One row per router, mutated in place -- revoke frees the IP, re-create reuses the row

**Decision: reject creating a second active peer; revoke-then-create
reuses the same row.**

`WireGuardPeer.router_id` is unique -- a router has at most one peer row,
ever. `create_tunnel` called against a router that already has a
non-revoked peer raises `WireGuardPeerAlreadyExistsError` (409) rather than
silently revoking the old one first: an explicit `DELETE .../wireguard-peer`
is always the one place a tunnel teardown is decided, never an implicit
side effect of creating a new one. `revoke_tunnel` marks the peer
`revoked` (`revoked_at` set) -- its tunnel IP is immediately excluded from
`list_occupied_tunnel_ips`'s occupancy set, i.e. "freed for reuse" by *any*
router, not necessarily the same one.

Calling `create_tunnel` again for a router whose only existing peer is
`revoked` reuses that same row: new keypair, a freshly allocated tunnel IP
(via the same allocator -- it may coincidentally get the same address back
if nothing else took it in the meantime, or a different one if another
router's tunnel occupied it first), `status` reset to `pending`,
`rotation_count` incremented, `revoked_at` cleared. This mirrors
`RouterAgentService.issue_credential_for_router`'s identical "reissue in
place, never a second row" design, for the identical reason: the FK is
unique, so anything else would require relaxing that constraint for no
distinct query need.

## 6. Tunnel rotation and key rotation are the same operation

**Decision: one `rotate_tunnel` method; no separate "tunnel-level" rotation.**

The module brief invited treating "tunnel rotation" (possibly including a
new tunnel IP) as distinct from "key rotation" (just the keypair). This was
considered and rejected: rotating a peer's keypair already forces the
device to re-pull its configuration and re-establish its handshake from
scratch (`PEER_STATUS_TRANSITIONS`'s `active -> pending` edge) -- there is
no meaningfully distinct "tunnel-level" state a second operation could
rotate independently of that key material. A full IP reallocation is
already available through the existing revoke-then-`create_tunnel` path
(§5); a second endpoint whose only difference would be "also picks a new
IP" would either duplicate that path or need its own bespoke IP-reuse rule,
and neither was judged to earn its keep as a separate operation.
`rotate_tunnel` therefore **always keeps the peer's existing
`tunnel_ip_address`** -- a deliberate choice consistent with real-world
operational practice too: firewall rules, DNS, or monitoring configured
against a router's known tunnel IP should not need to change just because
its keys were rotated. `rotate_tunnel` is legal from either non-revoked
status (`pending` or `active`, always landing back on `pending`) -- it is
deliberately **not** run through `validators.validate_peer_transition`,
since that function's "no same-status no-op" discipline (correct for
`revoke_tunnel`, an ordinary state transition) would wrongly reject
rotating an already-`pending` peer, which has real, non-no-op side effects
(a brand new keypair) despite the status value not changing.

## 7. Health status: read-time computed, DB-tracked, device-reported

**Decision: `compute_health_status` is never persisted; it derives a
`healthy`/`stale`/`unknown`/`revoked` signal from `last_handshake_at`
against `Settings.wireguard_handshake_stale_after_minutes` (default: 5
minutes) every time it is read.**

There is no live `wg show` integration in this sandbox -- the same honest
"interim design" posture BE-008's own `Router.health_status` and BE-009's
simulated provisioning already establish. `last_handshake_at` is updated
either implicitly (a peer's very first successful `GET
/agent/wireguard-config` pull flips `pending -> active`, though this alone
does not set `last_handshake_at` -- pulling a config is not the same event
as a live handshake) or explicitly via the dedicated
`POST /agent/wireguard-config/handshake` endpoint (§8 below). Five minutes
was chosen as roughly double WireGuard's own ~2-minute keepalive/
handshake-renegotiation cadence, so a single missed report does not
immediately read as unhealthy -- configurable per-environment via
`Settings.wireguard_handshake_stale_after_minutes`, following the exact
pattern every other domain-specific `Settings` field already uses (e.g.
`router_provisioning_token_expire_hours`).

A `revoked` peer's health status is always `revoked`, regardless of how
recent its last handshake was -- a torn-down tunnel is never "healthy" no
matter what its history says.

## 8. `POST /agent/wireguard-config/handshake`: an additive sixth endpoint

**Decision: a small, dedicated, `CurrentAgent`-gated endpoint in this
module -- not composing through `app.domains.router_agent`'s own
`POST /agent/status`.**

The module brief explicitly leaves "how `last_handshake_at` gets updated"
to this module's judgment: "via the device-facing status/heartbeat
composition, or via a dedicated endpoint the device calls -- your call."
Composing through `router_agent.router.agent_report_status` was considered
and rejected for two reasons: (1) that endpoint's request/response schemas
live in a module this task's scope explicitly forbids modifying, and (2)
stretching "the device just reported its software version/license state"
into "a live WireGuard handshake was observed" would conflate two
genuinely different concepts. Composing through `GET /agent/wireguard-config`
itself (treating every config pull as an implicit handshake) was also
rejected: pulling a config is not the same event as a live tunnel
handshake actually succeeding, and conflating the two would make the
health signal less honest, not more. A small, dedicated,
equally-`CurrentAgent`-gated endpoint keeps both signals independently
testable without touching any file outside this module's own directory.

## 9. Device-facing config delivery composes with `router_agent`'s `CurrentAgent`

**Decision: `GET /agent/wireguard-config` and
`POST /agent/wireguard-config/handshake` both depend on
`app.domains.router_agent.dependencies.CurrentAgent`, imported and reused
exactly as-is.**

`app.domains.router_agent`'s `POST /api/v1/agent/status`/action-queue
mechanism already exists as the device's ongoing communication channel,
authenticated by a persistent, hashed bearer credential presented via the
`X-Agent-Credential` header. Rather than inventing a third device-facing
auth scheme, this module's two device-facing endpoints depend on that same
`CurrentAgent` dependency -- resolving an `AgentIdentity` (the validated
`Router` row plus its `RouterAgentCredential`) with no further
tenant-scoping check needed: `router_id` always comes from the credential's
own FK, never from client-supplied input, so there is nothing left for a
caller to spoof.

`WireGuardService.get_config_for_agent(router=identity.router)` is then
called with the already-resolved, already-validated `Router` -- exactly
mirroring how `RouterAgentService.get_current_config(router_id=identity
.router.id)` composes with `CurrentAgent` in `app.domains.router_agent
.router`.

**Repeatable, not "shown once."** Unlike a one-time provisioning token or a
freshly-issued agent credential (each shown exactly once, never retrievable
again), the device may re-pull its own private key from
`GET /agent/wireguard-config` any number of times -- e.g. after a reboot,
after its local WireGuard config was wiped, or simply as part of its
periodic config-refresh cycle, mirroring `GET /agent/config`'s own
repeatable "current state" semantics rather than
`ProvisioningTokenResponse`'s "shown once" convention. This is safe
precisely because the platform is the intended, permanent custodian of
this secret (see §1) -- there is no security benefit to hiding it from the
device a second time, since the device already possesses it, and the admin
-facing create/rotate responses can also surface it once for manual
configuration.

**The device never receives the hub's private key.** Only the peer's own
(decrypted) private key, plus the hub's *public* key, endpoint host/port,
and tunnel network CIDR are ever included in a device-facing response --
see `tests/unit/test_wireguard.py::TestDeviceFacingConfigPull
::test_pull_config_never_leaks_hub_private_key`.

## 10. Router eligibility and soft-deleted (decommissioned) routers

`create_tunnel`/`rotate_tunnel` both look up the router with
`include_deleted=True` before checking
`validators.validate_router_eligible_for_wireguard` -- the identical
reasoning `app.domains.router_agent.dependencies.CurrentAgent` already
documents for its own router lookup:
`RouterService.decommission_router` both sets `status=decommissioned`
*and* soft-deletes the row, so without `include_deleted=True` a
decommissioned router would surface a misleading `RouterNotFoundError`
instead of the more informative `WireGuardRouterNotEligibleError` (409)
that the eligibility check is meant to raise. `revoke_tunnel`/`get_peer`
deliberately do **not** use `include_deleted=True` -- an admin should still
be able to view/revoke a stale tunnel record even after its router has
moved on, but "not found" is an acceptable answer there (mirrors how
BE-008's own admin `GET /routers/{id}` endpoint behaves for a decommissioned
router today).

## 11. Tenant isolation

Every admin-facing operation resolves the router first, through
`RouterService.get_router(..., requesting_organization_id=...)` -- tenant
scoping is inherited for free from BE-008: a caller acting outside its own
organization (or an MSP's child organizations) gets
`CrossOrganizationRouterAccessError` (403) before this module's own logic
ever runs. This module adds no second tenant-scoping check of its own.
