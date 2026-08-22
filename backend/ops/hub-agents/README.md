# Hub agents — recovered source of record

**These three HTTP services existed in no repository.** They ran only on the old
hub VM `radius-wg-vm` (`20.219.72.235`), written directly into
`/usr/local/sbin/` and never committed anywhere. The backend hardcodes their
URLs and its own comments describe them as "not part of this repository". If
that VM had been deleted, they were gone and would have had to be rewritten
from scratch.

Captured byte-for-byte from the live VM on **2026-08-22** and committed here.
This directory is now the source of record. Change these files here first, then
deploy — do not hand-edit the VM.

| Port | Service | Endpoint | Status |
|---|---|---|---|
| 9091 | `wg_agent.py` | `POST /wg/peer` | **live** — allocates a WireGuard peer + `/32`, returns keypair and endpoint |
| 9092 | `radius_agent.py` | `POST /radius/client` | **live** — appends a `client { }` stanza to `clients.conf`, validates, restarts FreeRADIUS |
| 9093 | `config_agent.py` | `POST /config/apply` | **RETIRED** — see below |

All three run as `User=root` and authenticate with a single static shared
secret in an `X-Agent-Secret` header. The secrets are redacted in
`systemd/*.service` here; see "Secret rotation".

## Port 9093 (`config_agent.py`) is retired — kept for reference only

Nothing calls it. Verified 2026-08-22 by exhaustive grep of both
`cloud-guest-repo/backend` and `cloudguest-foundation` (including
`node_modules/`, `.git/`, build output in `.output/`, and all worktrees):

* the backend retired it in commit `3ac8b94` (PR #53) in favour of
  `wyfy_device_gateway.push_config` over the WireGuard tunnel;
* the frontend has **zero** references to `9091`, `9092`, `9093`,
  `X-Agent-Secret`, or any agent path. Every frontend network call goes through
  an axios instance based on `VITE_API_BASE_URL || "/api/v1"`.

It is nonetheless the most dangerous of the three: it runs
`/import file-name=…` on any router reachable through the tunnel, listens on
`0.0.0.0`, sets `Access-Control-Allow-Origin: *` so a browser can call it
cross-origin, and on the old hub had **no host firewall rule and an NSG
allowing it from `*`**. On the new hub it is **not installed and not running**;
`wyfy-agent-firewall.sh` DROPs 9093 outright.

## New-estate deployment (wyfy-prod-hub-vm, 10.30.2.10)

```
/usr/local/sbin/wg_agent.py                  SERVER_ENDPOINT_HOST = "hub.wyfyguest.com"
/usr/local/sbin/radius_agent.py              unchanged
/usr/local/sbin/wyfy-agent-firewall.sh       9091/9092 -> 10.30.1.0/24 + localhost only; 9093 DROP
/usr/local/sbin/wg-agent-preflight.sh        startup gate, see below
/etc/systemd/system/wg-agent.service.d/10-safety-gates.conf
```

`config_agent.py` is archived at `/root/retired-agents/config_agent.py` on the
new hub and its unit is removed.

### Two silent-failure gates added 2026-08-22

`wg-agent-preflight.sh` runs as `ExecStartPre` and refuses to start wg-agent
unless **both** hold. Each guards a failure that is otherwise silent and
effectively unrepairable:

1. **`wg0` has at least 60 peers.** `wg_agent.next_free_ip()` allocates by
   scanning *live kernel state* (`wg show wg0 allowed-ips`), not `wg0.conf`. If
   wg0 is down or partially loaded it sees an empty list and starts handing out
   `10.20.0.2` again — re-issuing tunnel IPs that live routers already hold.
   The unit now also `Requires=wg-quick@wg0.service` (previously only
   `After=`, which does not fail if wg0 never came up).
2. **`SERVER_ENDPOINT_HOST` resolves.** The value is returned verbatim to the
   caller and baked into each router's `endpoint-address=`. The RouterOS
   WireGuard chunk is add-if-missing with no update path, so a router
   provisioned against an unresolvable name **cannot be repaired by re-pasting
   the script** — it needs manual on-device surgery.

As of this commit gate 2 deliberately fails, because `hub.wyfyguest.com` does
not exist yet. That is the intended cutover interlock.

## Known defects (present in the captured source — not introduced here)

These are recorded, not fixed, because fixing them changes live behaviour and
needs its own tested change:

* **`next_free_ip()` is a TOCTOU race.** `ThreadingHTTPServer` with no lock:
  two concurrent `POST /wg/peer` calls can read the same free IP and both
  allocate it. The unlocked `open(wg0.conf, "a")` appends can also interleave.
* **No deallocation path.** No `DELETE`, no peer removal. Every
  re-registration burns a fresh IP permanently. 60 of 253 are gone; exhaustion
  is a foreseeable outage.
* **`radius_agent.add_client()` does a full `systemctl restart freeradius` per
  call**, synchronously, inside the request handler. That drops the listening
  sockets for *every* router in the fleet to add *one* client. The journal
  shows 7 restarts in ~70 minutes on 2026-08-21. It should be
  `systemctl reload` (FreeRADIUS 3.2 re-reads clients on HUP) under an
  `flock`, which is what `ops/freeradius/sync_radius_clients.sh` already does
  correctly — the right behaviour exists in the repo and the wrong one is what
  is deployed.
* **`add_client()` is a blind append with no upsert.** Re-registering a router
  adds another stanza rather than updating. `clients.conf` currently holds 5
  stanzas named `cg-cg-04f81868` and 7 named `cg-cg-11462682`, each with a
  *different* secret. FreeRADIUS keys clients by IP/CIDR, not name, so these
  all load without error — but a router whose tunnel IP shifts onto a stale
  stanza authenticates with a dead secret and 401s with no useful log.
  "Duplicate stanzas are harmless" is true of config parsing and false of
  authentication.
* **Backup filename collision.** `clients.conf.bak-{int(time.time())}` — two
  adds in the same second overwrite each other's backup, and the failure path
  restores it, silently erasing a concurrent add.

## Secret rotation

The live secrets are committed in cleartext at
`app/domains/wireguard/router.py:87` and `app/domains/guest/router.py:142`, and
travel over **plain HTTP**. Anyone who can read the repo can add WireGuard
peers and add/remove FreeRADIUS clients. Rotate all three:

1. Generate new values (`wgagent-$(openssl rand -hex 16)` etc.).
2. Put them in a systemd `EnvironmentFile` (e.g. `/etc/wyfy/hub-agents.env`,
   `0600 root:root`) referenced by each unit, **not** inline `Environment=`
   (inline values are world-readable via `systemctl show`).
3. Replace the backend constants with settings read from the environment, so
   the value is never in git again.
4. Restart the agents and the backend together — the secret is compared with
   `!=` on both sides, so any skew is a hard 401, not a degraded mode.
5. `configagent-…` needs no replacement: retire the service instead.

Rotation alone is not sufficient — the transport is still cleartext HTTP. In
the new estate both callers are inside the VNet (`10.30.1.10` → `10.30.2.10`),
so the secret no longer crosses the public internet, which is the larger part
of the fix.

## 2026-08-22 — new-hub cutover (wg-agent + radius-agent live on 10.30.2.10)

Both agents are now **enabled and running** on `wyfy-prod-hub-vm`. Before this,
nothing listened on 9091/9092 anywhere and every new venue's provisioning hung
to timeout, because the backend still pointed at the deleted old hub.

**Secrets rotated.** The two values previously committed at
`wireguard/router.py:87` and `guest/router.py:142` were exposed in a **public**
GitHub repository from `fc937b6` (2026-07-31) until today — treat them as
compromised, not merely as bad practice. Both were replaced with freshly
minted values (never derived from the old ones) and the old ones are now dead:
`POST` with either leaked literal returns `401` and has no side effect.

* Hub side: `/etc/wyfy/hub-agents.env`, `0600 root:root`, referenced by both
  units as `EnvironmentFile=`. Not inline `Environment=` — that is
  world-readable via `systemctl show`. Verified: `systemctl show wg-agent
  radius-agent -p Environment` prints only `AGENT_BIND_ADDR`.
* Backend side: Settings fields `hub_wg_agent_secret` /
  `hub_radius_agent_secret` (env `CLOUDGUEST_HUB_*`), read per call. The URLs
  moved the same way (`hub_wg_agent_url` / `hub_radius_agent_url`), defaulting
  to the hub's **VNet-private** `10.30.2.10` so neither the secret nor the
  payload leaves the VNet over this cleartext-HTTP transport.

**Reachability is now three layers, not one.** `wyfy-prod-hub-nsg` allows
9091/9092 only from `10.30.1.0/24` and denies both Internet and the rest of the
VNet; `wyfy-agent-firewall.sh` DROPs anything else at the host (this is the only
layer that can see traffic arriving through the wg0 tunnel); and the agents now
bind to `AGENT_BIND_ADDR=10.30.2.10` rather than `0.0.0.0`, so the wg0 address
`10.20.0.1` has no listening socket at all. Default stays `0.0.0.0` in source.

### A seventh defect, found by hitting it

`radius-agent.service` must **not** declare `Requires=freeradius.service`.
`add_client()` shells out to `systemctl restart freeradius` from inside the
request handler (defect 3 above), and with `Requires=` systemd propagates that
restart back and **stops the agent mid-request**. The stanza is written and
FreeRADIUS comes back up, but the caller's connection dies, the backend returns
`502 Could not reach the RADIUS server bridge`, and its transaction rolls back —
leaving a client stanza on the hub with **no matching `radius_nas_clients` row**
in the platform DB. Observed live on 2026-08-22 with `Requires=` briefly set.
`After=` only, as the captured original had. Fixing defect 3 (restart -> reload
under flock) would remove the hazard at its root.
