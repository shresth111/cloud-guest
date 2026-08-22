# FreeRADIUS deployment (production, `cloudguest-vm`)

Real infrastructure notes for the `rlm_rest` bridge between a router's own
RADIUS UDP traffic and this backend's `POST /api/v1/radius/authorize` /
`POST /api/v1/radius/accounting` (see `docs/guest/FLOW.md` §5 for the
original HTTP-contract design doc -- that doc describes the *client*
contract this backend implements; this directory is the *server*
(FreeRADIUS itself) that actually calls it in production, which did not
exist as a running service anywhere until 2026-08-10).

## Why this exists

The backend's own RADIUS-facing endpoints, `RadiusNasClient` CRUD, and
`CurrentNas` shared-secret auth were all fully built and tested well before
this directory existed -- but no real FreeRADIUS process was ever deployed
to actually call them. A real router configured with `use-radius=yes`
would send genuine RADIUS Access-Requests into the void: `RADIUS server is
not responding`. Found and fixed live in production on 2026-08-10 (see
git blame on this directory's own commit for the full incident writeup).

## What's installed on the VM (not managed by this repo's own deploy step)

- `freeradius` + `freeradius-rest` (Ubuntu packages, `apt install freeradius
  freeradius-rest freeradius-utils`)
- `/etc/freeradius/3.0/mods-available/rest` → see `rest.conf` in this
  directory (the real file, minus nothing -- no secrets live in this one)
- `/etc/freeradius/3.0/sites-available/default`'s `authorize {}` /
  `accounting {}` sections → see `sites-default.snippets.conf` in this
  directory for the exact unlang inserted (real file has this inline,
  interleaved with Ubuntu's own stock config -- this is the diff, not a
  drop-in replacement)
- `/etc/freeradius/3.0/clients.wyfy.conf`, `$include`d from `clients.conf`
  -- **auto-generated, never hand-edited** (see Dynamic NAS clients below)
- Azure NSG `cloudguest-vmNSG`: inbound UDP 1812-1813 allowed (rule
  `allow-radius`, priority 340)

## Two real FreeRADIUS/rlm_rest bugs found fixing this, worth knowing before touching `rest.conf` again

1. **Config-string quoting.** `data = '{"key": "value"}'` (single-quoted
   outer, literal double quotes inside) looks natural but is wrong twice
   over: FreeRADIUS single-quoted strings never get `%{...}` xlat-expanded
   at all (so `%{User-Name}` stays literal), and even switching to
   double-quoted breaks unless every inner `"` is escaped as `\"`. The
   working form is `data = "{\"key\": \"%{User-Name}\"}"`.
2. **No nested `%{...}` inside `data`.** This FreeRADIUS/rlm_rest build's
   `data` template parser cannot handle *any* compound xlat expression --
   `%{urlencode:%{User-Name}}`, `%{tolower:%{Acct-Status-Type}}`, and even
   the plain default-value form `%{Acct-Input-Octets:-0}` all fail
   identically (`ERROR: ... ^ Unknown module`, then silently drops the
   packet -- `radclient` just sees "No reply from server"). The fix is
   structural, not a workaround: compute every value with real `unlang`
   *before* calling `rest` (an `if (!&Attr) { update request { Attr := 0
   } }` guard for defaults, `update control { Tmp-String-0 := "%{tolower:
   ...}" }` for string transforms into one of FreeRADIUS's built-in
   scratch attributes), then have `data` reference only flat,
   already-resolved attributes. See `sites-default.snippets.conf` for the
   exact pattern.

## Dynamic NAS clients -- `clients.wyfy.conf` is generated, not hand-maintained

A RADIUS shared secret must be known to FreeRADIUS *before* any
application-layer logic runs (the wire protocol's own Message-Authenticator
check happens first) -- so `clients.conf` needs a real entry per
`RadiusNasClient` row, with the same plaintext secret
`app.domains.router.crypto.decrypt_secret` recovers from
`shared_secret_encrypted`. Two pieces close that loop, both installed
directly on the VM (not containerized, since they need `docker exec` into
`deploy-api-1` for the Fernet key + DB session the app already has):

- `gen_clients_conf.py` → run inside `deploy-api-1`, queries every
  `is_deleted=false, status='active'` `radius_nas_clients` row (LEFT JOINed
  against `wireguard_peers` by `router_id`) and prints a `client { ... }`
  block per NAS, `nas_identifier` as `shortname`, `ipaddr` scoped to that
  router's real WireGuard tunnel IP as a `/32` (falls back to `0.0.0.0/0`
  only if the NAS has no tunnel peer row yet -- logged to stderr as a
  fallback count).
- `sync_radius_clients.sh` (installed at `/opt/wyfy/sync_radius_clients.sh`
  on the VM) → runs the above via `docker cp` + `docker exec`, diffs the
  result against the live `clients.wyfy.conf`, and only overwrites +
  `systemctl reload freeradius`s when something actually changed. Driven by
  `wyfy-radius-sync.timer` (systemd, `OnUnitActiveSec=60s` -- see
  `wyfy-radius-sync.service`/`.timer` in this directory), so a newly
  registered or rotated NAS client is picked up within a minute with zero
  manual `clients.conf` edits, ever.

**2026-08-18 incident, fixed**: every client block used to be emitted with
a blanket `ipaddr = 0.0.0.0/0`, called out here on 2026-08-10 as "fine with
one real NAS... wrong once there are two+." That became a real outage once
the fleet grew past one NAS (2026-08-15): FreeRADIUS indexes clients by
IP/CIDR, so only the first-parsed `0.0.0.0/0` stanza in a given
`clients.wyfy.conf` run ever loads -- every other NAS, regardless of its
own shortname, was rejected as `Failed to add duplicate client` (visible in
`journalctl -u freeradius`, e.g. `cg-5d3a509e`, `cg-549153bd`,
`cg-c61ae7af`, `cg-856aa5ca`). Those routers had zero working RADIUS auth
the entire time. Root cause was purely in this generator, **not** a
duplicate-row bug: `radius_nas_clients.router_id`/`nas_identifier` have
had partial-unique DB indexes since
`0061_fix_radius_nas_soft_delete_uniqueness`, and
`RadiusService.register_nas` independently raises
`RadiusNasAlreadyRegisteredError` on a second registration attempt for the
same router -- confirmed live on cloudguest-vm's actual DB while
investigating: no router ever had more than one non-deleted
`radius_nas_clients` row. Fixed by scoping each client's `ipaddr` to that
router's own `wireguard_peers.tunnel_ip_address` (`/32`) instead of the
shared catch-all -- see `gen_clients_conf.py`'s module docstring.

## 2026-08-22 — `accounting{}` was never wired up at all

Until this date the string `rest` appeared **exactly once** in
`/etc/freeradius/3.0/sites-available/default`, inside `authorize{}`. The
`accounting{}` section was stock Ubuntu:

```
accounting {
    detail
    unix
    -sql
    exec
    attr_filter.accounting_response
}
```

So no Accounting-Start / Interim-Update / Stop packet has **ever** reached
`POST /api/v1/radius/accounting` from a real router, on either estate. Every
`GuestSession.bytes_uploaded`/`bytes_downloaded` on the live platform is 0,
which means **data caps and FUP quotas did not enforce at all** and every usage
figure on the customer dashboard was zero. Not migration damage — the old hub
was identical. (The ~19 GB / 181 GB of session bytes visible in the live
database is seeded demo data: 221 of 299 non-zero rows are exact multiples of
1 MiB and all 318 rows share 55 distinct microsecond values.)

Fixed by inserting the block in `sites-default.snippets.conf` into the live
`accounting{}`, immediately **after** stock `detail`, plus the `accounting{}`
rewrite in `rest.conf`. Three things are worth knowing before touching it:

1. **Totals, not deltas.** RADIUS has no delta attribute — `Acct-Input-Octets`
   / `Acct-Output-Octets` are running session totals (RFC 2866 §5.3-5.4). The
   pre-existing `rest.conf` mapped them onto the backend's
   `bytes_uploaded_delta`/`bytes_downloaded_delta`, which would have made every
   interim update re-add the entire session to date. It now sends
   `bytes_*_total` and `RadiusService.accounting_interim_update` converts to a
   delta against what it already recorded — which also makes a RADIUS
   retransmit a no-op instead of a double count.
2. **`Acct-*-Gigawords` is not optional.** The octet counters are 32-bit and
   wrap every 4 GiB; the high word lives in a separate attribute (RFC 2869
   §5.1-5.2). Sending `Acct-Input-Octets` alone truncates every session past
   4 GiB back to near zero — on a data cap that reads as "this guest has used
   nothing" exactly when they have used the most.
3. **Deliberate asymmetry in the `rest` rcode handling.** 4xx continues to an
   `ok` so the NAS is acknowledged (resending a rejected packet cannot change
   the answer, and an unacknowledged NAS retransmits until it gives up). 5xx
   and connection failures are *not* overridden: `fail` keeps its default
   `return`, no Accounting-Response is sent, and the NAS retransmits — which is
   what a transient backend outage needs. Acking a packet the backend could not
   record would destroy the usage data silently.

### How this was verified before touching the live server

An isolated FreeRADIUS instance was built on the hub itself (`/opt/frtest`,
loopback-only on 18220/18230, same 3.2.1 binary, its own log/run dirs) with a
purpose-built loopback client carrying `shortname`/`backend_secret`. Confirmed
there, then removed:

* All five `Acct-Status-Type` values produce **valid JSON** and the exact five
  lowercase strings the backend dispatches on.
* `%{expr:(%{Acct-Input-Gigawords} * 4294967296) + %{Acct-Input-Octets}}`
  reassembles correctly: `3 GiB + 100` → `12884901988`.
* `X-RADIUS-NAS-Identifier`/`X-RADIUS-Shared-Secret` resolve per-client from
  the matched stanza.
* Backend 200 → Accounting-Response. Backend 404 → Accounting-Response anyway.
  Backend unreachable → **no** Accounting-Response, and the packet is in
  `radacct/.../detail-<date>` for replay.

After applying to the live server, the same rig was re-synced from the live
files and pointed at the **real** backend (`10.30.1.10:8000`). It sent
`{"status_type": "interim-update", ..., "bytes_uploaded_total": 12884901988,
"bytes_downloaded_total": 4294967496, "disconnect_reason": ""}` and received the
backend's genuine `401 {"success":false,"message":"RADIUS NAS authentication
failed",...}` — expected, since the rig's NAS is not registered, and proof that
the whole chain now runs.

**Note on the older FreeRADIUS parser bugs below.** Bug #1 (single-quoted
`data` never xlat-expands) still holds. Bug #2 (no nested `%{...}` inside
`data`) was **not** reproduced on this hub's FreeRADIUS 3.2.1 — but the
structural fix is kept anyway, because computing values in `unlang` first is
required regardless for the unset-attribute guards, and reverting it buys
nothing.

**Never re-apply `sites-available/default` wholesale from this repo.** The live
file is ahead of git: the 2026-08-18 dynamic-xlat and Message-Authenticator
fixes were applied on the box and never committed.
`sites-default.snippets.conf` is a diff, not a drop-in.

## Manual verification commands (matches what was actually run 2026-08-10)

```bash
# Config sanity check before any restart
sudo freeradius -C

# Full debug trace of one real Access-Request (kills the running service
# for the duration -- do not run against live guest traffic)
sudo systemctl stop freeradius
sudo timeout 10 freeradius -X > /tmp/frx.log 2>&1 &
# ... send a test request via radclient, then:
sudo systemctl start freeradius

# Real end-to-end Authorize test (secret must match a real clients.wyfy.conf entry)
echo 'User-Name = guest@example.com
Calling-Station-Id = AA:BB:CC:DD:EE:FF' | radclient -x 127.0.0.1:1812 auth <real-nas-secret>

# Real end-to-end Accounting test
echo 'User-Name = guest@example.com
Acct-Status-Type = Start
Acct-Session-Id = "test-1"' | radclient -x 127.0.0.1:1813 acct <real-nas-secret>
```
