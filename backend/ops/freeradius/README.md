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
  `is_deleted=false, status='active'` `radius_nas_clients` row and prints a
  `client { ... }` block per NAS, `nas_identifier` as `shortname`. Currently
  scopes every client to `ipaddr = 0.0.0.0/0` (there is exactly one real NAS
  in production as of this writing -- see the honest caveat below).
- `sync_radius_clients.sh` (installed at `/opt/wyfy/sync_radius_clients.sh`
  on the VM) → runs the above via `docker cp` + `docker exec`, diffs the
  result against the live `clients.wyfy.conf`, and only overwrites +
  `systemctl reload freeradius`s when something actually changed. Driven by
  `wyfy-radius-sync.timer` (systemd, `OnUnitActiveSec=60s` -- see
  `wyfy-radius-sync.service`/`.timer` in this directory), so a newly
  registered or rotated NAS client is picked up within a minute with zero
  manual `clients.conf` edits, ever.

**Known, honest scaling gap**: every client block currently accepts from
`0.0.0.0/0` rather than scoping to that NAS's actual router IP -- fine with
one real NAS (the shared secret itself is still the real auth boundary),
but wrong once there are two+ NAS clients that could otherwise
authenticate against each other's secrets from an unexpected source. Real
fix: track each router's real source IP (WireGuard tunnel address or
public IP, whichever this NAS's RADIUS traffic actually originates from)
on `RadiusNasClient` and emit `ipaddr = <that>` instead of `0.0.0.0/0`
per-client in `gen_clients_conf.py` -- not done here for lack of that
column existing yet on the model.

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
