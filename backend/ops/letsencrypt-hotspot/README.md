# Hotspot TLS: real Let's Encrypt certs for `wifi.wyfyguest.com` (production, `cloudguest-vm`)

Real infrastructure notes for how the MikroTik hotspot login page's TLS
certificate went from a self-signed cert (browser interstitial on every
guest, and on Safari a query-string-losing click-through into
`IncompletePortalLinkError`) to a real, publicly-trusted Let's Encrypt cert
-- and how it stays that way after the cert expires in 90 days, without
anyone remembering to do it by hand. Fixed live in production on
2026-08-18, same incident as [[ops/freeradius]].

## Why DNS-01, and why a hand-rolled hook instead of a certbot plugin

The router (`WYFY-GUEST`, `cloudguest-api@10.20.0.50` over WireGuard) has no
public port 80/443 path in -- its WAN (`ether1`) is `192.168.2.198/24`,
itself behind another NAT. HTTP-01 is a non-starter. DNS-01 needs no
inbound reachability to the router at all: only the DNS zone needs to
accept a `_acme-challenge` TXT record, which is done from wherever runs
`certbot`, not from the router.

`wyfyguest.com` (and everything under it, including `wifi.wyfyguest.com`)
is on **GoDaddy's own DNS** (`ns11/ns12.domaincontrol.com`) -- confirmed via
`whois`/`dig`, not assumed. There is no EFF-maintained `certbot-dns-godaddy`
plugin (the DNS providers Certbot ships plugins for are route53, cloudflare,
google, digitalocean, etc. -- not GoDaddy), and third-party PyPI packages
claiming that name are unmaintained/unverified. Rather than mix a
pip-installed plugin into an apt-installed certbot (a known source of
version-skew breakage), this uses certbot's own supported
`--manual --preferred-challenges dns` mode with two small hook scripts that
call GoDaddy's REST API directly -- fully unattended, no interactive
prompts, same idea as `ops/freeradius`'s own preference for a real,
readable script over a heavier dependency.

## The GoDaddy API credential

**`/etc/wyfy/godaddy-dns.env`** (root-only, `0600`, on `cloudguest-vm`):
```
GODADDY_API_KEY=...
GODADDY_API_SECRET=...
```
A **classic Production API key/secret** (`developer.godaddy.com` ->
"Open classic portal" -> Create New API Key -> Production), *not* the newer
"Personal Access Token" flow on the same site -- the new tokens
force-expire and their compatibility with GoDaddy's classic
`api.godaddy.com/v1` REST API (which `sso-key`-style auth and the hook
scripts below both assume) was not established. Account-level, not
domain-scoped -- GoDaddy's classic keys don't support scoping to a single
zone. Generating it required a step-up SMS verification code from the
account owner; it was created and placed on the VM directly by the account
owner, deliberately outside any chat transcript.

This key is the one credential that makes this whole mechanism work. If it
is ever revoked/rotated, renewal breaks silently until someone notices
(see "How to tell this has quietly broken" below) -- there is no
independent alert on the credential itself.

## The two DNS-01 hook scripts

`godaddy-dns-auth.sh` / `godaddy-dns-cleanup.sh` (installed at
`/opt/wyfy/`, `0750` root) -- certbot sets `CERTBOT_DOMAIN` and
`CERTBOT_VALIDATION` in the environment and calls these directly, once per
SAN in the cert.

Two real gotchas, worth knowing before touching either script again:

1. **The auth hook uses GoDaddy's `PATCH /v1/domains/{domain}/records`
   endpoint (additive), never `PUT /v1/domains/{domain}/records/TXT/{name}`
   (which *replaces* every record at that name).** `*.portal.wyfyguest.com`
   and `portal.wyfyguest.com` both validate against the identical record
   name (`_acme-challenge.portal.wyfyguest.com`) in the same certbot run --
   confirmed live: certbot calls the auth hook for both, and a `PUT` from
   the second call would silently clobber the first call's still-pending
   token, breaking that domain's validation non-deterministically depending
   on hook-call order. This was caught and fixed during a staging
   (`--dry-run`) test before ever touching the production ACME endpoint --
   see "Validation performed" below.
2. **The auth hook polls GoDaddy's own authoritative nameserver
   (`ns11.domaincontrol.com`) directly, not a public resolver**, before
   returning control to certbot. A public resolver can be stale/negatively
   cached in a way that has nothing to do with whether the record is
   actually live; querying the zone's own NS is the real signal. The
   cleanup hook never fails the certbot run (a leftover `_acme-challenge`
   TXT record is harmless clutter, not worth aborting a successful
   issuance over), and tolerates a `404` on `DELETE` (expected for the
   second of the two shared-name cleanup calls above).

## Getting the cert onto the router -- and the ordering that avoids ever breaking it mid-renewal

`renew-hotspot-certs.sh` (installed at `/opt/wyfy/`, `0750` root) does two
things: (1) `certbot renew --cert-name wyfy-hotspot-fleet` (a no-op until
~30 days before expiry, matching this VM's own `certbot.timer` convention
for its other certs), and (2), **only when a renewal actually happened**
(detected via a `--deploy-hook`-touched marker file, not by assuming), pushes
the new cert to every router in its `ROUTERS` array.

The router-side push is **one combined SSH command per router** (semicolon-
chained RouterOS script), never split across multiple `set` calls -- this
codebase's own hard-won lesson from earlier in this incident: splitting the
`ssl-certificate=`/`login-by=` rebind of `/ip hotspot profile` across
separate `set` calls is what silently no-op'd before. The full remote
sequence, and why each step is ordered the way it is:

1. `/certificate remove [find name~"<name>.fullchain.pem"]` -- clears any
   leftover intermediate/root artifacts from a *prior* renewal. RouterOS
   names an imported multi-cert PEM bundle `<filename>_0`, `_1`, `_2` (leaf,
   intermediate, root) deterministically off the uploaded filename, which
   this script always reuses -- so a stale `_1`/`_2` from last time would
   otherwise collide with this time's import.
2. Import the fresh `fullchain.pem` (3 objects) + `privkey.pem`.
3. Rename+trust the new leaf (`<name>_0` -> `<name>-new`, `trusted=yes`) --
   deliberately *not* yet the final stable name, so it can never collide
   with the currently-bound cert.
4. Rebind `hsprof1` to `<name>-new` (the one combined
   `ssl-certificate=... login-by=https,http-pap` command).
5. *Only now* remove the old `<name>` cert -- safe, because nothing
   references it anymore after step 4.
6. Rename `<name>-new` -> `<name>` for next round, and sweep any leftover
   `<name>.fullchain.pem_*` artifacts.

This ordering means `hsprof1` is never, even transiently, pointed at a
certificate object that's mid-deletion.

## Systemd timer

`wyfy-hotspot-cert-renew.timer` runs `wyfy-hotspot-cert-renew.service`
(-> `/opt/wyfy/renew-hotspot-certs.sh`) twice a day (`03:00`/`15:00` UTC,
30min random jitter) -- mirrors this VM's own `certbot.timer` cadence for
its other certs. `certbot renew`'s own 30-day-before-expiry window means
this has ~60 attempts before a cert would actually lapse; a single bad run
(transient GoDaddy API hiccup, one router unreachable) self-heals on the
next tick with no one needing to intervene. Enabled via
`systemctl enable --now wyfy-hotspot-cert-renew.timer`.

## How to tell this has quietly broken

`renew-hotspot-certs.sh` logs to syslog under the tag
`wyfy-hotspot-cert-renew` (`journalctl -t wyfy-hotspot-cert-renew`) and
exits non-zero on any router push failure -- wire that up to whatever this
platform's real alerting is (nothing was wired up as part of this fix;
today, "it broke" is only discoverable by reading the log or noticing a
guest-facing cert warning again). The GoDaddy API key itself has no
separate expiry/rotation alert either -- if it's ever revoked, every future
renewal attempt fails at the DNS-01 step and the router silently keeps
serving its last-successfully-issued cert until that one expires (Nov 16
2026 for the cert issued today), which is a real, honest gap: there is
currently no earlier warning than "the DNS-01 auth hook has been failing
silently for weeks."

## Fleet rollout -- what this does and doesn't cover yet

The cert issued covers **`wifi.wyfyguest.com`** (this router's actual,
already-deployed `dns-name`) *and* **`*.portal.wyfyguest.com` +
`portal.wyfyguest.com`** -- the fleet-wide naming pattern the Setup Script
generator (`app/domains/network_config/renderers.py`) actually renders for
every future router (`{tag}.portal.wyfyguest.com`, one per hotspot VLAN).
`wifi.wyfyguest.com` is a one-off manual deviation from that generator
pattern for this specific router (the QA-flagged drift this whole incident
started from) -- both are covered by the one cert issued here, at zero
extra DNS-01 cost, so neither today's reality nor the generator's intended
future naming needed to be chosen between.

`ROUTERS` in `renew-hotspot-certs.sh` currently has exactly one entry
(`WYFY-GUEST`). Real NAS clients already exist in FreeRADIUS beyond this
one router (`cg-04f81868`, `cg-c61ae7af`, `cg-5d3a509e`, per
`ops/freeradius`). Extending this mechanism to them is *not* done here, and
needs, honestly:

- **Each router's actual `dns-name`** confirmed via its own
  `/certificate print detail` / `/ip hotspot profile print detail` --
  per this same incident's own caution, do not assume it matches the
  generator's `{tag}.portal.wyfyguest.com` pattern without checking (this
  router didn't).
- **A per-router SSH credential.** `router-ssh.env` currently holds one
  shared password (`cloudguest-api`) reused via `ROUTER_SSH_USER`/
  `ROUTER_SSH_PASSWORD` for every entry in `ROUTERS` -- fine for one router,
  a real weakness the moment there's more than one (one leaked/rotated
  credential affects the whole fleet at once, and there's no way to revoke
  access to a single router). Real fix: a credential per NAS, analogous to
  the per-router RADIUS shared secret `ops/freeradius` already has to
  solve, ideally SSH keys rather than passwords.
- If a future router's `dns-name` doesn't fall under `wifi.wyfyguest.com`
  or `*.portal.wyfyguest.com`, the cert's SAN list needs a new entry
  (one more `-d` on the `certbot` invocation -- cheap, since DNS-01 doesn't
  care how many SANs are in one cert) or its own separate cert.

None of the above blocks adding a second `ROUTERS` line once that
information exists -- it's a one-line addition to the array, not a
redesign.

## Validation performed (2026-08-18)

- **Staging dry run first** (`--staging --dry-run`), specifically to catch
  the wildcard/apex shared-record-name issue above before ever touching
  production ACME or GoDaddy's real records -- caught it, fixed the auth
  hook to use `PATCH` instead of `PUT`, re-ran clean.
- **Real production issuance**: `certbot certonly` for
  `wifi.wyfyguest.com` + `*.portal.wyfyguest.com` + `portal.wyfyguest.com`,
  DNS-01 via the hooks above. Succeeded; cert valid 2026-08-18 ->
  2026-11-16.
- **Chain-of-trust verified independently of the router**: the issued
  `fullchain.pem` verifies successfully (`openssl verify`) against both
  macOS's system root store and the Mozilla/`certifi` root bundle (what
  Firefox and most non-Apple/Microsoft browsers use) -- i.e. any real
  browser will trust it, not just RouterOS's own store (which trusts it
  circularly, since this fix is the one that imported and marked it
  trusted there).
- **A live network handshake test (`openssl s_client` against the router
  itself) was not possible from this environment**, and this is worth
  being explicit about rather than glossing over: the guest hotspot network
  (`bridge`/`10.5.50.1`) is correctly firewalled off from the WireGuard
  management network this session had access to (RouterOS's hotspot HTTPS
  listener is bound specifically to the `bridge` interface and refuses
  connections arriving any other way -- confirmed via a self-fetch attempt
  from the router, which got `Connection refused`). That isolation is
  correct, intentional guest-network security, not a gap to route around.
  What *is* confirmed instead: `/certificate print detail` on the router
  shows the exact same cert (matching SHA-256 fingerprint) bound to
  `hsprof1.ssl-certificate`, `trusted=yes`. **Genuinely outstanding**: an
  actual device connecting to the real guest WiFi and loading the login
  page without a certificate warning has not been done by this session --
  flagged here rather than assumed, matching this codebase's own
  "confirmed live" discipline elsewhere (see
  `app/domains/network_config/renderers.py`'s module docstring for the
  precedent).
- **The full renewal path was exercised for real, not left untested until
  day 90**: `FORCE_RENEW=1 /opt/wyfy/renew-hotspot-certs.sh` (bypasses
  certbot's 30-day window via `certonly --force-renewal`) forced a second,
  genuinely new issuance and ran the complete router-side
  remove/import/rename/rebind sequence above against the *already-bound*
  first cert -- the one code path that never runs on a first issuance and
  is exactly where a naming collision would show up. Confirmed clean
  afterward: `/certificate print detail` shows exactly one
  `wyfy-hotspot-fleet` entry (the renewed cert, new serial), no orphaned
  `_new`/`.fullchain.pem_1`/`_2` artifacts, `hsprof1.ssl-certificate` still
  `wyfy-hotspot-fleet`.

## Manual commands

```bash
# Force a real renewal right now regardless of the 30-day window (this is
# what proved the router-side rebind path above, and is safe to re-run):
ssh azureuser@20.219.51.94 "sudo FORCE_RENEW=1 /opt/wyfy/renew-hotspot-certs.sh"

# Normal unattended path (what the timer runs; no-ops outside the 30-day
# renewal window):
ssh azureuser@20.219.51.94 "sudo /opt/wyfy/renew-hotspot-certs.sh"

# Check what's actually bound on the router right now:
ssh cloudguest-api@10.20.0.50 "/certificate print detail; /ip hotspot profile print detail where name=hsprof1"

# Recent renewal history/failures:
ssh azureuser@20.219.51.94 "journalctl -t wyfy-hotspot-cert-renew --since -7d"
```

## Old self-signed certs

`cloudguest-hotspot-cert` (self-signed CA) and `cloudguest-hotspot-leaf`
(the leaf it signed) are still present in the router's certificate store --
`hsprof1` no longer references either, but neither was deleted as part of
this fix (removing certificate objects that predate this change, when
leaving them is harmless, felt like scope creep on a live production
router). Safe to remove by hand later if wanted:
`/certificate remove [find name="cloudguest-hotspot-leaf"];
/certificate remove [find name="cloudguest-hotspot-cert"]`.
