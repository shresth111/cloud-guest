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

## Incident update (2026-08-18, later same day): missing intermediate certificate

A real guest reported a live "privacy error" / click-through certificate
warning after the cert above went live. Root cause, **confirmed** (not
assumed):

- `renew-hotspot-certs.sh`'s router-push imports `fullchain.pem` (which
  RouterOS explodes into separate objects: `<file>_0` leaf, `<file>_1`/`_2`
  intermediate(s)), promotes and rebinds only the leaf (`_0`), and then --
  as its *original* final step -- ran the exact same broad
  `/certificate remove [find name~"<name>.fullchain.pem"]` sweep a second
  time, meant only to clear a PRIOR run's stale artifacts. By the time that
  second sweep ran, the leaf had already been renamed off that pattern, so
  it matched (and deleted) only the freshly-imported intermediate/root
  objects -- right after importing them.
- Confirmed on-router: `/certificate print detail` for `wyfy-hotspot-fleet`
  showed `issuer=C=US,O=Let's Encrypt,CN=YR1`, no `ca=` field, and an
  `akid` (`1F2F35BE...`) that matched no `skid` of any other object in the
  store -- i.e. genuinely orphaned, not just unlabeled.
- Confirmed on the app VM: `/etc/letsencrypt/live/wyfy-hotspot-fleet/fullchain.pem`
  does contain all 3 PEM blocks (leaf, `YR1` intermediate, `Root YR`
  cross-sign to `ISRG Root X1`) -- the source file was always correct; the
  bug was purely in what the router-push step did with it afterward.
- Researched and confirmed against current MikroTik documentation/community
  reports: RouterOS's hotspot HTTPS server builds the served chain
  *dynamically* from whichever trusted certificate objects are present in
  the store and issuer-link (`skid`/`akid`) to the bound leaf -- it does
  **not** need an explicit `ca=` field, but it very much needs the
  intermediate object to still exist. This is also a currently-active,
  independently-reported MikroTik community issue for Let's Encrypt's newer
  `YR`/`YE` intermediate hierarchy specifically (RouterOS's own ACME client
  has the same failure mode for unrelated reasons) -- this codebase's
  version of the bug is in the custom `certbot`-based push script, not
  RouterOS's ACME client (which isn't used here), but the underlying
  RouterOS chain-serving behavior is the same.
- This exactly matches the guest-facing symptom: the leaf is genuinely
  Let's-Encrypt-issued and its offline chain-of-trust is real (confirmed
  above), but an incomplete on-the-wire chain is invisible to full desktop
  browsers (which often fetch the missing intermediate via AIA) and fatal
  to strict/embedded TLS clients that don't (iOS's Captive Network
  Assistant, most notably) -- consistent with "click through the warning,
  then it works."

**Live handshake test: attempted, could not be safely obtained, flagging
honestly rather than assuming.** Four avenues were tried:
1. Direct TCP/TLS from a WireGuard-tunneled machine to `10.5.50.1:443` --
   no route exists on the client side (`10.20.0.0/24` only via the tunnel
   interface); confirmed via `ip route` and a hung `openssl s_client`/`nc`
   that timed out rather than refused, meaning the packet never left the
   client -- this is a route-level restriction on the tunnel client, not
   (only) the router firewall.
2. The router's own firewall was checked in detail and is **not** actually
   the blocker it was assumed to be: `cloudguest-fw-allow-wg-mgmt`
   (`chain=input action=accept in-interface=wg-cloudguest`) has no
   dst-address/dst-port restriction, and the hotspot module's own dynamic
   rules only match already-tracked hotspot clients (`hotspot=from-client`),
   so a raw connection arriving via the WireGuard interface to `10.5.50.1:443`
   would pass the router's input chain uncontested. The real barrier is
   upstream of the router, on the tunnel client's own routing table.
3. SSH TCP-forwarding through the router itself (which *does* have a direct
   route to `10.5.50.1` as a directly-attached interface) was considered --
   RouterOS's own SSH server has `forwarding-enabled=no` -- but enabling it
   is a live config write on a router serving real guest traffic outside
   this incident's original scope, and was correctly declined rather than
   forced through.
4. RouterOS's packet sniffer (`/tool sniffer`) could capture a real guest's
   live handshake off the `bridge` interface -- but it was found **already
   actively running** a separate live capture (`radius-capture`, growing in
   real time) apparently from concurrent work on this same router; with only
   one sniffer instance available RouterOS-wide and very little free flash
   (~4.3MiB), reconfiguring it would have clobbered that other capture, so
   this was deliberately left alone.
5. `/tool fetch` from the router itself to its own bridge address
   (`10.5.50.1`, not loopback) was also tried, on the theory that the
   loopback-specific "Connection refused" noted below might not apply to
   the router's real bound address -- it does: same "Connection refused".
   This confirms (rather than routes around) the original note that
   self-testing hotspot-bound ports from the router itself is
   architecturally unreliable, not just a loopback quirk.

No safe path to a real client-side handshake trace was found this round
either. **What stands in for it**: the certificate-store evidence above is
mechanistic, not inferential -- the exact script bug that deletes the
intermediate was located and reproduced in the router's actual state before
the fix, and the fix was verified by re-running the *complete* real router-push
path (`FORCE_RENEW=1`, a genuinely new issuance, real import/rebind) and
confirming the resulting `/certificate print detail` shows the leaf correctly
issuer-linked to a present, trusted intermediate, which is present, trusted,
and issuer-linked to a present, trusted cross-sign root -- i.e. everything
a chain-building TLS server needs to serve the complete chain is confirmed
present. **Genuinely still outstanding**: an actual real handshake trace
(`openssl s_client` or an on-WiFi device) has still not been captured. If a
future session gets tunnel access that actually routes to `10.5.50.1`
(e.g. the WireGuard peer's `AllowedIPs` gets extended to cover
`10.5.50.0/24` -- a router-side WireGuard peer config change, not attempted
here), that is the fastest real path; short of that, watching for the
*next* live guest report (or lack of one) is the practical signal.

### The fix

`renew-hotspot-certs.sh`'s router-push script was corrected (steps
renumbered in the script's own comment):
- The stale-artifact sweep now also clears old stable
  `<name>-chain-N` objects from a prior renewal round (not just the
  ephemeral `<name>.fullchain.pem_N` names), so repeated renewals don't
  collide or accumulate.
- After the leaf is promoted, rebound, and the old leaf removed (unchanged,
  already-proven-safe steps), every *remaining* object still matching the
  ephemeral fullchain pattern -- i.e. the intermediate(s), whatever
  RouterOS didn't already dedupe against an already-present identical
  object -- is renamed onto a stable `<name>-chain-1`, `<name>-chain-2`, ...
  name and marked `trusted=yes`, via
  `:foreach chainCert in=[/certificate find name~"..."] do={ ... }`
  (RouterOS scripting -- note this must be written as a single line when
  sent over a non-interactive SSH exec; a multi-line `do={ }` block that
  works fine pasted into an interactive RouterOS console produced a
  `syntax error` when sent as one SSH command string during testing here,
  and computing the new name into a `:local newName (...)` variable first
  was needed too -- inlining the string-concatenation directly into the
  `/certificate set name=(...)` argument also errored).
- Only *after* that rename does the final sweep of the ephemeral pattern
  run -- now a true no-op safety net (everything wanted has already been
  renamed off that pattern), not the accidental deletion mechanism it was
  before.
- The fix does not assume exactly one intermediate: whatever count
  Let's Encrypt's current chain hierarchy produces, the `:foreach` picks
  up and preserves all of it.

**Deployed and verified for real**, not just reviewed: pushed to
`/opt/wyfy/renew-hotspot-certs.sh` on the app VM (previous version backed
up alongside it as `renew-hotspot-certs.sh.pre-chainfix-backup-20260818`),
then exercised through `FORCE_RENEW=1` end-to-end against the live router --
a genuinely new certificate was issued (new serial, new `skid`) and pushed
through the corrected import/rebind/chain-preserve sequence. Resulting
router state, confirmed via `/certificate print detail`:
`wyfy-hotspot-fleet` (leaf, new serial, bound to `hsprof1` as before),
`wyfy-hotspot-fleet-chain-1` (`YR1` intermediate, `trusted=yes`, `skid`
matches the leaf's `akid`), `wyfy-hotspot-fleet-chain-2` (`Root YR`
cross-sign to `ISRG Root X1`, `trusted=yes`, `skid` matches chain-1's
`akid`) -- a complete, correctly issuer-linked chain, with zero leftover
ephemeral artifacts and the old self-signed `cloudguest-hotspot-cert`/
`cloudguest-hotspot-leaf` objects untouched. `hsprof1.ssl-certificate`
never changed name (`wyfy-hotspot-fleet` throughout) -- the currently-bound
cert was never left dangling mid-sequence, same discipline as the original
fix.

The one-off manual correction on the router (applied *before* the script
fix was written, to restore the guest-facing chain immediately without
waiting for the next scheduled renewal) followed the identical principle:
re-imported just `fullchain.pem` under a throwaway filename
(`wyfy-chainfix.fullchain.pem`) -- RouterOS automatically deduped the
already-present, already-bound leaf and only added the 2 missing chain
objects -- renamed them to stable names, marked trusted, and deleted the
throwaway upload file. The already-bound leaf and `hsprof1` were never
touched by this manual step either.

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
  itself) was not possible from this environment** -- this held up on a
  second, more thorough attempt later the same day (see "Incident update"
  above for the four avenues tried and why each didn't pan out: no route
  from the WireGuard client to `10.5.50.1`, an overly-broad-but-irrelevant
  router firewall rule that turned out not to be the actual blocker,
  RouterOS's SSH forwarding disabled, and its packet sniffer already busy
  with a concurrent capture). **This is not being left as an accepted
  permanent gap without a path forward**: the fastest real fix is extending
  the relevant WireGuard peer's `AllowedIPs` to cover `10.5.50.0/24` (a
  router-side config change, deliberately not made in either session so
  far since it's outside what either incident needed) -- do that first,
  next time this needs testing for real, rather than re-deriving the same
  four dead ends.
- **Correction to this section, written same-day**: the `FORCE_RENEW=1`
  test described immediately below was originally read as "confirmed
  clean, no orphaned artifacts." In hindsight (see "Incident update"
  above) that read was wrong -- "no orphaned `.fullchain.pem_1`/`_2`
  artifacts" is *exactly* what it looks like when the intermediate
  certificate has been deleted along with the truly-stale leftovers, not
  evidence the chain was preserved correctly. The router-push script had
  this bug from the start; this test exercised the buggy code path and
  its output looked identical to success. Left in place below as a record
  of what was actually checked at the time, not removed, but don't take
  "no leftover objects" as chain-correctness evidence on its own --
  cross-check against `/certificate print detail` actually showing an
  intermediate object issuer-linked (`skid`/`akid`) to the leaf, which is
  what the fixed script's own validation (see "Incident update") checks
  for instead.
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
