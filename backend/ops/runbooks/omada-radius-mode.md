# Runbook — putting one Omada venue on RADIUS mode (`authType 2`)

**Status: NOT EXECUTED. Nothing in this file has been run.** It is written to be
run by the owner, in order, and it contains three steps that need his explicit
approval before anybody touches them — one of which is a change to this
platform's security posture.

**Date written:** 2026-09-12 · **Author:** TP-Link/Omada engineer
**Companion documents:** `~/wyfy-omada/RADIUS-PORTAL-MODE.md` (the verified
contract and the network audit), `~/wyfy-omada/STATUS.md` (what is live).

---

## 0. Read this before anything else

### 0.1 What the code in this repository does and does not do

The application half of RADIUS mode is built and merged-ready (cloud-guest
`feat/omada-radius-portal-mode`, cloudguest-foundation `feat/omada-radius-portal-mode`).
A venue can be **recorded** as RADIUS mode, the guest portal **will** submit to
the controller's `browserauth` endpoint, and a controller **can** be registered
as a RADIUS NAS client keyed on its public address.

None of that puts a guest online, because of this:

> **The controller cannot reach our RADIUS server. The hub's security group
> allows UDP 1812/1813/3799 from `10.20.0.0/24` (the WireGuard overlay) and
> `172.31.0.0/16` (the VPC) only. Nothing on the public internet can send us an
> Access-Request.**

Every step below exists to change that for **one lab controller**, safely, and
to prove the loop end to end before the question of real venues is even asked.

### 0.2 The three things that need your approval

| # | Step | Why it needs you |
|---|---|---|
| 1 | **Remove the `0.0.0.0/0` catch-all RADIUS client** (§2) | It is a live credential change on the production RADIUS server. It is also a **prerequisite**, not a cleanup task — see below. |
| 2 | **Remove the 16 orphan client stanzas** (§3) | Same: live credentials, on a box nobody has shell on. |
| 3 | **Open UDP 1812/1813 to `13.126.39.79/32`** (§5) | A change to this platform's security posture. It is the first inbound port this estate has opened to anything but WireGuard. |

### 0.3 Step 1 is a prerequisite and this is why

`clients.conf` on the hub contains:

```
client cloudguest-dynamic-wan {
    ipaddr = 0.0.0.0/0
    secret = 14a06e26…
    require_message_authenticator = yes
}
```

FreeRADIUS matches an Access-Request to a client by source address, **most
specific first**, and `0.0.0.0/0` matches *everything that nothing else
matched*. Today the security group is the only thing that makes this
irrelevant: no packet from outside the tunnel can arrive at all.

**The moment §5 opens UDP 1812 to anything, every unmatched source address on
the internet falls into that client, with a fixed shared secret.** An attacker
who learns that one secret can then send Access-Requests from anywhere, against
any venue's identifiers, and our `authorize` path answers them.

So the order is not a preference:

> **Remove the catch-all client BEFORE opening the port. If §2 cannot be
> completed, stop — do not run §5.**

### 0.4 What you cannot do, and what that forces

**Nobody has shell on the hub.** Confirmed three ways (2026-09-11, unchanged):
it is absent from `aws ssm describe-instance-information`; its security group
`sg-0572384f19ff7ee15` allows TCP 22 from `103.248.87.30/32` and
`103.248.87.26/32` only, and our current address is not one of them; and
`aws ec2 describe-instance-connect-endpoints` returns `[]` on a Debian 12 AMI
where EC2 Instance Connect is unsupported anyway.

Therefore **every change to `clients.conf` in this runbook goes through the
`radius_agent` HTTP bridge on port 9092**, which is the only write path that
exists. That bridge can add and remove client stanzas keyed on a shortname. It
cannot edit `sites-enabled/default`, it cannot read a file back, and it cannot
tell you what is currently in `clients.conf`.

Two consequences you should hold onto while reading the rest of this:

* **§2 and §3 are performed blind.** The agent reports how many stanzas it
  removed; it cannot show you the file. Its `DELETE` handler re-reads the file
  after the write and refuses to report success if the stanza is still there,
  which is the strongest confirmation available.
* **The agent running on the hub is older than the copy in this repository.**
  It reads `tunnel_ip` (the backend sends both `tunnel_ip` and `address`, so
  this works), and it **ignores** `require_message_authenticator`. So a
  controller stanza written today lands with the agent's own default (`no`)
  rather than the hardening this platform asks for. That is recorded in §6.3
  and it is a real gap, not a formality.

---

## 1. Preconditions

Tick every one before starting. If any is false, stop.

- [ ] The lab controller `https://13.126.39.79:8043` is up (`GET /api/info`
      answers `errorCode: 0` with no credentials — verified 2026-09-12).
- [ ] You have the hub's `radius_agent` shared secret (`RADIUS_AGENT_SECRET`)
      and the agent answers on `:9092`. **Do not put it in a shell history —
      read it from wherever it is stored into an environment variable.**
- [ ] You accept that §2 and §3 change the live RADIUS server for the whole
      fleet, and that a mistake there rejects every MikroTik venue's guests.
      (The agent validates with `freeradius -CX` and restores its backup on any
      failure, so the realistic failure is "no change", not "RADIUS down".)
- [ ] Both PRs are merged, deployed and the deploy is healthy. **Note:
      `cloud-guest` `main` was RED as of 2026-09-12 (see PR #235) and CD is
      gated on CI, so a merged PR does not mean a deployed PR. Check the
      running image, not the branch.**
- [ ] Nobody else is driving the lab controller. Two agents on one controller
      made results non-reproducible on 2026-09-11 and produced one wrong
      measurement that had to be retracted.

---

## 2. Remove the `0.0.0.0/0` catch-all client — **PREREQUISITE, NEEDS APPROVAL**

The stanza's shortname is `cloudguest-dynamic-wan`. The agent removes every
stanza with that shortname, re-reads the file, and fails if any survives.

```bash
# READ THE SECRET FROM WHEREVER IT LIVES. Do not type it inline.
: "${RADIUS_AGENT_SECRET:?set this from the stored value}"
HUB=<hub-private-address>          # the app server can reach it; your laptop cannot

curl -sS -X DELETE "http://$HUB:9092/radius/client" \
  -H "X-Agent-Secret: $RADIUS_AGENT_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"nas_identifier": "cloudguest-dynamic-wan"}'
```

**Expected:** `{"status": "ok", "removed": 1}`.

* `removed: 0` means no stanza with that shortname exists — either it has
  already gone, or **its `shortname` differs from its label**. The capture
  shows the label `cloudguest-dynamic-wan`; the shortname line inside it was
  not separately recorded. If you get `removed: 0`, **stop and do not proceed
  to §5** — a catch-all you could not find is worse than one you know about.
* A `501` response means the deployed agent predates the `DELETE` handler. Then
  this step is impossible through the bridge, and §5 must not be run. (This
  handler shipped in the repository on 2026-08-22; whether the hub runs that
  build is **UNVERIFIED** — there is no way to ask it.)
* A `500` carries the agent's own explanation in the body. Read it: that body
  is frequently the only description of the failure that exists anywhere.

**Verify:** immediately re-run the same DELETE. A second call must answer
`removed: 0`. That is the only confirmation available without shell.

**Rollback:** there is none through this bridge, and you do not want one. If
the catch-all turns out to have been load-bearing for some device nobody
documented, that device shows up as a venue whose guests stop authenticating,
and the fix is to give it its own client stanza — not to restore a wildcard.

---

## 3. Remove the 16 orphan client stanzas — **NEEDS APPROVAL**

`STATUS.md` records 16 orphan stanzas still holding real shared secrets. They
are duplicates left by repeated re-provisioning: the live hub holds several
stanzas for one `nas_identifier`, one per tunnel IP that router has ever been
allocated.

The agent's `add_client` is idempotent on shortname — it strips every stanza
with that shortname and writes exactly one — so **the cleanest removal is a
re-registration, not a deletion**, for any NAS that is still in use:

```bash
# For a router that is still live: re-register it from the application, which
# rotates its secret and collapses its stanzas to one.
#   POST /api/v1/radius/nas/register-external/{router_id}
```

For a NAS that is genuinely gone, delete by shortname exactly as in §2.

**Do not delete a shortname you cannot account for.** A wrongly deleted stanza
takes a venue's guests offline silently: FreeRADIUS drops an Access-Request
from an address it has no client for **without a reply and without a log
line**. That is root cause #1 of the 2026-08-18 incident, and it is the single
hardest failure in this estate to diagnose from the outside.

**This step is not a prerequisite for §5** — an orphan stanza is keyed on a
tunnel address, which the internet cannot reach even after §5. It is on this
list because the port opening is the moment the estate stops being protected by
"nothing can reach it at all", and every live secret on that box should be one
somebody can account for.

---

## 4. Register the controller as a NAS client — *no approval needed, reversible*

This is application work and writes one stanza keyed on the controller's public
address. Run it **after** §2.

```bash
# 1. Move the QA integration to RADIUS mode (Master console / platform API).
#    Customer-facing surfaces cannot do this, deliberately.
curl -sS -X PATCH "$API/api/v1/network-integrations/platform/integrations/$INTEGRATION_ID" \
  -H "Authorization: Bearer $MASTER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"portal_mode": "radius"}'

# 2. Register the controller as a NAS client. The response carries the shared
#    secret ONCE -- it is generated here and never readable again.
curl -sS -X POST "$API/api/v1/network-integrations/platform/integrations/$INTEGRATION_ID/radius-nas" \
  -H "Authorization: Bearer $MASTER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"controller_ip": "13.126.39.79"}'
```

**Expected:** `201` with `nas_identifier`, `controller_ip`, `shared_secret`,
`hub_confirmed: true`.

* `hub_confirmed: false` means the database is ahead of the RADIUS server. Do
  not continue: that is exactly the divergence that rejects every guest at a
  venue while every row looks healthy. Re-run the same call; it takes the
  rotate branch and converges.
* A `502` means the hub bridge refused; its own explanation is in the `detail`.
* A `400` names one specific missing precondition (not in RADIUS mode, no fleet
  device, or an address a `client{}` stanza cannot be keyed on).

**Then configure the controller** (its own UI or v2 API): a RADIUS profile
pointing at the hub's public address with that shared secret, `authMode 1`
(PAP), and a portal with `authType 2`, `portalCustom 2`, and the
`externalUrl`/`externalUrlScheme` the integration's own response now carries
(it gains `portalMode=radius`). **Type the secret into the controller; do not
echo it anywhere else.**

**Rollback:** set `portal_mode` back to `external_portal` and delete the NAS
client. The venue returns to the proven contract.

---

## 5. Open UDP 1812/1813 from the lab controller — **SECURITY CHANGE, NEEDS APPROVAL**

**Do not run this if §2 did not report a successful removal.**

```bash
aws ec2 authorize-security-group-ingress \
  --group-id sg-0572384f19ff7ee15 \
  --ip-permissions \
    'IpProtocol=udp,FromPort=1812,ToPort=1813,IpRanges=[{CidrIp=13.126.39.79/32,Description="Omada lab controller - RADIUS mode trial 2026-09-12"}]'
```

**Scope is one /32, and that is the whole point.** `13.126.39.79` is our own
disposable EC2 controller, in our own account. It is not a customer address and
it is not a range.

**Do NOT add 3799 here.** In RADIUS mode, 3799 is a port the *controller*
listens on for Disconnect-Requests we would send *to it*. An inbound rule for
it on our hub is architecturally backwards — and one already exists on this
security group, written by somebody thinking about CoA and never finished. It
should be removed, not extended, but that is a separate change and not this
one.

**Rollback** (run this the moment the trial ends — it is one command and it is
the whole safety story of this step):

```bash
aws ec2 revoke-security-group-ingress \
  --group-id sg-0572384f19ff7ee15 \
  --ip-permissions \
    'IpProtocol=udp,FromPort=1812,ToPort=1813,IpRanges=[{CidrIp=13.126.39.79/32}]'
```

### 5.1 Why this does not scale to venues, stated plainly

This rule works because the lab controller has one static public address that
we own. A real venue does not:

* an SMB venue's controller egresses from an **ISP-assigned address that
  changes**, so the rule and the `client{}` stanza both rot, silently, and the
  failure is a venue whose guests stop connecting with nothing in any log;
* one rule per venue means a security-group change per customer, and security
  groups have quota limits measured in dozens;
* opening 1812 to a venue's NAT address opens it to **every device behind that
  NAT**, which at a venue is every guest on the guest WiFi.

The three real answers, from `RADIUS-PORTAL-MODE.md` §2.1, none of them small:
open per-venue public IPs (rejected above), put every venue on the WireGuard
tunnel (that is the MikroTik box this integration exists to avoid), or
**terminate RADIUS on a public front end — RadSec, which the Omada RADIUS
profile schema supports (`radSecEnable`, `caCert`, `clientCert`)**. The third
is the only one that scales, and it is a new production service with its own
certificate lifecycle. **Nothing in this runbook builds toward it.** This
runbook proves one loop on one controller; it is not the first step of a
rollout.

---

## 6. Test the loop

### 6.1 Order

1. `GET /api/info` on the controller still answers (nothing here should have
   touched it).
2. From the controller's own instance, confirm the hub answers on 1812 at all
   — a UDP port gives no handshake, so the honest test is a real
   Access-Request, which is step 3.
3. Associate a real client to the RADIUS-mode SSID, let it be redirected, sign
   in through the portal, and watch.

### 6.2 What each outcome means

| What the guest sees | What it means |
|---|---|
| The site they were going to, or `/portal/session` | It worked. The controller got an Access-Accept and opened the gate. |
| A raw JSON blob `{"errorCode":-41530,…"times out"}` | **The controller could not reach our RADIUS server.** §5 did not take effect, or the profile points somewhere else. This is the expected failure before §5. |
| A raw JSON blob `{"errorCode":-41529,…"Incorrect username or password"}` | We answered Access-Reject. The identifier had no ACTIVE `GuestSession` on the NAS the request was matched to — the binding in §4 is wrong, or the session ended. |
| A raw JSON blob `{"errorCode":-41501,…}` | Catch-all. On a 6.x controller this covers a missing required field too, so it proves little on its own. |
| A certificate warning before anything else | §7.1. |

**Every one of those failures is a raw JSON blob rendered by the browser.** The
form POST is a top-level navigation, the controller answers it with
`Content-Type: application/json` and no page, and there is nothing our portal
can intercept — it has already navigated away. There is no failure-URL field in
`ExternalRadiusSetting` (re-read off the controller's own `/v3/api-docs`,
2026-09-12) and the controller's own portal bundle never references
`browserauth` at all. **This is what a guest sees on every failed login on this
contract, and it cannot be styled.**

### 6.3 What to check afterwards, and one thing to check by hand

* The integration's event feed: a `portal_authorize` error with
  `NETWORK_INTEGRATION_PORTAL_MODE_MISMATCH` means a guest reached the *old*
  authorize endpoint — a stale portal URL, which is harmless and expected for a
  device that had the venue's page cached.
* `radius_nas_clients` for the controller: `hub_client_synced_ip` should equal
  the controller's public address.
* **By hand, and it cannot be automated:** the controller stanza was written
  with `require_message_authenticator = no`, because the deployed hub agent
  ignores the flag this platform sends (§0.4). Until that agent is redeployed,
  the one client of ours whose source address is reachable from the internet is
  also the one not demanding a Message-Authenticator (BlastRADIUS,
  CVE-2024-3596). Omada *does* send the attribute on every request — measured
  on the wire, PAP and CHAP alike — so requiring it costs nothing and is purely
  blocked on getting a newer agent onto the hub.

---

## 7. Things I believe are unsafe, listed rather than omitted

### 7.1 The guest's browser is told to POST an identifier to a self-signed certificate

`scheme=https&target=13.126.39.79&targetPort=8843` tells the guest's browser to
submit to an **IP address over TLS**, and that controller presents
`CN=localhost, O=TP-Link`, self-signed, SAN `DNS:Omada`. No IP SAN, no matching
CN, no public CA. A phone will refuse it. My own cross-origin probes succeeded
only because that Chrome profile already held a manual exception from the admin
UI being open in another tab — **do not read those successes as evidence a
guest device works.**

This is not fixed by anything in this runbook, and I do not know how to fix it
per venue: the redirect hands the browser an **IP**, so there is no hostname to
get a certificate for. Whether `target` can be made a hostname was not
determined; it is worth 20 minutes in the controller UI before anyone plans a
venue rollout. Until then, treat §6 as a test of the RADIUS loop, not of the
guest experience.

### 7.2 The venue binding is weaker on this contract, not stronger

The Access-Request's source is the **controller**, and its `Framed-IP-Address`
is the venue's public NAT address — identical for every simultaneous guest.
Both are venue identifiers at best. A WyfyGuest-hosted controller serving
several venues would arrive from *one* address for all of them, and the
NAS→venue binding stops identifying the venue at all. Do not put a second venue
behind one controller on this contract without solving that first.

### 7.3 Accounting is the reason to want this mode and it did not run

Enabling `radiusAccountingEnable` on the test controller made **every**
authentication fail with `-41501` while emitting **zero** packets to 1813
across 19 authentications. Unresolved — possibly our misconfiguration,
possibly a controller defect. Until it is resolved, RADIUS mode's one genuine
advantage over the contract we already have is hypothetical. There is a
concrete next step in `RADIUS-PORTAL-MODE.md` §9 and it needs the capture
listener running on the controller's own instance.

### 7.4 Per-guest disconnect is weaker here, and the product says so

On this contract this platform never issued the authorization, so there is no
row to revoke and nothing to find the guest's session from. A staff
"Disconnect" asks the controller to drop the client and **does not stop the
guest logging straight back in** — what closes that is ending their
`GuestSession`, which is a separate action. The API now returns
`mechanism: "controller_client_only"` for exactly this reason; any UI that
renders "Disconnected" without reading it will overstate what happened.

---

## 8. What stands between this runbook and a guest actually getting online

In order, with nothing omitted:

1. **§2** — the catch-all client must go. Blocking, and blind.
2. **§5** — inbound UDP 1812/1813 must exist. Blocking, security-affecting,
   and one /32 only.
3. **§4** — the controller must be registered as a NAS and configured with the
   matching profile and portal.
4. **The certificate (§7.1).** Even with 1–3 done, a real phone is likely to
   refuse the submit. **This is the step I cannot tell you how to complete**,
   and it is the one that decides whether this is a product or a lab result.
5. **Accounting (§7.3)**, if the reason for wanting this mode is quota/FUP.
   Unproven on both sides.
6. **A scalable network path (§5.1)**, before a second venue. RadSec or
   nothing.

Steps 1–3 are a day. Step 4 is unknown. Steps 5–6 are projects.
