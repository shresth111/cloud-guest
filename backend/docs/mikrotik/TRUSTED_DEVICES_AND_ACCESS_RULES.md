# Trusted Devices and Access Rules — RouterOS realization design

**Status:** design only. No code in this document has been run against a device.
**Author's device access:** none. Every statement about the lab router below is
second-hand, from a read taken by the orchestrator and quoted verbatim in §1.3.

---

## 0. How to read this document

### 0.1 Evidence markers

Every load-bearing claim carries one of these. If a claim has no marker it is a
statement about *this codebase*, which I read directly and can be checked by
opening the cited file.

| Marker | Means |
|---|---|
| `[DOC]` | MikroTik official documentation (help.mikrotik.com / manual.mikrotik.com), quoted or paraphrased, cited inline. |
| `[FORUM]` | MikroTik community forum or community wiki. Corroboration only. Never used alone for a decision that writes to a device. |
| `[LAB]` | Observed on the lab router (hEX lite, RouterOS 7.23.3) and reported in §1.3. I did not take this read myself. |
| `[FIELD]` | Observed on a production router in this fleet, recorded in this codebase's own source comments, cited by file and line. |
| `[UNVERIFIED]` | Cannot be settled without hardware. Every one of these has an exact test in §7. **None of them may be treated as fact before that test runs.** |

### 0.2 A note on the missing companion document

The brief asked me to read `docs/vlan/BRIDGE_VLAN_FILTERING.md` — a colleague's
write-up of how a config change on this exact router took the guest network
down. **That file does not exist in this repository.** `docs/vlan/` contains
`DATABASE.md`, `FLOW.md`, `README.md` and nothing else, checked twice, ten
minutes apart, at 07:13 and 07:53 on 2026-09-03. There is no file matching
`*VLAN_FILTERING*` anywhere under `/Users/shresth/cloud-guest-repo`.

I have not read it, so I cannot claim to have applied its specific conclusions.
What I have applied is the discipline the brief attributes to it, which is also
the discipline this fleet has been taught twice by its own incidents:

> **A read-back of the object you just wrote is not evidence that the data plane
> changed.** Both real failures in §1.5 pass a read-back with flying colours.

Every verification step in §7 and §8 is a counter, a byte delta, or a real
client device. None of them is a `print` of the thing that was just written.

---

## 1. Ground truth

### 1.1 "Trusted Devices" — what it actually is

| Layer | Artifact |
|---|---|
| Catalog entry | `{ id: "mac-auth", label: "Trusted Devices", icon: Fingerprint }` in `/Users/shresth/cloudguest-foundation/src/config/customerFeatureCatalog.ts`, group `"Access & Policy"`, owner-only per `src/lib/customerNav.ts` |
| Component | `MacAuthView` in `/Users/shresth/cloudguest-foundation/src/components/features/OperationsFeatures.tsx` (line 3884) |
| API | `GET/POST /mac-authorization/entries`, `PUT/DELETE /mac-authorization/entries/{id}` |
| Backend | `/Users/shresth/cloud-guest-repo/backend/app/domains/mac_authorization/` |
| Table | `mac_authorization_entries` — `organization_id`, nullable `location_id`, `mac_address`, `authorization_type` (`permanent`/`temporary`), `expires_at`, `comment`, `is_enabled`. **No `router_id`.** |

The only code anywhere that reads a `MacAuthorizationEntry` for device purposes
is `render_mac_authorization_entry` in
`app/domains/network_config/renderers.py:1009`, reached only from
`NetworkConfigService.push_config` (`service.py:548`), reached only from
`POST /network-config/routers/{router_id}/push`. That endpoint is a Master
console action; nothing in the customer dashboard calls it.

### 1.2 "Access Rules" — what it actually is

The brief asked me to work out whether `policy` or `firewall` backs the
customer-facing Access Rules screen. **Neither, in the sense the question
implies.** The answer changes the whole design, so it goes first.

`{ id: "policies", label: "Access Rules", icon: ShieldCheck }` renders
`PoliciesHub` (`src/components/features/PoliciesHub.tsx`), which is a five-tab
shell:

```ts
const ACCESS_TABS = [
  { id: "location",  label: "Guest WiFi Limits" },
  { id: "block",     label: "Blocked Guests"    },
  { id: "whitelist", label: "Always Allowed"    },
  { id: "smartid",   label: "Sign-in Methods"   },
  { id: "group",     label: "Access Tiers"      },
];
```

Backed by:

| Tab | Backend domain | Endpoints |
|---|---|---|
| Blocked Guests / Always Allowed | **`app/domains/guest_access`** | `/guest-access/rules`, `/guest-access/device-rules`, `/guest-access/check` |
| Guest WiFi Limits / Access Tiers | **`app/domains/policy`** (+ queue_management) | `/policies`, `/policies/{id}/versions`, `/policies/{id}/assignments` |
| Sign-in Methods | `captive_portal` | `PUT /captive-portal-configs/{id}` |

**`app/domains/firewall` backs no customer screen at all.** Its consumer is
`src/components/network/FirewallManagement.tsx` at route `/network/firewall`,
which appears in neither `customerFeatureCatalog.ts` nor `customerNav.ts` — a
Master-console-only page whose own header says *"Device push happens through a
separate configuration pipeline."*

So there is not one feature here, there are three, and conflating them is the
first way to get this wrong:

1. **Guest access rules** (identifier + MAC allow/deny) — customer-facing, the
   thing the customer means by "access rule". Designed in §4.
2. **Bandwidth/quota policies** — customer-facing, already `queue_management`'s
   job (simple queues, RADIUS rate-limit attributes). **Out of scope here** and
   deliberately not redesigned.
3. **Firewall filter rules** — Master-console, five-tuple, has a real
   `priority` column. Designed in §5, because it is where the rule-ordering
   question actually lives, and because the ordering defect it would inherit is
   *already live* on this fleet (§1.5).

The customer's Access Rules screen has **no direction, no source, no
destination, no protocol, no port, and no priority field anywhere.** Designing a
five-tuple firewall pipeline for it would be building something nobody asked
for.

### 1.3 The lab router, as reported

Reproduced from the brief, unverified by me:

```
hEX lite / RB750r2, RouterOS 7.23.3, mipsbe, switch chip Atheros-8227
bridge 'bridge'  vlan-filtering=no   10.5.50.1/24 directly on it
  ports ether2..ether5  pvid=1  frame-types=admit-all  hw=True
ether1 = WAN (dhcp-client, 192.168.1.100/24), NOT a bridge port
wg-cloudguard = management tunnel, NOT a bridge port
/ip hotspot  hotspot1  interface=bridge  profile=hsprof1  address-pool=hotspot-pool
/ip pool     hotspot-pool  10.5.50.10-10.5.50.254
/ip hotspot profile hsprof1: use-radius=yes, radius-accounting=yes,
    radius-interim-update=received, login-by=http-pap,
    hotspot-address=10.5.50.1, dns-name=wifi.wyfyguest.com
/radius  service=hotspot  address=10.20.0.1  ports 1812/1813  comment='cloudguest-radius'
/radius incoming  accept=FALSE  port=3799        <- CoA/Disconnect is OFF
/ip firewall filter: 27 rules, several marked 'cloudguest-*', plus hotspot hs-* chains
/ip firewall nat: 18 rules, incl. srcnat masquerade out-interface=ether1
    comment='cloudguest-nat-wan1' with NO src-address (NATs every subnet)
```

Two things in that read deserve naming before anything else is designed.

**`/radius incoming port=3799` with `accept=FALSE` is a contradiction that tells
a story.** RouterOS's documented default for `/radius incoming` is
`accept=no, port=1700` [DOC — [RADIUS, RouterOS Manual](https://manual.mikrotik.com/docs/authentication-authorization-accounting/radius/): *"**accept** (yes | no; Default: **no**) - Whether to accept unsolicited messages"*, *"**port** (integer; Default: **1700**)"*]. Port 3799 is not a
default; it is exactly what this codebase writes, in two independent places:

- `app/domains/network_config/renderers.py:1413` — `"/radius incoming set accept=yes port=3799"`
- `vendor/wyfy-device-gateway/wyfy_device_gateway/mikrotik_adapter.py:2130` — `api.path("radius", "incoming").update(accept="yes", port="3799")`

Both set `accept=yes` in the same statement as `port=3799`. The device now holds
one half and not the other. That means either the port survived a later change
that reset `accept`, or a partial apply happened, or someone turned it off by
hand. **I do not know which, and neither does anything in this repository.** The
design consequence is in §3.3: CoA availability is a per-router runtime fact
that must be read, never assumed, and never inferred from "we configured it".

**`cloudguest-nat-wan1` has no `src-address` and therefore masquerades every
subnet on the box.** Not my problem to fix here, but it is the reason a
carelessly-placed `forward` drop rule on this router is more dangerous than it
looks: there is no subnet-scoped NAT boundary to contain a mistake.

### 1.4 The authorized-MAC pull loop, in full

The brief describes a router-side scheduler. Here is what it actually is, and
where it lives — which is not where you would expect.

**The scheduler is generated by the frontend, not the backend.** There is no
`authmac` string anywhere in `/Users/shresth/cloud-guest-repo`. It is produced
as copy-paste terminal text by the Master console's router setup panel:

- `/Users/shresth/cloudguest-foundation/src/components/routers/RouterDetailTabs.tsx:4250` — `buildAuthorizedMacStatements()`
- `RouterDetailTabs.tsx:7697-7698` — wraps it in `/system scheduler add name="cloudguest-authmac-sched" interval=1m start-time=startup on-event="..."`, preceded by a `remove` of any existing scheduler of that name.

The script body, transcribed from that function:

```routeros
:local amData ""
:do { :set amData ([/tool fetch url="<apiBase>/agent/authorized-macs" \
      http-header-field="X-Agent-Credential: <cred>" output=user as-value]->"data") } \
   on-error={ :log warning "cloudguest-am: authorized-MAC fetch failed" }
:local amBad 0
:local amMacs [:toarray ""]
:if ($amData != "") do={ :do { :set amMacs ([:deserialize from=json value=$amData]->"mac_addresses") } on-error={ :set amBad 1 } }
:if ($amBad = 1) do={ :log warning "cloudguest-am: authorized-MAC reply unparseable" }
:local amOk 0
:if ($amData != "" && $amBad = 0) do={ :set amOk 1 }
:if ($amOk = 1) do={ :foreach amB in=[/ip hotspot ip-binding find where comment="cloudguest-authmac"] \
   do={ :if ([:typeof [:find $amMacs [/ip hotspot ip-binding get $amB mac-address]]] = "nothing") \
        do={ /ip hotspot ip-binding remove $amB } } }
:if ($amOk = 1) do={ :foreach amM in=$amMacs \
   do={ :if ([:len [/ip hotspot ip-binding find where mac-address=$amM]] = 0 && \
             [:len [/ip hotspot active find where mac-address=$amM]] = 0) \
        do={ /ip hotspot ip-binding add mac-address=$amM type=bypassed comment="cloudguest-authmac" } } }
```

Four properties of this script are load-bearing and must survive any redesign.
They were each paid for with a real incident:

1. **Removal is scoped to `comment="cloudguest-authmac"`.** A venue AP that an
   operator bypassed by hand is never deleted out from under them.
   (`RouterDetailTabs.tsx:4090-4094`, quoting a real live router.)
2. **Addition requires `[find where mac-address=$amM]` to be empty** — not
   "none of ours". A MAC someone already bypassed manually does not collect a
   duplicate row every minute.
3. **Addition is skipped for a MAC in `/ip hotspot active`.** [FIELD] From
   `RouterDetailTabs.tsx:4276-4288`, on router `10.5.50.1` (huda city center):
   ```
   22:48:34 hotspot: <mac> (10.5.50.240): logged in       <- RADIUS OK
   22:48:35 hotspot: logged out: host removed: ip binding changed
   ```
   Adding a `type=bypassed` binding for a MAC RouterOS is already tracking as an
   authenticated hotspot host makes RouterOS reconcile the two by **removing the
   live host**. The session dies one tick after it succeeds. On iOS — which also
   rotates its MAC — the phone then flaps DHCP and shows "no internet".
4. **An empty reply still runs the removal pass.** "Nobody is signed in" is a
   legitimate answer that must revoke, not a reason to skip.

**And the endpoint it polls does not read Trusted Devices at all.**
`app/domains/router_agent/router.py:229-252`:

```python
async def agent_authorized_macs(
    identity: AgentIdentity = Depends(CurrentAgent),
    guest_repository: GuestRepositoryProtocol = Depends(get_guest_repository),
) -> AuthorizedMacsResponse:
    sessions = await guest_repository.list_active_sessions_for_router(identity.router.id)
    macs: list[str] = []
    for session in sessions:
        if session.device_id is None:
            continue
        device = await guest_repository.get_device_by_id(session.device_id)
        if device is not None:
            macs.append(device.mac_address)
    return AuthorizedMacsResponse(mac_addresses=sorted(set(macs)))
```

`list_active_sessions_for_router` — guests who already logged in via OTP.
`MacAuthorizationEntry` is not imported by this module.

**This is the whole gap for Trusted Devices, in one sentence:** the router polls
faithfully every 60 seconds, and the thing it polls has never heard of the
Trusted Devices list.

### 1.5 Two live defects this design must not repeat

**(a) The push path cannot reach a router.** From
`app/domains/vlan/device_adapters.py:17-23`, written by whoever built the first
real device adapter:

> `network_config`'s push path renders a script and ships it with SFTP +
> `/import` over **asyncssh on port 22**, which is filtered on the fleet. That
> path cannot reach a real router, and its handler returns 202 `success: true`
> regardless. Anything routed through it inherits both problems.

`POST /network-config/routers/{id}/push` returns HTTP 202 with `success=True`
(`network_config/router.py:159-180`). `render_mac_authorization_entry` and
`render_firewall_rule` both feed exclusively into that path. They are correct
code with no reachable consumer.

**(b) `_idempotent_lines` is add-only, and for firewall rules it is worse than
that.** `renderers.py:2552`:

```python
return [
    line if line.lstrip().startswith("#") else f":do {{ {line} }} on-error={{}}"
    for line in lines
]
```

Every rendered command is an `add`. Nothing is ever removed, so a full
"desired-state" re-render cannot express *"the customer un-trusted this
device"*. Worse, `/ip firewall filter add` does not reject a duplicate — an
identical rule added twice becomes two rules [UNVERIFIED, test T6 in §7; this
is the expected RouterOS behaviour and the reason `on-error={}` is a no-op
there]. If that path were ever revived, **every push would append another copy
of every firewall rule**, and the `on-error={}` wrapper would hide it.

**(c) The content-filter DROP rule is appended to the bottom of the forward
chain.** `mikrotik_adapter.py:2228-2245`:

```python
def _ensure_content_filter_enforcement_rule(self, api) -> None:
    existing_filters = list(api.path("ip", "firewall", "filter"))
    already_present = any(
        row.get("comment") == _CONTENT_FILTER_ENFORCEMENT_COMMENT
        for row in existing_filters
    )
    if not already_present:
        api.path("ip", "firewall", "filter").add(
            chain="forward",
            **{"dst-address-list": _CONTENT_FILTER_ADDRESS_LIST_NAME},
            action="drop",
            comment=_CONTENT_FILTER_ENFORCEMENT_COMMENT,
        )
```

No `place-before`. On a router with 27 filter rules where any earlier `accept`
matches guest forward traffic, this DROP is never evaluated — RouterOS processes
a chain top to bottom, first match wins [DOC — [Filter, RouterOS](https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter)]. The
dedup check reads back `comment == ...` and passes. The feature reports success
and blocks nothing.

This is the exact failure mode the brief warns about, already shipped. Any
`configure_access_rule` written the same way inherits it. §5 exists to prevent
that.

---

## 2. Trusted Devices: what "trusted" must mean on the device

### 2.1 The candidate mechanisms

| Mechanism | What it does | Verdict |
|---|---|---|
| `/ip hotspot ip-binding type=bypassed` | *"performs the translation, but excludes client from login to the HotSpot"* [DOC — [HotSpot](https://help.mikrotik.com/docs/spaces/ROS/pages/56459266/HotSpot)] | **Recommended.** |
| RADIUS MAC authentication | `login-by=mac` + a MAC-as-username Access-Request the server answers | Correct long-term; **not available today** (§2.3). |
| `/ip firewall filter action=accept` | Permits forwarding | **Wrong.** Does not stop the portal. |
| `/ip hotspot walled-garden` | Per-destination unauth allowance | **Wrong axis.** Destination-keyed, not client-keyed. |

**Why a firewall accept is wrong, specifically.** The captive portal is a
*destination NAT redirect*, not a filter drop. An unauthenticated host's HTTP is
dst-nat'd into the hotspot's own web server by the hotspot service's dynamic NAT
chain. A rule in `/ip firewall filter chain=forward action=accept` runs in a
different table entirely and cannot un-redirect an already-redirected packet.
A "trusted" device configured that way still gets the login page — while the
dashboard says it is trusted. That is a read-back-passes, data-plane-fails
defect of exactly the kind in §1.5(c).

**Why walled-garden is the wrong axis.** `/ip hotspot walled-garden` and
`walled-garden ip` are keyed on *destination* — `dst-host`, `dst-address`,
`dst-port` [DOC]. They answer *"which sites may an unauthenticated guest
reach"*, which is the captive portal's own allowlist (this codebase already owns
that as `MANAGED_WALLED_GARDEN_COMMENT`). They cannot express *"this MAC is
exempt"*. `walled-garden ip` does have `src-address`, but it takes an IP, not a
MAC, and a DHCP-pool address is not a device identity.

### 2.2 What the customer actually expects

The screen says "Trusted Devices". The customer is a hotel owner adding the
front-desk tablet, the lobby Chromecast, the POS terminal, the manager's laptop.
What they expect is: **this device joins the WiFi and works, permanently,
without anybody typing an OTP.** That is `type=bypassed`, precisely.

Three consequences of `bypassed` must be surfaced in the product, not buried:

1. **A bypassed device produces no RADIUS accounting.** It is excluded from
   login, so there is no hotspot session, no Accounting-Start, no
   `GuestSession` row, and no data-usage figure. The device will be invisible in
   every usage report. That is the correct RouterOS behaviour and the wrong
   thing to let a customer discover from a report.
2. **A bypassed device is exempt from every per-session policy** — session
   timeout, idle timeout, bandwidth cap, quota. Those are enforced through the
   hotspot user profile and RADIUS reply attributes, and a bypassed device never
   authenticates, so none apply. **Trusting a device silently removes it from
   Access Tiers.** If the product wants trusted devices to still be
   rate-limited, that needs a simple queue keyed on the device's address, which
   is `queue_management`'s job and a separate piece of work.
3. **`bypassed` is not `blocked`, and neither is "allowed with restrictions".**
   RouterOS gives exactly three types [DOC]: `regular` (translate + still log
   in), `bypassed` (translate + skip login), `blocked` (drop). There is no
   fourth. Any product concept that needs one must be built out of a queue or a
   filter rule, not out of `ip-binding`.

### 2.3 Why not RADIUS MAC authentication (yet)

The architecturally cleaner answer is: put the MAC in the RADIUS server's own
authorization decision, set `login-by=mac` on the hotspot profile, and let a
trusted device authenticate as itself. That gives accounting, session records,
per-device policy, and — critically — **revocation via Disconnect-Message**,
because the device now has a real session to disconnect.

It is not available today, for three independent reasons:

- The lab profile is `login-by=http-pap` [LAB]. `login-by=mac` is not set.
- Nothing in `ops/freeradius/` answers a MAC-as-username Access-Request; the
  RADIUS side is `rest.conf`-driven against this backend's own guest endpoints.
- `/radius incoming accept=FALSE` [LAB] means the Disconnect-Message that makes
  this design worthwhile cannot be delivered anyway.

Recommend it as the target state and build `bypassed` now. Do not build both.

### 2.4 MAC randomization is a structural limit, not an edge case

iOS 14+ and Android 10+ default to a per-SSID randomized MAC. A randomized MAC
has the *locally-administered* bit set — bit 1 (`0x02`) of the first octet. A
"Trusted Devices" list on a guest network is therefore, for phones, a list of
identities that expire without notice. This is not fixable at the router; it is
fixable only by telling the customer to disable Private Wi-Fi Address for this
network on that device. §6 makes it a refusal, so the customer is told at entry
time instead of discovering it three weeks later.

---

## 3. Trusted Devices: does anything reach the router, and does removal revoke?

### 3.1 Do the dashboard's writes reach `authorized-macs`?

**No. Zero bytes.** The chain breaks at the first hop:

```
Customer clicks "Trust this device"
  -> POST /mac-authorization/entries
  -> MacAuthorizationService.create_entry
  -> INSERT INTO mac_authorization_entries
  -> 201 Created, toast "MAC address authorized"
  -- END --

GET /agent/authorized-macs  (polled every 60s by the router)
  -> guest_repository.list_active_sessions_for_router(...)
  -> ACTIVE GuestSession rows only
  -- mac_authorization_entries is never queried --
```

The delay between a customer clicking and the router acting is **unbounded**.
Not "long" — the event never occurs. `render_mac_authorization_entry` exists and
would emit the right command, but only via the SSH `/import` path that §1.5(a)
establishes cannot reach a fleet router, from an endpoint the customer dashboard
does not call.

### 3.2 What the delay *would* be, once the endpoint is fixed

Assuming §4.2's recommendation (union the two sources into the existing
endpoint) and nothing else:

| Stage | Time |
|---|---|
| DB write, transaction commit | < 50 ms |
| Wait for next scheduler tick | 0–60 s, uniform (`interval=1m`) |
| `/tool fetch` round trip over the WireGuard tunnel | 0.2–3 s |
| RouterOS script reconcile (2 passes over a short list) | < 200 ms |
| **Total** | **p50 ≈ 30 s, p95 ≈ 58 s, worst ≈ 63 s** |

Two caveats that matter more than the numbers:

- **The scheduler exists only where an operator pasted it.** It is
  copy-paste output from the Master console (§1.4), not part of any push, not
  reasserted, not verified. A router provisioned before that panel existed, or
  by someone who skipped the Heartbeat chunk, has no scheduler and a permanent
  latency of infinity. There is no server-side signal that distinguishes "no
  trusted devices" from "no scheduler". §6 makes that a refusal
  (`TRUSTED_DEVICE_SYNC_ABSENT`) once §4.4's push exists to detect it.
- **A trusted device that is *already* on the network when it is trusted will
  not be bypassed** — property 3 in §1.4 skips any MAC in `/ip hotspot active`,
  correctly, to avoid the teardown race. It gets bypassed after its current
  session ends. This is right, and the UI should say "will take effect after
  this device reconnects" rather than "trusted".

### 3.3 Does removal revoke? Three cases, three answers.

**Case A — bypassed device, no hotspot session.** Removing the `ip-binding` at
the next tick means the device's *next new connection* hits the portal redirect
again. **Existing established flows are not affected** — the hotspot redirect is
destination NAT on new connections, and RouterOS's connection tracker keeps
forwarding an already-established flow. A guest mid-download keeps downloading.
[UNVERIFIED — test T3 in §7; if confirmed, a conntrack flush is mandatory in
revoke, and this is the single highest-value test in the list.]

**Case B — device with a live hotspot session (logged in via OTP).** Removing an
`ip-binding` does **nothing** to it. It was never bypassed; it was
authenticated. Its session lives in `/ip hotspot active` and survives.

To actually end it there are exactly two mechanisms:

- **Device-local:** `/ip hotspot active remove [find mac-address=...]`
  [FORUM — [Disconnecting unauthorized hotspot users](https://forum.mikrotik.com/t/disconnecting-unauthorized-hotspot-users/42819); the command form is standard and appears throughout MikroTik community scripting]. Issued over the API on 8728, the transport the fleet actually has.
- **Server-initiated:** a RADIUS Disconnect-Message. *"RADIUS disconnect and
  Change of Authorization (according to RFC3576)"* is supported, and *"RouterOS
  doesn't support POD (Packet of Disconnect)"* [DOC — [RADIUS, RouterOS Manual](https://manual.mikrotik.com/docs/authentication-authorization-accounting/radius/)]. It requires
  `/radius incoming set accept=yes port=<port>`.

**Case C — where `/radius incoming accept=no`, which is the lab router right
now.** [LAB] The server cannot kick an established session at all. A CoA
Disconnect sent to 10.5.50.1:3799 lands on a closed port and is dropped. The
platform would log a send, get no NAK and no ACK, and — if written carelessly —
report "revoked".

**Recommendation: revoke device-locally over 8728, not by CoA.**

Reasons, in order of weight:

1. It works today, on the router as it is actually configured. CoA does not.
2. It has no dependency on `/radius incoming` state, which §1.3 shows this
   platform cannot currently keep straight across a fleet.
3. It has no shared-secret or NAS-identity correctness problem. A CoA request
   must carry the right secret, reach the right NAS address, and identify the
   session by `Acct-Session-Id` or `User-Name` + `Framed-IP-Address`; getting
   any of those wrong yields a silent drop or a Disconnect-NAK the platform
   would have to parse. An 8728 `remove` either succeeds or raises.
4. It does not require the server to reach the router on an inbound UDP port —
   the same NAT-traversal property that makes the pull loop right in the first
   place. The WireGuard tunnel does provide inbound reachability, so this is the
   weakest of the four reasons, but it still holds for any router whose tunnel
   is down at the moment of revocation, where both mechanisms fail and only the
   local one fails *loudly*.

**CoA is still worth building later, for a different job.** It is the only
mechanism that can *change* a live session — `Mikrotik-Rate-Limit`,
`Session-Timeout`, `Filter-Id`, `Port-Limit` [DOC] — without dropping it.
Downgrading a guest's speed mid-session is a CoA problem. Kicking them is not.
Note the documented limit: *"It is not possible to change IP address, pool or
routes that way — for such changes a user must be disconnected first."* [DOC]

---

## 4. Trusted Devices: the recommended design

### 4.1 Keep the pull. Add a push. The pull stays authoritative.

**Keep the pull loop.** Its properties are not incidental, they are the reason
this fleet works at all:

- **Survives a reboot.** `start-time=startup` means a power-cycled router
  re-converges within 60 s with no server involvement. A push-only design leaves
  a rebooted router with an empty `ip-binding` table and no event to tell anyone.
- **Self-heals.** Any drift — a manual edit, a partial apply, a config restore
  from an old backup — is corrected on the next tick. A push-only design has no
  mechanism to notice drift, ever.
- **Works when the router is behind NAT and when the tunnel is down.** The
  router initiates. The server needs no inbound path and no knowledge of the
  router's current address.
- **Fails safe and loudly.** A failed fetch logs and changes nothing
  (`amOk = 0` gates both passes). A failed push, in a push-only design, means
  silent divergence.

**Add a push, for latency only, and make it structurally non-authoritative.**
The push exists to turn a 30-second median into a 2-second median. It must
never be the thing that makes state correct:

- A push failure is logged at `warning` and the API still returns success for
  the DB write, *with a field saying the device has not converged yet*. It is
  not an error, because the pull loop will converge within 60 s.
- A push is never the only writer of a binding. Every binding the push creates
  is one the pull loop would also create, under a marker the pull loop
  understands.
- There is no "push succeeded, therefore the device is correct" claim anywhere.

**Do not replace the pull with a push.** A naive push has none of the four
properties above, and this fleet has already been burned by the
"looks-wired-up-but-isn't" class of failure twice (§1.5).

### 4.2 Step one, which is nine lines and no device code

`GET /agent/authorized-macs` must return the union of:

- MACs with an `ACTIVE` guest session on this router (what it returns today), and
- MACs from `MacAuthorizationEntry` rows that apply to this router and are
  currently valid.

The second half already exists.
`MacAuthorizationService.list_active_entries_for_router` (`service.py:353`)
resolves org/location scoping and filters to enabled, unexpired entries — its
docstring names `render_mac_authorization_entry` as its intended consumer,
which is the dead path. Point it at the live one instead.

**But do not merge them into one list.** They have different lifetimes and must
be reconciled against different markers, or they will fight:

| | Session MACs | Trusted MACs |
|---|---|---|
| Lifetime | ephemeral — gone when the session ends | durable — gone when the customer says so |
| Marker | `cloudguest-authmac` | `cloudguest-trusted` |
| Removed when | absent from the reply | absent from the reply |

If they shared a marker, a trusted device would be removed and re-added every
time its guest session state changed, and a session MAC would linger under a
"trusted" marker after logout.

**Recommended wire change — additive, so no router needs updating first:**

```json
{
  "mac_addresses": ["AA:BB:CC:DD:EE:01"],
  "trusted_mac_addresses": ["AA:BB:CC:DD:EE:02"]
}
```

`AuthorizedMacsResponse` gains one field with a `default_factory=list`. Routers
running the current script read `mac_addresses` and ignore the new key — a
RouterOS `:deserialize from=json` of an object with an extra key is fine, and
`->"mac_addresses"` still resolves. **No router is broken by deploying this
before the script is updated**, which matters because the script is pasted by
hand and the fleet will be mixed for months.

**One hazard to name explicitly.** `MacAuthorizationEntryResponse.mac_address`
is typed `MaskedMac` (`app/common/masking.py:182`). The masking function is
currently a pass-through (`masking.py:122`, `return value`), retained *"so every
``MaskedMac``-annotated field across the codebase stays wired through one place
if masking is ever reintroduced"*. If masking is ever switched on and someone
builds the agent payload from that response schema, **every router in the fleet
receives `AA:BB:**:**:**:FF` and applies it as a MAC address.** The agent
endpoint must read `entry.mac_address` off the ORM object directly, never
through the masked response schema, and there should be a test that asserts the
payload matches `^([0-9A-F]{2}:){5}[0-9A-F]{2}$`. Refusal code
`MAC_PAYLOAD_NOT_CANONICAL` (§6).

### 4.3 The updated router script

Two reconcile passes instead of one, each scoped to its own marker. The three
safety properties from §1.4 are preserved verbatim in both passes.

```routeros
# ---- fetch (unchanged) ----
:local amData ""
:do { :set amData ([/tool fetch url="<apiBase>/agent/authorized-macs" \
      http-header-field="X-Agent-Credential: <cred>" output=user as-value]->"data") } \
   on-error={ :log warning "cloudguest-am: authorized-MAC fetch failed" }
:local amBad 0
:local amMacs [:toarray ""]
:local amTrust [:toarray ""]
:if ($amData != "") do={ :do { :set amMacs ([:deserialize from=json value=$amData]->"mac_addresses") } on-error={ :set amBad 1 } }
:if ($amData != "" && $amBad = 0) do={ :do { :set amTrust ([:deserialize from=json value=$amData]->"trusted_mac_addresses") } on-error={ :set amTrust [:toarray ""] } }
:if ($amBad = 1) do={ :log warning "cloudguest-am: authorized-MAC reply unparseable" }
:local amOk 0
:if ($amData != "" && $amBad = 0) do={ :set amOk 1 }

# ---- pass 1: session MACs, marker cloudguest-authmac ----
:if ($amOk = 1) do={ :foreach amB in=[/ip hotspot ip-binding find where comment="cloudguest-authmac"] \
   do={ :if ([:typeof [:find $amMacs [/ip hotspot ip-binding get $amB mac-address]]] = "nothing") \
        do={ /ip hotspot ip-binding remove $amB } } }
:if ($amOk = 1) do={ :foreach amM in=$amMacs \
   do={ :if ([:len [/ip hotspot ip-binding find where mac-address=$amM]] = 0 && \
             [:len [/ip hotspot active find where mac-address=$amM]] = 0) \
        do={ /ip hotspot ip-binding add mac-address=$amM type=bypassed comment="cloudguest-authmac" } } }

# ---- pass 2: trusted MACs, marker cloudguest-trusted ----
:if ($amOk = 1) do={ :foreach amB in=[/ip hotspot ip-binding find where comment="cloudguest-trusted"] \
   do={ :if ([:typeof [:find $amTrust [/ip hotspot ip-binding get $amB mac-address]]] = "nothing") \
        do={ /ip hotspot ip-binding remove $amB } } }
:if ($amOk = 1) do={ :foreach amM in=$amTrust \
   do={ :if ([:len [/ip hotspot ip-binding find where mac-address=$amM]] = 0 && \
             [:len [/ip hotspot active find where mac-address=$amM]] = 0) \
        do={ /ip hotspot ip-binding add mac-address=$amM type=bypassed comment="cloudguest-trusted" } } }
```

Constraints inherited from `RouterDetailTabs.tsx` and confirmed there against
real hardware, which this must not violate:

- **Every `do={ }` body holds exactly one statement.** A `;`-chained body is a
  real syntax error on this hardware (`RouterDetailTabs.tsx:4248`).
- **The scheduler `on-event` string is near the ~3300-char paste ceiling** past
  which WinBox mangles a paste (`RouterDetailTabs.tsx:4235-4240`). This doubles
  the script. **It will not fit in one scheduler.** Split it: keep
  `cloudguest-authmac-sched` as-is and add a second
  `cloudguest-trusted-sched` running the fetch and pass 2 only. Two fetches per
  minute per router is 2 KB/min — irrelevant next to a broken paste. This is a
  hard constraint from the existing generator's own test suite, not a
  preference.

### 4.4 The push: exact commands, idempotently expressed

A new `app/domains/mac_authorization/device_adapters.py`, mirroring
`app/domains/vlan/device_adapters.py` field for field: its own credentials
dataclass, its own narrow `Protocol`, a `MikroTikMacAuthorizationAdapter`
delegating to `wyfy_device_gateway.registry.get_adapter`, and a small vendor
registry. Credentials resolve exactly as `VlanService._resolve_device_credentials`
does (`vlan/service.py:960`): `router.management_ip_address or
router.public_ip_address`, `router.api_username`, decrypted API secret, **raise
rather than guess** if any is missing.

Two new gateway methods.

#### `configure_trusted_device(creds, *, mac_address, entry_id)`

```python
_TRUSTED_COMMENT_PREFIX = "cloudguest-trusted"

def _trusted_binding_comment(entry_id) -> str:
    # Per-entry marker on the push side. The pull loop's own bulk marker is the
    # bare prefix; see §4.5 for why the two coexist without fighting.
    return f"{_TRUSTED_COMMENT_PREFIX}:{entry_id}"


def _configure_trusted_device_sync(self, creds, mac_address, entry_id) -> None:
    api = self._connect_api(creds)
    try:
        # 0. The router must actually run a hotspot. An ip-binding on a router
        #    with no hotspot server is an inert row -- it reads back fine and
        #    changes nothing. Refuse instead of writing a lie.
        if not list(api.path("ip", "hotspot")):
            raise MikroTikNoHotspotError(creds.host, "TRUSTED_DEVICE_NO_HOTSPOT")

        # 1. Never bypass a MAC that is currently an authenticated hotspot host.
        #    RouterOS reconciles the two by removing the live host:
        #    "logged out: host removed: ip binding changed". [FIELD, §1.4]
        #    Refuse. The pull loop will apply it after the session ends.
        active = api.path("ip", "hotspot", "active")
        if any(normalize_mac_address(r.get("mac-address")) == mac_address for r in active):
            raise MikroTikTrustedDeviceSessionActiveError(
                creds.host, "TRUSTED_DEVICE_SESSION_ACTIVE"
            )

        comment = _trusted_binding_comment(entry_id)
        desired = {"mac-address": mac_address, "type": "bypassed"}
        menu = api.path("ip", "hotspot", "ip-binding")
        rows = list(menu)

        # 2. Comment identity: find the row THIS entry wrote, and bring it into
        #    line. Keyed on the MAC instead, an edited MAC would orphan the old
        #    binding and leave a device bypassed that nobody can see in the UI.
        #    Same argument as configure_nat_masquerade's own docstring.
        for row in rows:
            if row.get("comment") != comment:
                continue
            changed = {k: v for k, v in desired.items() if row.get(k) != v}
            # Boolean, never a string compare against "no" -- see _is_truthy.
            if _is_truthy(row.get("disabled")):
                changed["disabled"] = "no"
            if changed:
                menu.update(**{".id": row[".id"], **changed})
            return

        # 3. A binding for this MAC that is not ours -- an operator's manual
        #    bypass for a venue AP, or the pull loop's own session binding.
        #    Never adopt, never overwrite, never add a second row alongside it.
        for row in rows:
            if normalize_mac_address(row.get("mac-address")) != mac_address:
                continue
            existing = row.get("comment") or ""
            if not existing.startswith(_TRUSTED_COMMENT_PREFIX):
                raise MikroTikForeignBindingError(
                    creds.host,
                    f"TRUSTED_DEVICE_FOREIGN_BINDING: {mac_address} is already bound "
                    f"with comment {existing!r}",
                )
            return  # already trusted under the bulk marker; the pull loop owns it

        menu.add(**desired, comment=comment, disabled="no")
    finally:
        api.close()
```

Notes on the write itself:

- **`server=` is left unset**, which means `all` [DOC]. Correct while a router
  runs one hotspot. On a VLAN-segmented router (`configure_vlan_hotspot` exists
  in the adapter) a `server=all` bypass exempts the device from *every* SSID,
  including ones the customer did not intend. When a location's hotspot server
  name is known, pass it. §8 lists this as a follow-up, not a today problem.
- **`address=` is left unset.** A DHCP-pool address is not a device identity;
  binding on it would break on every lease change. [DOC — with `address`
  unset the entry matches on MAC alone; [FORUM] corroborates the `0.0.0.0`
  wildcard behaviour.]
- **`disabled="no"` is explicit on `add`,** so a row this platform creates is
  never ambiguous.

#### `revoke_trusted_device(creds, *, mac_address, entry_id)`

Removal is where the design earns its keep, because §3.3 showed that removing
the binding is only one of three things that have to happen.

```python
def _revoke_trusted_device_sync(self, creds, mac_address, entry_id) -> None:
    api = self._connect_api(creds)
    try:
        comment = _trusted_binding_comment(entry_id)

        # 1. Remove the binding by COMMENT, not by MAC. If the customer edited
        #    the MAC before deleting the entry, the stale binding still carries
        #    this comment -- matching on the current MAC is exactly how it gets
        #    orphaned instead of removed. (delete_nat_masquerade, same reason.)
        menu = api.path("ip", "hotspot", "ip-binding")
        for row in list(menu):
            if row.get("comment") == comment:
                menu.remove(row[".id"])

        # 2. Kick any live hotspot session for this MAC. THIS is the step that
        #    actually revokes -- step 1 alone does nothing to an authenticated
        #    host (§3.3 case B). No CoA, no /radius incoming dependency.
        active = api.path("ip", "hotspot", "active")
        for row in list(active):
            if normalize_mac_address(row.get("mac-address")) == mac_address:
                active.remove(row[".id"])

        # 3. Flush tracked connections for the host, so an in-flight download
        #    stops rather than running to completion after "revoked".
        #    [UNVERIFIED -- test T3 and T9. If T3 shows established flows die on
        #    their own, drop this step rather than keep an unverified write.]
        conns = api.path("ip", "firewall", "connection")
        for row in list(conns):
            if row.get("src-address", "").split(":")[0] == host_ip:
                conns.remove(row[".id"])
    finally:
        api.close()
```

**Idempotent by construction:** removing what is already absent is a no-op, not
an error — the same contract `delete_nat_masquerade` documents. Revoking twice,
or revoking a device that was never pushed, is safe.

**Ordering matters within the method.** Binding first, session second. Reversed,
the kicked device could re-associate and be re-bypassed by the still-present
binding before step 1 runs.

### 4.5 Why two markers, and why they do not fight

| Marker | Written by | Removed by | Meaning |
|---|---|---|---|
| `cloudguest-authmac` | pull loop, pass 1 | pull loop, pass 1 | has a live guest session |
| `cloudguest-trusted` | pull loop, pass 2 | pull loop, pass 2 | on the trusted list |
| `cloudguest-trusted:{uuid}` | push adapter | push adapter | on the trusted list, pushed early |

The pull loop's pass-2 removal is scoped to `comment="cloudguest-trusted"`
**exactly**, so it never deletes a `cloudguest-trusted:{uuid}` row the push
wrote. The pull loop's pass-2 addition is gated on
`[:len [find where mac-address=$amM]] = 0`, so it never adds a duplicate
alongside one. The two converge to the same device state by different routes and
neither can remove the other's row. That asymmetry is deliberate: a *removal*
must be able to fail without the device being left in an inconsistent state, and
the push's removal (§4.4 step 1) matches the per-entry comment while the pull's
matches the bulk one, so a missed push leaves a row that the *next customer
edit's* push will not find — which is why:

**The pull loop must also sweep orphaned per-entry markers.** Add to pass 2's
removal predicate: a row whose comment starts with `cloudguest-trusted` (bulk
or per-entry) and whose MAC is absent from `trusted_mac_addresses` is removed.
In RouterOS script that is a prefix test rather than an equality test:

```routeros
:if ($amOk = 1) do={ :foreach amB in=[/ip hotspot ip-binding find] \
   do={ :if ([:pick [/ip hotspot ip-binding get $amB comment] 0 18] = "cloudguest-trusted" && \
             [:typeof [:find $amTrust [/ip hotspot ip-binding get $amB mac-address]]] = "nothing") \
        do={ /ip hotspot ip-binding remove $amB } } }
```

(`[:pick ... 0 18]` because `"cloudguest-trusted"` is 18 characters. A
`:find`-based prefix test would also match the substring anywhere in the
comment, which is worse.) [UNVERIFIED — `:pick` on an absent `comment` property:
test T10.]

### 4.6 The renderer, if the SSH path is ever revived

`render_mac_authorization_entry` (`renderers.py:1009`) currently emits:

```python
identifier = f"mac-auth-{entry.id}"
return [
    f"/ip hotspot ip-binding add mac-address={entry.mac_address} "
    f'type=bypassed comment="{identifier}"'
]
```

That is a **fourth marker** that neither the pull loop nor the push recognizes.
A binding it writes is invisible to both, is never removed, and cannot be
revoked by anything. If that path is ever revived, change the identifier to
`cloudguest-trusted:{entry.id}` so it joins the same identity scheme. Until
then, its docstring's claim that this is *"the same mechanism ... this
platform's own device-agent heartbeat sync already uses"* is aspirational: the
mechanism matches, the marker does not.

---

## 5. Access Rules: what maps to what, and the ordering answer

### 5.1 The customer-facing rules

| Rule | RouterOS realization | Why |
|---|---|---|
| Identifier `blocklist` (phone/email) | **Nothing on the device.** Server-side login denial, plus a kick if a session exists. | The router has never seen a phone number. Inventing a device object for it would be fabrication. |
| Identifier `whitelist` / `vip` / `temporary` | **Nothing on the device.** | These are precedence modifiers in `AccessDecisionResolver` (`guest_access/constants.py`: VIP > TEMPORARY > BLOCKLIST > WHITELIST). They change *who may log in*, not *how the device behaves*. |
| Device (MAC) `blocklist` | `/ip hotspot ip-binding type=blocked` + kick any live session | `blocked` is documented as *"translation is not performed and packets from a host are dropped"* [DOC]. This is the exact primitive. |
| Device (MAC) `whitelist` / `vip` | **Nothing on the device.** | A whitelist here means "a blocklist must not stop this device". It does **not** mean "skip the portal" — that is Trusted Devices. Rendering it as `bypassed` would silently duplicate Trusted Devices under a second UI with different precedence rules and no shared revocation path. |
| Device `temporary` | `blocked` (or nothing) + a **server-side** expiry sweep | Never a router-side `/system scheduler` per rule. A scheduler per rule is unbounded device state that outlives the DB row. |
| Guest WiFi Limits / Access Tiers | simple queues + RADIUS reply attributes | Already `queue_management`'s job. Out of scope. |

**The honest answer for most of this table is "nothing on the device", and that
is correct, not a gap.** A guest access rule is an authorization decision made
when a guest logs in. The one that *does* need a device object is the MAC
blocklist, because a blocked device must be stopped before it can reach the
portal at all.

Note what this means for the "Blocked Guests" tab as it exists today: blocking a
*guest identifier* is fully server-side and already works. Blocking a *device*
needs the `blocked` binding, and the existing `connected_devices` block flow
(`connected_devices/service.py:481-517`) creates the `guest_access` device rule
and stops — it never contacts the router, and `disconnect_device`
(`mikrotik_adapter.py:565`) does a wireless kick plus a DHCP-lease removal but
**never touches `/ip hotspot active`**, so it does not end a hotspot session
either. Blocking a device today is a database row.

### 5.2 Rule ordering — the answer

This is the question the firewall domain lives or dies on, and §1.5(c) shows the
current answer is already wrong on shipped code.

**The principle: position is never an integer.** A stored "this rule goes at
index 7" is stale the moment anything is added or removed anywhere above it —
including by the hotspot service, which adds and removes its own rules
continuously as clients come and go. Any re-push that computes an index is
computing it against a chain that has already changed.

**Position is determined by anchors that this platform owns and that nothing
else moves.**

#### 5.2.1 The sentinel band

Create, exactly once per router at provisioning time, two rules per managed
chain:

```
/ip firewall filter add chain=forward action=passthrough \
    comment="cloudguest-fw-band-begin"
/ip firewall filter add chain=forward action=passthrough \
    comment="cloudguest-fw-band-end"
```

`action=passthrough` is a documented no-op: it counts the packet and continues
to the next rule — the explicit exception to first-match-wins [DOC — [Filter](https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter): *"If a packet matches the criteria of the rule, then the specified action is performed on it, and no more rules are processed in that chain (the exception is the `passthrough` action)"*]. A sentinel therefore cannot change
behaviour, and its packet counter doubles as free evidence that traffic actually
reaches the band — which is the single cheapest guard against the §1.5(c)
failure. **A band whose begin-sentinel counter is zero after real guest traffic
is a band in the wrong place**, and that is visible in `print stats` without a
client device.

Every platform rule is then written with
`place-before=<.id of cloudguest-fw-band-end>`, in ascending `priority`. Position
becomes a pure function of (band location, `priority`), stable across every
re-push, and unaffected by anything outside the band.

#### 5.2.2 Where the band goes, relative to the existing 27 rules

I cannot answer this from here, and I will not guess. I have not seen the 27
rules — only that "several" carry `cloudguest-*` markers and that hotspot `hs-*`
chains are present.

What I can state:

- **Hotspot's dynamic rules sit at the top of the built-in chains and are not
  movable.** [FORUM — [How do you add a firewall rule before hotspot dynamic rules?](https://forum.mikrotik.com/viewtopic.php?t=139505): *"Hotspot puts its rules at the top."*] The sanctioned pre-hook for the input chain is `pre-hs-input`,
  which is documented as administratively controlled and empty by default
  [FORUM/legacy-wiki; the current help.mikrotik.com HotSpot page does not
  enumerate the dynamic chains, and I could not find an authoritative current
  page that does — this is corroboration, not documentation]. There is **no
  documented equivalent pre-hook for `forward`.** Whether a static rule can be
  placed above hotspot's dynamic forward rules with `place-before=0` is
  [UNVERIFIED — test T2].
- **Placement is therefore a provisioning-time decision, made once, against a
  real `print` of that specific router, and recorded.** The recommended
  recording place is the router's `ConfigVersion` — the same object that already
  represents a router's whole config. A later push reads the sentinels by
  comment and **never recomputes where they should be.**
- **A push that cannot find both sentinels refuses** (`ACCESS_RULES_BAND_MISSING`,
  §6). It does not create the band at a guessed position mid-push. Creating a
  filter band at a guessed position on a router someone else configured is the
  exact shape of "took the guest network down".

The recommended initial position, to be confirmed against the real print: **after
the established `cloudguest-*` accept rules that carry the guest data path, and
before any catch-all drop.** Above the accepts, a platform rule could block the
portal or the management tunnel; below the drop, it never runs.

#### 5.2.3 The re-push algorithm

Converge, never append. One read, then a diff.

1. **Read** `/ip firewall filter` once into memory. Every decision below is made
   against that one snapshot.
2. **Locate** `cloudguest-fw-band-begin` and `cloudguest-fw-band-end` by comment,
   per managed chain. Either missing → refuse (`ACCESS_RULES_BAND_MISSING`).
3. **Index** existing platform rules by comment marker `cloudguest-fw:{uuid}`
   (§5.3).
4. **Preflight** (§5.4): any `cloudguest-fw:` marker on the device whose UUID is
   not in the desired set *and* not in this organization's DB at all → refuse the
   whole push (`ACCESS_RULES_ORPHAN_MARKER`). Something else is writing here.
5. **Upsert.** For each desired rule in ascending `priority`:
   - marker present → field-diff and `update` in place, exactly as
     `_ensure_nat_masquerade_rule` does. Compute `changed` and skip the write
     entirely when it is empty, so a no-op push issues no writes.
   - marker absent → `add(..., **{"place-before": <band_end_id>})`.
6. **Sweep.** Every `cloudguest-fw:{uuid}` row inside the band whose UUID is not
   in the desired set → `remove` by `.id`. This is what makes the push a
   desired-state push rather than the add-only `_idempotent_lines` (§1.5(b)).
7. **Reorder.** Walk the band; if the platform rules are not in ascending
   `priority`, `move` the offenders. **Only rules strictly between the two
   sentinels are ever moved.**
8. **Verify.** Re-read and assert: both sentinels present, every desired UUID
   present exactly once, band ordering ascending, no `cloudguest-fw:` row outside
   the band. This is a structural check, not a data-plane one — §8 covers the
   data plane.

**Chain is desired state but not identity.** A rule whose `chain` changed must
move to a different chain's band. Over the API, updating `chain` in place would
land it at an arbitrary position in the new chain, so a chain change is
`remove` + `add` with the new chain's `place-before`. State that explicitly in
the adapter rather than letting a field-diff do it silently.

**`place-before` over the API takes a `.id`, not an ordinal.** [FORUM —
[REST API insert firewall rule](https://forum.mikrotik.com/t/rest-api-insert-firewall-rule/161471), ["place before" Mikrotik API](https://forum.mikrotik.com/t/place-before-mikrotik-api/109934)] Whether
`librouteros`' `Path.add()` accepts it as a keyword on 7.23.3 is [UNVERIFIED —
test T1]. **Nothing in step 5 may ship before T1 passes.**

### 5.3 Stable rule identity

`comment = "cloudguest-fw:{FirewallRule.id}"` — the row's UUID primary key.

Every field a customer can edit is a bad key, and this codebase already says so.
`configure_nat_masquerade`'s docstring
(`mikrotik_adapter.py:1958-1967`):

> **The comment is the rule's identity, and that is the whole design.** Every
> other field is something an operator edits: re-subnet a VLAN and
> `src-address` changes, re-cable a site and `out-interface` changes. Keyed on
> any of those, the next push would find no match, add a second rule, and leave
> the first one masquerading a subnet nothing uses — silent, cumulative, and
> invisible in this platform's own UI.

The same argument, unchanged, for filter rules — where it is worse, because a
firewall rule that is silently duplicated in the wrong order changes behaviour,
where a duplicated masquerade merely wastes a row.

The UUID specifically, not the `name`: `name` is a customer-editable string
(`FirewallRuleUpdateRequest.name`), and two rules may share one. Precedent
across this codebase: `_nat_rule_comment(vlan_id)`,
`MANAGED_WALLED_GARDEN_COMMENT`, `_CONTENT_FILTER_ENFORCEMENT_COMMENT`,
`cloudguest-authmac`, `cloudguest-nat-wan1`.

**Do not put the customer's own comment in the RouterOS comment field.**
`FirewallRule.comment` is free text the customer controls; concatenating it into
the marker gives the customer control of this platform's identity scheme.
Render it into the rule's `name` if it must be visible on the device, or nowhere.

**Reject a marker collision rather than overwrite it.** Before writing, if a row
carries a comment matching `^cloudguest-fw:` but not the exact expected UUID
form `^cloudguest-fw:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
refuse.

### 5.4 How to never touch a rule this platform did not create

Four layers, defence in depth, because one bad `remove [find]` on a firewall is
a site outage.

1. **Every read-modify-write is keyed on an exact comment match.** Never on
   address, port, action, chain, or any combination of them. A rule that matches
   ours by shape is not ours.
2. **Every removal is per-row by `.id`.** Never
   `menu.remove(*menu.select(...))`, never a bare `remove [find]`. The existing
   `_remove_where` helper already establishes this. A `find` predicate that
   evaluates to nothing must produce zero removals, and the only way to
   guarantee that in every RouterOS idiom is to enumerate rows in Python and
   remove the ones that matched.
3. **Removal is bounded twice: by marker prefix AND by band membership.** A rule
   carrying `cloudguest-fw:` that sits *outside* the sentinels is not removed —
   it is reported. Something put it there, and this platform does not know what.
4. **Orphan preflight refuses the whole push, and names the rule.** A
   `cloudguest-fw:{uuid}` on the device whose UUID exists in no
   `firewall_rules` row means either a second controller is writing to this
   router, or a rule survived an org deletion. Both are situations where the
   right action is to stop and tell a human, not to reconcile. Refuse, log the
   `.id`, the comment, and the full rule, and do not write anything.

**One more, for the input chain specifically.** A `chain=input action=drop` rule
that matches the WireGuard tunnel, port 8728, or the RADIUS source address locks
this platform out of the router permanently, and the only fix is a site visit.
Static preflight every proposed `input` rule against the router's own
`management_ip_address`, `wg-cloudguard`, 8728, 22, 1812/1813, 3799 →
`ACCESS_RULES_WOULD_ORPHAN_MANAGEMENT` (§6). This check is cheap and it is the
difference between a bad push and a truck roll.

---

## 6. Refusal codes

These are failures that must be **refused, named, and surfaced** — never
guessed at, never defaulted, never reported as success. The organising rule: if
the platform does not know what the device state is, it says so; it does not
write a plausible value and move on.

| Code | Trigger | Why refuse rather than guess |
|---|---|---|
| `TRUSTED_DEVICE_NO_HOTSPOT` | `/ip hotspot` has no server on this router | An `ip-binding` on a hotspot-less router is an inert row. It reads back perfectly and does nothing. Writing it produces a UI that says "trusted" about a device nothing was ever done for. |
| `TRUSTED_DEVICE_SESSION_ACTIVE` | MAC is in `/ip hotspot active` at push time | Adding a `bypassed` binding tears down the live session [FIELD, §1.4]. Refusing the *immediate* push costs one minute; guessing costs a working guest their connection. |
| `TRUSTED_DEVICE_FOREIGN_BINDING` | A binding for this MAC exists with a comment this platform does not own | It is a venue's manual bypass for their own AP. Adopting it means this platform will later delete hardware it did not install. Overwriting it means the same. |
| `TRUSTED_DEVICE_MAC_RANDOMIZED` | Locally-administered bit (`0x02` of octet 1) set on the submitted MAC | A private Wi-Fi address is not a stable identity. Accepting it produces a trusted device that silently stops being trusted. Refuse at the API with the fix ("turn off Private Wi-Fi Address for this network"). |
| `TRUSTED_DEVICE_SYNC_ABSENT` | No `cloudguest-*-sched` scheduler on the router | Without the pull loop there is no convergence and no revocation. "No trusted devices configured" and "the sync was never installed" must not look the same. |
| `MAC_PAYLOAD_NOT_CANONICAL` | An agent-bound MAC does not match `^([0-9A-F]{2}:){5}[0-9A-F]{2}$` | Guards the masking hazard in §4.2. A masked MAC applied as an `ip-binding` is a garbage row on every router in the fleet. |
| `REVOKE_UNCONFIRMED` | Revocation requested; the 8728 write failed *and* the MAC had a live session | The customer asked to cut someone off. Reporting success without having done it is the worst possible outcome for this feature. Report "not revoked", with the reason. |
| `ACCESS_RULES_BAND_MISSING` | Either sentinel absent from a managed chain | The router was never provisioned for ordered platform rules, or someone deleted them. Creating the band mid-push means choosing a position blind, on a live firewall. |
| `ACCESS_RULES_ORPHAN_MARKER` | A `cloudguest-fw:{uuid}` on the device whose UUID is in no DB row | Either a second controller is writing to this router, or a rule outlived its org. Reconciling silently destroys evidence of whichever it is. |
| `ACCESS_RULES_MARKER_MALFORMED` | A comment starting `cloudguest-fw:` that is not a well-formed UUID marker | Someone hand-edited a marker. Overwriting it loses whatever they meant. |
| `ACCESS_RULES_CHAIN_UNSUPPORTED` | A chain other than `input`/`forward`/`output` | The band only exists in managed chains. A rule elsewhere would have no ordering guarantee at all. |
| `ACCESS_RULES_WOULD_ORPHAN_MANAGEMENT` | A proposed `drop`/`reject` matching the tunnel, 8728, 22, 1812/1813, or 3799 | Locks the platform out permanently. The recovery is a site visit. |
| `ACCESS_RULES_WOULD_BREAK_GUEST_PATH` | A `forward` `drop` with no src/dst narrower than the guest subnet | An unqualified guest-subnet drop is a site outage that reads back as a correctly-created rule. |
| `DEVICE_UNREACHABLE` | The 8728 connection failed | This is the defect class `vlan/device_adapters.py` was written to end: a 202 `success: true` for a write that never left the building. Every device write refuses; none returns success on a DB row alone. |
| `ROUTEROS_VERSION_UNSUPPORTED` | `/system/resource` version outside the tested set | See §7. |
| `CREDENTIALS_MISSING` | No `management_ip_address`/`public_ip_address`, `api_username`, or decryptable secret | *"Raise rather than guess"* — `VlanService._resolve_device_credentials`'s own rule. |

---

## 7. What cannot be settled without hardware

Every `[UNVERIFIED]` above appears here with the exact test that settles it. **A
test that only re-reads what was written proves nothing** — where a test needs a
counter or a real client, it says so.

Prefix every test object's comment with `cg-test-` and clean up with an explicit
per-`.id` removal, never a broad `find`.

| # | Question | Why it matters | Exact test |
|---|---|---|---|
| **T1** | Does `librouteros` `Path.add()` accept `place-before` on 7.23.3, and does it take a `.id`? | §5.2.3 step 5 is unbuildable otherwise; the fallback is `add` then `move`, two round trips and a window where the rule is live in the wrong place. | CLI: `/ip firewall filter add chain=forward action=passthrough comment=cg-test-a`; same for `cg-test-b`. Note b's `.id`. API: `api.path("ip","firewall","filter").add(chain="forward", action="passthrough", comment="cg-test-c", **{"place-before": "<b .id>"})`. Then `/ip firewall filter print where comment~"cg-test"` — **expect order a, c, b**. If it instead accepts an ordinal, or errors, record which. |
| **T2** | Can a static rule be placed above hotspot's dynamic rules in `forward`? | Determines whether the band can sit above the hotspot chains at all, or must sit below them. | `/ip firewall filter add chain=forward action=passthrough comment=cg-test-top place-before=0` then `/ip firewall filter print` and read the `D` flags: is `cg-test-top` above or below the first `D` rule? |
| **T3** | Does removing a `type=bypassed` binding drop *established* flows, or only new ones? | **Highest-value test in this list.** If established flows survive, revocation without a conntrack flush is theatre — the guest keeps browsing. Determines whether §4.4 step 3 ships. | Bypass a real client's MAC. Start a long download (`iperf3 -c ... -t 300`, or a large file). Mid-transfer, `/ip hotspot ip-binding remove [find comment="cloudguest-trusted"]`. **Watch the transfer, not the router.** Does it continue? |
| **T4** | On 7.23.3, does adding a `bypassed` binding for a MAC in `/ip hotspot active` still tear down the session? | The whole `TRUSTED_DEVICE_SESSION_ACTIVE` refusal rests on it. Observed in this fleet [FIELD] but on an unrecorded version. | Log a real client in via the portal. Confirm in `/ip hotspot active`. Add a `bypassed` binding for its MAC. Immediately `/log print where topics~"hotspot"` — look for `logged out: host removed: ip binding changed`. |
| **T5** | Does `/ip hotspot ip-binding add` with a duplicate `mac-address` error, or create a second row? | Decides whether the pull loop's `find`-then-`add` guard is belt-and-braces or load-bearing. | Add the same MAC twice. `/ip hotspot ip-binding print count-only`. |
| **T6** | Does `/ip firewall filter add` of an identical rule create a duplicate? | Confirms (or refutes) the §1.5(b) claim that reviving the SSH push would multiply every firewall rule per push. | Add an identical rule twice. `/ip firewall filter print count-only where comment="cg-test-dup"`. |
| **T7** | Does `/ip hotspot active remove` cut the data plane, or only clear the table? | §3.3's whole recommendation rests on it. | Log a client in, start a long download, `/ip hotspot active remove [find mac-address=...]`. **Watch the transfer.** Then request a fresh http URL — expect the portal. |
| **T8** | Once `/radius incoming set accept=yes port=3799`, does the hEX lite accept a Disconnect-Request over the WireGuard tunnel? | Decides whether CoA is a viable follow-up at all, and whether `/radius incoming` binds to a specific interface (docs give `vrf`, not `interface` [DOC]). | From the RADIUS host: `echo "Acct-Session-Id=<id>" \| radclient -x 10.5.50.1:3799 disconnect <secret>`. Expect Disconnect-ACK. Repeat with the router's tunnel address as the target. Record which addresses work. |
| **T9** | Does `/ip firewall connection` support `remove` over 8728 on 7.23.3? | §4.4 step 3. | `api.path("ip","firewall","connection")` — list it, remove one row by `.id`, confirm it is gone and nothing else changed. |
| **T10** | Does `[:pick [... get $id comment] 0 18]` behave when `comment` is unset? | §4.5's prefix sweep runs over **every** `ip-binding` row, including operator rows with no comment. A script error there aborts the pass and leaves stale bindings. | Create a binding with no comment. Run the pass-2 loop by hand. Check `/log print` for a script error, and that the uncommented binding survives. |
| **T11** | Does `server=all` vs `server=hotspot1` differ in effect on a single-hotspot router? | Decides whether §4.4 needs the `server=` refinement now or later. | Bypass a MAC with each, confirm the client skips the portal both times, and diff `/ip hotspot ip-binding print detail`. |

#### Results so far — T1 and T2, run 2026-09-03

Run against the lab hEX lite (`rcjgfc`, 10.20.0.14), RouterOS 7.23.3, over
`librouteros` on 8728 from the API container. Probes are kept in
`backend/ops/probes/` so both are re-runnable rather than described.

| # | Result | What it means |
|---|---|---|
| **T1** | **PASS** | `Path.add()` accepts `place-before` and it takes a **`.id`**, not an ordinal. `a`, `b`, then `c` with `place-before=<b .id>` printed as `a, c, b`. §5.2.3 step 5 is buildable as written; the `add`-then-`move` fallback is not needed. |
| **T2** | **PASS** | A static rule **can** sit above hotspot's dynamic `forward` rules. Placed before the first dynamic row, it landed at index 0, above both `jump`s. The band is not forced below the hotspot chains. |

Both probes write only `action=passthrough` rules commented `cg-test-*`,
remove them in a `finally`, refuse to run if any `cg-test-` row is already
present, and never touch a rule that is not their own. Both reported
`cleanup leftover: none`.

**The `forward` chain as actually read, which §5.2.2 said it would not guess
at.** This is the lab router; it is *not* the "27 rules" that section
imagines, and placement on any other router still has to be read first:

```
 0 D jump   -> hs-unauth      hotspot=from-client,!auth
 1 D jump   -> hs-unauth-to   hotspot=to-client,!auth
 2   drop   cloudguest-block-dot-udp      hotspot=!auth udp/853
 3   drop   cloudguest-block-dot-tcp      hotspot=!auth tcp/853
 4   drop   cloudguest-block-doh          hotspot=!auth tcp/443 dst-list=cloudguest-doh-ips
 5   accept cloudguest-fw-fwd-established connection-state=established,related
 6   drop   cloudguest-fw-fwd-drop-invalid connection-state=invalid
```

Two things follow that were previously assumed rather than known. **Both
hotspot jumps are gated `!auth`**, so authenticated guest traffic does not
enter them and falls through to the static rules — there is no broad accept
above for logged-in guests, and `hs-unauth` itself only `return`s or
`reject`s, never accepts. And **the only `accept` in the chain is
`connection-state=established,related`**, so a DROP appended at the bottom
bites on new connections but lets an already-open flow continue.

`_ensure_content_filter_enforcement_rule` now places its DROP immediately
before that first `accept`, and re-checks the position on every push instead
of only at creation. See its own docstring for why that is safe for this
specific rule and would not be for a general access rule.

**T3–T11 remain unrun.** T3, T4, T7 and T8 all need a real client behind
`ether2` generating traffic; they cannot be answered from the platform.

**Version coverage.** Run T1, T2, T5, T6 on a RouterOS 6.x router as well as
7.23.3 before the fleet push. `/ip hotspot ip-binding`, `/ip hotspot active` and
`/ip firewall filter` exist with the same parameter names in both, and v7 keeps
the v6 space-separated CLI syntax for compatibility [DOC — [Upgrading to v7](https://help.mikrotik.com/docs/spaces/ROS/pages/115736772/Upgrading+to+v7)]. But v7
*"introduced significant changes to the firewall framework"* [DOC, same page]
and MikroTik explicitly flags that hotspot behaviour changed in v7 and warrants
testing. Until both are tested, gate on `/system/resource` version and refuse
outside the tested set (`ROUTEROS_VERSION_UNSUPPORTED`).

---

## 8. Verification that would actually prove it

The discipline, stated once and applied to each feature.

**Never accept a read-back of the object you just wrote as proof.** Both real
failures in this codebase pass a read-back:

- The `hs-auth` NAT chain at 0 bytes while `/agent/authorized-macs` returned the
  right MAC and the heartbeat scheduler showed `run-count=475`
  (`RouterDetailTabs.tsx:4222-4226`). Every read-back was green. No guest had
  internet.
- The content-filter DROP rule at the bottom of the forward chain (§1.5(c)). Its
  own dedup check reads it back and passes, every time, forever.

**Trusted Devices — the proof.** A real client device whose MAC is on the list
joins the SSID and requests a non-cached plain-HTTP URL. It gets the page, not
the portal. Simultaneously: `/ip firewall nat print stats` shows the hotspot
redirect rules **not counting that host's packets**, and
`/ip hotspot ip-binding print` shows the binding with a non-zero hit. The binding
existing is necessary and not sufficient; the redirect *not firing* is the
sufficient part.

**Revocation — the proof.** The same device, mid-download. Revoke. The download
**stops**. `/ip hotspot active print` no longer lists the MAC. A fresh HTTP
request returns the portal. Anything short of "the download stops" means the
conntrack question (T3) has not been answered.

**Access rule position — the proof.** `/ip firewall filter print stats`. **A rule
with zero packets after a flow that should have matched it is a rule in the
wrong place**, and the counter is the only thing in RouterOS that says so.
Deploy every rule with a known-matching test flow, run the flow, read the
counter, then remove the test flow. The begin-sentinel's own counter is the
cheap continuous version of this: zero packets on `cloudguest-fw-band-begin`
after real guest traffic means the band is unreachable, and that alarm costs
nothing to run on every health check.

**What "the config is correct" is worth: nothing on its own.** Counters, byte
deltas, and a real client. In that order of preference.

---

## 9. Sequenced recommendation

Ordered by (value delivered) ÷ (risk taken). Each step is independently
shippable and independently revertible.

| # | Work | Risk | Unblocks |
|---|---|---|---|
| **1** | Union `MacAuthorizationService.list_active_entries_for_router` into `GET /agent/authorized-macs` as a new `trusted_mac_addresses` key. Add the canonical-MAC assertion test. | **None on-device.** Additive JSON; existing scripts ignore the new key. | Makes Trusted Devices real, with ≤60 s latency, on every router that already runs the scheduler — with no new device code and no new failure mode. |
| **2** | Second scheduler `cloudguest-trusted-sched` (§4.3), generated by the same Master console panel. | Low. Same shape as an existing, field-proven script. Paste-ceiling constraint respected by splitting. | Convergence and revocation for trusted devices. |
| **3** | `revoke_trusted_device` over 8728 (§4.4) — binding removal + `/ip hotspot active` kick. Conntrack flush **only if T3 says it is needed**. | Medium. First write. Bounded by comment identity; idempotent; no ordering concerns. | Real revocation. Step 2 alone cannot kick a live session. |
| **4** | `mac_authorization/device_adapters.py` + `configure_trusted_device` for the low-latency push (§4.4). Best-effort, never authoritative. | Medium. Refusals in §6 are the guard rails. | 30 s → 2 s median. Also gives `TRUSTED_DEVICE_SYNC_ABSENT` detection. |
| **5** | Device rule (MAC) blocklist → `type=blocked` + kick, same adapter. | Medium. Same primitives as step 3. | Makes "Blocked Guests" real for devices. |
| **6** | Sentinel band + `firewall/device_adapters.py` (§5). | **High.** Ordered firewall writes on a live guest network. | The Master-console firewall feature. **Blocked on T1, T2, T6.** |
| **7** | Fix `_ensure_content_filter_enforcement_rule` to place inside the band. | Medium, but it fixes a live silent failure. | Content filtering actually filtering. **Blocked on step 6.** |
| **8** | RADIUS MAC auth + CoA. | High, low urgency. | Accounting and policy for trusted devices; mid-session rate changes. **Blocked on T8 passing on two different customer routers.** |

Steps 1 and 2 together turn a feature that does nothing into a feature that
works, and neither of them writes to a device. That is where to start.

---

## Sources

- [HotSpot — RouterOS Documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/56459266/HotSpot) — `ip-binding` types (`regular`/`bypassed`/`blocked`), walled garden, user profiles, RADIUS profile properties
- [HotSpot - Captive portal — RouterOS Documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/56459266/HotSpot+-+Captive+portal) — `ip-binding` and `walled-garden ip` property lists
- [RADIUS — RouterOS Manual](https://manual.mikrotik.com/docs/authentication-authorization-accounting/radius/) — `/radius incoming` (`accept` default `no`, `port` default `1700`, `vrf`), RFC 3576 CoA/Disconnect support, no POD support, HotSpot-applicable reply attributes
- [Filter — RouterOS Documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter) — chain evaluation order, first-match-wins, `passthrough` as the documented exception
- [Upgrading to v7 — RouterOS Documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/115736772/Upgrading+to+v7) — v6/v7 CLI compatibility, firewall framework changes, hotspot behaviour change warning
- [Tips and Tricks — MikroTik Wiki](https://wiki.mikrotik.com/wiki/Tips_and_Tricks_for_Beginners_and_Experienced_Users_of_RouterOS) — `place-before=0` and `place-before=[find ...]` usage examples

Forum corroboration, used only where official documentation is silent, and
marked `[FORUM]` at each use:

- [How do you add a firewall rule before hotspot dynamic rules?](https://forum.mikrotik.com/viewtopic.php?t=139505) — hotspot places its rules at the top; `pre-hs-input` as the sanctioned input pre-hook
- [Disconnecting unauthorized hotspot users](https://forum.mikrotik.com/t/disconnecting-unauthorized-hotspot-users/42819) — `/ip hotspot active remove [find ...]`
- [REST API insert firewall rule](https://forum.mikrotik.com/t/rest-api-insert-firewall-rule/161471) and ["place before" Mikrotik API](https://forum.mikrotik.com/t/place-before-mikrotik-api/109934) — `place-before` over the API takes a `.id`
- [logged out: host removed: overrided by static entry](https://forum.mikrotik.com/t/logged-out-host-removed-overrided-by-static-entry/69699) — the ip-binding/active-host reconciliation class of logout
