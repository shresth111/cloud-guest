# Country blocking — design

Status: **design only, nothing built.** Written 2026-10-01. Supersedes the
sketch in `PRD.md` §13 where they disagree. The main disagreement is that
§13 puts the drop in `input`; this design never touches `input`.

## 1. What a venue owner would actually get

"Block by country" means two different things, and only one of them works.

| Direction | Example | Verdict |
|---|---|---|
| **Inbound**: someone abroad connecting *into* the venue | A scanner in another country hammering the CCTV recorder the owner port-forwarded so they can watch it from their phone | **Works.** The source address of a connection is real, and country ownership of address blocks is well known. |
| **Outbound**: a guest reaching a site *hosted* in a country | "Block Chinese websites" | **Does not work, so we do not build it.** Popular sites are served from CDN edges in many countries at once, so the same site resolves to an Indian edge for one guest and a Singapore edge for the next. A country list blocks some legitimate sites at random and misses the intended ones. Category filtering (Cloudflare) and website/app blocking are the honest tools for this job. |

So the feature is: **"Who can reach the devices you've opened to the
internet"**. In practice that means port forwards (CCTV/NVR, a PMS or POS
server, a DVR). For each one, the owner picks *Anyone*, *Only from India*,
or *Only from these countries*.

### Why only port forwards

The venue router already drops everything else that arrives on WAN. The
router setup script (`cloudguest-foundation`
`src/components/routers/RouterDetailTabs.tsx`, and
`backend/ops/runbooks/mikrotik-router-setup.rsc`) writes
`cloudguest-fw-drop-wan-input` below the WireGuard management accept
(`cloudguest-fw-allow-wg-mgmt`). Nothing on
the router itself is reachable from the internet except the management
tunnel, and that tunnel must never be geo-filtered. The only inbound path
a country rule can usefully narrow is a **dst-nat port forward**. A venue
with no port forwards has nothing to protect, and the UI should say so
rather than offer a switch that does nothing.

## 2. Enforcement: narrow the NAT rule, never add a drop

The design has no new firewall drop, no `input` rule, and no band change.
Each port forward is already a `/ip firewall nat chain=dstnat
action=dst-nat` row written over 8728
(`mikrotik_adapter.configure_port_forward`, one row per protocol, found
by its comment marker). Country restriction adds **one matcher to that
same row**:

```
/ip firewall nat set [find comment="cloudguest-pf:<rule-id>:tcp"] \
    src-address-list=wyfy-geo-allow-<rule-id>
```

- **Allowed source:** the connection matches, is forwarded, and reaches the device.
- **Any other source:** the dst-nat never happens, so the packet is addressed to the router itself. It goes to `input` and dies on the existing `cloudguest-fw-drop-wan-input`. No new drop rule means no new way to drop the wrong thing.
- **Management stays untouched.** The WireGuard tunnel, 8728 and RADIUS are `input`/`output` traffic, and a NAT matcher cannot affect them. The 2026-08-16 lockout class, where a WAN-input drop was appended above the WireGuard accept, cannot happen here.
- **Per-forward lists, not one shared list.** "CCTV: India only" and "PMS: India + UAE" are different allow-sets. Each forward gets its own list name, `wyfy-geo-allow-<rule-id>`. The lists are built from per-country entries that the sync shares between forwards (§4).

### Hard precondition: the WAN-input drop must be there

The guarantee that "any other source" dies rests entirely on
`cloudguest-fw-drop-wan-input`. On a router that lacks it, a non-matching
packet to, say, external port 80 is not forwarded. It then lands on the
router's **own** service on that port (webfig on 80, or whatever listens).
Narrowing the forward would *open* the router itself. So, before the first
write and on every sync, read `chain=input` and **refuse** with
`GEO_WAN_INPUT_DROP_MISSING` unless the drop row exists exactly once, sits
below `cloudguest-fw-allow-wg-mgmt`, and matches `in-interface-list=WAN`
with a non-empty WAN list. Routers provisioned before the setup script
wrote it need a re-run of that script, not a fix from this feature.

`src-address-list` and the existing single `src-address` matcher are
mutually exclusive in the UI. A forward is open to *anyone*, to *one
address you typed*, or to *countries*.

### Fail-closed, deliberately

If the router's list is empty (first sync not done, router rebooted with
RAM-only entries, see §4.3), the NAT row matches nothing, and the forward
is closed until the sync lands. For a CCTV recorder that is the right
failure: "I can't see my cameras for ten minutes after a power cut" is
recoverable, while "the world can see my cameras" is not. The UI shows the
state per forward: *Active (n addresses)* / *Waiting for country list* /
*Failed: <reason>*.

## 3. Data: where country → address ranges come from

| Source | Licence | Notes |
|---|---|---|
| **RIR delegated-stats** (`delegated-apnic-extended-latest` and the other four RIRs) | Free, no attribution required | Records which country an address block is *registered* to, not where it is used. Updated daily. One source of truth with no account. **Recommended.** |
| DB-IP Lite Country (CSV) | CC BY 4.0 (attribution in UI/docs) | Geolocation-based, which is closer to "where the user is". Monthly. A good second source if registration-based data proves too coarse. |
| MaxMind GeoLite2 Country | Free with account + licence key; EULA | Most accurate free option, but it needs a key, an EULA, and redistribution care. Not worth it for allow-listing. |

**Recommendation: RIR delegated-stats, aggregated.** For an *allow-list*,
"registered to India" is the property we want: Indian ISPs, Jio and Airtel
mobile, and Indian clouds. Aggregate adjacent ranges (`ipaddress.collapse_addresses`)
before pushing.

**Size check (to measure in phase 0, not assume):** India's IPv4 space
collapses to a few thousand prefixes. A hEX lite (64 MB RAM) already
carries ~1,960 address-list entries for the DoH bypass layer
(hardware-verified 2026-10-01). Set the hard caps the same way
`mikrotik_dns_filtering` does (`MAX_DOH_IPV4 = 5000`). A large multi-country
allow-set that would exceed the cap is refused up front with the count,
never truncated silently.

## 4. Sync pipeline

### 4.1 Platform side (once a day)

New domain `app/domains/geo_blocking/`, feed sync only.

1. A Celery Beat task on the `device_io` queue downloads the five RIR files. They are checksummed, cached, and the last good copy is kept.
2. It parses the `ipv4` (and later `ipv6`) rows into per-country sets, collapses them, and stores them as `geo_country_ranges(country, family, cidrs[], sha, fetched_at)`.
3. It refuses a refresh that shrinks a country by more than 30% or comes back empty, and keeps the last good copy. This is the same rule `dns_filtering.bypass_lists` uses for the DoH lists.

### 4.2 Router side

For each router that has a country-restricted forward:

1. Desired allow-set = union of the forward's countries, collapsed. Compare it with the router's `wyfy-geo-allow-<rule-id>` entries, read back by list name.
2. **Diff, never rewrite.** Add what's missing and remove what's gone, in chunks, the way `mikrotik_dns_filtering._converge_address_list`
   already does for the DoH list.
3. Set `src-address-list` on the forward's NAT rows (idempotent) and read back.
4. Record `geo_sha`, `synced_at` and `entry_count` per forward.
5. Hold the per-router lock `app.common.router_firewall_lock` so this never interleaves with a firewall or bypass push.

### 4.3 Static vs RAM-only entries — the one real trade-off

| | Static entries | `timeout=`-based (dynamic, RAM) |
|---|---|---|
| Survive reboot | Yes | No, so the list is empty after a reboot and the forward is closed until resync (fail-closed, §2) |
| Flash wear | Each daily diff writes flash; small diffs are fine | None |
| Recommendation | **Static**, with diffs. Daily churn for one country is tens of entries, not thousands. | Only if measurement shows big daily churn |

Router heartbeat gets a cheap `entry_count` read, so a mismatch (reboot,
manual edit) triggers a resync instead of waiting for the nightly run.

## 5. Product surface

**Where:** the Port Forwarding screen, per forward. That is where the
owner already thinks about "opening my CCTV to the internet". It is **not**
a Blocking tab: there is nothing to block for a venue with no forwards.
Security Score links to it.

```
CCTV recorder   :8000 → 192.168.88.20:80
Who can connect   (•) Anyone   ( ) Only from India   ( ) Only from these countries [▾]
                  Active · 4,812 address ranges · updated today 03:10
```

Copy that must appear, in plain words:

- "Someone using a VPN in an allowed country can still connect."
- "Mobile data while roaming abroad will be blocked. Add that country while you travel."
- "Country information comes from address registrations and is about 99% right, not 100%."

The Security catalogue entry `geo_blocking` changes from "needs …" to
AVAILABLE **only** after phase 2 is hardware-verified. Its text is "Limit
who can reach your opened devices by country", not "Block by country".

## 6. Phases

| Phase | What | Exit criterion |
|---|---|---|
| 0 | Measure: download the RIR files, collapse India and a 3-country set, count entries, push a list to Hall Router, and time the push and read-back. Check memory on the hEX lite. Count fleet routers that have `cloudguest-fw-drop-wan-input` (§2 precondition). | Numbers in this doc, replacing the estimates |
| 1 | Backend: `geo_blocking` feed sync + `geo_country_ranges` + the refusal rules. No device writes. | Unit tests; a nightly task runs in staging |
| 2 | Gateway + port-forward integration: per-forward allow-list, NAT `src-address-list`, diff sync, lock, read-back | Hall Router: a forward restricted to IN accepts from an Indian source and is unreachable from a non-IN source. Use an EC2 instance in another region as the test client. |
| 3 | FE on Port Forwarding, Security catalogue flip, en + hi copy | CI + one owner walkthrough |
| 4 (later) | IPv6: `/ipv6 firewall nat` does not apply to typical venue IPv6, so IPv6 forwards need a separate `/ipv6 firewall filter` design. Until then a forward with countries set is **IPv4-only**, and the UI says so. | — |

## 7. Explicitly out of scope

- **Outbound country blocking:** unreliable, see §1. Point owners to categories or apps.
- **Any rule in `chain=input`:** the management path. Never geo-filtered.
- **Blocking guests by the country of their phone:** guests are on the venue LAN, so their source is a private address with no country.
- **Omada venues:** Omada has no port forwarding on our AP-only fleet (see `wyfy_omada_controller_management_api` notes), so the feature does not apply there and is hidden.

## 8. Open questions

1. Is any real venue using port forwards today? If none, phase 2 waits for a customer who does. Check `port_forward_rules` counts.
2. Does the hotspot's dynamic `hs-unauth-to` jump interfere when the forwarded device sits *on the hotspot bridge*? Test in phase 2 with the device on and off the hotspot interface.
3. Is CC BY 4.0 attribution (if we ever add DB-IP) acceptable in the dashboard footer?
