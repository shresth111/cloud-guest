# Network features audit — does the customer dashboard reach the router?

**Scope:** the six Network features in `src/config/customerFeatureCatalog.ts`
(`dhcp`, `vlans`, `port-forwarding`, `voip`, `website-blocking`, `isp-details`).

**Method:** code reading only. No device was contacted.

**Commits audited**

| Repo | Ref | Commit |
|---|---|---|
| `cloud-guest-repo/backend` | `origin/main` | `f2bfa51` (Merge PR #109 `feat/vlan-spec-backend`) |
| `cloudguest-foundation` | content of `origin/main` (`52da04e`), checked out as `feat/vlan-form-spec` @ `70bc360` | includes PR #189 `feat/dhcp-apply-to-router`, PR #190 `feat/vlan-form-spec` |

> **Note on tree stability.** Between 07:52 and 07:55 on 2026-09-03 the backend
> working tree was transiently on an older `main` (`eff4713`) — `dhcp/device_adapters.py`
> absent, `vlan/service.py` at 420 lines, the gateway at 2146 lines — while a
> branch was being brought up to date. Every finding below was re-verified against
> the settled `f2bfa51`. If you read this report against a tree that does not have
> `app/domains/dhcp/device_adapters.py`, you are on the older main and the DHCP
> verdict flips to DATABASE ONLY.

**The question being answered, per feature:** does a customer action in the
dashboard result in a write on the MikroTik, and does the UI tell the truth
about it?

**The device-write inventory.** `vendor/wyfy-device-gateway/wyfy_device_gateway/mikrotik_adapter.py`
holds the real writers. Which of them have a caller in `app/`:

| Gateway writer | Line | Called from `app/`? |
|---|---|---|
| `configure_vlan` | 1225 | yes — `vlan/device_adapters.py:431` |
| `delete_vlan` | 1311 | yes — `vlan/device_adapters.py:458` |
| `configure_vlan_hotspot` | 1377 | yes — `vlan/device_adapters.py:375` |
| `delete_vlan_hotspot` | 1580 | yes — `vlan/device_adapters.py:404` |
| `configure_dhcp_pool` | 1673 | yes — `dhcp/device_adapters.py:175` |
| `delete_dhcp_pool` | 1626 | yes — `dhcp/device_adapters.py:207` |
| `configure_nat_masquerade` | 1943 | yes — `vlan/device_adapters.py:473` |
| `delete_nat_masquerade` | 2060 | yes — `vlan/device_adapters.py:500` |
| `create_queue_tree` | 2383 | yes — `qos/device_adapters.py:178` |
| `set_priority` / `remove_queue` | 2426 / 2455 | yes — `qos/device_adapters.py:197,213` |
| **`configure_port_forward`** | **1814** | **no caller anywhere in `app/`** |
| **`configure_content_filter_rule`** | **2138** | **no caller anywhere in `app/`** |

There is no `delete_port_forward` and no `delete_content_filter_rule` in the
gateway at all (`grep -n "    async def " mikrotik_adapter.py`, 44 methods).

---

## 1. `dhcp` — "IP Addresses"

### Verdict: **REACHES DEVICE**

### Evidence

- Service push: `app/domains/dhcp/service.py:343` `push_pool_to_device`, real
  device call at `:405` `await adapter.configure_dhcp_pool(...)` →
  `app/domains/dhcp/device_adapters.py:175` → gateway `mikrotik_adapter.py:1673`,
  which issues the three real writes (`/ip pool`, `/ip dhcp-server`,
  `/ip dhcp-server network`).
- Endpoint: `app/domains/dhcp/router.py:229-262`, `POST /dhcp-pools/{pool_id}/push`,
  gated on `dhcp.execute`.
- Customer trigger: `src/components/network/DhcpManagement.tsx:277` `usePushDhcpPool()`,
  button at `:480-489` rendering "Apply" / "Re-apply" per row. Reached by the
  customer at `src/components/customer/CustomerFeaturePage.tsx:313`
  (`feature === "dhcp"` → `DhcpView` → `DhcpManagement`).
- Failure honesty: `service.py:414-424` writes `FAILED` + `device_push_error`,
  **commits**, then re-raises. The exception propagates as a real non-2xx —
  never a `200 {"success": false}`. This matters because
  `src/services/api.ts:419-425` unwraps `data` and never reads `success`.
  Badge and hover error at `DhcpManagement.tsx:204-222`.
- Idempotency: real. All three writes are read-before-write —
  `_ensure_ip_pool` (`mikrotik_adapter.py:1783`) updates `ranges` if changed,
  `_ensure_dhcp_server` (`:1799`) diffs the desired fields, `_ensure_dhcp_network`
  (`:1842`) keys on `address`. A second push of an unchanged pool writes nothing
  and raises nothing.
- Delete reaches the device: `service.py:306` calls `_remove_from_device`
  (`:451`), which calls `delete_dhcp_pool` (`:474`) — skipped only when
  `device_push_status != ACTIVE`, i.e. when there is genuinely nothing there.
- UI truth: the previously-flagged "Device push happens through a separate
  configuration pipeline" copy is gone; `DhcpManagement.tsx:347-350` now reads
  "Apply a pool to send it to the router" (master console) and a plain-language
  description for the customer.

### Defects

- **(low)** The customer-facing description (`DhcpManagement.tsx:348`) does not
  mention that a pool is inert until Applied. The per-row badge does say
  "Not yet applied", so this is a nudge, not a lie.

---

## 2. `vlans` — "Network Zones"

### Verdict: **REACHES DEVICE**

### Evidence

- Service push: `app/domains/vlan/service.py:535` `push_vlan_to_device`.
  Device calls: `:607` `configure_vlan`, `:624` `_apply_hotspot`, `:637/:641`
  `configure_nat_masquerade` / `delete_nat_masquerade`. Adapter at
  `vlan/device_adapters.py:431/375/473/500`, gateway at
  `mikrotik_adapter.py:1225/1377/1943/2060`.
- Endpoint: `app/domains/vlan/router.py:299`, `POST /vlans/{vlan_pk}/push`,
  gated on `vlan.execute`.
- Customer trigger: `src/components/network/VlanManagement.tsx:232` `usePushVlan()`,
  button at `:449-465`. `useVlan.ts:20` polls every 4 s while any row is
  `provisioning`.
- Failure honesty: `service.py:645-654` — `FAILED` + error written and
  **committed** before the re-raise, and `PROVISIONING` is committed *before*
  the first socket (`:591-599`) so a killed process never leaves a stale
  `ACTIVE`. Real non-2xx.
- Idempotency: real. `_interface_vlan_exists` (`mikrotik_adapter.py:1326`)
  guards the `/interface vlan add`; `_ensure_ip_address` (`:1329`) matches on
  address **and** interface before adding.
- Delete reaches the device: `service.py:492` `delete_vlan` calls
  `_remove_from_device` (`:886`) → `delete_nat_masquerade` (`:933`) +
  `delete_vlan` (`:934`) **before** the soft-delete, and a device failure aborts
  the delete rather than orphaning a live interface.
- Disabled-state teardown is real, not a no-op: turning NAT off issues a delete
  (`service.py:641`), turning the portal off issues a hotspot delete
  (`_apply_hotspot`, `:842`) — so "off" actually removes what "on" created.
- The create form is honest about the DHCP dependency
  (`VlanManagement.tsx`, form note: "This creates the network only — no addresses
  are handed out automatically. To assign IPs to guests, create a DHCP Pool
  afterward with Interface set to `vlan<tag>`").

### Defects

- **(medium) An edited VLAN's re-Apply reports success without changing the
  device.** `_configure_vlan_trunk` (`mikrotik_adapter.py:1288-1305`) checks only
  whether an interface *named* `vlan{id}` exists. Change the parent interface on
  the row (`ether2` → `bridge`) and re-Apply: the existence check short-circuits,
  the old parent stays, the row flips to `ACTIVE`. Similarly `_ensure_ip_address`
  only *adds* — change the CIDR/gateway and the interface ends up carrying both
  the old and the new address, with the push reporting success. Idempotency was
  built for "re-push unchanged", not for "re-push edited".
- **(medium) Access mode permanently unbridges a physical port.**
  `_configure_vlan_access` (`mikrotik_adapter.py:1306-1325`) removes the chosen
  port from every bridge. `_delete_vlan_access` (`:1390`) deliberately does not
  put it back ("which bridge it belonged to was never recorded"). A customer who
  picks the wrong port in access mode takes that port off the LAN and cannot
  undo it from the dashboard. Nothing in the form warns of this.
- **(low) Stale copy in the master-console variant.** `VlanManagement.tsx:301`
  still reads "Device push happens through a separate configuration pipeline" —
  the same sentence just removed from the DHCP page. Only shown when `locationId`
  is absent (master console), so no customer sees it, but it is now false.

---

## 3. `port-forwarding` — "Port Forwarding"

### Verdict: **DATABASE ONLY**

### Evidence

- `app/domains/port_forwarding/` has no `device_adapters.py`
  (`find app -name device_adapters.py`), no `/push` route
  (`router.py` exposes only `POST/GET/GET/PUT/DELETE /rules`, lines 86-208), and
  no device call anywhere in `service.py`.
- The service docstring states it outright — `service.py:12-20`: *"this domain
  has no `device_adapters.py` and no Celery task -- it is a pure rules/inventory
  domain"*.
- The gateway writer exists and is unreferenced: `configure_port_forward`
  at `mikrotik_adapter.py:1814`, zero callers in `app/`.
- The only path that would render this rule onto a device is
  `network_config.renderers.render_port_forwarding_rule`
  (`app/domains/network_config/renderers.py:912`, wired into the combined script
  at `:2473`), applied by `POST /network-config/routers/{router_id}/push`
  (`network_config/router.py:158`) — **which no customer surface calls.** The
  only frontend consumer of `network-config.service.ts` is
  `src/hooks/useNetworkConfig.ts`, used only by
  `src/components/routers/RouterDetailTabs.tsx`, rendered only by
  `src/routes/_authenticated/routers.$routerId.tsx`. No customer nav entry
  reaches that route (`src/lib/customerNav.ts:105-116` lists the six Network
  features; there is no router-detail item), and `customerFeatures.tsx:12`
  says as much: `RouterDetailTabs` is a chunk "none of which a venue owner opens".
- No scheduled push either — no Celery beat task calls `push_config`
  (`grep -rn "push_config" app/`: only `provisioning_engine`, `router_provisioning`
  and `router` device adapters, all operator-initiated).

### Defects (ranked)

1. **(high) A forwarded port never opens.** The customer maps 8080 → the CCTV
   NVR, gets a 201, sees the rule listed, and no `/ip firewall nat` entry is ever
   created. The device is never contacted on any code path a customer can reach.
2. **(high) The UI asserts the rule is live.** `PortForwardingManagement.tsx:299-301`
   renders a green `Enabled` badge per row and `:204` a green "Enabled" stat card.
   There is no device-push badge, no "not applied" state, and the page description
   (`:194`, "Per-router NAT rules mapping a public destination port to an internal
   address/port") describes a router object, not a database row.
3. **(medium) Even the master-console pipeline is add-only for this domain.**
   `_idempotent_lines` (`renderers.py:2552-2564`) wraps every command in
   `:do { ... } on-error={}`. For an *edited* rule that means the old NAT entry
   is silently kept and the change is swallowed; for a *deleted* row it means the
   NAT entry stays on the router forever. There is no `delete_port_forward` in
   the gateway to call.
4. **(low) The service docstring cites a precedent that no longer exists.**
   `service.py:16-19` justifies the gap by "mirroring `app.domains.dhcp`/
   `app.domains.vlan`'s own 'config resource, realized onto a device later'
   precedent". Both of those domains now push. This domain is the outlier, not
   the pattern.

---

## 4. `voip` — "Call Priority"

### Verdict: **PARTIAL — the queue reaches the device; the packet mark it depends on does not**

RouterOS realizes QoS in two independent halves: a `/ip firewall mangle`
rule that *sets* a packet mark, and a `/queue tree` entry that *references*
that mark. A queue referencing a mark nothing sets is inert.

### Evidence

- **Half 2 (the queue) is real and customer-triggerable.**
  `app/domains/qos/service.py:343` `push_rule_to_device` → `:414`
  `create_priority_queue` → `qos/device_adapters.py:178` → gateway
  `create_queue_tree` (`mikrotik_adapter.py:2383`). Endpoint
  `POST /qos-rules/{rule_id}/push` (`qos/router.py:133`, `qos.execute`).
  Button: `QosManagement.tsx:257` `handlePush`, rendered at `:387-390`.
- **Half 1 (the mark) is only rendered by `network_config`.**
  `render_qos_traffic_rule` (`network_config/renderers.py:954-971`) emits the
  `/ip firewall mangle ... action=mark-packet new-packet-mark=<id>` line; it is
  reached only through `POST /network-config/routers/{id}/push`, which — per the
  Port Forwarding section above — **no customer surface calls.**
- The code says this in three places and none of them reach the UI:
  `qos/device_adapters.py:8-16`, `qos/service.py:18-30`,
  `qos/exceptions.py:120-128`.

So a customer who creates a "prioritise SIP" rule and clicks Apply gets a
`/queue tree` entry on the router that matches zero packets, and a badge that
reads **"Applied to your router"**.

### Defects (ranked)

1. **(high) The badge claims a device state that does not exist.**
   `QosManagement.tsx:120-124` maps `active` → **"Applied to your router"**. On a
   customer-only path, `active` means "half of the mechanism is on the router".
   Calls are not prioritised and nothing in the dashboard says so. This is worse
   than Port Forwarding's silence: it is an affirmative claim of device success.
2. **(medium) A failed push leaves no record.** `qos/service.py:420-426` writes
   `FAILED` + `device_push_error` and re-raises **without committing**. Unlike
   `dhcp` (`service.py:414-424`) and `vlan` (`service.py:645-654`), which both
   call `await self.repository.commit()` before the raise, `GenericRepository.update`
   only flushes and `get_db_session` rolls back on the exception — so the failure
   record is discarded. After a real device failure the row still reads
   "Not yet applied" with a NULL error, and `DevicePushBadge`'s failure tooltip
   (`QosManagement.tsx:146-153`) can never fire. The `vlan` docstring
   (`vlan/service.py:551-561`) already documents this exact bug in `qos` and says
   the unit test that "proves" otherwise uses an in-memory fake with no transaction.
3. **(medium) Re-push is not idempotent once the device-id pointer is lost.**
   Idempotency here rests entirely on the DB column `device_queue_id`
   (`qos/service.py:394-397`). The underlying write is a bare
   `api.path("queue","tree").add(...)` with no existence check
   (`mikrotik_adapter.py:2258-2270`) against the deterministic name
   `cloudguest-qos-{rule.id}` (`service.py:415`). If that pointer is ever lost —
   which defect 2 makes likely, since any post-`add` failure rolls the row back —
   every subsequent Apply fails with RouterOS's "already have such item", forever.
4. **(medium) Delete leaves the mangle rule behind.** `delete_rule`
   (`qos/service.py:281-336`) correctly removes the `/queue tree` entry, but the
   mangle mark is only removed by the *next* `network_config` push, which nobody
   triggers. The router keeps marking packets for a rule the customer deleted.
5. **(unverified, flagged) `max-limit=0` on a child of `global`.**
   `QOS_QUEUE_TREE_PARENT = "global"` and `QOS_QUEUE_UNLIMITED_MAX_LIMIT_KBPS = 0`
   (`qos/constants.py:88,100`). Whether RouterOS applies `priority` on a queue
   tree whose parent has no bandwidth ceiling is a device-behaviour question I
   cannot settle by reading. Worth a live check before claiming this feature works
   even after the mangle half is wired.

---

## 5. `website-blocking` — "Website Blocking"

### Verdict: **DATABASE ONLY**

### Evidence

- `app/domains/content_filtering/` has no `device_adapters.py`, no `/push` route
  (`router.py` exposes only CRUD at lines 79-202), and no device call in
  `service.py`.
- Stated in `content_filtering/service.py:11-20`: *"No live device push in this
  pass ... real RouterOS DNS-sinkhole/address-list provisioning happens through
  `app.domains.network_config`'s existing push pipeline
  (`renderers.render_content_filter_rule`), not this one."*
- The gateway writer exists and is unreferenced: `configure_content_filter_rule`
  at `mikrotik_adapter.py:2138`, zero callers in `app/`.
- The cited pipeline (`renderers.py:1043`, wired at `:2497`, applied by
  `network-config/.../push`) is **not reachable from the customer dashboard** —
  same chain of evidence as Port Forwarding above.

### Defects (ranked)

1. **(high) Nothing is blocked.** The customer blocks a domain, the row is
   created, and no `/ip dns static` sinkhole entry and no
   `/ip firewall address-list` entry is ever written. For a venue blocking adult
   content or a school blocking social media, the dashboard reports a control
   that does not exist.
2. **(high) The UI asserts the rule is live.** `ContentFilterManagement.tsx:280-282`
   renders a green `Enabled` badge per row and `:193` a green "Enabled" stat card.
   The page description (`:183`) hedges with "Applies the next time this router's
   configuration is pushed" — which is technically true and practically
   meaningless, because there is no customer-reachable way to push, and no
   scheduled job that ever will. The delete dialog repeats the same phrase
   (`:344`).
3. **(medium) "Website Blocking" is missing from the staff-access renderer.**
   `src/config/customerFeatures.tsx:157-166` handles `port-forwarding`, `dhcp`,
   `vlans`, `voip` — but not `website-blocking`, so it falls through to
   `GenericFeatureView` ("Not configured yet. Configuration for website blocking
   will appear here.", `OperationsFeatures.tsx:4887-4905`). `renderFeature` is what
   `src/routes/agent.index.tsx:211` uses, so an owner who grants a staff member
   the Website Blocking feature sees an empty placeholder. `WebsiteBlockingView`
   exists (`OperationsFeatures.tsx:4221`) and *is* wired on the owner path
   (`CustomerFeaturePage.tsx:316`) — this is a one-line omission in the second
   registry.
4. **(medium) Even the master-console pipeline is add-only.** Same
   `_idempotent_lines` problem as Port Forwarding (`renderers.py:2552`): an edited
   block is swallowed, a deleted block stays on the router. There is no
   `delete_content_filter_rule` in the gateway.
5. **(medium, cross-feature) The blocking mechanism can be defeated from the
   IP Addresses page.** The sinkhole works only for guests using the router as
   their DNS server (`mikrotik_adapter.py:2138`ff). The DHCP pool advertises
   whatever the customer typed (`dhcp/service.py:483-491` passes
   `pool.dns_primary`/`dns_secondary` straight through). A customer who sets
   `8.8.8.8` on the IP Addresses page silently disables every domain block, and
   neither page mentions the other.

---

## 6. `isp-details` — "Internet Connection"

### Verdict: **PARTIAL — every read is real; every write is database-only**

### Evidence — the reads are genuinely live

`app/domains/isp/device_adapters.py:290` `MikroTikIspHealthAdapter` delegates
five real RouterOS reads to the gateway: `ping` (`:308`),
`get_active_default_gateway` (`:332`), `get_pppoe_interface_status` (`:347`),
`get_interface_traffic_counters` (`:362`), `run_speed_test` (`:377`). These back
"Check health now", the speed test, and the 60-second sweep, and the frontend
polls them every 20 s (`OperationsFeatures.tsx:2634-2670`). Health status shown
to the customer is real.

### Evidence — every write stops at the database

The adapter is **read-only**: there is no write method on it at all. Consequently:

- **`trigger_failover` (`isp/service.py:1377-1431`)** flips two boolean columns —
  `is_active_uplink` false on the old link, true on the candidate — and writes an
  audit row. No route change, no distance change, no mangle change, no device call.
- **`trigger_failback` (`isp/service.py:1434-1473`)** — identical shape, same
  two column writes.
- **`set_wan_routing_mode` (`:644-696`)** writes `Router.wan_routing_mode` and
  says so in its own docstring: *"the RouterOS script generator (frontend) reads
  this ... to decide between"* — i.e. it is an input to a script somebody else
  must later generate and push.
- **`create_link`/`update_link`/`delete_link` (`:306`, `:546`, `:699`)** — plain
  row writes; `delete_link` does no device teardown.
- **`set_manual_health_status` (`:1269`)** — a column override, correctly
  described as such in the UI comment (`OperationsFeatures.tsx:2815-2820`).
- Policy routing rules are a separate database-only domain:
  `app/domains/isp_routing/service.py:13-18`, *"this domain has no
  `device_adapters.py` ... Real RouterOS policy routing needs ..."*. No
  `device_adapters.py` exists for it.

### Defects (ranked)

1. **(highest in this audit) "Trigger failover" does not move any traffic.**
   The customer's primary ISP is down. They open Internet Connection, read the
   card — *"Manually switch this router's active uplink, or fail back to its
   primary once it's healthy again"* (`OperationsFeatures.tsx:3062-3064`) — click
   **Trigger failover** (`:3067-3075`), and get `toast.success("Failover triggered")`
   (`:2854`). Two booleans changed. The router's routing table is untouched. The
   venue is still offline, and the dashboard now shows the *backup* as the
   "Active uplink" stat (`:3050`), so the one screen they would check to diagnose
   the outage is now actively lying about which uplink is carrying traffic.
   Every subsequent health read still reports the truth, which makes the screen
   internally contradictory rather than merely wrong.
2. **(medium) Failback has the same shape**, plus it can be triggered against a
   primary the platform believes is healthy while the device is still routing out
   of the backup — a state nothing reconciles.
3. **(medium) Routing rules are inert.** The rules table in the same view
   (`OperationsFeatures.tsx:2880`ff) is backed by `isp_routing`, which has no
   device path at all and is not even rendered into the `network_config` script.
4. **(low) `delete_link` leaves nothing behind on the device** only because
   nothing was ever put there. Once ISP writes become real this becomes a
   drift source.
5. **(low) The page description overstates.** `OperationsFeatures.tsx:2965`:
   "…live health status, manual/automatic failover, and policy-based routing
   rules." The health status is live; the failover and the routing rules are not.

---

## Summary

| Feature (customer label) | Verdict | Device write on the customer path | Customer can trigger it | Failure is a real non-2xx | Idempotent re-push | Delete reaches device | UI tells the truth |
|---|---|---|---|---|---|---|---|
| `dhcp` — IP Addresses | **REACHES DEVICE** | yes (`dhcp/service.py:405`) | yes (Apply button) | yes (committed, `:414`) | yes | yes (`:474`) | yes |
| `vlans` — Network Zones | **REACHES DEVICE** | yes (`vlan/service.py:607`) | yes (Apply button) | yes (committed, `:645`) | on unchanged rows only | yes (`:934`) | mostly (stale master-console copy) |
| `port-forwarding` — Port Forwarding | **DATABASE ONLY** | no | no | n/a | n/a | no | **no** — green "Enabled" |
| `voip` — Call Priority | **PARTIAL** — queue yes, packet mark no | half | yes (Apply button) | **no** (rollback, `:420`) | only via a DB pointer | queue yes, mangle no | **no** — "Applied to your router" |
| `website-blocking` — Website Blocking | **DATABASE ONLY** | no | no | n/a | n/a | no | **no** — green "Enabled" |
| `isp-details` — Internet Connection | **PARTIAL** — reads yes, writes no | no (reads only) | n/a | n/a | n/a | n/a | **no** — "Trigger failover" |

## Prioritised fix list

Ranked by harm to a paying venue, not by effort.

1. **Make ISP failover reach the router, or stop offering the button.**
   `isp/service.py:1377`/`:1434`. Until a real route/distance write exists, the
   two buttons and the "Active uplink" tile should not claim to switch traffic.
   The interim honest state is: remove the buttons, keep the health reads. This
   is the only defect in this audit that fires during an outage, when the
   customer is least able to absorb a lie.
2. **Stop `Call Priority` claiming "Applied to your router".**
   `QosManagement.tsx:120-124`. Either (a) push the mangle half from
   `qos.push_rule_to_device` alongside the queue — the gateway would need a
   `configure_packet_mark` writer — or (b) relabel `active` to something that
   does not assert end-to-end effect until (a) lands. Do (b) today regardless.
3. **Give `content_filtering` a `device_adapters.py` and a `/push` endpoint.**
   The gateway writer already exists, tested and read-before-write for the DROP
   rule: `mikrotik_adapter.py:2138`. Copy the `dhcp` shape exactly —
   `device_adapters.py`, `POST /content-filter-rules/{id}/push` on
   `content_filtering.execute`, `device_push_status`/`device_push_error` columns,
   commit-then-raise on failure, and an Apply button beside the Enabled badge.
   Blocking that silently does nothing is a safety/compliance exposure, not a
   convenience gap.
4. **Give `port_forwarding` the same treatment.** Gateway writer at
   `mikrotik_adapter.py:1814`. Same shape.
5. **Fix the `qos` failure-record rollback.** One line: `await self.repository.commit()`
   before the `raise` at `qos/service.py:426`, matching `dhcp/service.py:423` and
   `vlan/service.py:653`. This also removes the main way `device_queue_id` gets
   lost, which is what makes defect 4.3 (permanent "already have such item")
   reachable.
6. **Make VLAN re-Apply handle an edited row.** `mikrotik_adapter.py:1288-1305`
   and `_ensure_ip_address` (`:1329`): compare the existing `/interface vlan`'s
   `interface` and `comment` and update on drift; remove addresses on that
   interface that this VLAN no longer claims. Today an edit + Apply reports
   success and changes nothing.
7. **Write the missing gateway deletes** — `delete_port_forward`,
   `delete_content_filter_rule` — before (3) and (4) ship, so those domains do
   not repeat the drift that `vlan`/`dhcp` just fixed. Note that
   `_idempotent_lines` (`renderers.py:2552`) means the script pipeline can never
   express a delete or an update for these two, only an add.
8. **Add `website-blocking` to `renderFeature`.** One case at
   `src/config/customerFeatures.tsx:166`, so granting the feature to a staff
   member stops rendering "Not configured yet".
9. **Warn on the two irreversible/silent VLAN behaviours.** Access mode
   permanently unbridges the chosen port (`mikrotik_adapter.py:1306`,
   `:1390`); and the Captive-portal toggle interacts with a push path the
   form does not explain.
10. **Cross-link DNS between IP Addresses and Website Blocking.** Setting a
    public resolver on a DHCP pool (`dhcp/service.py:483`) silently defeats every
    domain block. Neither page mentions it.
11. **Delete the stale precedent claims in the two docstrings.**
    `port_forwarding/service.py:16-19` and `content_filtering/service.py:11-20`
    both cite `dhcp`/`vlan` as the "realized onto a device later" pattern. Both
    now push. Leaving that text in place is how the next engineer concludes the
    gap is deliberate.

## What I could not determine by reading

- **Whether the RBAC permission seed has been re-run in production.**
  `rbac/seed.py:334-338` carries an explicit deploy warning: *"seeding is a manual
  entrypoint ... Shipping the push endpoint without re-running the seed gives
  every operator a 403 on it."* `dhcp.execute`, `vlan.execute` and `qos.execute`
  are all newly-added actions. Organization Owner defaults to `GrantLevel.FULL`
  (`seed.py:926`) so the grant expands automatically *if the permission rows
  exist*. Whether they exist in the production database is not answerable from
  code. If they do not, the DHCP and VLAN Apply buttons 403 and the two
  "REACHES DEVICE" verdicts are academic. **Check this first.**
- **Whether a `/queue tree` child of `global` with `max-limit=0` applies priority
  at all on RouterOS** (`qos/constants.py:88,100`) — device behaviour, needs a
  live check.
- **Whether fleet routers already carry a general NAT masquerade.** This decides
  whether a Network Zone pushed with `nat_enabled = false` has internet or not;
  the VLAN form does not explain the toggle's consequence either way.
- **The actual device state of any production router** — whether mangle marks,
  orphaned NAT entries from deleted port-forward rows, or stale DNS sinkholes are
  present. Every drift claim above is derived from the code path, not from a
  device read. Device access is held by the orchestrator.
- **Master-console reachability for a customer.** I established that no customer
  nav entry routes to `/routers/$routerId` (`src/lib/customerNav.ts:105-116`) and
  that `RouterDetailTabs` has exactly one renderer. I did not test whether a
  customer session can reach that URL by typing it — the route sits under
  `_authenticated`, not under a role guard I could see, so a customer with
  `network_config.execute` (which `GrantLevel.FULL` grants) might be able to push
  by URL. Worth a live check; if true, it is a workaround for defects 3 and 4 and
  also a surface the customer was never meant to see.
