# Bridge VLAN filtering on MikroTik — root cause, corrected sequence, and a safe provisioning algorithm

**Status:** research + verified design. No live device was touched to produce this document.
**Audience:** engineers implementing VLAN provisioning in `wyfy-device-gateway` / `network_config`.
**Date:** 2026-09-02.

---

## 0. Reading note on citations

MikroTik moved its documentation. `help.mikrotik.com` now carries the banner:

> "This documentation site has been frozen, no further edits will be made here! The new RouterOS documentation site is available here: https://manual.mikrotik.com/docs/introduction/"

Both sites currently carry identical text for the sections cited below (verified by fetching both).
Primary citations point at **manual.mikrotik.com**; the frozen `help.mikrotik.com` page IDs are given
alongside because most existing internal links and search results still resolve there.

| Short name | New URL | Frozen mirror |
|---|---|---|
| **[BRSW]** Bridging and Switching | https://manual.mikrotik.com/docs/bridging-and-switching/ | https://help.mikrotik.com/docs/spaces/ROS/pages/328068/Bridging+and+Switching |
| **[BVT]** Bridge VLAN Table (case study) | https://manual.mikrotik.com/docs/bridging-and-switching/user-guides/bridge-vlan-table/ | https://help.mikrotik.com/docs/spaces/ROS/pages/28606465/Bridge+VLAN+Table |
| **[SCF]** Switch Chip Features | https://manual.mikrotik.com/docs/bridging-and-switching/switch-chip-features | https://help.mikrotik.com/docs/spaces/ROS/pages/15302988/Switch+Chip+Features |
| **[L2MIS]** Layer2 misconfiguration | https://manual.mikrotik.com/docs/bridging-and-switching/user-guides/layer2-misconfiguration | https://help.mikrotik.com/docs/spaces/ROS/pages/19136718/Layer2+misconfiguration |
| **[VXLAN]** VXLAN | https://manual.mikrotik.com/docs/bridging-and-switching/vxlan | https://help.mikrotik.com/docs/spaces/ROS/pages/100007937/VXLAN |
| **[VETH]** Containers / veth | https://manual.mikrotik.com/docs/containers/veth | https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Virtual+Ethernet |

Everything below marked **[DOC]** is quoted or directly paraphrased from those pages.
Everything marked **[INFER]** is reasoning from documented behaviour and is not itself stated in the docs.
Everything marked **[NEEDS LIVE TEST]** could not be settled without hardware.

---

## 1. Deliverable 1 — root cause, settled

### 1.1 Verdict

**The working hypothesis is CONFIRMED.** Putting the bridge interface in the `tagged=` list for the
native VLAN, while the router's IP sits directly on the `bridge` interface and no
`/interface vlan vlan-id=1 interface=bridge` exists, is the documented-wrong configuration. MikroTik's
own manual gives a worked example for exactly this topology and it uses **`untagged=bridge`**, not
`tagged=bridge`.

There is a **second, independent** fault on this specific model that also fired at the same moment:
the hEX lite's switch chip cannot hardware-offload bridge VLAN filtering, so `vlan-filtering=yes`
dropped hardware offload and triggered a switch-chip reset. See §1.6.

### 1.2 The bridge interface is itself a VLAN-aware port, with its own PVID

> "Turning on `vlan-filtering` enables all bridge VLAN related functionality and
> independent-VLAN-learning (IVL) mode. Besides joining the ports for Layer2 forwarding, **the bridge
> itself is also an interface therefore it has Port VLAN ID (pvid)**." — [BRSW], *Bridge VLAN Filtering* **[DOC]**

> "`pvid` (integer: 1..4094; Default: 1) Port VLAN ID (pvid) specifies which VLAN the untagged ingress
> traffic is assigned to. **It applies e.g. to frames sent from bridge IP and destined to a bridge
> port.** This property only has an effect when `vlan-filtering` is set to `yes`."
> — [BRSW], `/interface bridge` property table **[DOC]**

That last sentence is the one that matters here. The bridge's `pvid` governs traffic *originated by the
router's own IP stack on the bridge interface*. Default is 1.

And the CPU-port framing:

> "CPU port — Every device with a switch chip has a special purpose port called CPU port and it is used
> to communicate with the device's CPU. For devices that support VLAN filtering with hardware
> offloading, **this port is the bridge interface itself**." — [BVT], *Background* **[DOC]**

So `bridge` is simultaneously (a) the L3 interface holding `10.5.50.1/24`, and (b) a VLAN-aware port of
the VLAN-aware bridge. `/interface bridge vlan` decides the egress tag treatment for that port exactly
as it does for `ether2`.

### 1.3 What `tagged=` and `untagged=` mean for the bridge port

> "The `tagged` ports send out frames with a corresponding VLAN ID tag. The `untagged` ports remove a
> VLAN tag before sending out frames." — [BRSW], *Bridge VLAN table* **[DOC]**

> "By specifying a tagged port the bridge will always set a VLAN tag for packets that are being sent out
> through this port (egress). By specifying an untagged port the bridge will always remove the VLAN tag
> from egress packets." — [BVT], *Background* **[DOC]**

"Egress toward the bridge port" means *toward the router's own IP stack*. So:

- `tagged=bridge` for VID *n* ⇒ frames handed up to the CPU carry an 802.1Q tag with VID *n*.
  The only thing in RouterOS that consumes a tagged frame arriving on `bridge` is an
  `/interface vlan vlan-id=n interface=bridge`. If that sub-interface does not exist, nothing at L3 owns
  the frame. **[INFER, strongly supported]**
- `untagged=bridge` for VID *n* ⇒ the tag is stripped before the frame reaches the CPU, and the frame is
  delivered to the plain `bridge` interface — which is where `10.5.50.1/24`, `hotspot-dhcp` and
  `hotspot1` are bound.

### 1.4 The bridge is normally an *untagged* member of its own PVID — automatically

> "Bridge ports with `frame-types` set to `admit-all` or `admit-only-untagged-and-priority-tagged` will be
> automatically added as untagged ports for the `pvid` VLAN." — [BRSW], *Bridge VLAN table* **[DOC]**

> "You don't have to add access ports as untagged ports, because they will be added dynamically as an
> untagged port with the VLAN ID that is specified in `pvid` […] **You must take into account that the
> bridge itself is a port and it also has a `pvid` value, this means that the bridge port also will be
> added as an untagged port for the ports that have the same `pvid`.** You can circumvent this behavior
> by either setting different `pvid` on all ports (even the trunk port and bridge itself), or to use
> `frame-type` set to `accept-only-vlan-tagged`."
> — [BRSW], *VLAN Example - Trunk and Hybrid Ports* **[DOC]**

The lab bridge had `pvid=1` and (by default) `frame-types=admit-all`. Left alone, RouterOS would have
created a dynamic `;;; added by pvid` VLAN-1 entry with `bridge`, `ether2`, `ether3`, `ether4`, `ether5`
all **untagged** — the correct outcome, requiring zero commands. [BRSW] shows those dynamic entries
verbatim in the *Interface lists in VLAN table* example.

The command that was run:

```
/interface bridge vlan add bridge=bridge vlan-ids=1 tagged=bridge untagged=ether2,ether3,ether4,ether5
```

created a **static** entry that named `bridge` in `tagged=` and *omitted it* from `untagged=`. The
device's own post-change read is the proof that the static declaration won over the automatic PVID
membership:

```
current-tagged   = bridge      <-- bridge became a TAGGED member of VLAN 1
current-untagged = ether2      <-- bridge is absent
```

(`current-untagged` listing only `ether2` and not `ether3..5` is expected — `current-*` reflect
*currently running* interfaces, and only `ether2` had link. **[INFER]**)

### 1.5 What that did to the data path

With `vlan-filtering=yes`, `bridge` tagged in VLAN 1, and no `/interface vlan vlan-id=1 interface=bridge`:

1. Guest DHCP DISCOVER (untagged broadcast) arrives on `ether2`.
2. Ingress: `pvid=1` assigns VID 1. `ingress-filtering=yes` (v7 default, see §5.6) checks membership —
   `ether2` *is* an untagged member of VLAN 1, so the frame is accepted.
3. Egress flood to all VLAN-1 members: `ether3/4/5` (link down) and `bridge` (**tagged**).
4. The frame is handed to the CPU carrying an 802.1Q VID-1 header.
5. Nothing at L3 owns VID-1-on-`bridge`. `hotspot-dhcp` and `hotspot1` are bound to `interface=bridge`
   and expect untagged frames. No DHCP OFFER is ever generated. **[INFER]**
6. Symmetrically, replies originated by the bridge IP would be emitted into VLAN `pvid=1` and
   *would* egress untagged out `ether2` — the return path was fine. The break is one-directional at the
   CPU boundary, which is precisely why nothing looked broken in the config.

**The manual's own contrasting pair of examples is the decisive citation.** From
[BRSW], *Management access configuration*:

*"Tagged access with VLAN filtering"* — L3 lives on a **VLAN sub-interface** of the bridge:

```
/interface vlan  add interface=bridge1 name=MGMT vlan-id=99
/ip address      add address=192.168.99.1/24 interface=MGMT
/interface bridge vlan add bridge=bridge1 tagged=bridge1,ether3,ether4,sfp-sfpplus1 vlan-ids=99
```
> "Note that the `bridge1` interface is also included in the tagged port list" **[DOC]**

*"Changing untagged VLAN for the bridge interface"* — L3 lives **directly on the bridge**:

```
/ip address add address=192.168.99.1/24 interface=bridge1
/interface bridge set [find name=bridge1] pvid=99
/interface bridge port set [find interface=ether2] pvid=99
/interface bridge port set [find interface=ether3] pvid=99
/interface bridge vlan add bridge=bridge1 tagged=sfp-sfpplus1 untagged=bridge1,ether2,ether3 vlan-ids=99
```
**`untagged=bridge1`.** **[DOC]**

That is our topology, one-for-one, and it says `untagged`. The `tagged=<bridge>` advice — including the
often-quoted line "*For routing functions to work properly on the same device through ports that use
bridge VLAN filtering, you will need to allow access to the bridge interface […] This can be done
manually by adding the bridge interface itself to the VLAN table as a tagged port*" ([BRSW]) — belongs to
the case where a `/interface vlan` sub-interface exists on the bridge for that VID. It is not universal
advice. Since RouterOS 7.16 RouterOS even adds that tagged entry itself:

> "Since RouterOS v7.16, this is done automatically when adding a VLAN interface to a bridge with
> vlan-filtering enabled (a dynamic entry with the comment `added by vlan on bridge` will appear under
> the `/interface/bridge/vlan` menu)." — [BRSW] **[DOC]**

The lab's *other* VLAN entry was therefore **correct**: `vlan-ids=100 tagged=bridge` is right, because
`/interface vlan vlan100 vlan-id=100 interface=bridge` with `10.0.0.1/24` does exist.

### 1.6 Second, independent fault: this model cannot offload VLAN filtering

Per [SCF], the RB750r2 (hEX lite) uses an **Atheros8227** switch chip:

> "RB951Ui-2nD (hAP); RB952Ui-5ac2nD (hAP ac lite); **RB750r2 (hEX lite)**; RB750UPr2 (hEX PoE lite);
> RB750P-PBr2 (PowerBox); RB750P r2; RBOmniTikU-5HnDr2; RBOmniTikUPA-5HnDr2 → **Atheros8227**
> (ether1-ether5)" — [SCF] **[DOC]**

And per the offload matrix in [BRSW] *Bridge Hardware Offloading*, `Atheros8227` scores **`-` for VLAN
Filtering**:

> "Currently, MikroTik devices with Marvell Prestera switch and `RTL8367, 88E6393X, 88E6191X, 88E6190,
> MT7621, MT7531, EN7523` switch chips (since RouterOS v7) are capable of using bridge VLAN filtering
> and hardware offloading at the same time, **other devices will not be able to use the benefits of a
> built-in switch chip when bridge VLAN filtering is enabled**. […] If an improper configuration method
> is used, your device can cause throughput issues in your network." — [BRSW] **[DOC]**

Consequences on this box:

- Enabling `vlan-filtering=yes` **removes the `H` (hw-offload) flag from every bridge port** and moves all
  L2 forwarding to the 850 MHz single-core MIPS CPU. **[DOC + INFER]**
- The transition itself bounces the ports:
  > "Certain bridge and Ethernet port properties are directly related to switch chip settings. Changing
  > such properties can trigger a **switch chip reset, temporarily disabling all Ethernet ports** that are
  > on the switch chip for the settings to take effect. This must be taken into account whenever changing
  > properties in production environments. Such properties include DHCP Snooping, IGMP Snooping,
  > **VLAN filtering**, L2MTU, Flow Control, and others." — [BRSW] **[DOC]**

A switch-chip reset flushes learned MACs and bounces links. **[INFER]**

### 1.7 The empty bridge host table

Observed: while filtering was on, `/interface bridge host` contained *only* the bridge's own local MACs
(across vid 1 / 100 / 200) and **zero** non-local hosts. After reverting, the AP's MAC
`B8:FB:B3:5D:64:3E` reappeared on `ether2`.

Two mechanisms are consistent with that, and they are not mutually exclusive:

1. **Switch-chip reset + no return traffic.** The reset flushed the table and bounced `ether2`. With DHCP
   dead and the router unable to answer anything, the AP had nothing to transmit except periodic
   broadcast retries; the default bridge `ageing-time` is 5 minutes, so between retries the entry
   expires and the table reads empty. **[INFER]**
2. **Ingress was also being dropped.** This would make it an L2 break, not only an L3 one.

Reading §1.5 strictly, ingress on `ether2` *should* have been accepted and learned (VID 1, `ether2` is an
untagged member, `ingress-filtering` passes). So mechanism (1) is the better-supported explanation and
the total absence of non-local hosts is a *downstream symptom* of the L3 break plus the chip reset,
rather than a separate cause.

**[NEEDS LIVE TEST]** — to settle this, re-run the broken configuration in the lab with a client actively
retrying DHCP and, in the same window:
- `/interface bridge host print where !local` (does the AP MAC appear at all, with `VID=1`?)
- `/tool sniffer quick interface=ether2` (are DISCOVERs arriving?)
- `/tool sniffer quick interface=bridge` (do they surface on the CPU, and *with* a VLAN tag?)

The sniffer on `bridge` is the single observation that would distinguish the two mechanisms. Do not
deploy anything on the strength of mechanism (2) until that test is run; the fix in §2 addresses both.

### 1.8 Summary of the correct rule

> **If an IP address lives directly on the `bridge` interface, the bridge must be an `untagged` member of
> the VLAN whose ID equals the bridge's own `pvid`. It must be a `tagged` member only of VLANs for which
> a `/interface vlan vlan-id=<n> interface=<bridge>` sub-interface exists.**

Corollary: the two are not exclusive. A bridge can be `untagged` in VLAN 1 (native L3 on `bridge`) and
`tagged` in VLAN 100 (L3 on `vlan100`) simultaneously — which is exactly the shape this lab router needs.

---

## 2. Deliverable 2 — corrected, ordered sequence for THIS topology

Target state, unchanged from today except that the bridge becomes VLAN-aware:

| | |
|---|---|
| bridge | `bridge`, `pvid=1`, `frame-types=admit-all`, holds `10.5.50.1/24` |
| ports | `ether2..ether5`, `pvid=1`, `frame-types=admit-all` |
| VLAN 1 | native/untagged; `bridge` **untagged**; serves DHCP + hotspot |
| VLAN 100 | tagged to CPU via `vlan100`; `bridge` **tagged** |
| WAN | `ether1`, not a bridge port |
| Mgmt | `wg-cloudguard`, not a bridge port — survives a bridge outage |

### 2.0 Pre-flight reads (no writes) — all must be captured before touching anything

```
/system resource print                                   # version, architecture-name
/system routerboard print                                # model
/interface ethernet switch print                         # TYPE column -> switch chip
/interface bridge print detail where name=bridge         # vlan-filtering, pvid, frame-types
/interface bridge port print detail where bridge=bridge  # per-port pvid, frame-types, hw, H flag
/interface bridge vlan print detail                      # EVERY existing entry, static and dynamic
/interface vlan print detail                             # which VIDs already have sub-interfaces
/ip address print detail                                 # what is bound to bridge
/ip dhcp-server print detail                             # interface= bindings
/ip hotspot print detail                                 # interface= bindings
/interface list member print                             # LAN/WAN/MGMT list membership
/ip firewall filter print                                # rules naming in-interface=bridge
```

**Baseline counters** — record the numbers, they are the only honest success criteria:

```
:put [:len [/interface bridge host find where !local]]              # N_HOSTS   (expect >= 1)
:put [:len [/ip dhcp-server lease find where status="bound"]]       # N_LEASES
:put [:len [/ip arp find where interface=bridge && dynamic]]        # N_ARP
```
Also note **one live guest IP** to ping, and the AP MAC (`B8:FB:B3:5D:64:3E`).

**Hard gate:** confirm the management path does not traverse `bridge`. Here it does not
(`wg-cloudguard` rides `ether1`/WAN), which is the only reason the earlier failure was recoverable.
If management *does* cross the bridge, do not proceed without §2.1.

### 2.1 Safety net: scheduled auto-revert (arm BEFORE any write)

RouterOS Safe Mode is a console feature and is not usable over the API. The API-side equivalent is a
self-deleting scheduler:

```
/system scheduler add name=vlanfilter-rollback interval=3m \
  on-event="/interface bridge set [find name=bridge] vlan-filtering=no; \
            /system scheduler remove [find name=vlanfilter-rollback]"
```

Delete it by hand once verification passes. **[NEEDS LIVE TEST]** — confirm on the bench that
`interval=` starts counting from creation (rather than requiring `start-time`), and that the scheduler
survives the switch-chip reset. Do not rely on this in production until proven.

### 2.2 Write sequence

All of steps 1–4 are safe with `vlan-filtering=no` still set; the VLAN table is inert until step 5.

```
# --- Step 1: repair (or create) the NATIVE VLAN 1 entry. The bridge is UNTAGGED. ---
# If the bad static entry is still present, SET it rather than add a second one:
/interface bridge vlan set [find bridge=bridge vlan-ids=1] \
    tagged="" untagged=bridge,ether2,ether3,ether4,ether5

# If no static VLAN-1 entry exists, prefer creating none at all: with pvid=1 +
# frame-types=admit-all on the bridge and on ether2..5, RouterOS generates the
# ";;; added by pvid" dynamic entry with all of them untagged, which is correct.
# If you want it explicit (recommended for provisioning determinism):
/interface bridge vlan add bridge=bridge vlan-ids=1 \
    untagged=bridge,ether2,ether3,ether4,ether5

# --- Step 2: VLAN 100 keeps tagged=bridge. It HAS /interface vlan vlan100 interface=bridge. ---
/interface bridge vlan add bridge=bridge vlan-ids=100 tagged=bridge
# (add any real trunk port to tagged= as well, if 100 must leave the box tagged)

# --- Step 3: pin the bridge's own PVID and frame handling explicitly. ---
/interface bridge set [find name=bridge] pvid=1 frame-types=admit-all
# Do NOT set frame-types=admit-only-vlan-tagged on the bridge here: the manual offers that as an
# "optional step […] in order to disable the default untagged VLAN 1", which is the exact opposite
# of what this topology needs.

# --- Step 4: pin the access ports (already the current values; make them explicit anyway). ---
/interface bridge port set [find bridge=bridge] pvid=1 frame-types=admit-all

# --- Step 5: LAST. Enable filtering. Expect a switch-chip reset and a link bounce. ---
/interface bridge set [find name=bridge] vlan-filtering=yes
```

### 2.3 Verification — and what our earlier verification got wrong

#### Why the previous checks were worthless

| Check we ran | Why it proved nothing |
|---|---|
| `/ip dhcp-server` `invalid=false` | `invalid` means "the interface named in this row still exists and is running". It is a **config-integrity** flag, not a data-plane flag. `bridge` never went away, so it stayed `false` regardless of VLAN membership. |
| `/ip hotspot` `invalid=false` | Same. |
| "no addresses lost" | `/ip address` rows bind to an *interface*, not to a VLAN membership. `vlan-filtering` never removes addresses. It changes **which frames reach that interface**. Addresses surviving is expected in both the working and the broken case. |
| `current-tagged='bridge'` | This *was* the failure. It was read as a success signal. |

Every one of those is satisfied by a router that is passing zero guest traffic. None of them touches the
data plane.

#### V1 — the check that would have caught it, runnable BEFORE step 5

```
/interface bridge vlan print detail where vlan-ids=1
```
**Pass:** `current-untagged` contains `bridge`. **Fail:** `current-tagged` contains `bridge`.

Assert exactly that, and refuse to proceed to step 5 on failure. This is the single most valuable line
in this document.

**[NEEDS LIVE TEST]** — confirm `current-tagged` / `current-untagged` are populated while
`vlan-filtering=no`. If they are only computed once filtering is on, fall back to asserting on the
static `tagged` / `untagged` fields pre-enable and re-asserting on `current-*` post-enable.

#### V2 — data-plane checks, inside the rollback window, with a real client attached

Run these on a network that has at least one live guest. An idle LAN passes every check while broken.

```
# V2a  Guest MACs are being learned, with the right VID.
/interface bridge host print where !local
#   PASS: >= N_HOSTS entries; the AP MAC B8:FB:B3:5D:64:3E present on ether2 with VID=1.
#   FAIL: only local entries.  <-- this is what we saw, and it should have blocked the change

# V2b  ARP on the native segment is still resolving.
/ip arp print where interface=bridge && dynamic
#   PASS: >= N_ARP entries, refreshing.

# V2c  The router can actually reach a guest.  Strongest single test.
/ping <live guest IP> interface=bridge count=5
#   PASS: replies.

# V2d  DHCP is actually serving. Force a renew on a client, then:
/ip dhcp-server lease print where status="bound"
/log print where topics~"dhcp"
#   PASS: OFFER/ACK in the log, lease count >= N_LEASES.

# V2e  Hotspot still intercepts.
/ip hotspot host print
/ip hotspot active print

# V2f  Record the offload cost (informational, not pass/fail on this model).
/interface bridge port print          # H flag: expected GONE on Atheros8227
/system resource print                # cpu-load under load
```

**Only after V1 + V2a + V2c + V2d all pass**, delete the rollback scheduler.

### 2.4 Should the native LAN's L3 move to `/interface vlan` instead?

**Recommendation: no, not for this change. Yes, eventually, and not to VLAN 1.**

- **For the immediate fix:** `untagged=bridge` (§2.2) is correct, is MikroTik's own documented pattern for
  this topology, touches no L3/service binding, and carries no guest outage. Do that.
- **The manual does prefer the sub-interface shape in general:**
  > "Note that creating routable VLAN interfaces and allowing tagged traffic on the bridge is a more
  > flexible and generally recommended option." — [BRSW], *Changing untagged VLAN for the bridge interface* **[DOC]**
- **But do not migrate to a tagged VLAN 1.** VID 1 is the industry-wide native/default VLAN and many
  switches and APs treat it specially (untag it, or refuse to tag it). If you migrate, migrate the guest
  network to a purpose-chosen non-1 VID (e.g. 10) and leave VLAN 1 as a dead native VLAN — which is the
  configuration most people mean by "do VLANs properly".

**What the migration costs.** Everything currently bound to `interface=bridge` must move to
`interface=vlanN` in one atomic maintenance window:

| Object | Change | Guest impact |
|---|---|---|
| `/ip address 10.5.50.1/24` | `interface=bridge` → `interface=vlanN` | brief |
| `/ip dhcp-server hotspot-dhcp` | `interface=bridge` → `interface=vlanN` | **all existing leases invalidated; every guest re-DHCPs** |
| `/ip dhcp-server network` | address-keyed — no change | none |
| `/ip pool hotspot-pool` | no change | none |
| `/ip hotspot hotspot1` | `interface=bridge` → `interface=vlanN` | **every active hotspot session drops; guests re-authenticate** |
| `/ip hotspot profile hsprof1` | `hotspot-address` unchanged | none |
| `/ip firewall filter/nat/mangle` | any `in-interface=bridge` / `out-interface=bridge` → `vlanN` | silent breakage if missed |
| `/interface list member` (LAN) | `bridge` → `vlanN` (or add both) | firewall rules keyed on lists break if missed |
| `/queue` trees/simple bound to `bridge` | retarget | rate limits stop applying |
| `/ip neighbor discovery-settings`, `/tool mac-server` | interface lists | management convenience only |
| RADIUS NAS identity / `nas-port-id` | may change with the interface name | **CoA and accounting can break — check against the FreeRADIUS side** |
| `/ip dns` static, walled garden | address-keyed — no change | none |
| MTU | `vlanN` inherits `l2mtu-4`; verify member `l2mtu >= 1504` | fragmentation if wrong |

**[NEEDS LIVE TEST]** — whether `/ip hotspot set <id> interface=` is accepted on a running server, or
whether the server must be removed and re-added (which also drops its dynamic firewall chains). This
determines whether the migration is a 5-second blip or a 60-second rebuild. Test on the bench.

Given that guest re-authentication is the visible cost, and that `untagged=bridge` is fully correct and
supported, **do not bundle the migration with the VLAN-filtering enablement.** Two separate changes, two
separate windows.

---

## 3. Deliverable 3 — access-type VLAN, generalized

### 3.1 Correct access-port configuration

```
# 1. Port: assign untagged ingress to the VLAN, and reject tagged ingress.
/interface bridge port set [find interface=<PORT> bridge=<BR>] \
    pvid=<VID> \
    frame-types=admit-only-untagged-and-priority-tagged \
    ingress-filtering=yes

# 2. VLAN table: the port egresses untagged. Trunks that must carry it go in tagged=.
/interface bridge vlan add bridge=<BR> vlan-ids=<VID> untagged=<PORT> [tagged=<TRUNKS>]

# 3. ONLY if the router itself must route/serve this VLAN: sub-interface + L3 + bridge tagged.
/interface vlan add name=vlan<VID> vlan-id=<VID> interface=<BR>
/ip address add address=<CIDR> interface=vlan<VID>
# On RouterOS < 7.16 you must also add the bridge to the tagged list yourself:
/interface bridge vlan set [find bridge=<BR> vlan-ids=<VID>] tagged=<BR>,<TRUNKS>
# On >= 7.16 RouterOS adds a dynamic ";;; added by vlan on bridge" tagged entry automatically. [DOC]
```

Step 2's `untagged=<PORT>` is technically redundant with step 1 — [BRSW] states ports with
`admit-only-untagged-and-priority-tagged` are auto-added as untagged for their pvid — but stating it
explicitly makes the provisioning result deterministic and diffable. Keep it.

One documented trap in the same paragraph:

> "The `vlan-ids` parameter can be used to specify a set or range of VLANs, but specifying multiple VLANs
> in a single bridge VLAN table entry should only be used for ports that are tagged ports. In case
> multiple VLANs are specified for access ports, then tagged packets might get sent out as untagged
> packets through the wrong access port, regardless of the PVID value." — [BRSW] **[DOC]**

⇒ **Never write an access port into a multi-VID or ranged `/interface bridge vlan` entry.** One VID per
entry when `untagged=` is non-empty.

### 3.2 Does it work on a *virtual* bridge port?

Yes — a virtual interface is an ordinary bridge port. The manual says so implicitly by carving them out
of hardware offload only:

> "`hw` (yes | no; Default: yes) Allows to enable or disable hardware offloading on interfaces capable of
> HW offloading. **For software interfaces like EoIP or VLAN this setting is ignored and has no effect.**"
> — [BRSW], `/interface bridge port` property table **[DOC]**

And VXLAN has first-class bridge properties:

> "`bridge` (name) Name of the bridge interface to which VXLAN interface will be added as a slave port.
> `bridge-pvid` (integer 1..4094; Default: 1) Used to assign PVID parameter for dynamically bridge port.
> This property only has an effect when bridge vlan-filtering is set to yes." — [VXLAN] **[DOC]**

[VXLAN] carries a complete worked example of exactly this pattern:

```
/interface bridge add name=bridge1 vlan-filtering=yes
/interface vxlan add bridge=bridge1 bridge-pvid=10 local-address=192.168.1.1 name=vxlan-10010 vni=10010
/interface vxlan add bridge=bridge1 bridge-pvid=20 local-address=192.168.1.1 name=vxlan-10020 vni=10020
/interface bridge port add bridge=bridge1 interface=sfp-sfpplus3 pvid=10
/interface bridge port add bridge=bridge1 interface=sfp-sfpplus4 pvid=20
/interface vxlan vteps add interface=vxlan-10010 remote-ip=192.168.1.2
```

### 3.3 What the VXLAN test proved — and what it did not

Our test: `/interface vxlan` → bridge port with `pvid=200
frame-types=admit-only-untagged-and-priority-tagged`, and RouterOS reported
`current-untagged='vxlan-wyfy200'`.

**Proved:**
- RouterOS accepts a virtual interface as a bridge port and applies `pvid` / `frame-types` to it.
- The bridge's VLAN table *control plane* computed the egress-untag set correctly and reported it back —
  i.e. our command shape and our read-back parsing are right.
- The same command shape is therefore syntactically valid for a physical access port.

**Did NOT prove:**
- **That any frame ever traversed it.** A `/interface vxlan` with no `/interface vxlan vteps` peer has no
  remote endpoint and carries nothing. `current-untagged` is a computed membership list, not a traffic
  counter.
- **That untagged ingress actually receives PVID 200** — there was no ingress traffic.
- **Anything about a physical port.** A physical port's behaviour additionally depends on the switch chip
  and on whether offload is active; a VXLAN port is always pure software. On this hEX lite that
  distinction is moot (nothing offloads under filtering), but it is *not* moot on an MT7621 or a CRS3xx,
  where the physical path is executed by silicon and the virtual path by the CPU.
- **Anything about MAC learning, DHCP, ARP, or the hotspot** on that VLAN.

⇒ Treat the VXLAN result as a *syntax and read-back* test only. Access-port behaviour must be proven on a
physical port with a live client before it is shipped.

### 3.4 Virtual bridge-port options per architecture

| Interface | Bridgeable? | Availability | Notes |
|---|---|---|---|
| `bonding` | yes | v6 + v7, all architectures | A single-member bond is the reliable "virtual port that exists everywhere" trick. Offloaded only on Prestera / 88E639x (802.3ad, balance-xor, active-backup only) — [BRSW] footnote 2. |
| `eoip` | yes | v6 + v7, all architectures | Real Ethernet payload, so genuinely bridgeable; carries nothing without a remote peer. |
| `vxlan` | yes | **v7 only** | Present on this mipsbe hEX lite. Carries nothing without `/interface vxlan vteps`. HW-offloaded VXLAN only since 7.18 on L3HW devices — [VXLAN]. |
| `vlan` (`/interface vlan`) | yes | v6 + v7 | Bridging a `/interface vlan` built on an interface **that is itself a bridge port** is a documented misconfiguration: "*VLAN interface that is created on a slave interface will never capture any traffic at all since it is immediately forwarded to the master interface before any packet processing is being done*" — [L2MIS]. **[DOC]** |
| `wifi` / `wireless` | yes | only on devices with radios | hEX lite has none. `wifi` is the v7 driver, `wireless` the v6/legacy one — the menu name differs by version *and* by model. |
| `wireguard` | **no** | v7 only | Pure L3 tunnel, no Ethernet header. The menu being present does **not** mean it can be a bridge port. **[INFER — high confidence, but confirm on the bench before relying on it in a capability probe.]** |
| `veth` | yes | **arm / arm64 / x86 only** | Explains its absence on this mipsbe box: "*Container package is compatible with arm, arm64 and x86 architectures*" — [VETH] **[DOC]**. Also needs `/system/device-mode/update container=yes`, which requires a **physical reset-button press or cold reboot** to confirm — disqualifying for remote provisioning. |
| `lo` / `loopback` | no | v7 | L3 only. |

**Recommendation:** do not build a capability probe around virtual ports. Use a single-member `bonding`
interface if you need an architecture-independent synthetic bridge port for a smoke test, and accept that
it proves control plane only.

---

## 4. Deliverable 4 — what varies across customer routers

### 4.1 Hardware offload

**Which chips offload bridge VLAN filtering** (`+` in the VLAN Filtering column of [BRSW]'s matrix):

| Chip / family | VLAN filtering offload | Note |
|---|---|---|
| Marvell Prestera (CRS3xx, CRS5xx) | **+** | full feature set, incl. MLAG, DHCP/IGMP snooping |
| 88E6393X, 88E6191X, 88E6190 | **+** | footnote 6: no `ether-type` 0x88a8/0x9100, no `tag-stacking` — using those disables offload |
| MT7621, MT7531, EN7523 | **+** | same footnote 6. Added in RouterOS 7.1 |
| RTL8367 | **+** | same footnote 6. Added in RouterOS 7.1 |
| CRS1xx / CRS2xx series | **–** | has its own `/interface ethernet switch` VLAN table instead |
| **QCA8337** | **–** | RB750Gr2, hAP ac, hEX PoE, PowerBox Pro, RB3011, OmniTik ac |
| **Atheros8327** | **–** | RB2011 ether1-5 |
| **Atheros8316** | **–** | |
| **Atheros8227** | **–** | **RB750r2 (hEX lite)** ← our lab box, hAP, hAP ac lite, hEX PoE lite, PowerBox |
| **Atheros7240** | **–** | RB750, RB951-2n |
| IPQ-PPE | **–** | offloaded bridge itself is "work in progress"; MikroTik recommends the non-offloaded bridge |
| ICPlus175D | **–** | |

Source: [BRSW] *Bridge Hardware Offloading* matrix and [SCF] RouterBoard→chip table. **[DOC]**

**Throughput consequence on a non-offloading device.** All inter-port L2 forwarding moves from silicon
to the CPU. MikroTik states the consequence without a number:

> "While a bridge is a software feature that will consume CPU's resources, the bridge hardware offloading
> feature will allow you to use the built-in switch chip to forward packets. This allows you to achieve
> higher throughput if configured correctly." … "If an improper configuration method is used, your
> device can cause throughput issues in your network." — [BRSW] **[DOC]**

> "Hardware offloading can achieve full wire-speed performance when it is active […] When comparing
> throughput results, you would get such results: **Hardware offloading > Fast Forward > Fast Path >
> Slow Path**." — [BRSW] **[DOC]** (Note also: "Fast Forward is disabled when hardware offloading is
> enabled" — the converse means losing offload at least re-enables Fast Forward as a partial mitigation,
> but only for two-port bridges.)

**I will not invent a Mbps figure.** **[NEEDS LIVE TEST]** — bench-measure `iperf3` client-to-client
across two bridge ports on a representative low-end model with `vlan-filtering=no` then `=yes`, and
record the pair. That number is what the refusal threshold in §5 should be calibrated against.

**Important nuance for Wyfy Guest specifically:** guest traffic in a captive-portal deployment is almost
entirely north-south (client ↔ WAN), which is *already* routed by the CPU and *already* not offloaded.
The loss that matters is client↔client switching on the same LAN, which for a guest network is small and
often actively undesirable. So on an Atheros8227-class box, enabling VLAN filtering is likely
**acceptable** for our workload — but that must be a *measured, recorded decision per model*, not an
assumption, and it must not be made silently on the customer's behalf.

**Programmatic detection, in order of reliability:**

1. **Chip type** — `/interface ethernet switch print` exposes a `TYPE` column:
   ```
   [admin@MikroTik] > /interface ethernet switch print
   Flags: I - invalid
    # NAME     TYPE           MIRROR-SOURCE  MIRROR-TARGET  SWITCH-ALL-PORTS
    0 switch1  Atheros-8327   none           none
    1 switch2  Atheros-8227   none           none
   ```
   — [SCF] **[DOC]**. Match `type` against the offload-capable set above. Note the printed form uses
   hyphens (`Atheros-8227`) while the docs' matrix uses none (`Atheros8227`) — normalise before matching.
   An empty menu means no switch chip at all.
2. **The `H` flag** — `/interface bridge port print`, `Flags: X - disabled, I - inactive, D - dynamic,
   H - hw-offload`. [BRSW] explicitly tells you to check it:
   > "Certain bridge or port functions can automatically disable HW offloading, use the `print` command to
   > see whether the 'H' flag is active." **[DOC]**

   **[NEEDS LIVE TEST]** — the exact key the RouterOS **API** returns for that flag (as opposed to CLI
   print). `hw` is the *requested* setting and is always present; the *actual* offload state is a
   separate read-only field, likely `hw-offload`. Confirm with a raw `librouteros` dump of
   `/interface/bridge/port` on an offloaded and a non-offloaded device. **Until confirmed, do not gate on
   it — gate on chip type (method 1), which is unambiguous.**
3. `/interface/bridge/port/monitor` returns `hw-offload-group: switchX` — this indicates *which* switch
   chip the port belongs to, not whether offload is currently active. Useful for grouping ports by chip
   (see §4.4), not for offload state.

### 4.2 Bridge naming — never assume

Known variants already in our own artefacts: `bridge` (lab), `bridge-LAN` (product spec example),
`bridgeLocal` (a form placeholder), plus MikroTik's default `bridge1` and the factory-default `bridge`
on modern RouterOS. Name matching is not a strategy.

**Derive the bridge from the port:**

```python
rows = api.path("interface", "bridge", "port")
match = [r for r in rows if r.get("interface") == port_name]
if not match:
    return Refuse(f"{port_name} is not a member of any bridge")
if len({r["bridge"] for r in match}) > 1:
    return Refuse(f"{port_name} appears in multiple bridge-port rows")   # shouldn't happen; refuse anyway
bridge = match[0]["bridge"]
```

The existing adapter already builds this map correctly at
`vendor/wyfy-device-gateway/wyfy_device_gateway/mikrotik_adapter.py:428` (`bridge_of`). Reuse it; do not
re-derive by name anywhere.

Caveat: a port can be a bridge member **dynamically**, via `/interface list member` + a bridge-port row
whose `interface` is an *interface list name*. Such rows show the list name, and dynamic per-interface
rows carry the `D` flag ([BRSW], *Interface lists*). A lookup keyed on the physical interface name will
find the dynamic row; a lookup that only considers static rows will miss it. Match on all rows,
static and dynamic.

### 4.3 Multiple bridges on one router

- Each bridge has its **own** `vlan-filtering` flag and its **own** VLAN table. VLAN IDs are scoped per
  bridge. Never read the state of one bridge and act on another.
- Every `/interface bridge vlan` query must be filtered `where bridge=<BR>`.
- **Only one hardware-offloaded bridge per switch chip**, except CRS1xx/2xx:
  > "The CRS1xx/2xx series switches support multiple hardware offloaded bridges per switch chip. **All
  > other devices support only one hardware offloaded bridge per switch chip.** Use the `hw=yes/no`
  > parameter to select which bridge will use hardware offloading." — [BRSW] **[DOC]**

  ⇒ Creating a second bridge on a customer router silently de-offloads it. Never create bridges.
- If the requested port and an existing VLAN's ports are on different bridges, refuse — bridging them
  would merge two L2 domains.

### 4.4 Two switch chips, one bridge — a hard trap

> "If you have a device with two or more switch chips and use a single bridge with VLAN filtering
> configured at hardware level, packets from ports on different switch chips are simply dropped because
> these ports are located on different switch chips and the switch chip is not aware of the VLAN table's
> contents on a different switch chip. To solve this issue you must create two separate bridges and
> configure VLAN filtering on each switch chip." — [L2MIS] **[DOC]**

Affects real, common customer hardware: **RB3011** (`QCA8337` ether1-5 + `QCA8337` ether6-10) and
**RB2011** (`Atheros8327` ether1-5+sfp1 + `Atheros8227` ether6-10) — [SCF]. Neither of those chips
offloads VLAN filtering anyway, so on those specific models the trap does not fire; but the rule must be
encoded because it *does* fire on multi-chip devices whose chips do offload.

Detection: group the bridge's ports by `hw-offload-group` from `/interface/bridge/port/monitor`. If a
single bridge spans more than one group **and** the chips are offload-capable ⇒ **refuse**.

(RouterOS 7.20+ mitigates by adding a dynamic `;;; added by switch-cpu` tagged entry when a VID spans
multiple chips or mixes HW and SW ports — [BRSW] **[DOC]** — but do not rely on it for older versions.)

### 4.5 Pre-existing VLAN entries and PVIDs — merge, never clobber

- **Read before every write.** `/interface bridge vlan print detail where bridge=<BR>`.
- **`vlan-ids` may be a list or a range:** `vlan-ids=100-115,120,122,128-130` is one row ([BRSW]). Any
  parser must expand ranges. A requested VID may fall *inside* an existing range row. Splitting a range
  row is error-prone ⇒ **refuse** with "VLAN <n> is already covered by entry <id> (`vlan-ids=<range>`);
  a human must split it" rather than attempting it.
- **Dynamic rows are read-only.** Rows flagged `D` with comments `added by pvid`,
  `added by vlan on bridge`, or `added by switch-cpu` are regenerated by RouterOS. Never `set` or
  `remove` them. If the only row for a VID is dynamic, `add` a static one — RouterOS will reconcile.
  **[NEEDS LIVE TEST]** — confirm the exact reconciliation when a static row and a `added by pvid`
  dynamic row cover the same bridge+VID (which wins for `current-untagged`?). Our lab's own
  `current-tagged='bridge'` reading is evidence the **static row's explicit declaration wins over the
  implicit PVID membership** for the same interface, but confirm before depending on it.
- **Never `add` a second row for an existing bridge+VID.** `set` the existing one with the **union** of
  members. Removing a VLAN must subtract only the members we added, never blank the field.
- **Pre-existing PVIDs.** If `/interface bridge port` for the target port already has
  `pvid != 1` and `pvid != requested`, that port belongs to somebody else's VLAN ⇒ **refuse**.
- **Interface lists in `tagged=` / `untagged=` (RouterOS ≥ 7.17).** Those fields may contain *interface
  list names*, not interfaces:
  > "Starting from RouterOS version 7.17, you can use interface lists for the `tagged` and `untagged`
  > properties in the bridge VLAN table." … "If different interface lists are specified for the `tagged`
  > and `untagged` settings, and there is overlap between the interface members, **the `untagged` list
  > will take priority**." — [BRSW] **[DOC]**

  A naive substring compare against `tagged`/`untagged` will silently miss members. Resolve list names via
  `/interface list member` before deciding membership. Use `tagged`/`untagged` for **writes** and
  `current-tagged`/`current-untagged` for **verification** — they are different fields with different
  semantics, and `current-*` reflects only *running* interfaces.

### 4.6 Routers with no bridge at all

- **Trunk mode** (`/interface vlan` on a routed port): works fine, needs no bridge. Allow.
- **Access mode**: a VLAN access port has no meaning without a VLAN-aware bridge. **Refuse** with
  "port `<x>` is not in a bridge; access-mode VLANs require a bridge". Do **not** create one — creating a
  bridge on a customer router changes the forwarding topology and, per §4.3, can de-offload an existing
  one.
- Note what the current `_configure_vlan_access` does instead (`mikrotik_adapter.py:1130`): it *removes*
  the port from the bridge and puts the subnet directly on it. That is a legitimate physical-separation
  design — and its docstring is honest that it is deliberately not 802.1Q — but it is **not** a VLAN, it
  bypasses the bridge entirely, and it silently rewires the customer's L2. If the new bridge-VLAN path
  supersedes it, the two must not be reachable from the same API call without an explicit mode flag.

### 4.7 RouterOS v6 vs v7 differences that matter here

| Behaviour | v6 | v7 |
|---|---|---|
| `ingress-filtering` default | **`no`** | **`yes`** — "*The setting is enabled by default since RouterOS v7*" [BRSW] **[DOC]**. A v6 config that "worked" can start dropping on upgrade. |
| `/interface bridge vlan` | since 6.41 (before: `master-port`) | present |
| `frame-types`, `ether-type`, 802.1ad | since 6.43 | present |
| HW-offloaded VLAN filtering | Marvell Prestera only | + RTL8367, MT7621, MT7531, EN7523 (7.1); + 88E6393X/6191X/6190 |
| Auto tagged entry for a bridge VLAN sub-interface | no — add `tagged=<bridge>` yourself | **since 7.16**, dynamic `added by vlan on bridge` [BRSW] **[DOC]** |
| Interface lists in `tagged=`/`untagged=` | no | **since 7.17** [BRSW] **[DOC]** |
| `added by switch-cpu` dynamic entry | no | **since 7.20** [BRSW] **[DOC]** |
| `/interface vxlan`, `/interface wireguard`, containers/`veth` | absent | present (veth still arch-gated) |
| Wireless menu | `/interface wireless` | `/interface wifi` (new driver) or `wireless` (legacy pkg) |
| Downgrade | — | offload config is **not** converted back below 6.41 [BRSW] |

Gate every version-dependent behaviour on `/system resource get version`. Parse it as a tuple; do not
string-compare.

### 4.8 Anything else that makes a blind "enable vlan-filtering" unsafe

1. **Switch-chip reset / link bounce** on the transition ([BRSW], quoted §1.6). Every Ethernet port on
   the chip goes down briefly. If management crosses the bridge, you are gone. **Always verify the
   management path is off-bridge, and always arm an auto-revert.**
2. **The default VLAN 1 trap** — the shape that broke us. Covered by §1.8.
3. **Services bound to `interface=bridge`** (DHCP server, hotspot, PPPoE server, DNS, queues, firewall
   rules). They keep `invalid=false` while serving nothing. Enumerate them and treat each as a thing that
   must still be an untagged VLAN member afterwards.
4. **Dynamically added bridge ports** whose `pvid` you never set: CAPsMAN/`wifi` datapath ports, VPN
   interfaces, interface-list members. They land on `pvid=1` and become untagged VLAN-1 members whether
   you meant it or not.
5. **`use-ip-firewall` / `use-ip-firewall-for-vlan`** under `/interface bridge settings` — "*Direct
   bridged VLAN tagged traffic to IP/IPv6 firewall. This property only has an effect when
   `vlan-filtering`…*" [BRSW]. Firewall rules can start or stop applying when filtering is enabled.
6. **L2MTU**: "*The L2MTU value will be automatically set by the bridge and it will use the lowest L2MTU
   value of any associated bridge port*" [BRSW]. Adding an EoIP/VXLAN port can lower the bridge's l2mtu
   and break 1500-byte tagged frames. Require `l2mtu >= 1504` on every member before enabling.
7. **DHCP snooping** — "*The feature will not work properly in VLAN switching setups*" for several chips
   ([BRSW] footnotes 7/8). If the customer has it on, enabling VLAN filtering may break it.
8. **Security**: "*When allowing access to the CPU, you are allowing access from a certain port to the
   actual router/switch […] Make sure you implement proper firewall filter rules*" and "*Improperly
   configured bridge VLAN filtering can cause security issues*" — [BRSW] **[DOC]**. A guest VLAN that is
   an untagged member of the management VLAN is a guest-to-router-console path.
9. **Host-table size** on cheap chips ([SCF] discusses per-chip limits and eviction policy). A busy guest
   LAN with IVL consumes entries per MAC *per VLAN*.
10. **STP interaction**: enabling filtering does not change `protocol-mode`, but MSTP *requires* it, and
    RSTP topology can change when ports gain VLAN membership.

---

## 5. Deliverable 5 — safe, generic provisioning algorithm

Design contracts:

- **C1** Never enable `vlan-filtering` as a side effect of creating a VLAN. Enabling it is a separate,
  explicitly-requested, separately-approved operation with its own pre-flight and its own rollback.
- **C2** Idempotent. Re-running with the same request is a no-op and returns success.
- **C3** Merge, never clobber. Every write is read-modify-write on a union.
- **C4** Degrade honestly. Refuse with a customer-actionable reason. Never guess a bridge, never create a
  bridge, never split a range, never move an L3 binding implicitly.
- **C5** Every refusal carries a stable machine code plus human text, so the dashboard can render it.

```python
# ---------------------------------------------------------------- capabilities

OFFLOAD_VLAN_FILTERING = {                      # normalised chip ids, from [BRSW] matrix
    "marvell-prestera", "88E6393X", "88E6191X", "88E6190",
    "MT7621", "MT7531", "EN7523", "RTL8367",
}

def normalise_chip(t):                          # "Atheros-8227" -> "Atheros8227"
    return t.replace("-", "").strip()

def probe(api):
    ver   = parse_version(api.get("/system/resource")["version"])       # (7, 23, 3)
    model = api.get("/system/routerboard").get("model", "unknown")
    chips = [normalise_chip(r["type"]) for r in api.path("interface","ethernet","switch")]
    return Device(version=ver, model=model, chips=chips,
                  offloads_vlan_filtering=any(c in OFFLOAD_VLAN_FILTERING for c in chips),
                  has_switch_chip=bool(chips))

# ---------------------------------------------------------------- topology read

def read_topology(api, port):
    ports = list(api.path("interface","bridge","port"))          # static AND dynamic rows
    rows  = [p for p in ports if p.get("interface") == port]
    if not rows:
        return None                                              # port is not bridged
    bridges = {p["bridge"] for p in rows}
    if len(bridges) != 1:
        raise Refuse("BRIDGE_AMBIGUOUS", f"{port} maps to bridges {sorted(bridges)}")
    br_name = bridges.pop()
    br      = one(api.path("interface","bridge"), name=br_name)
    return Topology(
        bridge          = br_name,
        vlan_filtering  = br["vlan-filtering"] == "true",
        bridge_pvid     = int(br.get("pvid", 1)),
        bridge_frame    = br.get("frame-types", "admit-all"),
        port_row        = rows[0],
        port_pvid       = int(rows[0].get("pvid", 1)),
        members         = [p for p in ports if p["bridge"] == br_name],
        vlan_rows       = [v for v in api.path("interface","bridge","vlan")
                             if v["bridge"] == br_name],
        vlan_ifaces     = [v for v in api.path("interface","vlan")],
        addresses       = list(api.path("ip","address")),
        dhcp_servers    = list(api.path("ip","dhcp-server")),
        hotspots        = list(api.path("ip","hotspot")),
        lists           = resolve_interface_lists(api),          # name -> {members}
    )

# ---------------------------------------------------------------- VLAN-table helpers

def expand(vlan_ids: str) -> set[int]:
    """'1' | '100-115,120' -> {…}. Ranges MUST be expanded, never string-matched."""
    out = set()
    for part in vlan_ids.split(","):
        if "-" in part:
            a, b = part.split("-", 1); out |= set(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out

def find_vlan_row(topo, vid):
    hits = [r for r in topo.vlan_rows if vid in expand(r["vlan-ids"])]
    if not hits:
        return None
    if len(hits) > 1:
        raise Refuse("VLAN_ROW_DUPLICATE",
                     f"VLAN {vid} appears in {len(hits)} entries on {topo.bridge}; "
                     "a human must consolidate them")
    row = hits[0]
    if row.get("dynamic") == "true":
        return ("dynamic", row)
    if expand(row["vlan-ids"]) != {vid}:
        raise Refuse("VLAN_ROW_IS_RANGE",
                     f"VLAN {vid} is inside ranged entry '{row['vlan-ids']}' on {topo.bridge}; "
                     "splitting a range is not automated -- edit it manually first")
    return ("static", row)

def members_of(field: str, lists) -> set[str]:
    """tagged=/untagged= may name interface LISTS since v7.17. Resolve them."""
    out = set()
    for token in (t for t in (field or "").split(",") if t):
        out |= lists.get(token, {token})
    return out

# ---------------------------------------------------------------- the two operations

def configure_vlan_access(api, req):                       # req: port, vid, cidr?, want_l3
    dev  = probe(api)
    topo = read_topology(api, req.port)

    # ---- refusals, cheapest first ----------------------------------------
    if topo is None:
        raise Refuse("PORT_NOT_BRIDGED",
                     f"{req.port} is not a member of any bridge. Access-mode VLANs need a "
                     "VLAN-aware bridge; we will not create one for you.")
    if req.port in wan_interfaces(api) or has_dhcp_client(api, req.port):
        raise Refuse("PORT_IS_WAN", f"{req.port} looks like an uplink; refusing.")
    if is_management_path(api, req.port):
        raise Refuse("PORT_IS_MGMT", f"{req.port} carries this management session.")
    if not (1 <= req.vid <= 4094):
        raise Refuse("VID_OUT_OF_RANGE", ...)
    if req.vid == topo.bridge_pvid:
        raise Refuse("VID_IS_NATIVE",
                     f"VLAN {req.vid} is the bridge's own PVID (the untagged/native LAN). "
                     "Pick a different VLAN ID.")
    if topo.port_pvid not in (1, req.vid):
        raise Refuse("PORT_PVID_IN_USE",
                     f"{req.port} already has pvid={topo.port_pvid}; it belongs to another VLAN.")
    if spans_multiple_switch_chips(api, topo) and dev.offloads_vlan_filtering:
        raise Refuse("BRIDGE_SPANS_CHIPS",
                     f"{topo.bridge} spans more than one switch chip; MikroTik requires one "
                     "bridge per chip for hardware VLAN filtering.")
    if min_l2mtu(topo.members) < 1504:
        raise Refuse("L2MTU_TOO_SMALL",
                     f"lowest member l2mtu is {min_l2mtu(topo.members)}; tagged frames need >= 1504.")

    # ---- writes: idempotent, merging ------------------------------------
    # 1. port
    if topo.port_pvid != req.vid or topo.port_row.get("frame-types") != ACCESS_FRAMES:
        api.path("interface","bridge","port").update(
            **{".id": topo.port_row[".id"], "pvid": str(req.vid),
               "frame-types": ACCESS_FRAMES, "ingress-filtering": "yes"})

    # 2. bridge VLAN row: UNION, never replace
    found = find_vlan_row(topo, req.vid)
    tagged   = set()
    untagged = {req.port}
    if req.want_l3:
        # the bridge is TAGGED here because the L3 lives on a /interface vlan sub-interface
        if dev.version < (7, 16):
            tagged.add(topo.bridge)          # >= 7.16 RouterOS adds it dynamically
    if found is None:
        api.path("interface","bridge","vlan").add(
            bridge=topo.bridge, **{"vlan-ids": str(req.vid)},
            untagged=",".join(sorted(untagged)),
            **({"tagged": ",".join(sorted(tagged))} if tagged else {}))
    else:
        kind, row = found
        if kind == "dynamic":
            api.path("interface","bridge","vlan").add(...)        # promote to a static row
        else:
            new_u = members_of(row.get("untagged"), topo.lists) | untagged
            new_t = members_of(row.get("tagged"),   topo.lists) | tagged
            if new_u != members_of(row.get("untagged"), topo.lists) or \
               new_t != members_of(row.get("tagged"), topo.lists):
                api.path("interface","bridge","vlan").update(
                    **{".id": row[".id"],
                       "untagged": ",".join(sorted(new_u)),
                       "tagged":   ",".join(sorted(new_t))})

    # 3. optional L3 for this VLAN -- ALWAYS on a sub-interface, never on the bridge
    if req.want_l3:
        ifname = f"vlan{req.vid}"
        if not exists(topo.vlan_ifaces, name=ifname):
            api.path("interface","vlan").add(name=ifname, interface=topo.bridge,
                                             **{"vlan-id": str(req.vid)})
        ensure_ip_address(api, req.cidr, ifname)

    # 4. C1: DO NOT touch vlan-filtering here.
    if not topo.vlan_filtering:
        return Result(state="STAGED",
                      message=(f"VLAN {req.vid} is written into {topo.bridge}'s VLAN table but "
                               f"{topo.bridge} has vlan-filtering=no, so it is not yet enforcing. "
                               "Run the separate 'enable VLAN filtering' operation to activate it."))
    return Result(state="ACTIVE")


def enable_vlan_filtering(api, bridge_name, *, accept_offload_loss=False):
    dev  = probe(api)
    br   = one(api.path("interface","bridge"), name=bridge_name)
    if br["vlan-filtering"] == "true":
        return Result(state="ALREADY_ENABLED")                    # C2

    topo = read_bridge(api, bridge_name)

    # --- R1: management must not cross this bridge -------------------------
    if management_path_crosses(api, bridge_name):
        raise Refuse("MGMT_ON_BRIDGE",
                     f"this session reaches the router through {bridge_name}. Enabling VLAN "
                     "filtering resets the switch chip and bounces every port. Reconnect over an "
                     "out-of-band path (WAN/WireGuard) first.")

    # --- R2: the native VLAN must survive ---------------------------------
    # THIS IS THE CHECK THAT WOULD HAVE CAUGHT THE 2026-09 LAB OUTAGE.
    native = topo.bridge_pvid
    l3_on_bridge = [a for a in topo.addresses if a["interface"] == bridge_name]
    if l3_on_bridge:
        row = find_vlan_row(topo, native)
        if row is None:
            pass    # fine: RouterOS will create ";;; added by pvid" with the bridge untagged
        else:
            kind, r = row
            tagged   = members_of(r.get("tagged"),   topo.lists)
            untagged = members_of(r.get("untagged"), topo.lists)
            if bridge_name in tagged:
                raise Refuse("NATIVE_BRIDGE_TAGGED",
                    f"{bridge_name} carries {l3_on_bridge[0]['address']} directly and is listed as a "
                    f"TAGGED member of its own native VLAN {native}. Tagged frames would reach the "
                    f"router's IP stack with no /interface vlan vlan-id={native} to receive them, and "
                    f"DHCP/hotspot on {bridge_name} would stop answering. Change that entry to "
                    f"untagged={bridge_name},... or move the L3 onto a VLAN sub-interface.")
            if bridge_name not in untagged and kind == "static":
                raise Refuse("NATIVE_BRIDGE_ABSENT",
                    f"{bridge_name} carries {l3_on_bridge[0]['address']} but is in neither the tagged "
                    f"nor untagged list of VLAN {native}. Add untagged={bridge_name}.")

    # --- R3: every VLAN that has a bridge sub-interface must have the bridge TAGGED
    for vif in topo.vlan_ifaces:
        if vif["interface"] != bridge_name:
            continue
        vid = int(vif["vlan-id"])
        row = find_vlan_row(topo, vid)
        if dev.version < (7, 16):
            if row is None or bridge_name not in members_of(row[1].get("tagged"), topo.lists):
                raise Refuse("SUBIF_BRIDGE_NOT_TAGGED",
                    f"{vif['name']} routes VLAN {vid} off {bridge_name}, but {bridge_name} is not a "
                    f"tagged member of VLAN {vid}. On RouterOS < 7.16 you must add it explicitly.")

    # --- R4: services bound to the bridge must be on the native untagged VLAN
    bound = [s for s in topo.dhcp_servers + topo.hotspots if s.get("interface") == bridge_name]
    if bound and not l3_on_bridge:
        raise Refuse("SERVICE_WITHOUT_L3",
                     f"{[s['name'] for s in bound]} are bound to {bridge_name} which holds no address.")

    # --- R5: offload loss must be an explicit, informed decision -----------
    if dev.has_switch_chip and not dev.offloads_vlan_filtering and not accept_offload_loss:
        raise Refuse("OFFLOAD_WILL_BE_LOST",
            f"{dev.model} uses {dev.chips}, which cannot hardware-offload bridge VLAN filtering. "
            "Enabling it moves all LAN switching to the CPU and will reduce client-to-client "
            "throughput on this model. Re-run with accept_offload_loss=true to proceed.")

    # --- R6: ports with no explicit pvid will silently join the native VLAN
    strays = [p for p in topo.members if "pvid" not in p and p["interface"] not in known_ports]
    if strays:
        warn("UNPINNED_PORTS", [p["interface"] for p in strays])   # warn, do not refuse

    # --- arm rollback, flip, verify, disarm -------------------------------
    arm_rollback(api, bridge_name, minutes=3)
    baseline = snapshot(api, bridge_name)          # host count, arp count, lease count
    api.path("interface","bridge").update(**{".id": br[".id"], "vlan-filtering": "yes"})

    settle(seconds=30)                             # switch-chip reset + link renegotiation
    ok, why = verify(api, bridge_name, baseline)
    if not ok:
        api.path("interface","bridge").update(**{".id": br[".id"], "vlan-filtering": "no"})
        disarm_rollback(api, bridge_name)
        raise Refuse("VERIFY_FAILED", why)         # rolled back already
    disarm_rollback(api, bridge_name)
    return Result(state="ENABLED")


def verify(api, bridge_name, baseline):
    topo = read_bridge(api, bridge_name)

    # V1 -- control plane. Runnable pre-enable too. The check we did not run.
    if [a for a in topo.addresses if a["interface"] == bridge_name]:
        row = find_vlan_row(topo, topo.bridge_pvid)
        if row and bridge_name in members_of(row[1].get("current-tagged"), topo.lists):
            return False, f"{bridge_name} is a TAGGED member of its own native VLAN"
        if row and bridge_name not in members_of(row[1].get("current-untagged"), topo.lists):
            return False, f"{bridge_name} is not an untagged member of its own native VLAN"

    # V2 -- data plane. Meaningless on an idle LAN; require a live client.
    hosts = [h for h in api.path("interface","bridge","host")
             if h["bridge"] == bridge_name and h.get("local") != "true"]
    if baseline.hosts > 0 and len(hosts) == 0:
        return False, ("bridge host table lost every non-local MAC: L2 learning or forwarding "
                       "is broken")
    arp = [a for a in api.path("ip","arp") if a["interface"] == bridge_name and a.get("dynamic")]
    if baseline.arp > 0 and len(arp) == 0:
        return False, "ARP table on the bridge went empty"
    if baseline.probe_ip and not ping(api, baseline.probe_ip, interface=bridge_name):
        return False, f"cannot reach known client {baseline.probe_ip} through {bridge_name}"
    leases = [l for l in api.path("ip","dhcp-server","lease") if l.get("status") == "bound"]
    if baseline.leases > 0 and len(leases) == 0:
        return False, "all DHCP leases disappeared"

    # DELIBERATELY NOT USED as success criteria: invalid=false on dhcp-server/hotspot,
    # and "addresses still present". Both were true throughout the 2026-09 outage.
    return True, ""
```

### 5.1 Refusal codes the dashboard must be able to render

| Code | Customer-facing meaning |
|---|---|
| `PORT_NOT_BRIDGED` | That port isn't part of a LAN switch group on this router. |
| `PORT_IS_WAN` / `PORT_IS_MGMT` | That port is the internet uplink / carries our management link. |
| `BRIDGE_AMBIGUOUS` | This router's LAN configuration is unusual; needs a manual look. |
| `VID_IS_NATIVE` | VLAN <n> is already this router's main LAN. |
| `PORT_PVID_IN_USE` | That port already belongs to VLAN <m>. |
| `VLAN_ROW_IS_RANGE` / `VLAN_ROW_DUPLICATE` | Existing VLAN config on this router needs tidying first. |
| `BRIDGE_SPANS_CHIPS` | This router model needs one LAN group per switch chip. |
| `L2MTU_TOO_SMALL` | A port on this router can't carry tagged frames at full size. |
| `MGMT_ON_BRIDGE` | We'd lose our management link; needs an out-of-band path. |
| `NATIVE_BRIDGE_TAGGED` / `NATIVE_BRIDGE_ABSENT` | The main LAN would stop working; config must be corrected first. |
| `SUBIF_BRIDGE_NOT_TAGGED` | A routed VLAN on this router is missing its uplink to the router itself. |
| `OFFLOAD_WILL_BE_LOST` | This router model will switch traffic in software; confirm you accept the speed cost. |
| `VERIFY_FAILED` | We enabled it, it broke traffic, we rolled it back. Nothing changed. |

---

## 6. Cross-references to our code

| Location | Note |
|---|---|
| `vendor/wyfy-device-gateway/wyfy_device_gateway/mikrotik_adapter.py:419-457` | Already builds `bridge_of: {interface -> bridge}` correctly. Reuse for §4.2; do not derive the bridge by name anywhere else. |
| `…/mikrotik_adapter.py:1112` `_configure_vlan_trunk` | Creates `/interface vlan` + address on a parent trunk. Safe, bridge-untouched. Unchanged by this document, except: if `vlan.interface` names the **bridge**, RouterOS ≥ 7.16 will auto-add the `added by vlan on bridge` tagged entry only when filtering is already on — on < 7.16, or with filtering off, nothing links it to the VLAN table. |
| `…/mikrotik_adapter.py:1130` `_configure_vlan_access` | Removes the port from the bridge and addresses it directly. Physical separation, **not** 802.1Q. See §4.6 — must not be reachable from the same call as a real bridge-VLAN access port without an explicit mode. |
| `…/mikrotik_adapter.py:1214` `_delete_vlan_access` | Leaves the port unbridged by design because the original bridge was never recorded. Under the bridge-VLAN design, the bridge **is** recoverable (`bridge_of`), so a real teardown becomes possible: reset `pvid=1 frame-types=admit-all` and subtract the port from the VLAN row's `untagged` (never blank the field — §4.5). |
| `app/domains/network_config/renderers.py:851` `render_vlan` | Same two branches; same notes. |
| `app/domains/network_config/renderers.py:810` `_render_vlan_hotspot` | Binds pool/dhcp-server/hotspot to `bind_interface`. Under §2.4's migration those bindings are exactly what must move. Keeping the hotspot on a `vlanN` sub-interface (rather than the bridge) is the shape that composes cleanly with VLAN filtering. |

---

## 7. What could not be verified without hardware

All of these are marked **[NEEDS LIVE TEST]** inline; collected here as a bench checklist.

1. **§1.7** Whether the empty bridge host table was aging/reset (mechanism 1) or a genuine ingress drop
   (mechanism 2). Test: reproduce the broken config with a client actively retrying DHCP; sniff `ether2`
   *and* `bridge`; check whether DISCOVERs surface on the CPU **with** a VLAN tag. This is the one
   observation that closes the case.
2. **§2.1** That `/system scheduler` with `interval=3m` and no `start-time` fires 3 minutes after
   creation, and survives the switch-chip reset.
3. **§2.3 V1** Whether `current-tagged` / `current-untagged` are populated while `vlan-filtering=no`.
   Determines whether the decisive check can run *before* the flip or only after.
4. **§2.4** Whether `/ip hotspot set <id> interface=` is accepted on a running server, or requires
   remove+re-add. Sizes the migration outage.
5. **§4.1** The exact **API** field name for the `H` (hw-offload) state on `/interface/bridge/port`
   (candidate `hw-offload`, distinct from the `hw` request field). Until confirmed, gate on chip type.
6. **§4.1** Measured client-to-client throughput on a non-offloading model with `vlan-filtering` off vs
   on. Needed to calibrate the `OFFLOAD_WILL_BE_LOST` threshold with a real number instead of a warning.
7. **§4.5** Reconciliation when a static `/interface bridge vlan` row and a dynamic `added by pvid` row
   cover the same bridge+VID. Our lab's `current-tagged='bridge'` is strong evidence the static
   declaration wins, but confirm.
8. **§3.4** That `/interface wireguard` genuinely cannot be a bridge port (high confidence — it is a pure
   L3 tunnel — but the menu exists on this box and a capability probe should not assume).
9. **§3.3** Real access-port traffic behaviour on a physical port with a live client. The VXLAN result is
   a control-plane test only.
