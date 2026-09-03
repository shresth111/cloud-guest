# Delivering a dashboard-created VLAN to the access point, tagged

The requirement, in the customer's own words: create a VLAN from the portal,
have it reach the access point **tagged** over the cable that is already
there, with a **with / without captive portal** option, and have the IP pool,
DHCP server, gateway and DNS all created for it — and the same for a trunk
port.

This document is the design for the one piece that does not exist. It is
written against the lab router and says explicitly which claims are observed,
which are documented, and which are neither.

## What already exists, and what the customer hit instead

| Requirement | Status |
|---|---|
| A VLAN that consumes no new physical port | **Exists** — `port_mode="trunk"` creates `/interface vlan vlan<tag>` on a parent |
| Captive portal on/off per VLAN | **Exists** — `Vlan.enable_hotspot` |
| Pool + DHCP + gateway + DNS created automatically | **Exists** — `configure_vlan_hotspot` writes `/ip pool`, `/ip dhcp-server`, its network row, the hotspot profile and the hotspot server |
| Internet for that VLAN | **Exists** — `Vlan.nat_enabled` writes the masquerade |
| **The tag reaching the AP's port** | **Nothing in the platform writes it** — whether anything *needs* to is the open question below |

The customer chose `port_mode="access"` because their access point is on that
port and "access" read as the matching word. Access mode does the opposite of
what they wanted: it pulls the physical port out of the bridge and gives it
the subnet untagged, which cut the AP off from the guest network. In RouterOS
terms the port they want is a **trunk** port — it carries tagged VLANs — and
"access port" means the single-untagged-network case. That naming collision is
the whole incident, and it is a product problem, not a user error.

Their VLAN also created no IP pool because nothing does in that combination:
`access` + `enable_hotspot=false` writes an interface and an address and
stops. `trunk` + `enable_hotspot=true` writes the whole set.

## What the platform does and does not write

`grep` over `wyfy_device_gateway/mikrotik_adapter.py` finds **no occurrence of
`vlan-filtering` and none of `tagged=`**. `_configure_vlan_trunk` creates the
sub-interface and the address; nothing ever tells the bridge which ports carry
that tag. Whether that is a gap or simply unnecessary depends on the open
question below.

Read off the lab router (`rcjgfc`, 10.20.0.14, RouterOS 7.23.3):

```
/interface bridge        name=bridge  vlan-filtering=False  protocol-mode=rstp
/interface bridge vlan   bridge=bridge  vlan-ids=100  tagged='bridge'  untagged=''
/interface ethernet switch  name=switch1  type=Atheros-8227
/interface bridge port   ether2 (inactive=False)  ether3/4/5 (inactive=True)  all pvid=1
/ip hotspot              hotspot1 -> interface=bridge  profile=hsprof1
/ip dhcp-server          hotspot-dhcp -> interface=bridge  pool=hotspot-pool
/ip pool                 hotspot-pool  10.5.50.10-10.5.50.254
```

Two things in that read matter.

**`vlan-filtering=False`.** MikroTik documents this as the bridge ignoring
VLAN tags and working in shared-VLAN-learning (SVL) mode, unable to modify
tags.

**What that does NOT settle, and an earlier draft of this document wrongly
claimed it did:** whether a `/interface vlan` created *on top of* the bridge
still receives frames tagged with its VID when filtering is off. "The bridge
does not do VLAN-aware forwarding" and "a VLAN interface on the bridge cannot
receive tagged frames" are different statements, and MikroTik's Bridging and
Switching page states only the first
[DOC — [Bridging and Switching](https://help.mikrotik.com/docs/spaces/ROS/pages/328068/Bridging+and+Switching); checked, and it does not address the second].

This is the single question that decides the whole architecture:

* **If a VLAN interface on the bridge does receive tagged frames** with
  filtering off, then the platform needs no bridge changes at all. Trunk mode
  already creates that interface, `enable_hotspot` already gives it a pool, a
  DHCP server and a portal, and the only remaining work is on the access
  point. No `vlan-filtering`, no switch-chip reset, no risk to the live guest
  network. What is lost is isolation: with no ingress filtering, tagged frames
  flood to every bridge port and any port could inject any VID.
* **If it does not**, bridge VLAN filtering is required, and the sequence
  below applies with all of its risk.

It is cheap to find out and it has not been done: put one SSID on VLAN 900 at
the access point, then read `rx-packet`/`rx-byte` on the `vlan900` interface.
Non-zero counters answer it without needing a client to complete DHCP — the
AP's own broadcast traffic is enough.

**There is already a stale entry for `vlan-ids=100`, tagged on `bridge` only.**
`ether2` is not in its tagged list. So even with filtering enabled, VLAN 100
would not reach the AP. That entry is left over and should be removed as part
of any change.

## The sequence

`ether2` must end up carrying the existing guest network **untagged** (so the
current SSID keeps working) and the new VLAN **tagged** (so the AP can map it
to a second SSID). Order matters: every membership row goes in *before*
filtering is switched on, so the bridge never runs a moment with filtering
active and an incomplete table.

```python
# 1. The L3 endpoint. Virtual: no new physical port. This is what the
#    platform's trunk mode already writes today.
api.path("interface", "vlan").add(
    name="vlan900", **{"vlan-id": "900"}, interface="bridge", comment="<vlan name>")
api.path("ip", "address").add(address="10.90.0.1/24", interface="vlan900")

# 2. The NATIVE vlan, declared explicitly. The guest subnet 10.5.50.0/24 is
#    on the `bridge` interface itself, so for VLAN 1 the bridge is UNTAGGED,
#    not tagged. Getting this backwards is what took the guest LAN down
#    earlier in this project: `vlan-ids=1 tagged=bridge` makes the bridge
#    expect tagged frames for the network its own IP serves untagged.
api.path("interface", "bridge", "vlan").add(
    bridge="bridge", **{"vlan-ids": "1",
                        "untagged": "bridge,ether2,ether3,ether4,ether5"})

# 3. The new VLAN. `bridge` tagged so vlan900 receives it; `ether2` tagged so
#    the AP does.
api.path("interface", "bridge", "vlan").add(
    bridge="bridge", **{"vlan-ids": "900", "tagged": "bridge,ether2"})

# 4. Last, and only last.
api.path("interface", "bridge").update(
    **{".id": bridge_id, "vlan-filtering": "yes"})
```

`pvid=1` on every port is already correct and needs no change — it is what
makes untagged ingress land in VLAN 1. Leave `frame-types` at `admit-all` and
`ingress-filtering=no` for the first pass: tightening them is a separate,
later change, and doing both at once makes a failure impossible to attribute.

Then the portal half is the platform's existing work, unchanged: with
`enable_hotspot=true` on the VLAN row, `configure_vlan_hotspot` writes the
pool, the DHCP server and its network row, the hotspot profile and the hotspot
server on `vlan900`; with it false the VLAN is a plain routed network and the
customer creates a pool on the IP Addresses page. `nat_enabled` gives it
internet.

## What each step does to live traffic

Steps 1–3 are additive and inert: with `vlan-filtering=False` the bridge is
not consulting the VLAN table at all, so rows can be added freely.

**Step 4 is the one that hurts.** `switch1` is an **Atheros-8227**, which
cannot hardware-offload VLAN filtering. Enabling it forces the bridge onto the
CPU path and resets the switch chip, and **every Ethernet port bounces** —
including `ether1`. Management runs over `wg-cloudguard`, whose transport is
`ether1`, and `ether1` is *not* a bridge port, so the tunnel is not
structurally broken by the bridge change; but it rides a port that bounces, so
expect the API session to drop and return. Plan for losing the connection
mid-step rather than being surprised by it.

## Rollback

```python
api.path("interface", "bridge").update(**{".id": bridge_id, "vlan-filtering": "no"})
# then remove the rows added in steps 2 and 3, then the vlan900 address and
# interface if the VLAN is being abandoned entirely.
```

Turning filtering off first is the whole rollback: it returns the bridge to
ignoring tags, which is the state the guest network is known to work in. The
rows can be cleaned up afterwards at no risk.

## Not verified — do not present any of this as proven

1. **That the AP tags at all.** The whole design assumes the access point can
   map an SSID to VLAN 900 and emit tagged frames on its uplink. Its config is
   not visible from the platform. If it cannot tag, no bridge configuration
   helps and the answer is different (see below).
2. **The data plane.** Whether a client on the tagged SSID actually receives a
   lease from `vlan900`'s DHCP server has never been observed on this
   hardware. It needs a real client behind `ether2`, which is the same blocker
   as device tests T3/T4/T7.
3. **The exact bounce behaviour** of enabling `vlan-filtering` on this box.
   The offload limitation is documented for this chip and the port bounce is
   the expected consequence; the duration is not measured.
4. **Whether the tunnel survives.** Reasoned above from `ether1` not being a
   bridge port. Not tested.

## If the AP cannot tag

Then multiple isolated networks over one cable is not achievable, and saying
otherwise would be false. The honest alternatives are one network with
per-user policy rather than per-SSID VLANs: hotspot user profiles for
different rate limits and session rules, plus client isolation. That is a
different product answer, not a worse implementation of this one.
