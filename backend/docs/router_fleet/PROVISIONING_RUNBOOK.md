# Router Fleet Provisioning Runbook (Wave 1)

Operator guide for provisioning a **new** MikroTik router through the Master Console
wizard. Assumes the router record already exists in CloudGuest (organization → location
→ router) and the venue is **not** one of the legacy live sites already serving guests
via the old `cloudguest-*` script flow — see
[`LIVE_VENUE_ADOPTION.md`](./LIVE_VENUE_ADOPTION.md) for those.

---

## 0. Prerequisites

| Requirement | Why |
|---|---|
| Master Console access with `routers.manage` | Discovery, WAN apply, plan build/approve/apply |
| Router reachable on its management path **or** ready for bootstrap | Until WireGuard + API user exist, the platform cannot push config |
| Correct `Router.vendor` = `mikrotik` | Other vendors show "not yet supported" in the fleet UI |
| ISP links configured (or ready to configure in wizard step 3) | WAN apply reads `isp_links` rows (physical/routing split, PPPoE creds) |

**Transport of record after bootstrap:** backend → vendored `wyfy-device-gateway`
(`librouteros` API + `asyncssh` for file push) over the **WireGuard tunnel**. The
`router_agent` pull path remains for day-2 config and heartbeats and is not replaced
by Wave 1.

---

## 1. Bootstrap (irreducible manual step)

A factory-fresh router has **no tunnel and no API user**. The platform cannot discover
or push until bootstrap completes.

1. Open **Router Fleet** → select the router → **Advanced setup script** (or use the
   legacy script panel if the wizard offers a bootstrap chunk).
2. Generate and paste/run the **short bootstrap script** on the device (API user +
   WireGuard peer + heartbeat scheduler — typically ~20 lines). This is the only step
   that intentionally exposes credentials to a human operator.
3. Confirm the router checks in: status moves from **Awaiting check-in** toward
   **online**; WireGuard tunnel shows healthy on the full router screen
   (`/routers/$routerId`).

Do **not** paste the full legacy 1-shot guest script for new deployments — use the
wizard for everything after bootstrap.

---

## 2. Open the provisioning wizard

**Router Fleet** → row action **Wizard** → `/master/routers/setup/$routerId`.

The wizard has **12 steps**. Status badges use `PASS` / `WARNING` / `ERROR` /
`BLOCKED` / `PENDING`. A `BLOCKED` or failed gate stops forward progress until resolved.

| Step | Name | What happens |
|------|------|----------------|
| 1 | **Discover** | `POST /routers/{id}/discover` — read-only RouterOS sweep via `ReadOnlyDeviceReader`; persists sanitized `router_snapshots` row |
| 2 | **Compatibility** | Model/firmware/memory checks against compatibility matrix (`GET /compatibility` or bundled in discover response) |
| 3 | **WAN input** | Technician sets ISP link modes (DHCP/static/PPPoE), physical interfaces, optional DNS override |
| 4 | **WAN apply** | Preview + push basic WAN profile (`GET/POST .../wan/basic/preview|apply`) |
| 5 | **WAN verify** | `POST .../verify/wan` — per-link checks; **hard gate** (`gate_passes`) must be true before guest planning |
| 6 | **Topology review** | Human review of bridges, WAN-in-bridge findings, addressing from snapshot (recommendations only — no device writes) |
| 7 | **Guest input** | Select guest ports/VLAN intent; `GET .../guest/interfaces/availability` |
| 8 | **Conflict review** | `POST .../plans` — rule engine output; subnet overlaps → `BLOCKED` |
| 9 | **Plan approval** | Review human-readable actions; approve plan |
| 10 | **Apply** | `prepare` → `render` → `apply` — gateway push + job polling |
| 11 | **Final verify** | `POST .../plans/{id}/verify/final` → `ROUTER_ONLINE` / `PARTIAL` / `FAILED` |
| 12 | **Fleet online** | Checklist summary; return to fleet |

---

## 3. Step-by-step operator notes

### 3.1 Discover (read-only)

- Uses **`ReadOnlyDeviceReader`** (vendored gateway) — structurally incapable of
  writing to the device; secrets stripped before persistence.
- If discovery returns `partial` or `failed`, read `error_detail` on the snapshot and
  fix connectivity (tunnel down, API disabled, wrong credentials) before retrying.
- Snapshots are append-only history; latest snapshot drives compatibility and planning.

### 3.2 Compatibility

- **ERROR** or **BLOCKED** overall → do not continue without hardware upgrade or
  exception approval.
- **WARNING** → document and proceed only if acceptable (e.g. low memory headroom).

### 3.3 WAN input & apply

- **Physical vs routing interface:** for PPPoE, physical = `etherN`, routing =
  `pppoe-wan{slot}` (derived — never typed manually).
- PPPoE passwords are write-only at the API; never appear in snapshots or wizard UI
  after save.
- **WAN apply** pushes server-rendered profiles (ported from the legacy client generator
  chunk bodies) — not browser-built script text.
- After apply, re-run discovery if you need a fresh snapshot of addressing (optional).

### 3.4 WAN verify (hard gate)

Checks typically include link up, address acquired, gateway ping, DNS resolve, backend
reachability. **`gate_passes: false`** blocks guest/plan steps (rule R8).

Use `GET /routers/{id}/verify/wan/gate` to re-check without re-running full verify.

### 3.5 Topology review

Surface-only step: WAN inside a bridge, existing hotspot/DHCP, bridge inventory.
The planner may recommend removing a bridge port from WAN — that lands in the plan as
an action requiring explicit approval, never auto-applied silently.

### 3.6 Guest input → plan build

- Pick interfaces the availability endpoint marks suitable.
- VLAN mode: engine enforces **one parent bridge** (Rule R5); WAN ports must not be
  parent-bridge members.
- **Conflict review:** CIDR overlap with snapshot or desired state → plan status
  **BLOCKED** (Rule R6) — fix subnets before approval.

### 3.7 Plan approval → apply

1. **Approve** — records approver; plan must be in approvable state.
2. **Render** — compiles approved plan → draft `config_versions` row (secret
   placeholders, not plaintext secrets in stored content for new rows).
3. **Prepare** — pre-apply backup marker (`is_backup=True` version).
4. **Apply** — gateway push via existing apply pipeline; poll provision job if shown.

**Management-connectivity risk (R10):** actions touching WireGuard path, active default
route interface, or firewall order may trigger the **scheduled-revert safety net**
(10-minute binary restore + reboot if tunnel verification fails). Expect brief guest
impact if revert fires — see §5.

### 3.8 Final verification

Writes `verification_runs` (`scope=final`) and updates readiness checklist items.
Outcomes:

| Overall | Meaning |
|---|---|
| `ROUTER_ONLINE` | Safe to mark venue ready |
| `PARTIAL` | Investigate failed checks before go-live |
| `FAILED` | Do not hand off; rollback or on-site intervention |

---

## 4. Comment tags and managed resources

| Era | Comment prefix | Recognition |
|---|---|---|
| Legacy live venues | `cloudguest-*` | Always treated as Wyfy-managed in discovery/planner |
| Wave 1 new resources | `WYFYGUEST-*` | Emitted by server profile renderers |

Dual-recognize, single-emit — **never re-tag live `cloudguest-*` rules on device**
during adoption (see live-venue doc).

After apply, `managed_router_resources` rows track what the platform owns for drift and
rollback audit.

---

## 5. Rollback and safety (honest limits)

RouterOS **safe mode** is terminal-only — unavailable to API automation.

| Layer | Mechanism | Limit |
|---|---|---|
| Pre-apply | `/export` text + binary backup via SFTP | Binary restore **reboots** full device (~2 min guest outage) |
| Mid-apply | Scheduled revert script (10 min) on high-risk steps | Full binary restore; power loss before scheduler upload = no protection |
| Post-apply | Roll back to `config_versions` backup row | Export re-import is not a perfect inverse |

For production venues where a reboot is unacceptable, schedule a maintenance window
before approving plans flagged `management_connectivity` risk.

---

## 6. Troubleshooting quick reference

| Symptom | Likely cause | Action |
|---|---|---|
| Discover fails immediately | Tunnel down, API blocked, bad creds | Fix WireGuard; verify API service on router |
| WAN verify OFFLINE | Wrong interface/mode, ISP issue | Fix ISP link row; check physical cabling |
| Plan BLOCKED | Subnet overlap | Change guest CIDR or remove conflicting address |
| Apply succeeds but final FAILED | Hotspot/RADIUS/WG partial apply | Device Console diagnostics; consider rollback |
| Wizard stuck after WAN | Gate not passed | Re-run WAN verify; check `verify/wan/gate` |

**Escalation data to capture:** router id, latest `snapshot_id`, latest `plan_id`,
`verification_runs` JSON, provision job id from apply step.

---

## 7. Advanced / escape hatch

**Advanced setup script** (`/master/routers?advanced=<id>`) remains for expert manual
bootstrap or debugging. It generates client-side script text (including secrets in the
browser) — **not** the supported path for new fleet deployments after Wave 1.

Device Console (`/master/console`) remains the supported path for ad-hoc RouterOS
commands on live hardware.
