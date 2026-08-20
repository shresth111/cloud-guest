# Live Venue Adoption Procedure (Wave 1)

How to onboard the **~12 existing production venues** already serving guests via
legacy `cloudguest-*`-tagged RouterOS config onto the Wave 1 platform **without
downtime or unsolicited device changes**.

Grounding: implementation plan §D3.4 and §C5 — *"for the 12 live venues, plan
application is opt-in per router and always snapshot-first; the first release never
auto-modifies an existing venue — it only discovers and reports until a plan is
explicitly approved."*

---

## 1. What "adoption" means here

Adoption is **not** "run the wizard and apply on every live router on deploy day."

It is a phased program:

| Phase | Device impact | Platform impact |
|---|---|---|
| **A — Inventory** | None (read-only discover) | Snapshots + compatibility reports |
| **B — Managed-resource backfill** | None | DB rows marking existing `cloudguest-*` as managed |
| **C — Report-only planning** | None | Build plans, review conflicts/topology, **do not approve** |
| **D — Opt-in apply** | Writes only after explicit approval per router | Normal wizard apply pipeline |

Phases A–C are safe to run fleet-wide. Phase D is **per-router, per-maintenance-window**.

---

## 2. Preconditions

- [ ] Wave 1 backend + frontend deployed (wizard + discovery APIs live)
- [ ] WireGuard tunnel healthy on the venue router (same as today)
- [ ] API credentials valid (platform already manages these venues)
- [ ] Account owner acknowledges Phase D may cause brief guest impact if revert/rollback runs
- [ ] NOC briefed on `ROUTER_ONLINE` / `PARTIAL` / `FAILED` final verification outcomes

**Do not** bulk-delete or re-tag `cloudguest-*` comments on device — dual-recognition
handles legacy tags in discovery and planner (`WYFYGUEST-*` for new resources only).

---

## 3. Phase A — Snapshot-only discovery (every live router)

For each live venue router:

1. Master Console → Router Fleet → **Wizard** (or API:
   `POST /api/v1/routers/{id}/discover?trigger=manual`).
2. Confirm discovery completes with status **`complete`** (or document `partial` with
   `error_detail`).
3. Review compatibility — **WARNING** is expected on some older boards; **ERROR/BLOCKED**
   must be triaged before any future apply.
4. **Stop here** — do not run WAN apply, plan build approve, or apply on first pass.

Optional: export snapshot id for audit:

```http
GET /api/v1/routers/{id}/snapshots?limit=1
```

**Success criteria:** every live router has at least one `router_snapshots` row; zero
configuration pushes performed.

---

## 4. Phase B — Managed resource backfill (automatic on first discover)

When discovery runs against a live venue, the platform **backfills
`managed_router_resources` from the snapshot** — existing resources whose comments
match `cloudguest-*` or `WYFYGUEST-*` are recorded as `status=applied` with
`plan_id=NULL`.

| Property | Implication |
|---|---|
| No device writes | Tags on router stay `cloudguest-*` |
| Drift detection enabled | Future verification can compare desired vs observed |
| Rollback audit | Platform knows what it considers "ours" before any new plan |

Verify in DB or admin tooling after Phase A: managed rows exist for NAT/DHCP/hotspot
resources visible in the snapshot firewall/hotspot summaries.

---

## 5. Phase C — Report-only planning

Goal: understand what the rule engine **would** change without approving anything.

1. Complete wizard steps 1–6 (through topology review) using **current** ISP link data
   — skip WAN apply if WAN is already correct unless testing in a lab clone.
2. Enter guest intent matching **existing** guest network (same VLANs/subnets as today).
3. Run **Conflict review** (`POST .../plans`) — capture plan id.
4. Review actions list:
   - **`noop`** / informational → good sign for low-risk adoption
   - **`remove` / `modify` on non-WyFy resources** → requires venue owner decision (Rule R7)
   - **`BLOCKED` conflicts** → must resolve before any Phase D
   - **`management_connectivity` risk** → schedule maintenance window for Phase D

**Hard rule:** do **not** click Approve or Apply in Phase C. Plan stays `draft` or
`awaiting_approval` until Phase D.

Store for each venue: `{router_id, snapshot_id, plan_id, highest_risk, blocked: bool}`.

---

## 6. Phase D — Opt-in apply (one router at a time)

Only after account owner sign-off **for that specific router**:

1. Schedule maintenance window if plan includes `management_connectivity` risk or binary
   revert safety net is expected.
2. Re-run **Discover** immediately before apply (fresh snapshot → new plan if inputs changed).
3. Re-build plan if snapshot id changed; diff against Phase C report.
4. Wizard steps 9–12:
   - Approve → Render → Prepare → Apply → Final verify
5. Accept outcome:
   - **`ROUTER_ONLINE`** → monitor guest auth for 24h
   - **`PARTIAL`** → do not declare adoption complete; investigate before next venue
   - **`FAILED`** → execute rollback procedure (§7)

**Never** parallelize Phase D across multiple live venues until the first venue has
24h clean operation.

---

## 7. Rollback on a live venue

1. Identify `pre_apply_backup_version_id` on the plan (from prepare step) or latest
   `config_versions` row with `is_backup=true`.
2. Use existing config rollback path (`POST .../config-versions/{id}/rollback`) or
   binary restore via provisioning pipeline — **expect reboot and guest disconnect**.
3. If scheduled-revert fired on device, wait for automatic restore (~10 min) before
   manual intervention.
4. Post-incident: new discover snapshot; mark plan `superseded`; document in audit log.

---

## 8. Venue checklist (printable)

```text
Venue: _______________  Router: _______________  Date: ___________

Phase A — Snapshot only
  [ ] Discover complete (snapshot id: ____________)
  [ ] Compatibility reviewed (overall: ____________)
  [ ] No WAN apply / no plan approve

Phase B — Backfill
  [ ] managed_router_resources rows present for cloudguest-* resources

Phase C — Report only
  [ ] Plan built (plan id: ____________)
  [ ] Conflicts reviewed (BLOCKED: yes/no)
  [ ] Highest risk: ____________
  [ ] Owner reviewed report (name: ____________)

Phase D — Opt-in apply (skip until signed off)
  [ ] Maintenance window scheduled
  [ ] Fresh discover + plan rebuild
  [ ] Approve / render / prepare / apply
  [ ] Final verify: ROUTER_ONLINE / PARTIAL / FAILED
  [ ] 24h guest auth monitoring clean
```

---

## 9. What not to do

- Do not run **WAN basic apply** on a live venue to "test" without a rollback plan.
- Do not bulk-approve plans across all 12 routers.
- Do not rename `cloudguest-*` comments to `WYFYGUEST-*` on device.
- Do not use **Advanced setup script** to re-push full guest config on live venues
  while also running the wizard — pick one transport per change window.
- Do not assume export rollback is a perfect undo — binary backup is the real last resort.

---

## 10. Related docs

- Full new-router procedure: [`PROVISIONING_RUNBOOK.md`](./PROVISIONING_RUNBOOK.md)
- Architecture constraints on live data: `~/wyfy-specs/router-fleet-current-architecture.md` §7
- Implementation plan safety section: `~/wyfy-specs/router-fleet-implementation-plan.md` §D3
