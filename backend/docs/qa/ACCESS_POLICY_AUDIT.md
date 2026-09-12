# Access, Policy & Guest-Facing Features — QA Audit

**Scope:** the eight customer-dashboard features in `src/config/customerFeatureCatalog.ts` under
Engagement / Access & Policy / Devices & Team: `portal`, `vouchers`, `policies`, `whitelist`,
`mac-auth`, `business-hours`, `teams`, `agents`.

**Out of scope (audited in parallel by a colleague):** `dhcp`, `vlan`, `port_forwarding`, `qos`,
`content_filtering`, `isp` and their components. Nothing in this document should be read as a
finding about those.

**Method:** code reading only. No device was contacted, no application file was modified.
Repos: `/Users/shresth/cloud-guest-repo/backend` (FastAPI), `/Users/shresth/cloudguest-foundation`
(React). Every claim carries a `file:line`. Where I could not establish something by reading, it is
listed in [§11 Could not determine by reading](#11-could-not-determine-by-reading) rather than
inferred.

**Date:** 2026-09-03

---

## 0. The two structural facts that colour everything below

### 0.1 A `200 {"success": false}` is invisible to the entire frontend

`src/services/api.ts:40-45` declares the envelope with a `success: boolean`. The response
interceptor at `src/services/api.ts:419-426` tests only `"data" in response.data` and then does
`response.data = (envelope).data` — **`success` is never read anywhere in `src/`**. A 200 carrying
`{success: false, data: null}` resolves the promise, so every call site in scope treats
"promise resolved" as "it worked".

This is not hypothetical for this audit: `POST /network-config/routers/{id}/versions/{vid}/apply-live`
returns `200 success=true` with `applied: false` on a device failure
(`app/domains/network_config/router.py:238-247` and `:265-274`). Only one component in the entire
repo checks a push result before claiming success —
`src/components/routers/RouterDetailTabs.tsx:539` — and it is operator-only.

### 0.2 The customer dashboard has no path to the router config push

`src/services/network-config.service.ts` (`push` :105, `applyLive` :114, `rollback` :160) is
imported by exactly one module, `src/hooks/useNetworkConfig.ts:2`, consumed by exactly one
component, `src/components/routers/RouterDetailTabs.tsx:80-85, 513-586` ("Push config" button at
`:583-586`). That component is reachable only from
`src/routes/_authenticated/routers.$routerId.tsx:17,147`, which
`src/routes/_authenticated.tsx:92-94` hard-redirects away from for any non-operator session.

So: **anything in scope whose effect depends on `render_network_config` reaching a device can only
be triggered by a master-console operator, never by the customer.** The relevant push path is real
and does hit the device inline (`app/domains/router_provisioning/service.py:917` →
`_push_version_and_complete`) — it simply has no customer-facing trigger.

---

## 1. Trusted Devices (`mac-auth`) — **BROKEN**

> Verdict: **the effect never lands.** A device added here does not bypass the captive portal, does
> not get an `/ip hotspot ip-binding`, and does not reach `/agent/authorized-macs`. The UI says
> "MAC address authorized". Nothing on the network changes.

### Where the effect is supposed to land

Two paths exist in code. Both are real code; neither fires in the field.

**Path A — login-time bypass via RADIUS.**
`app/domains/mac_authorization/service.py:388` `is_mac_authorized` is genuinely wired into
`GuestService` (`app/domains/guest/dependencies.py:156`) and consumed by
`app/domains/guest/service.py:2315` inside `login_via_mac_whitelist`. That method is in turn called
from `RadiusService.authorize` at `app/domains/guest/service.py:4743-4751`, on the branch that fires
when an Access-Request arrives with a `Calling-Station-Id` and no existing session.

**The blocker:** RouterOS only originates a MAC-only Access-Request when the hotspot profile's
`login-by` includes `mac`. The single writer of that property in the whole platform is
`src/components/routers/RouterDetailTabs.tsx:6384`, and its value is
`const HOTSPOT_LOGIN_BY = "http-pap"` (`src/components/routers/RouterDetailTabs.tsx:1803`), optionally
prefixed with `https` at `:6383`. `mac` is never in it, and `mac-auth-mode` is never set anywhere in
either repo (grep across `app/`, `vendor/`, `src/`). The generator's own test suite asserts a
**single writer** for this property (`:1799-1802`), so there is no second place that could add it.

Consequence: a trusted device that never opens the portal never produces an Access-Request, so
`login_via_mac_whitelist` is never reached, so no session is created, so the device gets nothing.

**Path B — `/ip hotspot ip-binding` via the config push.**
`app/domains/network_config/renderers.py:1010-1027` `render_mac_authorization_entry` emits a real
`/ip hotspot ip-binding add mac-address=… type=bypassed comment="mac-auth-{id}"`. It is wired end to
end: `app/domains/network_config/dependencies.py:92-95` →
`app/domains/network_config/service.py:470-476` `_gather_mac_authorization` →
`app/domains/mac_authorization/service.py:353` `list_active_entries_for_router` → included in
`render_network_config` at `app/domains/network_config/renderers.py:2490-2493`.

**The blocker:** that render only reaches a device through `POST /network-config/routers/{id}/push`
(`app/domains/network_config/router.py:158-164`, gated on `network_config.execute`), which per §0.2
has no customer-facing caller. An Organization Owner *holds* the permission
(`app/domains/rbac/seed.py:909-916`, `default_level=_L.FULL`, `NETWORK_CONFIG` not overridden) — the
dashboard just never offers the button.

### The `/agent/authorized-macs` scheduler does not read this table

The router-side scheduler is real and is generated — `buildAuthorizedMacStatements` at
`src/components/routers/RouterDetailTabs.tsx:4245-4276`, comment tag
`AUTHORIZED_MAC_COMMENT = "cloudguest-authmac"` (`:4095`). It is part of the operator's copy-paste
setup script, not anything the platform installs (`cloudguest-authmac-sched` appears nowhere in the
backend repo).

Its source endpoint is `app/domains/router_agent/router.py:225-251` `agent_authorized_macs`, and
that endpoint reads **`guest_repository.list_active_sessions_for_router`** (`:242`) — i.e. currently
ACTIVE guest sessions — not `mac_authorization_entries`. It has no reference to the MAC
Authorization domain at all. So a Trusted Device with no active session is never in the list, and
the scheduler never binds it.

This is a circular dependency the code cannot break: the device needs a session to be listed, and
needs to be listed (or MAC-authenticated) to get a session.

### Delete/disable does not undo

- `delete_entry` (`app/domains/mac_authorization/service.py:275-303`) soft-deletes the row and
  audits. It terminates no session and contacts nothing.
- `is_enabled=false` correctly blocks *future* `is_mac_authorized` calls
  (`app/domains/mac_authorization/service.py:401-405`), but an already-ACTIVE session under identity
  `mac:{MAC}` keeps authorizing: `RadiusService.authorize`'s first lookup
  (`app/domains/guest/service.py:4733-4736` → `_find_active_session_for_identifier` at `:4799`)
  checks only session status and router, never the whitelist.
- `render_network_config` is **add-only** (`app/domains/network_config/renderers.py:2440-2500`,
  `_idempotent_lines` at `:2552-2556` only wraps each line in `:do{}on-error={}`). There is no
  removal pass for stale `mac-auth-{id}` bindings, and the authmac scheduler's own removal pass
  (`RouterDetailTabs.tsx:4265`) is scoped to `comment="cloudguest-authmac"`, so it will never clean
  them either. If a binding ever did land, deleting the entry leaves it on the device forever.

### UI defects on top

| # | Severity | Finding |
|---|---|---|
| 1.1 | **Critical** | The feature has no effect on the network. Copy at `OperationsFeatures.tsx:4027-4029` — *"Devices allowed onto the network without going through the captive portal."* — and `:4103` *"Authorize a device to skip the captive portal."* are both false today. |
| 1.2 | High | `OperationsFeatures.tsx:3932` gates the real `POST` on `if (!isDemo() && locationId)`. `locationId` is optional (`:3884`) and `customerFeatures.tsx:156` passes `ctx.locationId` unguarded. A **real** customer with no venue selected falls into `:3945-3956`, gets a local row with `id: String(Date.now())`, and the same `toast.success("MAC address authorized")` at `:3958`. The subsequent toggle (`:3975`) and delete (`:3990`) guard only on `!isDemo()` and will fire `PUT`/`DELETE /mac-authorization/entries/1735…` against a fabricated id. |
| 1.3 | Low | `toast.success("Entry removed")` at `OperationsFeatures.tsx:3989` fires **before** the `DELETE` at `:3992`. Rollback exists (`:3995`) but the user saw success first. |
| 1.4 | Low | The enable/disable Switch (`:4073`) shows no success toast at all — only a failure toast at `:3979`. |

The domain's own module docstring (`app/domains/mac_authorization/service.py:18-27`) says the login
integration is deliberately not wired; that is now stale — it *is* wired
(`app/domains/guest/dependencies.py:156`). The honest statement today is different and worse: it is
wired to a code path the hardware never exercises.

---

## 2. Always Allowed (`whitelist`) — **NO-OP**

> Verdict: **the row is written and correctly scoped, and it changes no decision, ever.** A
> `WHITELIST` rule cannot grant anything that default-allow does not already grant, and cannot
> override a block.

### Where the effect is supposed to land

`WhiteList.tsx:454` → `guestService.createAccessRule` (`src/services/guest.service.ts:573`) →
`POST /guest-access/rules` or `POST /guest-access/device-rules`
(`src/services/guest.service.ts:574-575, 596`). Backend:
`app/domains/guest_access/router.py:63-93` / `:216-246`. Rows land in `guest_access_rules` /
`device_access_rules` (`app/domains/guest_access/models.py:51`, `:105`).

Enforcement is at login only: `GuestService._enforce_access_control`
(`app/domains/guest/service.py:3473-3510`), hook wired at `app/domains/guest/dependencies.py:155`,
which raises `GuestAccessDeniedError` **only** when `decision.allowed` is false (`:3509-3510`).

### Why it is a no-op

`AccessDecisionResolver.resolve` (`app/domains/guest_access/service.py:128-149`) walks
`ACCESS_RULE_TYPE_PRECEDENCE`, which is
`(VIP, TEMPORARY, BLOCKLIST, WHITELIST)` (`app/domains/guest_access/constants.py:48-53`), and falls
through to `_DEFAULT_ALLOW` when nothing matches (`:149`).

Therefore:
- With no other rule, the guest is allowed anyway — the whitelist row changes nothing.
- With a `BLOCKLIST` rule for the same guest/device, `BLOCKLIST` is checked **first** and wins — the
  whitelist row still changes nothing.

There is no third case. A `WHITELIST` rule is inert in every possible input.

Separately, the UI's promise is a different mechanism entirely:
`WhiteList.tsx:572-574` — *"Allow specific numbers or devices to bypass the captive portal."*,
`:691-692` — *"The number that skips the portal…"*, `:887` — *"…let a trusted number or device skip
the portal."* Nothing in `_enforce_access_control` skips OTP; portal bypass lives in
`login_via_mac_whitelist` (§1), which reads a different table (`mac_authorization_entries`) that
this form never writes.

### Defects

| # | Severity | Finding |
|---|---|---|
| 2.1 | **High** | A `WHITELIST` rule cannot change any access decision (`app/domains/guest_access/constants.py:48-53` + `service.py:128-149`). The feature persists a row and does nothing. |
| 2.2 | **High** | Copy claims portal bypass (`WhiteList.tsx:572-574, 691-692, 887`) which this code path does not implement. A venue owner who allow-lists the manager's phone and then blocks a nuisance guest on the same identifier will find the block wins, contrary to the label "Always Allowed". |
| 2.3 | Medium | **"Start Date" is required and never sent.** Rendered `WhiteList.tsx:816-820`, red-asterisked `:814`, validated `:367` (*"Start date is required."*). The payload at `:454-464` sends only `expiresAt`; `guest.service.ts:576-595` has no start field, and `GuestAccessRule` has no such column (`app/domains/guest_access/models.py:71-88`). On reload `toEntry` (`WhiteList.tsx:259`) backfills it from `createdAt`, so the value silently changes. Copy at `:809` — *"When this bypass starts and automatically ends."* |
| 2.4 | Low | The country-code Select (`WhiteList.tsx:702-713`, state `:278`) is decorative — `f.mobileCC` never reaches the submitted identifier (`:390`) or the payload. |
| 2.5 | Low | Delete is a real `DELETE` (`WhiteList.tsx:536` → `guest.service.ts:615,621`) but silent — optimistic removal at `:532` with rollback at `:542` and no toast either way. |

Delete/disable does undo the row honestly (real `DELETE`), but since the row had no effect, so does its removal.

---

## 3. Access Rules (`policies`) — **PARTLY REAL, FALSELY DESCRIBED**

`PoliciesHub.tsx` is a pure tab shell (five tabs at `:153-159`, delegated at `:241-245`). Verdict differs per tab.

### 3a. "Guest WiFi Limits" (`LocationPolicies.tsx`) and "Access Tiers" (`CreateGroup.tsx`)

> Verdict: **download/upload rate and Devices Per User are real and reach the router. Everything
> else on the form is stored and never read.**

**What lands.** Both write a `PolicyType.BANDWIDTH` policy via
`bandwidth-policy.service.ts:113` → `policy-engine.ts:102/147` (`POST /policies`,
`POST /policies/{id}/versions`, `POST …/publish`), then an assignment via
`policy-engine.ts:208`. The consumer is real:
`app/domains/queue_management/service.py:1039-1055` resolves `PolicyType.BANDWIDTH`, finds/creates a
`QueueProfile` from `download_rate_kbps`/`upload_rate_kbps`, and `apply_queue` pushes a genuine
RouterOS simple queue. It is triggered from guest login
(`app/domains/guest/service.py:1419-1425` via the dispatcher wired at
`app/domains/guest/dependencies.py:151`). Devices Per User is written as a **separate**
`PolicyType.DEVICE` policy (`LocationPolicies.tsx:509/517`) and is genuinely enforced at
`app/domains/guest/service.py:3550-3556`.

**What does not land.** `BandwidthPolicyRules`
(`app/domains/policy/schemas.py:105-146`) accepts six extra fields the UI writes. Grepping `app/`
for consumers:

| Field written by the UI | Consumer in `app/` |
|---|---|
| `session_timeout_minutes` | **none** on a Policy. Sessions always use `DEFAULT_SESSION_TIMEOUT_MINUTES` (`app/domains/guest/service.py:1637, 1934, 2213, 2370`); only vouchers override it (`:1773`). The only `session_timeout_minutes` reader is `HotspotProfile` (`app/domains/network_config/renderers.py:936`), a different table. |
| `idle_timeout_minutes` | **none** on a Policy (same `HotspotProfile`-only story). |
| `devices_per_user` | **none** — zero hits in `app/`. The real limit is `max_devices_per_guest` on `PolicyType.DEVICE` (`app/domains/policy/constants.py:208`). `CreateGroup.tsx:24-30, 797` already documents this. |
| `daily_limit_minutes` | **none** — zero hits in `app/`. |
| `login_hours` | **none** — zero hits in `app/`. |
| `data_limit` (`{quota, unit, resets}`) | **none.** FUP enforcement (`app/domains/guest/service.py:3628-3639`) reads `daily_data_limit_mb` / `weekly_data_limit_mb` / `monthly_data_limit_mb` / `*_time_limit_minutes` off a **`PolicyType.FUP`** policy. No frontend surface anywhere creates a `fup` or `session` policy — grep of `src/` for `POLICY_TYPE` returns only `bandwidth`, `access`, `routing`, `authn`. |

**"Applies immediately" is false.** `LocationPolicies.tsx:887` reads, verbatim, with an amber
`AlertTriangle` directly above Save:

> *"Applies immediately — including to guests already connected."*

`PolicyService.publish_version` (`app/domains/policy/service.py:390-435`) flips the version status,
re-points `current_version_id`, logs and audits. **No queue re-application, no session termination,
no push.** `app/domains/policy/service.py:8-21` states the module is a leaf with zero outbound
dependencies. A new rate applies to the *next* login, via `_assign_guest_queue`. An already-connected
guest keeps the old queue until they reconnect.

`CreateGroup.tsx:1988` gets this right for its own case — *"A tier only applies to guests once it's
mapped to their location below."* — which makes `LocationPolicies.tsx:887` the outlier, not the rule.

**Delete is soft.** `bandwidth-policy.service.ts:135` → `policy-engine.ts:172` →
`POST /policies/{id}/deactivate`. There is no hard delete on the backend
(`app/domains/policy/router.py` has create/get/list/deactivate/versions/assignments only), and
`statusOf` (`policy-engine.ts:62-67`) therefore renders a deactivated policy as permanently
"archived" with no path back. Deactivating does not remove an already-applied RouterOS queue.

### 3b. "Blocked Guests" (`BlockUsers.tsx`)

> Verdict: **blocks future logins. Does not end the session it says it ends.**

Real writes: `BlockUsers.tsx:511` → `POST /guest-access/rules` with `ruleType: "blocklist"`;
unblock `:586` → `POST …/deactivate`; delete `:610` → real `DELETE`. The block is genuinely enforced
at the next login attempt (`app/domains/guest/service.py:3502-3510`).

The copy, verbatim:

- `BlockUsers.tsx:872` — *"Takes effect immediately, ending any session these users currently have."*
- `BlockUsers.tsx:873` (tooltip) — *"Blocking a number or email ends that guest's active session right away, if they have one, and prevents them from signing in again until unblocked."*
- `BlockUsers.tsx:674` (confirm modal) — *"Their current sessions will end right away."*
- `BlockUsers.tsx:705` — *"Cut off a guest's access to your network immediately."*
- `BlockUsers.tsx:935` — *"…it takes effect immediately."*

None of this happens. `create_guest_rule` (`app/domains/guest_access/service.py:186-232`) writes a
row and audits — there is no `terminate`/`disconnect` anywhere in
`app/domains/guest_access/service.py` (the full method list is `:186-492`). `BlockUsers.tsx` never
calls the session-termination endpoint that exists at `guest.service.ts:517`. And RADIUS
re-authorization does not re-check access rules: `_find_active_session_for_identifier`
(`app/domains/guest/service.py:4799-4827`) checks only `guest.is_blocked` (the separate
`Guest.is_blocked` flag, which this form does not set) and session status.

So a blocked guest stays online for the remainder of their session. **This is the "a blocked device
still gets online" case, stated in the UI as the opposite.**

### 3c. "Sign-in Methods" (`SmartIdPage.tsx`)

> Verdict: **the five real toggles persist and are enforced. The ordering control is a mock.**

Real: `SmartIdPage.tsx:250/256` `PUT /captive-portal-configs/{id}` (or lazy-create at `:258-268`)
for the five flags in `BACKED_FLAGS` (`:44-59`). Those columns are genuinely enforced —
`app/domains/captive_portal/models.py:362-397` and `GuestService._require_method_enabled`
(referenced at `app/domains/guest/service.py:2280-2287`).

Mock: `moveUp` (`SmartIdPage.tsx:290-295`, button `:391`) reorders local array state and sends no
`order` field in any request (`:250, 256, 259`). The copy asserts otherwise:

- `SmartIdPage.tsx:316-318` — *"…guests can use any enabled method, in the order you set below."*
- `SmartIdPage.tsx:363-365` — *"The order below is the order the sign-in tabs appear in for guests — use the arrow to move a method up."*
- `SmartIdPage.tsx:417` — `` `Shown ${enabledRank + 1} of ${enabledLiveMethods.length} to guests` ``

There is no ordering column on `CaptivePortalConfig` (`app/domains/captive_portal/models.py:362-400`).

Also `SmartIdPage.tsx:234-241`: an unbacked method short-circuits to the same success toast as a real
save (`:237-239` vs `:279-281`, byte-identical). Currently unreachable outside demo because
`UNAVAILABLE_METHOD_IDS` (`:83`) hides those switches — a latent trap, not a live defect.

### 3d. Cross-cutting: `PolicyType.ACCESS` has no consumer

`src/services/policy.service.ts:23` sets `POLICY_TYPE = "access"` and persists a composite
bandwidth/quota/device/authMethods/timeWindow blob. Grepping `app/` for `PolicyType.ACCESS`
consumers outside `app/domains/policy/` returns **nothing** — the only resolved types are
`SESSION` (`app/domains/provisioning_engine/service.py:420`), `BANDWIDTH`
(`app/domains/queue_management/service.py:1040`), `FUP` and `DEVICE`
(`app/domains/guest/service.py:986, 3551, 3623, 3717`). Any `access`-type policy is inert.

`policy.service.ts` is **not** reached from `PoliciesHub` (only `src/hooks/usePolicy.ts` →
`src/components/policies/PolicyManagement.tsx`, an operator surface), so this is out of the customer
blast radius — recorded here because the file's own header comment at `policy.service.ts:12-22`
asserts it is the persistence for "the full composite Policy shape this UI edits".

---

## 4. Open Hours (`business-hours`) — **NOT ENFORCED**

> Verdict: **saves correctly to the portal config; the backend enforces nothing.** The gate is
> entirely client-side in the guest portal app.

**The save is real.** `OperationsFeatures.tsx:978` → `business-hours.service.ts:66` →
`PUT /captive-portal-configs/{configId}` (`:76`) writing `business_hours_enabled`,
`business_hours_timezone`, `business_hours_schedule`, `business_hours_closed_message`. Columns exist
(`app/domains/captive_portal/models.py:413-432`), are validated
(`app/domains/captive_portal/service.py:885-891`), and the resolve cache is invalidated on update
(`app/domains/captive_portal/service.py:970`).

**Nothing enforces it.** A grep of `app/` for `business_hours` outside
`app/domains/captive_portal/` returns exactly one hit: the unused enum member
`PolicyType.BUSINESS_HOURS` at `app/domains/policy/constants.py:91`. `is_open_now` is computed only
in the resolve response (`app/domains/captive_portal/router.py:537`, validator at
`app/domains/captive_portal/validators.py:286`) and is advisory — it is a field, not a gate.

Concretely: `login_via_otp`, `login_via_voucher`, `login_via_password`, `login_via_pin`
(`app/domains/guest/router.py:413, 453, 486, 519`) contain no open-hours check. A guest whose device
posts to `POST /guest/login/otp` outside opening hours is signed in normally. And nothing terminates
sessions at closing time — no scheduled sweep references business hours.

The copy claims enforcement, verbatim:

- `OperationsFeatures.tsx:1027` — *"Guests can only sign in inside this schedule -- outside it, they see a closed message instead of the portal."*
- `OperationsFeatures.tsx:1128-1130` — *"Outside open hours, guests are shown the closed message below instead of the sign-in page."*
- `OperationsFeatures.tsx:1118` — *"…how strictly the schedule above is enforced."*

The first is the accurate description of a *portal-app* behaviour; it is presented as a network
control. For a venue using this to stop after-hours WiFi use, it does not.

### Defects

| # | Severity | Finding |
|---|---|---|
| 4.1 | **High** | No backend enforcement of open hours anywhere (`app/` grep: one unused enum member). Direct API login and already-connected guests are unaffected. Copy at `:1027`, `:1128-1130` claims otherwise. |
| 4.2 | Medium | KPI tile literally labelled **"Enforced"** (`OperationsFeatures.tsx:1014-1015`) is driven by the **unsaved local** `enabled` state — it flips to "On" the instant the switch moves, before the `PUT` at `business-hours.service.ts:76`. |
| 4.3 | Low | With no venue selected, `OperationsFeatures.tsx:927` returns before `setLoading(false)`, leaving a permanent `LoadingSkeleton` (`:1048`) and a permanently disabled Apply (`:1030`) with no explanation. |

Disable is honest — the `enabled` switch persists via the same real `PUT`. There is no delete.

---

## 5. Portal (`portal`) — **CORRECT ARCHITECTURE, THREE DEAD CONTROLS**

> Verdict: **lands where it should.** Portal edits are a database-and-portal-HTML concern, not a
> router one; they take effect within one cache TTL and often instantly. Three controls on the form
> write to nothing.

### Where the effect lands, and why no router push is needed

`PortalPage.tsx:743/745` → `portalService.update`/`create`
(`src/services/portal.service.ts:612` `PUT /captive-portal-configs/{id}` at `:662`;
`:567` `POST /captive-portal-configs` at `:576`). The guest-facing portal reads the same row live at
`GET /captive-portal/resolve` (`src/services/portal-runtime.service.ts:257, 269-270`;
`app/domains/captive_portal/router.py:409-414`).

The router is deliberately not involved. The MikroTik's `hsprof1` carries
`html-directory='flash/hotspot'` with a redirect to the cloud portal, and the only device-side
prerequisite is the walled garden, which is rendered once at provisioning
(`app/domains/network_config/renderers.py:1337-1404` `render_hotspot_walled_garden`) plus the
operator setup script (`RouterDetailTabs.tsx:1641-1645`). Portal *content* never needs a push. That
is the right design and it is implemented correctly.

Cache staleness is bounded and honest: TTL 60s (`app/core/config.py:117-118`) with real invalidation
on every mutation to the exact `(organization_id, location_id)` pair
(`app/domains/captive_portal/service.py:804, 970, 1055, 1081, 1108`). The one documented gap — an
organization-level default edit not fanning out to every location that falls back to it — is
TTL-backstopped and written up at `app/domains/captive_portal/cache.py:23-30`.

Logo and background are org-level assets persisted immediately, outside Save:
`PortalPage.tsx:553, 583, 631, 657` → `src/services/brand-asset.service.ts:200, 210, 159, 169`.

### Defects

| # | Severity | Finding |
|---|---|---|
| 5.1 | **High** | **Three controls write to nothing, then report success.** `saveConfig`'s patch (`PortalPage.tsx:706-740`) contains no `themeId`, no `branding.fontChoice`, and no `consent` key. So: **Theme** select (`:1021-1033`), **Font** select (`:1034-1046`), and the **Terms & Conditions** textarea (`:1191-1198`) are all discarded. `toast.success("Portal configuration saved")` fires at `:754` regardless. Note the service layer *does* map all three (`portal.service.ts:614` `theme`, `:625-626` `terms_and_conditions_url`, `:655-656` `guest_font_choice`) — the gap is purely in the patch the page builds. The T&C case is doubly wrong: the field is a free-text textarea round-tripped from a **URL** column (`PortalPage.tsx:318` reads `p.consent.termsUrl`; the backend has a separate `terms_and_conditions_text` column at `app/domains/captive_portal/models.py:280`). |
| 5.2 | Medium | `portal.service.ts:660` — `if (Object.keys(body).length > 0)`. An empty patch issues **no HTTP request at all**, re-fetches the row and returns it, and `PortalPage.tsx:754` still shows "Portal configuration saved". |
| 5.3 | Medium | **"Download QR"** (`PortalPage.tsx:1359-1366`) is `onClick={() => toast.success("QR code downloaded")}`. Nothing is generated or downloaded. The "QR code" above it is a static lucide `<QrCode>` glyph (`:1356`) and the URL beneath is the hardcoded string `auth.wyfyguest.com` (`:1358`) — not this venue's portal URL. |
| 5.4 | Low | `portal.service.ts` `restoreVersion` (`:748`) ignores its `_versionId` and persists nothing; `saveAsTheme` (`:726`), `addAd` (`:755`), `removeAd` (`:761`) are in-memory only; `analytics` (`:769`) returns hardcoded zeros, as does `kpis` for `todaysLogins`/`conversionRate`/`portalViews` (`:525-527`). None is reachable from `PortalPage`, but they are live exports. |
| 5.5 | Low | `src/services/branding.service.ts` (462 lines) has **no `api` import at all** — it is a `setTimeout`-backed in-memory mock, including `verifyDomain` (`:398`) which unconditionally sets `ssl: "issued", dns: "verified"` and returns `true`. Reachable only from `src/routes/_authenticated/branding.index.tsx`, i.e. outside this feature — recorded for completeness. |

**Honest behaviour worth crediting:** the post-login HTML round-trip is the one place in the whole
audit that verifies what the server actually stored. `PortalPage.tsx:766-786` compares what was sent
against what came back and warns (`:775-777`) or repaints and informs (`:782-784`). No Portal copy
claims a router push, and the "Live" badge (`:1234-1240`) is scoped to the on-page preview
(`:1317-1318, 1322-1324`).

---

## 6. Vouchers (`vouchers`) — **LANDS CORRECTLY**

> Verdict: **this one works.** Vouchers are legitimately a database + RADIUS + queue concern, and
> all three land. Defects are peripheral.

Effect chain, verified end to end:
- Create: `VouchersPage.tsx:381-391` → `voucher.service.ts:212` → `POST /voucher-batches`
  (`app/domains/voucher/router.py`). An Organization Owner holds `voucher.manage`
  (`app/domains/rbac/seed.py:909-916`, `default_level=_L.FULL`), so `create_batch` runs
  `_approve_and_activate` in the same call and the batch is live immediately
  (`app/domains/voucher/service.py:29-56`).
- Redemption: `POST /guest/login/voucher` (`app/domains/guest/router.py:453`) →
  session with `session_timeout_minutes = batch.validity_minutes`
  (`app/domains/guest/service.py:1773`).
- RADIUS: that timeout is returned as `Session-Timeout`
  (`app/domains/guest/router.py:1925-1926`) alongside `Mikrotik-Rate-Limit` (`:1927`).
- Router: the voucher plan's `queue_profile_id` produces a genuine RouterOS queue via
  `_assign_voucher_queue` (`app/domains/guest/service.py:1453-1480`).

No device adapter is expected here and none is needed. Correct.

### Defects

| # | Severity | Finding |
|---|---|---|
| 6.1 | **High** | **A failed load silently shows fabricated data.** `VouchersPage.tsx:338-340` catches a real-mode fetch failure and falls back to `setItems(DEMO_SEED)` — four invented voucher codes `VCH-8821`…`VCH-8824` (`:62-95`) rendered as if real. A venue owner could hand a guest a code that does not exist. |
| 6.2 | Medium | **"Import CSV"** (`VouchersPage.tsx:448`) is `onClick={() => toast.success("Bulk import started")}` — no service call in demo or real mode, and no import endpoint is called anywhere. |
| 6.3 | Medium | **Revoke does not disconnect.** `revoke_batch` (`app/domains/voucher/service.py:518-550`) flips the batch status and bulk-revokes voucher rows. It terminates no session — grep of `app/domains/voucher/service.py` for `terminate`/`disconnect`/`session` returns nothing. RADIUS re-authorization does not re-check the voucher (`app/domains/guest/service.py:4799-4827`). A guest already online on a revoked voucher stays online. Copy at `VouchersPage.tsx:423` is a bare `"Batch revoked"`, which is at least not an over-claim. |
| 6.4 | Low | `approveBatch` (`voucher.service.ts:238`) is never called from `VouchersPage` — only from `src/hooks/useVoucher.ts:60`, which this page does not use. Immaterial for an Owner (§6 above) but a batch created by a `voucher.create`-only agent lands in `PENDING_APPROVAL` with no approve control on this screen. The toast at `:406` does at least print the status verbatim. |
| 6.5 | Low | Demo-only fake controls that ship in the bundle: per-row plan dropdown (`:614-633`, `toast.success` at `:620`, local state, no `updateVoucherPlan` exists) and the page-level CSV/Print/Email buttons (`:686-699`). |

---

## 7. Guest Groups (`teams`) — **HALF REAL**

> Verdict: **create and revoke are real, and revoke genuinely disconnects — the only revoke in this
> audit that does. Edit is a local mock, and the shared quota is reporting-only.**

**What works, and works well.** `revoke_team` (`app/domains/guest_teams/service.py:462-510`) walks
every active member, fetches their sessions and calls
`guest_service.terminate_session` (`:500-503`). This is the correct behaviour that
`guest_access`/`voucher` lack. The member cap is genuinely enforced on join
(`app/domains/guest_teams/service.py:609-612`).

Real calls: create `ManageTeamsPage.tsx:371-381` → `guest.service.ts:668` `POST /guest-teams`;
revoke `:408` → `guest.service.ts:688` `POST /guest-teams/{id}/revoke`;
list `:239` → `guest.service.ts:650`; summary `:272` → `guest.service.ts:661`.

### Defects

| # | Severity | Finding |
|---|---|---|
| 7.1 | **High** | **"Save Changes" in the Manage dialog persists nothing.** `saveManage` (`ManageTeamsPage.tsx:319-335`) is `setTeams(...)` at `:326-332` then `toast.success(\`${manageDraft.name} updated\`)` at `:333`. No `guestService` call. There is no `PATCH /guest-teams/{id}` in `guest.service.ts` (mutating team endpoints are create `:668`, `removeTeamMember` `:684`, revoke `:688` only) and none in `app/domains/guest_teams/router.py` (`:115, 152, 183, 222, 259, 293`). The dialog edits name, location and member count (`:836-869`); all three are lost on reload. Copy at `:833` — *"Update this team's name, location, or member count."* |
| 7.2 | **High** | **The shared data quota is never enforced.** `check_shared_quota` (`app/domains/guest_teams/service.py:767`) has **zero production callers** — only `tests/unit/test_guest_teams.py:953, 968, 990, 1006`. The module docstring says so plainly at `:145-163` (*"a real check, not the enforcement point"*). Nothing disconnects a team over quota and no login path consults it. UI copy at `ManageTeamsPage.tsx:436` — *"Group guests into teams with shared data quotas…"* — and the quota progress bar (`:594-612`) present it as a live limit. |
| 7.3 | Medium | **Both bulk-CSV uploads discard the file.** "Upload & Create" (`:718-728`) toasts `` `Uploaded ${teamsCsv?.name} — teams queued for import.` `` at `:721` then `setTeamsCsv(null)` at `:722` — the file is never read or sent. "Upload & Map" (`:788-798`, toast `:791`) is identical. No such endpoint exists. |
| 7.4 | Medium | **Revoke toast fires before the call.** `toast.success("Team revoked")` at `:405`, `revokeTeam` at `:408`. On failure the user sees success then `toast.error("Could not revoke on the server.")` at `:411`. |
| 7.5 | Low | The required-starred "Location *" picker (`:485-503`) is validated only in demo (`:339`). `businessUnit` is hardcoded `""` for every real row (`:249, 386`) and rendered at `:588`. |
| 7.6 | Low | "Find User" (`:674-684`) toasts *"Looked up user — no changes yet."* and calls nothing. Stated limits at `:752` (≤5000 shared users) and `:750/:820` (≤30kb file) are unvalidated — `createTeam` at `:369` does only `parseInt(sharedUsers) \|\| 0`, and the file input at `:115-120` has no size check. |
| 7.7 | Low | `getTeam` (`guest.service.ts:661`) and `removeTeamMember` (`:684`) send no `X-Organization-Id` header, unlike their siblings. |
| 7.8 | Low | A failed load renders "No team accounts yet" (`:574`) via `catch { }` at `:297-299`, indistinguishable from a genuinely empty org. |

---

## 8. Staff Access (`agents`) — **REAL RBAC, WITH TWO TRAPS**

> Verdict: **for a real (non-demo) session this is genuine RBAC and correctly enforced server-side.**
> Pure database/RBAC — no router involvement is expected and none is needed. Two real problems: a
> fail-open permission check, and a live backend endpoint that is a no-op stub.

**What works.** `AgentsPage.tsx` in the `!demo` branch calls real endpoints throughout:
invite `:503-511` → `rbac.service.ts:350` `POST /users/invite`; activate/deactivate `:574/576` →
`:422/429`; role assign/revoke `:593-611` → `:614/634`; create role `:412-421` → `:493`;
save role permissions `:358-366` → `:519` `PUT /roles/{id}`. Enforcement is the platform's own
`RequirePermission` on every endpoint. The copy is honest here —
`AgentsPage.tsx:934-940` and `:1556-1558` (*"Permissions are set by the role you assign to this staff
member, not by this page."*) accurately describe the mechanism. Self-lockout guards at `:450, 1498,
1503`. Role delete is deliberately absent with a documented reason at `:385-395` (an Organization
Owner 403s on `DELETE /roles/{id}`).

### Defects

| # | Severity | Finding |
|---|---|---|
| 8.1 | **High** | **`permissions.service.ts` fails open.** `fetchRealPermissionKeys` (`:90-98`) calls `rbacService.getUserPermissions` and returns `null` on **any** error (`:95-96`). `getPermissions` (`:1184`, real keys fetched at `:1213`) then leaves the frontend-owned static table (`:21-39`) untouched — and real keys can only ever **downgrade** `view` to `false` (`:1211-1218`, `:101-110`), never grant. So a 403 or a network blip on `GET /users/{id}/permissions` yields the **more permissive** static grants. This is client-side navigation only (every endpoint still enforces server-side), so it is a UI-integrity bug rather than a privilege escalation — but it points a staff member at surfaces they will then 403 on, and it is exactly backwards for a fail-safe. |
| 8.2 | **High (latent)** | **`POST /agents/{agent_id}/permissions` is a no-op stub that returns success.** `app/domains/agent_permissions/service.py:413-428`: it loops over `role_ids` calling `get_role` inside `contextlib.suppress(Exception)` (`:418`) — so even validation failures are swallowed — and returns `AgentPermissionAssignResponse(assigned_permissions=request.permission_keys, message="Permissions assigned to agent")`. **Nothing is persisted.** The route (`app/domains/agent_permissions/router.py:69-86`) is gated on `roles.assign` and mounted live (`app/api/v1/router.py:5, 134`), and the router's own module docstring claims it *"allows permission assignment to agents — composing the existing RBAC service"*. No frontend caller exists today (grep of `src/` for `agents/…/permissions`, `roles/suggested`, `permissions/tree` returns nothing), which is the only reason this is not currently causing harm. Any future integration against it would silently grant nothing while reporting success. |
| 8.3 | Medium | **Demo mode is 100% `localStorage` and says otherwise.** `src/stores/agentPermissionStore.ts` is `persist(...)` (`:117-118`) under key `"cg-agent-permissions"` (`:161`) with no `api` import at all; every mutator is a plain `set()` (`:123-159`). The demo `/agent` preview reads the same store via `grantedFor` (`:154-159`). Meanwhile `AgentsPage.tsx:678-680` asserts, in both modes: *"Use role-based access control to limit the features your team can access."* and `:715-718` describes the Read-Only role as immutable and permission-limited. Anyone with devtools can grant themselves every feature. The store's own docstring (`:5-12`) is candid that it is a placeholder seam. |
| 8.4 | Medium | **Delete-staff has no rollback.** `AgentsPage.tsx:630-633` optimistically filters the row out at `:630` then fires `deactivateUser` with only a `.catch` toast at `:633`. A failed deactivation leaves the user permanently missing from the UI while still active on the server. (`updateAgent` at `:619` does roll back — the inconsistency is the tell.) |
| 8.5 | Medium | **Per-agent location scoping does not exist in real mode.** The "Select Locations" chips render only behind `demo &&` (`:1340, 1520`); real agents are mapped with `locations: []` hardcoded at `:257`. `AgentRecord.locations` (`agentPermissionStore.ts:30-31`, *"Location ids this agent can access"*) is never sent anywhere. Compounding this, `customerFeatures.tsx:139-140` renders `<AgentsPage />` with **no** `locationId` prop, so `AgentsPage.tsx:406-409, 275` can never take the location-scope branch and the "Location — assignable at this location only" option is permanently `disabled` (`:978-981`). |
| 8.6 | Low | `permissionsService.updateFeatureFlag` (`:1268`) mutates an in-memory `featureOverrides` object (`:1269`) and emits on a bus (`:1270-1271`) — no persistence, lost on reload. |
| 8.7 | Low | The trash icon (`:1477-1488`) **deactivates**; it does not delete. Copy does not say so. |
| 8.8 | Low | A failed load renders "No staff yet" (`:1383`) / "No roles yet" (`:1053`) via `catch { }` at `:251-253`. |

---

## 9. Summary table

| Feature | Where the effect is *supposed* to land | Does it land? | Worst defect |
|---|---|---|---|
| **Trusted Devices** (`mac-auth`) | Router `/ip hotspot ip-binding`, or a RADIUS MAC-auth bypass | ❌ **No.** Neither path is reachable in the field | Feature has no network effect at all (§1) |
| **Always Allowed** (`whitelist`) | Login-time access decision | ❌ **No.** `WHITELIST` cannot change any decision | Inert by construction (§2.1) |
| **Access Rules → Blocked Guests** | Login gate + session termination | ⚠️ **Half.** Blocks new logins; never ends a session | UI claims immediate disconnect (§3b) |
| **Access Rules → WiFi Limits / Tiers** | RouterOS simple queue via `queue_management` | ⚠️ **Half.** Rates + device limit land at *next* login; 6 other form fields land nowhere | "Applies immediately — including to guests already connected" is false (§3a) |
| **Access Rules → Sign-in Methods** | `captive_portal_configs` login flags | ✅ **Yes** for the 5 real flags | Ordering control is a mock (§3c) |
| **Open Hours** (`business-hours`) | Portal-app gate (correctly not a router concern) | ⚠️ **Portal only.** Zero backend enforcement | Direct-API login and live sessions unaffected (§4.1) |
| **Portal** (`portal`) | `captive_portal_configs`, read live at `/resolve` | ✅ **Yes** — correct architecture, ≤60s | Theme / Font / T&C write to nothing (§5.1) |
| **Vouchers** (`vouchers`) | DB + RADIUS reply + RouterOS queue | ✅ **Yes**, all three | Failed load shows fabricated codes (§6.1) |
| **Guest Groups** (`teams`) | DB + real session termination on revoke | ⚠️ **Half.** Create/revoke real; edit and quota are not | "Save Changes" persists nothing (§7.1) |
| **Staff Access** (`agents`) | RBAC tables (pure DB — correctly no device) | ✅ **Yes** in real mode | Permission check fails **open** (§8.1) |

**On "no device adapter":** none of `captive_portal`, `voucher`, `policy`, `mac_authorization`,
`guest_access`, `hotspot` has a `device_adapters.py`, and for five of the six that is **correct** —
portal content, vouchers, access rules, open hours and staff access are database/RADIUS/portal-HTML
concerns by design. `mac_authorization` is the one case where a customer reasonably expects the
router to change and it does not, and even there the missing piece is not an adapter (the renderer
and the push pipeline both exist) but a trigger and a hotspot `login-by` value.

---

## 10. Prioritised fix list

Ranked by customer harm — "a blocked device still gets online" over "a label is wrong".

### P0 — a security control the UI says is in force, and is not

1. **Blocking a guest does not end their session** (§3b). `BlockUsers.tsx:872-873, 674` promise
   immediate disconnection in three places. Fix at the backend:
   `app/domains/guest_access/service.py:186` `create_guest_rule` (and `create_device_rule` at `:311`)
   should terminate matching active sessions, mirroring what
   `app/domains/guest_teams/service.py:487-503` already does correctly. Failing that,
   `RadiusService._find_active_session_for_identifier`
   (`app/domains/guest/service.py:4799`) should consult `check_access` so the next
   re-authorization drops them. Until one of those ships, correct the copy.

2. **Trusted Devices has no effect** (§1). Two independent fixes, both needed:
   (a) add `mac` to `HOTSPOT_LOGIN_BY` (`src/components/routers/RouterDetailTabs.tsx:1803`) and set
   `mac-auth-mode`, so RouterOS actually attempts MAC authentication — this makes the already-wired
   `login_via_mac_whitelist` path live; and/or (b) make
   `app/domains/router_agent/router.py:242` union `mac_authorization` entries into
   `/agent/authorized-macs`, which the existing on-device scheduler
   (`RouterDetailTabs.tsx:4245-4276`) would then pick up within a minute with no new mechanism.
   Option (b) is smaller and closes the circular dependency. Until then, the copy at
   `OperationsFeatures.tsx:4027-4029, 4103` should not promise portal bypass.

3. **Open Hours is not enforced** (§4.1). Add a check against
   `app/domains/captive_portal/validators.py:286` `is_open_now` inside the login paths
   (`app/domains/guest/service.py`, alongside `_require_method_enabled`), and decide explicitly
   whether closing time should terminate live sessions. Fix the "Enforced" KPI at
   `OperationsFeatures.tsx:1014-1015` to read persisted, not draft, state.

4. **`permissions.service.ts` fails open** (§8.1). `fetchRealPermissionKeys`
   (`src/services/permissions.service.ts:90-98`) must distinguish "no data" from "error" and deny by
   default on error.

### P1 — controls that report success and persist nothing

5. **Always Allowed is inert** (§2.1-2.2). Decide what the feature means. If it is portal bypass,
   it must write `mac_authorization_entries`, not `guest_access_rules`. If it is an allow-list
   override, `WHITELIST` must outrank `BLOCKLIST` in
   `app/domains/guest_access/constants.py:48-53`. Either way the copy at `WhiteList.tsx:572-574`
   needs to match.

6. **Guest Groups "Save Changes"** (§7.1) — add `PATCH /guest-teams/{id}` and wire
   `ManageTeamsPage.tsx:319-335`, or remove the dialog's editable fields.

7. **Portal Theme / Font / Terms & Conditions** (§5.1) — add `themeId`, `branding.fontChoice` and
   `consent` to the patch at `PortalPage.tsx:706-740`; the service already maps all three
   (`portal.service.ts:614, 625-626, 655-656`). Point the T&C textarea at
   `terms_and_conditions_text`, not `terms_and_conditions_url`.

8. **Sign-in method ordering** (§3c) — either add an ordering column and send it, or remove the
   arrows and the three copy lines at `SmartIdPage.tsx:316-318, 363-365, 417`.

9. **Voucher "Import CSV"** (§6.2) and **Guest Groups bulk CSV** (§7.3) — remove the buttons or
   implement them. `app/domains/voucher` already has an import path
   (`import_vouchers`, referenced at `app/domains/mac_authorization/service.py:33-37`) that the
   frontend never calls.

10. **MacAuthView local-add fallback** (§1.2) — `OperationsFeatures.tsx:3932` should block the
    action with an honest "pick a venue first" state rather than falling through to `:3945-3956`.

### P2 — misleading state and copy

11. **"Applies immediately — including to guests already connected"** (`LocationPolicies.tsx:887`)
    — false (§3a). Either re-apply queues to active sessions on publish, or change the wording to
    match `CreateGroup.tsx:1988`.

12. **Six policy fields stored and never read** (§3a) — `session_timeout_minutes`,
    `idle_timeout_minutes`, `devices_per_user`, `daily_limit_minutes`, `login_hours`, `data_limit`.
    Either route them to the policy types that are actually resolved (`SESSION`, `FUP`, `DEVICE`) or
    stop rendering the inputs. Note no frontend surface creates a `fup` or `session` policy at all,
    so FUP quotas are unconfigurable from the dashboard today.

13. **Team shared quota is reporting-only** (§7.2) — `check_shared_quota` has no production caller.
    Either wire it into login enforcement / a sweep, or relabel the progress bar as usage rather
    than a limit.

14. **Voucher revoke leaves guests online** (§6.3) — mirror `revoke_team`'s termination loop.

15. **Failed loads that fabricate or hide data** — `VouchersPage.tsx:338-340` (demo seed shown to
    real customers, §6.1) is the worst; then the bare `catch {}` empty states at
    `ManageTeamsPage.tsx:297-299`, `AgentsPage.tsx:251-253`.

16. **Optimistic toasts that precede the call** — `ManageTeamsPage.tsx:405`,
    `OperationsFeatures.tsx:3989`, and the no-rollback delete at `AgentsPage.tsx:630-633`.

17. **`POST /agents/{id}/permissions` stub** (§8.2) — `app/domains/agent_permissions/service.py:413-428`
    should either persist through `RBACService` or be removed from
    `app/api/v1/router.py:134` before anything integrates against it.

18. **Dead route files** — `policies.authentication.tsx`, `policies.bandwidth.tsx`,
    `policies.network.tsx` at the repo root are unrouted `ComingSoonPanel` duplicates of the live
    `src/routes/_authenticated/policies.*` pages, and declare colliding
    `createFileRoute("/_authenticated/policies/<x>")` ids (L5 of each). Delete them.

19. **Portal "Download QR"** (§5.3) and the hardcoded `auth.wyfyguest.com` URL
    (`PortalPage.tsx:1358`).

### P3 — cross-cutting

20. **Read the envelope's `success`** (§0.1). One change at `src/services/api.ts:419-426` — reject
    when `success === false` — closes an entire class of invisible failure across every feature,
    including the `applied: false` path at `app/domains/network_config/router.py:238-247`.

21. **Stale docstring** — `app/domains/mac_authorization/service.py:18-27` says the guest-login
    integration is deliberately not wired. It has been wired since
    `app/domains/guest/dependencies.py:156`.

---

## 11. Could not determine by reading

Stated plainly rather than inferred:

- **Whether the production router's `hsprof1` currently has `login-by` including `mac`.** I
  established that no code in either repo writes it, and that the sole writer
  (`RouterDetailTabs.tsx:6384`) writes `http-pap`. A hand-edited device could differ. Verifying
  requires reading the live device, which was out of bounds. If it *were* set by hand, §1 Path A
  would work for that one router and break on the next script re-paste (`:6384` unconditionally
  `set`s the property).
- **Whether the `cloudguest-authmac-sched` scheduler is actually installed on any given router.** It
  is generated only into an operator copy-paste script (`RouterDetailTabs.tsx:4245-4276`) and appears
  nowhere in the backend. Its presence per-device is not knowable from code.
- **Whether `render_agent_heartbeat_scheduler` (`app/domains/network_config/renderers.py:2378`) has
  ever run.** It has zero production callers — only `tests/unit/test_network_config.py:1240, 1245` —
  and its own docstring (`:2390-2397`) says the only correct caller "today is nothing in this
  codebase". The equivalent is generated into the operator paste script instead.
- **Whether any `mac-auth-{id}` ip-binding rows exist on live devices** from a past manual
  `network_config` push. Only a device read would tell.
- **Runtime behaviour of `useIsDemo`** (`src/hooks/useCustomerDashboard.ts:25-31`). It defaults to
  `true` and corrects on mount from `localStorage.getItem("cloudguest_token") === "demo-access-token"`
  (`src/services/customer.service.ts:658-661`). I have not verified by execution whether any demo
  branch can paint for a real session before the effect runs; the risk is a first-render flash, not
  a persisted write.
- **Whether FreeRADIUS is actually configured with `rlm_rest` pointing at
  `POST /radius/authorize`** (`app/domains/guest/router.py:1889`). The backend contract is real and
  well documented (`app/domains/guest/service.py:19-45`); the server-side config lives outside both
  repos.
