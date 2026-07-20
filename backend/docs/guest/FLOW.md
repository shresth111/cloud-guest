# Guest: Flow &amp; Design

## 1. The full guest login journey

```text
1. Guest's device is redirected to the captive portal.
   Frontend: GET /api/v1/captive-portal/resolve?location_id=...
   (app.domains.captive_portal -- already resolves branding + which
   methods are enabled: otp_sms/otp_email/voucher/username_password)

2. Guest submits a code.
   POST /api/v1/guest/login/otp    { identifier, code, auth_method, location_id, router_id, device_mac }
   POST /api/v1/guest/login/voucher { code, identifier, location_id, router_id, device_mac }

   GuestService:
     a. resolve_portal_config(organization_id, location_id)
        -> raise GuestAuthMethodNotEnabledError if the requested method's
           flag is False on the resolved config.
     b. look up an existing Guest by (resolved_org_id, identifier);
        if found and is_blocked -> raise GuestBlockedError immediately,
        BEFORE the OTP/voucher call (a blocked guest never learns whether
        their code would otherwise have worked).
     c. resolve the router (RouterService.get_router) and reject a
        decommissioned/suspended one (RouterNotEligibleForGuestSessionError).
     d. call OtpService.verify_otp / VoucherService.redeem_voucher.
        On failure: record a GuestLoginHistory row (success=False) and
        re-raise the ORIGINAL exception from otp/voucher untouched.
     e. On success: get-or-create the Guest row, get-or-create the
        GuestDevice row (by MAC), create a GuestSession (ACTIVE),
        bump Guest.last_seen_at/total_visit_count, record a
        GuestLoginHistory row (success=True).

3. Guest browses. The router (a RADIUS NAS) periodically sends RADIUS
   Accounting-Interim-Update packets -- translated by this module's
   FreeRADIUS rlm_rest integration into:
   POST /api/v1/radius/accounting  { status_type: "interim-update", session_id, bytes_uploaded_delta, bytes_downloaded_delta }
   -> RadiusService.accounting_interim_update -> GuestService.record_usage
      -> if the running total now exceeds session.data_limit_mb, the
         session is immediately flipped to EXPIRED (disconnect_reason=
         "data_limit_exceeded") -- see §6.

4. Guest disconnects (or the router sends Accounting-Stop, or an admin
   ends the session, or enforce_timeouts sweeps a stale one):
   POST /api/v1/guest-sessions/{id}/disconnect          (admin, normal)
   POST /api/v1/guest-sessions/{id}/terminate            (admin, punitive)
   POST /api/v1/radius/accounting { status_type: "stop", ... }  (RADIUS)
   -> GuestService.disconnect_session / terminate_session
      -> ACTIVE -> DISCONNECTED / TERMINATED (see §4 for the distinction).

5. Guest returns later, still within the reconnect grace window (and,
   if their prior session was TERMINATED, past the termination cooldown):
   POST /api/v1/guests/{id}/reconnect
   -> GuestService.reconnect -> a brand NEW GuestSession row, never a
      resurrected one (see §3).
```

## 2. Composition, not duplication, with OTP/Voucher/CaptivePortal/Router

`GuestService` never verifies an OTP code, redeems a voucher, or checks a
captive portal's enabled-methods flags itself -- it composes with
`OtpService`/`VoucherService`/`CaptivePortalService`/`RouterService` through
narrow, duck-typed protocols (`OtpVerifyProtocol`, `VoucherRedeemProtocol`,
`CaptivePortalLookupProtocol`, `RouterLookupProtocol` in `service.py`), the
exact "`ServiceX` depends on a Protocol satisfied by the real `ServiceY`"
pattern every prior BE-010 part already established (`VoucherService` <-
`OrganizationLookupProtocol`/`LocationLookupProtocol`,
`CaptivePortalService` <- the same two, etc.). On a failed OTP/voucher call,
this module re-raises the **original** exception from that domain
unmodified -- a guest sees exactly the same `OtpCodeMismatchError`/
`VoucherExpiredError` OTP/Voucher's own guest-facing endpoints would
produce, never a re-wrapped or re-worded Guest-domain exception.

## 3. Sessions are append-only: reconnect creates a new session, never resurrects the old one

A `GuestSession` row describes one continuous connection interval: a
`started_at`, an eventual `ended_at`, and monotonically-increasing
`bytes_uploaded`/`bytes_downloaded` counters -- exactly the shape a real
RADIUS accounting trail (Start/Interim-Update/Stop) produces. Every
terminal status (`DISCONNECTED`/`EXPIRED`/`TERMINATED`) is truly terminal --
`constants.GUEST_SESSION_STATUS_TRANSITIONS` gives every non-`ACTIVE`
status zero outgoing edges, including back to itself. Reusing a row across
two different physical connection intervals would corrupt that interval's
own historical accounting and misrepresent the connect/disconnect event
history analytics/audit needs to reconstruct -- the same reasoning
`app.domains.voucher.models.Voucher`'s append-only-per-code convention and
`OtpRequest.is_consumed`'s one-way state already establish.

`GuestService.reconnect` therefore always derives a **new** `GuestSession`
row from the guest's most recent one (same device/router/auth_method,
copied quota+timeout values), bounded by:

* `constants.RECONNECT_GRACE_MINUTES` (30) -- how long after an ordinary
  ended session (`DISCONNECTED`/`EXPIRED`) a guest may reconnect without
  presenting a fresh code.
* `constants.TERMINATION_RECONNECT_COOLDOWN_MINUTES` (60) -- if the guest's
  *most recent* session was an admin `terminate_session` (punitive), the
  guest cannot reconnect at all until this cooldown elapses
  (`SessionTerminationCooldownError`). Once the cooldown elapses, the
  generic grace window is deliberately **not** re-applied to a terminated
  prior session (it would always have already elapsed by then, silently
  turning a temporary punitive block into a permanent one) -- termination
  eligibility is governed entirely by the cooldown check.
* If the guest already has an `ACTIVE` session, `reconnect` is an
  idempotent no-op returning it, rather than creating a duplicate
  concurrent session for the same guest.

**Honest scope limitation:** for a voucher-derived prior session,
`reconnect` does not re-run the voucher's own remaining-uses/validity check
against the original code -- this module never retains a voucher's
plaintext code on a `GuestSession` (nothing after redemption needs it, and
storing it would be a needless secret-retention regression), and
`VoucherService.validate_voucher`/`redeem_voucher` are both keyed by code,
not `voucher_id`. A caller needing a hard revalidation guarantee should have
the guest present the voucher code again via `login_via_voucher`.

## 4. `terminate_session` vs. `disconnect_session`

| | `disconnect_session` | `terminate_session` |
|---|---|---|
| Intent | Normal, non-punitive end of use | Punitive, admin-driven, immediate kill (abuse, policy violation) |
| Who calls it | Admin, or system (RADIUS Accounting-Stop, `enforce_timeouts` calling it indirectly via EXPIRED) | Admin only |
| Audit | Only when `actor_user_id` supplied (admin-initiated) -- a system-initiated disconnect is routine churn, not an admin action | Always audited (`AuditAction.GUEST_SESSION_TERMINATED`) |
| Reconnect afterward | Allowed immediately (within `RECONNECT_GRACE_MINUTES`) | Blocked for `TERMINATION_RECONNECT_COOLDOWN_MINUTES` (`SessionTerminationCooldownError`) |

## 5. FreeRADIUS integration: `rlm_rest`, not raw RADIUS-UDP

There is no real FreeRADIUS server, no `pyrad`/RADIUS-protocol library, and
no live network in this sandbox. The realistic, actually-deployed way to
integrate a Python HTTP backend with FreeRADIUS is via FreeRADIUS's own
**`rlm_rest`** module, which lets FreeRADIUS call out to an HTTP API for its
Authorize/Accounting phases instead of (or alongside) its normal RADIUS-
protocol backends. This module implements exactly that shape -- plain HTTP
endpoints `rlm_rest` would be configured (via `freeradius`'s
`mods-available/rest`) to `POST` to:

* `POST /api/v1/radius/authorize` -- Authorize phase. Given a `username`
  (the guest's identifier) and the calling NAS's identity, returns whether
  a currently-`ACTIVE` `GuestSession` exists on a router bound to that NAS,
  plus reply attributes a real deployment would forward (`Session-Timeout`,
  a bandwidth/data-limit hint).
* `POST /api/v1/radius/accounting` -- one endpoint covering all three
  Acct-Status-Type values (`start`/`interim-update`/`stop`) in a single,
  documented JSON contract (`schemas.RadiusAccountingRequest`), rather than
  three separate endpoints -- `rlm_rest` itself is commonly configured this
  way (one Accounting section dispatching on `%{Acct-Status-Type}`).

A raw UDP RADIUS server would be the wrong transport for a FastAPI app, and
nothing in this sandbox could exercise the real RADIUS wire protocol
anyway -- the honest, useful boundary is the HTTP contract a real
FreeRADIUS deployment's `rlm_rest` module would actually call, the same
interim-design posture `app.domains.wireguard`'s simulated tunnel health
and `app.domains.router_provisioning`/`app.domains.router_agent`'s
simulated device dispatch already establish.

**Auth scheme -- NAS shared secret, not RBAC.** `RadiusService
.authenticate_nas` is a shared-secret comparison against a registered
`RadiusNasClient` (looked up by `nas_identifier`, presented via
`X-RADIUS-NAS-Identifier`/`X-RADIUS-Shared-Secret` headers -- see
`dependencies.CurrentNas`), **not** RBAC's `RequirePermission`: FreeRADIUS
is not a platform user and has no JWT/session to present, exactly the same
posture BE-009's `app.domains.router_agent.dependencies.CurrentAgent`
(device credential via a header) and BE-008's own provisioning check-in
already established for their own non-platform-user callers. The shared
secret is Fernet-encrypted via `app.domains.router.crypto.encrypt_secret`/
`decrypt_secret` (reused, not reimplemented) rather than hashed: unlike a
bearer token/OTP code, a RADIUS shared secret must be recoverable in
plaintext to compare against what `rlm_rest` presents on every single
call -- the identical "must decrypt for live use" reasoning
`Router.api_credentials_encrypted` already established for RouterOS API
credentials.

**`accounting_start` confirms, it does not fabricate.** In this module's
design, a `GuestSession` is always originated by this module's own
guest-facing login endpoints -- a NAS never authenticates a guest
independently of CloudGuest's own OTP/voucher flow (unlike a generic
enterprise RADIUS deployment, where a NAS might originate sessions for
usernames/passwords it has no other record of). The session id handed back
to the guest's device at login (and, in a real deployment, echoed into the
router's RADIUS accounting attributes as `Acct-Session-Id`) is exactly the
`GuestSession.id` already created -- `accounting_start`'s job is to confirm
that id exists and belongs to a router this NAS is registered for.

**NAS registration is a standalone, explicit admin action, not auto-wired
into `router_provisioning`'s completion seam.** The module brief allowed
composing with `router_provisioning`'s provisioning-completion seam for
"Dynamic Client Registration" if it could be done purely additively,
without editing that module at all. On inspection, `router_provisioning
.RouterProvisioningService.complete_provisioning_job` has no
publish/subscribe or webhook mechanism a foreign module could attach a
listener to -- the only way to react to it would be to edit that module's
own service (adding a call out to `guest`), which is outside this task's
directory rule (only additive edits to `otp`/`voucher` are permitted, and
only if genuinely needed) and would invert BE-010's own dependency
direction (Part 4 depending *on* Part 4 code being called *by* an earlier,
independently-releasable module). `POST /api/v1/radius/nas` (RBAC-gated,
`radius.create`) is therefore the sole, explicit way a `RadiusNasClient` is
created -- an honest, simpler design than fabricating a cross-module event
bus that does not exist anywhere else in this codebase either.

## 6. Timeout/quota: a reporting mechanism, not live enforcement

There is no live RADIUS daemon in this sandbox actually disconnecting
devices. `GuestService.enforce_timeouts` (a thin delegation to the
module-level `service.enforce_session_timeouts` -- see the Phase 1 addendum
below) is a status-transition/reporting mechanism: it queries `ACTIVE`
sessions whose `last_activity_at` plus their own `session_timeout_minutes`
has already passed "now" (a real SQL predicate using Postgres's
`make_interval`, not a Python-side scan) and flips them to `EXPIRED` -- the
same honest, "simulated, DB-tracked signal" posture `app.domains.wireguard`'s
tunnel-health computation and `app.domains.router`'s heartbeat-derived
online/offline status already document. A real deployment would pair this
with FreeRADIUS's own `Session-Timeout` reply attribute (already returned by
`RadiusService.authorize`); nothing in this module ever issues a live
CoA-Disconnect packet to a real NAS.

> **Guest Session Engine (Phase 1) addendum:** the "and/or a scheduled sweep
> calling `enforce_timeouts`" this section used to describe as a future
> possibility is now real. `app.domains.guest.tasks.run_session_timeout_sweep`
> is registered with `app.core.celery_app` and fires every
> `constants.SESSION_TIMEOUT_SWEEP_INTERVAL_SECONDS` (5 minutes) via Celery
> Beat's `guest-session-timeout-sweep` entry. The sweep logic itself did not
> change -- it was pulled from `GuestService.enforce_timeouts`'s method body
> into a standalone `service.enforce_session_timeouts(repository)` function
> so the Celery task can call it with just a `GuestRepository`, without
> constructing a full `GuestService` and its unrelated
> otp/voucher/captive-portal/router dependency chain. `GuestService
> .enforce_timeouts` still exists, unchanged in signature/behavior, and now
> simply delegates to that function.

Quota enforcement (`validators.is_quota_exceeded`) is a pure, in-memory
check of `bytes_uploaded + bytes_downloaded >= data_limit_mb * 1MB` -- it
runs synchronously inside `GuestService.record_usage` (the method the
RADIUS Interim-Update accounting call drives), immediately flipping the
session to `EXPIRED` the moment a reported usage delta crosses the limit.
This is more "live" than the pure timeout sweep only because it piggybacks
on an accounting call this module already receives -- there is still no
independent, out-of-band mechanism polling live network usage.

## 6a. Concurrent session limit (Guest Session Engine, Phase 1)

`login_via_otp`/`login_via_voucher` now reject a login with
`ConcurrentSessionLimitExceededError` (`409`) if the resolved guest already
holds `constants.DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST` (currently `3`)
`ACTIVE` sessions. The check:

* Runs via `GuestService._enforce_concurrent_session_limit`, backed by
  `GuestRepository.count_active_sessions_for_guest` (a plain
  equality-filtered `GenericRepository.count` -- no hand-written SQL
  needed) and the pure `validators.is_concurrent_session_limit_reached`.
* Is placed **before** `OtpService.verify_otp`/`VoucherService
  .redeem_voucher` are called, not after -- a guest already at the limit
  never spends a real OTP attempt or a single-use voucher on a login that
  was always going to be rejected.
* Is skipped entirely for a never-before-seen identifier (`existing_guest
  is None`): a brand-new guest trivially holds zero active sessions, so
  there is no `guest_id` yet to count against.
* Is **not** applied to `reconnect` -- that method is already idempotent
  against the guest's own existing `ACTIVE` session (returns it unchanged,
  see §3) and only ever derives a new row when the guest holds zero active
  sessions, so it can never itself push a guest over the limit.
* Does **not** auto-evict the guest's oldest session to make room. An admin
  frees a slot with the existing `terminate_session`/`disconnect_session`
  endpoints -- this module never ends a session the guest didn't ask to end
  and an admin didn't explicitly choose to end.

The limit is a single platform-wide constant in Phase 1, not yet
per-organization/location configurable -- see the Architecture Design
Document §13 ("Policy Engine Integration") for why full configurability is
deliberately deferred to the Phase 2 `policy` module rather than added here
as a one-off `Organization.settings` key.

## 6b. Per-guest device limit (Phase 1 BhaiFi-parity)

`login_via_otp`/`login_via_voucher` also reject a login with
`GuestDeviceLimitExceededError` (`409`) if registering the presented MAC
against the resolved guest would push their distinct-device count to or
past the resolved limit. Unlike §6a's concurrent-session limit, this one
**is** wired through the real Policy Engine:

* `GuestService._resolve_device_limit` calls
  `PolicyService.resolve_effective_policy(policy_type=PolicyType.DEVICE,
  ...)` when a `policy_lookup` hook is wired (see
  `app.domains.policy.schemas.DevicePolicyRules.max_devices_per_guest`),
  falling back to `constants.DEFAULT_MAX_DEVICES_PER_GUEST` (`3`) only when
  no Policy Engine is configured at all, or the resolved rules omit the
  field.
* `_enforce_device_limit` is a no-op when `device_mac` is absent (nothing
  to register) or when the MAC already belongs to this exact guest (a
  returning device, not a new one) -- checked via `get_device_by_mac`
  without mutating anything.
* Placed in the identical "reject before OTP verification/voucher
  redemption" position §6a's own check occupies.

## 7. `data_limit_mb`/`session_timeout_minutes`: copied, not referenced

Mirrors `app.domains.voucher.models.Voucher.expires_at`'s identical
reasoning: `login_via_voucher` copies the redeeming voucher's
`batch.data_limit_mb`/`batch.validity_minutes` onto the new
`GuestSession` at creation time, rather than the session holding a live
reference back to the voucher batch. A later change to the batch's own
`data_limit_mb` (an admin editing an in-flight campaign) must never
retroactively alter an already-in-progress guest's quota. For a voucher
session, `session_timeout_minutes` is populated from
`batch.validity_minutes` -- deliberately repurposed from "inactivity
timeout" into "this session's overall remaining lifetime since redemption",
since a voucher's whole point is a bounded total access window. For an
OTP-authenticated session (no voucher to copy from), `session_timeout_minutes`
falls back to `constants.DEFAULT_SESSION_TIMEOUT_MINUTES` (240, a
platform-wide default -- this module has no per-location default config of
its own) and `data_limit_mb` is left `None` (unlimited).

## 8. Audit-volume judgment call

Guest logins (`login_via_otp`/`login_via_voucher`) are high-volume,
guest-facing traffic -- the identical profile OTP's own *request* tiering
already establishes. This module writes **no** audit entry of its own for a
routine successful or failed login: the composed calls it makes already
write their own audit entries for the moments that matter
(`OtpService.verify_otp` writes `OTP_VERIFIED`/`OTP_VERIFICATION_FAILED`;
`VoucherService.redeem_voucher` writes `VOUCHER_REDEEMED`/
`VOUCHER_REDEMPTION_FAILED`) -- a second, guest-flavoured audit row for the
same event would be pure duplication. Every attempt is still recorded, at
guest-module granularity, in `GuestLoginHistory` (a purpose-built,
high-volume table, not RBAC's audit table -- mirrors
`app.domains.router_provisioning.models.RouterEvent`'s identical
separation) and logged via the structured logger.

`GuestBlocked`/`GuestUnblocked`/`GuestSessionTerminated` **are** always
audited -- low-volume, always admin-initiated, exactly the profile every
other domain's own lifecycle events meet. `GuestSessionDisconnected` is
audited only when admin-initiated (see §4). `RadiusNasRegistered` is always
audited (low-volume, admin-driven infrastructure change).

## 9. `GuestLoginHistory.guest_id` nullability

A failed login attempt (wrong OTP code, expired/revoked voucher, blocked
guest, disabled auth method) must still be logged for audit/analytics
visibility, but the identifier presented may not correspond to any real,
already-created `Guest` row yet. Mirrors `app.domains.otp.models
.OtpRequest`'s own "self-contained, no forced FK" posture:  `guest_id` is
populated whenever a real `Guest` row for that identifier+organization
already exists (a *known* guest's failed attempt is still attributed to
them), but a failure never force-creates a `Guest` row purely to have
something to attach the history row to. Only a *successful* login ever
creates a new `Guest` row. `identifier` is always the raw presented value;
`guest_id` is best-effort.

## 10. MAC-address uniqueness: globally unique, `guest_id` reassignable

A MAC address is a real-world hardware identifier for one physical device,
independent of which guest identifier happens to be presented alongside it
at any given login. `GuestDevice.mac_address` is therefore **globally
unique** (not unique per `(guest_id, mac_address)`), and `guest_id` is
reassignable: if the same MAC is later presented alongside a *different*
identifier (e.g. a shared family phone first used with a parent's number,
later a child's), `GuestService.get_or_create_device` re-points the
existing row's `guest_id` at the new owner rather than creating a second
row for the same physical device.

The alternative (unique per `(guest_id, mac_address)`) was considered and
rejected: it would let one physical phone accumulate an unbounded number of
`GuestDevice` rows (one per identifier ever used with it), fragmenting "top
devices" analytics (the same phone logging in with 3 different numbers
would count as 3 devices) for no real benefit -- nothing in this module's
scope needs to remember "this MAC was once associated with guest X" after
guest Y has since claimed it. A `GuestDevice` row is a statement about a
device, not about a guest-device pairing -- the same way a real captive
portal's MAC-based device recognition works in practice.

## 11. Composing analytics without touching otp/voucher tables

`GuestAnalyticsService.get_otp_success_rate`/`get_voucher_usage` are
derived entirely from this module's **own** tables (`GuestLoginHistory`,
`GuestSession`) -- no new method was added to `app.domains.otp`/
`app.domains.voucher`'s repository or service layer, and neither module's
own tables are queried directly. This module's own login orchestration
already records every OTP-driven attempt (success or failure) it brokers
into `GuestLoginHistory`, and every voucher-authenticated session into
`GuestSession` -- that data is not just sufficient, it is *more* precisely
scoped to guest-WiFi traffic than a naive aggregate over `otp_requests`
would be (which also carries any other `OtpPurpose` value and any request
that was rate-limited before a `verify_otp` call ever happened). This was a
deliberate check-first decision per the module brief's "prefer composing
over adding" guidance.

All other analytics queries (`get_summary`, `get_top_locations`,
`get_top_devices`) are real SQL aggregates (`func.count`/`func.sum`/
`func.avg`, `GROUP BY`) over `GuestSession` (denormalized with its own
`organization_id`, copied from `location_id` at session-start time --
mirrors `app.domains.router.models.Router.organization_id`'s identical
denormalization rationale, avoiding a join through `locations` on every
tenant-scoped analytics call), never a Python-side loop over fetched rows.

## 12. FUP (Fair Usage Policy) quota tracking (Phase 1 BhaiFi-parity)

`models.GuestQuotaUsage` holds one row per `(guest_id, period_type)`
(daily/weekly/monthly) -- the guest-level aggregate a single
`GuestSession`'s own byte counters cannot answer on their own (see §3's
"append-only" write-up: a session describes one connection interval, not a
calendar period spanning many reconnects/devices).

* **Rollover** goes through one shared function,
  `service.get_or_reset_quota_usage`, which checks whether real wall-clock
  time (in the guest's own organization's `Organization.timezone`, via
  `validators.compute_period_start`) has carried a row past its own
  `period_start` -- if so, the row's counters reset to zero and
  `period_start` advances, before the caller ever sees it. Both
  request-triggered call sites (`_enforce_fup_quota`, `record_usage`) and
  the two Beat sweeps below call this exact function, so there is one
  non-divergent definition of "has this guest's day/week/month rolled
  over" in the codebase.
* **Bytes** are bumped incrementally on every RADIUS Interim-Update
  (`record_usage` -> `_track_fup_data_usage`), riding for free on a call
  that already happens. **Minutes** count guest-level wall-clock connected
  time -- deliberately **not** summed across a guest's concurrent sessions
  (two simultaneous devices connected for 10 minutes is 10 minutes of
  usage, not 20) -- accrued instead by
  `tasks.run_fup_time_accrual_sweep` (Celery Beat, every 5 minutes), since
  RADIUS has no equivalent "elapsed time" push the way it does for bytes.
* **Enforcement**: `_enforce_fup_quota` (the real, never-swallowed
  checkpoint) runs once at the start of `login_via_otp`/`login_via_voucher`,
  in the identical position §6a/§6b's own checks occupy -- but only when a
  `policy_lookup` hook is wired **and** a `PolicyType.FUP` rule resolves a
  concrete limit; there is no platform-wide fallback constant here at all
  (unlike `DEFAULT_MAX_DEVICES_PER_GUEST`), since no existing hardcoded
  constant anywhere in this codebase ever named a daily/weekly/monthly cap
  to honestly mirror. Mid-session, both a data cap (`record_usage`) and a
  time cap (`run_fup_time_accrual_sweep`) crossing lead to the same
  outcome: the offending session(s) flip to `EXPIRED` (mirrors
  `enforce_session_timeouts`'s own system-initiated `EXPIRED`, never
  `DISCONNECTED`) -- best-effort, additive tightening on top of the
  login-time gate, never a replacement for it.
* **`tasks.run_quota_reset_sweep`** (Celery Beat, hourly) proactively rolls
  every `GuestQuotaUsage` row over the moment its own period boundary
  passes, so e.g. an admin's "quota remaining" view reflects a fresh
  allowance even for a guest who hasn't reconnected yet in the new period --
  idempotent (a row already reset for the current period is a no-op).

## 13. Session Pause/Resume/Extend + real RADIUS Disconnect-Request (Phase 1 BhaiFi-parity)

`constants.GuestSessionStatus.PAUSED` is the one status with an outgoing
edge back to `ACTIVE` (see §"Status transition graph" in `DATABASE.md`) --
an admin-driven, *reversible* temporary suspension, distinct from
`terminate_session`'s permanent kill:

* `pause_session` validates `ACTIVE -> PAUSED`, updates the row in place
  (never a new session, unlike reconnect -- see §3), and issues a real live
  RADIUS Disconnect-Request (below) to actually cut the guest's network
  access, not just flip a database flag.
* `resume_session` reverses it (`PAUSED -> ACTIVE`), refreshing
  `last_activity_at` so a just-resumed session is never immediately
  eligible for the timeout sweep. **Honest scope limitation:** this only
  flips CloudGuest's own authorization state back to `ACTIVE` (so the
  *next* RADIUS Authorize call succeeds again) -- it cannot force the
  guest's device to reassociate with the NAS on its own; the guest
  reconnects the same way any client does after any Disconnect-Request.
* `extend_session` pushes `session_timeout_minutes` forward by an
  admin-specified amount (legal on `ACTIVE` or `PAUSED`) -- a DB-level
  extension only, mirroring §6's "reporting mechanism, not live
  enforcement" posture; no RADIUS attribute is pushed for this one (unlike
  pause's Disconnect-Request, there is no universally-supported CoA
  equivalent for "extend remaining time" against a typical RouterOS
  hotspot deployment).

**Real RADIUS Disconnect-Request, replacing §5/§6's own documented
no-op:** `app.domains.guest.radius_coa` builds a genuine, wire-correct RFC
2865/5176 Disconnect-Request packet (Code/Identifier/Length header, an MD5
Request Authenticator, User-Name/Acct-Session-Id/NAS-IP-Address/
Framed-IP-Address attributes) and sends it via a real UDP socket
(`asyncio.to_thread`-wrapped, mirroring `app.core.celery_app
.ping_celery_workers`'s identical "blocking network call, bridged for
async callers" posture). `service.issue_live_disconnect` -- a module-level,
best-effort function shared by `disconnect_session`/`terminate_session`/
`pause_session` **and** the two system-driven sweeps
(`enforce_session_timeouts`/`run_fup_time_accrual`) -- resolves the
session's `RadiusNasClient`, decrypts its shared secret, and sends the
packet, never raising: an unreachable/misconfigured NAS must never prevent
a session from ending in this platform's own records. What remains honest
about "no live counterpart in this sandbox": there is no real FreeRADIUS/
RouterOS device here to return a real Disconnect-ACK, so `send_packet`
timing out (`None`) is this function's expected, non-fatal common case --
see `radius_coa.py`'s own module docstring for the full "what's real, what
isn't" write-up. Deliberately **no** Message-Authenticator (RFC 3579
attribute 80): most FreeRADIUS/RouterOS deployments accept a
Disconnect-Request authenticated by the Request Authenticator alone, and
adding a second crypto primitive for a packet type this sandbox can never
round-trip test against a live NAS anyway would be complexity without
verifiable payoff.

## 14. Speed-linked voucher redemption (Phase 1 BhaiFi-parity)

`login_via_voucher` composes with `app.domains.voucher`'s new
`VoucherPlan`/`VoucherSeries` (see `docs/voucher/FLOW.md`) via
`_assign_voucher_queue`: when the redeemed `Voucher.plan_id` resolves (via
`VoucherService.get_plan_queue_profile_id`, a narrow, read-only method --
`voucher` never composes `queue_management` itself) to a plan carrying a
real `queue_profile_id`, this method creates **and applies** a real
`QueueAssignment` (`QueueTargetType.VOUCHER`, `target_id=voucher.id`) via
`QueueManagementService.create_assignment`/`apply_queue` -- **not**
`resolve_and_assign_queue` (the mechanism `_assign_guest_queue`'s own
per-`SESSION` assignment already uses), since that method always resolves
`PolicyType.BANDWIDTH` internally and has no override for an already-known,
explicit profile. Best-effort and additive (mirrors `_assign_guest_queue`'s
identical posture): a no-op when no `queue_assignment_hook` is wired, the
voucher has no `plan_id`, the plan has no `queue_profile_id`, or
`session.ip_address` is unknown; never raises.

**Why this composition lives in `GuestService`, not
`VoucherService.redeem_voucher`:** a `QueueTargetType.VOUCHER` assignment
is device-bound (requires a real `router_id`/`device_target`, per
`queue_management.validators.validate_target`'s
`DEVICE_BOUND_TARGET_TYPES` check) -- `redeem_voucher` is deliberately
router-agnostic (a voucher code by itself names no router; only the guest
login redeeming it does), so only `GuestService`, which already has the
session's real router in hand after session creation, can supply what a
real assignment needs.
