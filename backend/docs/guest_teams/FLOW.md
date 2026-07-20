# Guest Teams -- Design Write-Up

This document covers every non-obvious design decision made while building
Guest Teams, and the reasoning behind each -- see `README.md` for the
folder/API surface overview and `DATABASE.md` for the schema.

## 1. What "Guest Teams" is, and what it composes

A `GuestTeam` is a named group of guests sharing one access grant: a
shareable join code (like a voucher code, but for joining a *group* rather
than redeeming individual access), an optional shared/pooled data quota
distinct from any individual guest's own per-session quota, an optional
member cap, and an optional expiry. Members join via `POST
/guest-teams/join` (guest-facing, no RBAC) and can be individually removed
or have the whole team's access revoked at once.

This module never reimplements guest identity resolution or session
lifecycle -- both already exist, fully built, in `app.domains.guest`. Every
guest-/session-level operation is a real composition of
`app.domains.guest.service.GuestService`'s own methods, never a
parallel implementation that could silently drift from the original.

## 2. Team status graph

`GuestTeamStatus` is `ACTIVE -> {EXPIRED, REVOKED}`, both terminal (no
outgoing edges, not even to themselves) -- a real, explicit, exhaustively
validated transition graph (`constants.GUEST_TEAM_STATUS_TRANSITIONS`), the
same structural rigor `VoucherBatchStatus`/`GuestSessionStatus` already
establish in their own sibling domains.

This is deliberately **not** `VoucherBatch`'s much richer
draft/pending-approval/approved workflow. A guest team has no analogous
approval gate in this feature's scope: an admin creating a team (an
authenticated, RBAC-gated action) is, by itself, the full authorization
event. There is no print-vendor-style "vouchers get approved before going
live" step for a team roster -- a team is simply created `ACTIVE` and stays
that way until it expires (lazily, on read -- see §3) or is explicitly
revoked (§5). The module brief explicitly allowed this ("a team doesn't
need the SAME approval workflow, but should have an equally real, explicit
status graph, not an ad hoc string") -- this is that real graph, sized to
what this feature actually needs.

## 3. Expiry: lazy, checked on read

`GuestTeamService._refresh_team_expiry` is a structural copy of
`VoucherService._refresh_batch_expiry`: an `ACTIVE` team whose `expires_at`
has passed is flipped to `EXPIRED` the next time it is read (`get_team`,
`list_teams`, `join_team`), not by a background sweep. This mirrors
`VoucherBatchStatus.EXPIRED`'s and `OtpRequest.is_expired`'s identical
"checked on read, not swept by a cron" posture already established
elsewhere in this codebase.

## 4. Join semantics

### 4.1 Reusing `GuestService._get_or_create_guest`

`join_team` composes `GuestService._get_or_create_guest` -- the exact
method the module brief named -- for guest identity resolution. This method
is a leading-underscore "private" method on the concrete `GuestService`
class, which breaks this codebase's usual "depend on a narrow Protocol"
composition convention in exactly one place. That break is deliberate, not
an oversight:

* The brief explicitly requires reusing *this exact method* rather than
  reimplementing "look up an existing guest by identifier, or create one" a
  second time. Two implementations of that logic would inevitably drift on
  edge cases (`total_visit_count`/`first_seen_at` initialization, the
  blocked-guest check's exact placement).
* A `Protocol` cannot honestly describe "depends on this private
  implementation detail" as a loosely-coupled shape. Doing so would be
  theater around a coupling that already exists by design mandate, so
  `GuestTeamService` instead depends on the concrete `GuestService` class
  directly for this one composition, and documents why (see
  `service.py`'s own module docstring).
* `_get_or_create_guest` itself only decides "is there already a row, or do
  we create one" -- it does not perform the identifier lookup. That is
  `GuestRepositoryProtocol.get_guest_by_identifier`, called through
  `guest_service.repository` (a public attribute of `GuestService`,
  exposing its already-public repository) -- the *exact same two calls, in
  the exact same order*, `GuestService.login_via_otp`/`login_via_voucher`
  already make internally. This is composition, not a partial
  reimplementation.

Every *other* composition with `GuestService` in this module
(`get_guest_sessions`, `terminate_session`, `get_or_create_device`) uses
only its ordinary public API, exactly like every other domain's own
compositions do.

### 4.2 Idempotent re-join while active

Calling `join_team` again for a guest who is already an active member of
the team is a no-op: it returns the existing membership unchanged, applies
no `max_members` re-check, and reports `is_new_membership=False` -- mirrors
`GuestService.reconnect`'s own "already connected, no duplicate" posture.

### 4.3 Re-join after removal creates a new membership row

Rejoining after being removed is **allowed** (there is no "once removed,
permanently barred" rule in this feature's scope -- team rosters change as
real groups do: someone stepped out and is now back) and creates a **new**
`GuestTeamMember` row rather than reactivating the old one. See
`models.py`'s own docstring for the schema-level reasoning
(append-only-per-membership-stint, mirroring `GuestSession`'s "reconnect
creates a new row, never resurrects the old one" convention) -- every
join/leave cycle keeps its own permanent `joined_at`/`left_at`/
`removal_reason` history, rather than one mutable row silently overwriting
its own past. This is enforced at the database level by a **partial**
unique index (`(team_id, guest_id)` `WHERE is_active = true AND is_deleted
= false`), not just an application-level check, per the module brief's
explicit requirement -- see `DATABASE.md`.

## 5. Removal ends the member's current session(s) too

`remove_team_member` does not just stop counting a guest towards the
team's roster/shared quota going forward -- it also calls
`GuestService.terminate_session` for every currently-`ACTIVE` session that
guest has. This was a real design decision with two defensible options; the
one taken, and the argument for it:

* This feature's own premise is that a team's members are "tracked/managed
  together as a unit" through their team membership. A guest's continued
  network access, once removed from that unit, is no longer sanctioned by
  the grant that (at least in intent) brought them onto the network as part
  of this group -- silently letting their session continue would undermine
  the entire "manage as a unit" value proposition this domain exists to
  provide, in favor of a purely cosmetic roster change.
* It mirrors this codebase's own one-level-up precedent:
  `GuestService.block_guest` and `VoucherService.revoke_batch` ->
  `bulk_revoke_vouchers_for_batch` are both real access-ending events, not
  just bookkeeping. `remove_team_member` is the individual-member analogue
  of exactly that pattern, one level down from `revoke_team`'s whole-team
  version of the same idea.
* `terminate_session` (not the gentler `disconnect_session`) is used
  because `remove_team_member` is always admin-initiated -- the resulting
  reconnect cooldown (`TERMINATION_RECONNECT_COOLDOWN_MINUTES`) is an
  intended consequence: an ejected member should not be able to trivially
  reconnect via the low-friction `reconnect` flow moments later; they would
  need to present fresh credentials (a new OTP/voucher) to regain network
  access on their own, independent of team membership.
* Failure isolation: a session-termination failure for this one guest never
  prevents the membership-removal itself from succeeding -- it is wrapped
  in its own try/except and only ever logged. The roster change is the
  primary, always-honored effect; ending the session is a best-effort
  follow-up.

The counterargument (removal should only stop counting the member towards
the roster/quota, leaving any already-independently-granted network access
alone) was considered and rejected: since `join_team` itself never
originates a session (see §7), a member's active session was always granted
through an independent OTP/voucher login, not through the team join call
itself -- but the team's whole reason to exist is treating membership as
the unit of control, and a "managed as a unit" revocation that leaves live
network access untouched would be a surprising, easily-overlooked gap for
an operator who just removed someone specifically to cut their access.

## 6. Revocation: real per-member failure isolation

`revoke_team` transitions the team to `REVOKED` **unconditionally, before**
any per-member work begins -- so a caller can always trust that a
successful `revoke_team` call means the team itself is revoked, regardless
of what happens next. It then, for every currently-active member, calls
`GuestService.get_guest_sessions` and `GuestService.terminate_session` (the
real methods -- never a hand-rolled bulk `UPDATE ... SET status =
'terminated'` that would bypass their own audit entry, event, and
reconnect-cooldown side effects) for each currently-`ACTIVE` session.

Each member's lookup+termination work is wrapped in its own try/except: one
member's failure (a stale/already-terminal session, a transient repository
error) is logged and that member is recorded in `failed_member_ids`, but
the loop always continues to the next member -- mirrors the per-item
failure-isolation shape this codebase already established for its own batch
operations (Analytics' daily aggregation sweep, Billing's
`RenewalService` renewal sweep): one bad row must never abort the whole
batch.

**How this was verified, not just asserted:** `test_guest_teams.py`'s
`TestTeamRevocation.test_revoke_has_per_member_failure_isolation` builds two
real team members against a real `GuestService`, then swaps in a fake
`GuestRepositoryProtocol` whose `list_sessions_for_guest` raises for one
specific guest id only. The test asserts (a) the team is still transitioned
to `REVOKED`, (b) the *other* member's session is still terminated and
appears in `terminated_session_ids`, and (c) the failing member appears in
`failed_member_ids` rather than the call raising or silently dropping them.
A second test (`test_revoke_transitions_status_and_terminates_active_sessions`)
additionally asserts on the *real* `GuestService`'s own audit trail
(`guest_session_terminated` written twice, once per member) to prove
`terminate_session` genuinely ran end-to-end, not a mock standing in for it.

## 7. `join_team` never originates a `GuestSession`

`join_team`'s job is guest identity resolution + team roster membership,
nothing more -- it does not call `login_via_otp`/`login_via_voucher` and
never creates a `GuestSession`. A guest's actual WiFi network access is
still granted through the existing, independent
`login_via_otp`/`login_via_voucher` flows; joining a team is an orthogonal
"which group is this guest tracked as part of" fact, not a network-access
grant in its own right. `device_mac`/`device_name` are still accepted and,
if supplied, composed through `GuestService.get_or_create_device` (the same
device-tracking hook `login_via_otp`/`login_via_voucher` themselves use) --
recognizing the physical device presenting the join code is useful even
though no session is created here.

This is why `remove_team_member`/`revoke_team` must independently *look up*
a member's sessions (via `get_guest_sessions`) rather than tracking a
`session_id` on `GuestTeamMember` itself -- there is no such direct link;
membership and session are related only through the shared `guest_id`, and
a member may have zero, one, or (in principle) more than one session by the
time removal/revocation happens.

## 8. Shared quota: a real check, not the enforcement point

`check_shared_quota` sums every currently-active member's *currently-active*
session's own `bytes_uploaded + bytes_downloaded` (via
`GuestSession.total_bytes()`, the model's own existing helper) and compares
it against `shared_data_limit_mb`. Like
`app.domains.billing.service.UsageService.validate_usage_against_license`,
it is deliberately *only* the check, not the mechanism that would cut a
guest's network access mid-session -- there is no live RADIUS daemon in
this sandbox to issue a CoA-Disconnect once a team's pooled quota is
exceeded (the identical honest limitation `GuestService.enforce_timeouts`'s
own docstring already documents for individual-session quota/timeout
detection). A future gate (a scheduled sweep, or a hook inside RADIUS
accounting) could call this method to decide whether to reject further
usage, exactly as a future caller of `validate_usage_against_license` would
decide whether to block a billing action.

`check_shared_quota` sums only **currently-active** sessions (a live "how
much is the team using right now" snapshot). `get_team_summary`'s own
`total_bandwidth_bytes` deliberately sums **every** session (all statuses,
all-time) for a "how much has this team ever consumed" cumulative figure --
two different, both real, questions, answered differently on purpose.

Neither method reuses `app.domains.guest.service.GuestAnalyticsService`'s
own aggregate methods. Those are organization/location- and date-range-
scoped SQL aggregates over *every* guest in scope -- not "sum bandwidth for
this specific list of member guest ids", a genuinely different query shape
`GuestAnalyticsService`/`GuestRepository` do not expose (and this module's
own directory boundary forbids adding a new method to either just for
this). Composing `GuestService.get_guest_sessions` per member (already a
real, public, tenant-scope-enforcing method) and summing via
`GuestSession.total_bytes()` is the honest, available alternative: it
reuses the guest domain's own real session-listing capability and the
model's own existing per-session byte-total helper, rather than re-deriving
either the SQL aggregate logic `GuestAnalyticsService` already owns, or the
`bytes_uploaded + bytes_downloaded` formula, a second, subtly different way.

## 9. Audit-volume judgment call

`create_team`/`remove_team_member`/`revoke_team` are always admin-
initiated, moderate-volume, human-attributable actions -- audited
(`AuditAction.GUEST_TEAM_CREATED`/`GUEST_TEAM_MEMBER_REMOVED`/
`GUEST_TEAM_REVOKED`), the same profile every other domain's own lifecycle
events already meet.

`join_team` is deliberately **not** audited at all, and has no placeholder
`AuditAction` value either -- it is guest-facing, high-volume,
unauthenticated traffic, the identical profile `GuestService.login_via_otp`/
`login_via_voucher`'s own audit-volume judgment call already establishes for
guest logins (which likewise have zero corresponding `AuditAction` values).
Unlike those two methods, this module has no purpose-built high-volume
history table of its own to record every join attempt into either: a guest
team's whole roster, including every historical membership stint, is
already fully visible via `GuestTeamMember` itself (see §4.3's
"append-only-per-stint" write-up), so there is no analogous gap to a
dedicated `GuestLoginHistory`-style table here. Every join is still logged
via the structured logger and as a domain event (`events.GuestMemberJoined`)
for observability.

## 10. RBAC permission-module decision: new, additive `GUEST_TEAMS`

The module brief asked for a real, argued decision between reusing an
existing seeded module (`GUEST_USERS`/`GUEST_SESSIONS`) and adding a new
one. **Decision: add a new, additive `PermissionModule.GUEST_TEAMS`.**

Reasoning:

* `GUEST_USERS` governs individual guest identity records (block/unblock, a
  guest's own profile) and `GUEST_SESSIONS` governs individual WiFi
  connection intervals (disconnect/terminate/reconnect a specific session).
  Neither concern is "team lifecycle/membership" -- creating/revoking a
  *group* grant, capping/pooling quota across a roster, and managing a
  join-code-based roster are a genuinely distinct administrative concern
  from either existing module, exactly the kind of "distinct enough" case
  the module brief itself flagged as warranting a new value.
* This codebase already has precedent for *both* choices at different
  times: `app.domains.voucher` got its own brand-new `VOUCHER` module
  (rather than folding into `GUEST_WIFI`) because a voucher batch's own
  approval workflow/import/export concerns were judged distinct enough;
  `app.domains.captive_portal` similarly got its own module. Meanwhile
  smaller, tightly-scoped additions elsewhere (e.g. RADIUS NAS registration)
  reused an existing seeded module (`RADIUS`) rather than inventing a new
  one, because that concern genuinely *was* just another RADIUS-domain
  action. Guest Teams reads much closer to the first camp: it has its own
  real entity (`GuestTeam`), its own lifecycle graph, and its own dedicated
  endpoints -- not just one more action bolted onto an existing entity's
  surface.
* Reusing `GUEST_SESSIONS.execute` for `revoke_team`, for instance, would
  conflate "end one WiFi connection" with "cancel an entire group's access
  grant and roster" under the same permission key -- a role holder granted
  session-termination rights for support/helpdesk purposes would silently
  also gain team-revocation rights, a real, avoidable privilege-scope
  surprise a new, narrower module avoids entirely.

**What was added, concretely** (see `app/domains/rbac/enums.py`/`seed.py`):

* `PermissionModule.GUEST_TEAMS = "guest_teams"` (additive enum value).
* `MODULE_ACTIONS[GUEST_TEAMS] = (CREATE, READ, DELETE, EXECUTE, MANAGE)` --
  `DELETE` is reserved (not currently wired to any endpoint, mirroring
  `GUEST_USERS`'s own unused `.delete`/`.create`/`.export` actions already
  present in this codebase) for a possible future hard-delete-a-team admin
  action; `EXECUTE` is what `router.py` actually gates member-removal and
  revocation behind (see `README.md`'s own reasoning for why, mirroring
  `GUEST_SESSIONS`'s `.execute` choice for disconnect/terminate).
* `MODULE_DISPLAY_NAMES[GUEST_TEAMS] = "Guest Teams"`.
* `MODULE_NARROWEST_SCOPE[GUEST_TEAMS] = ScopeType.LOCATION` -- same as
  `GUEST_USERS`/`GUEST_SESSIONS`/`VOUCHER` (a team may be org-wide or
  location-specific; `LOCATION` is the narrowest meaningful scope, and
  broader scopes -- `ORGANIZATION`/`GLOBAL` -- remain allowed per
  `allowed_scope_types_for_module`'s existing "narrowest and everything
  broader" rule).
* `SYSTEM_ROLES` overrides added for the roles whose existing profile
  already covers day-to-day guest-roster operations: `Platform Support`
  (`OPERATE`, alongside its existing `GUEST_USERS`/`GUEST_SESSIONS`
  overrides), `Location Manager` (`OPERATE`), `Reception Staff` (`OPERATE`
  -- front-desk staff plausibly create/manage a delegation's team at
  check-in), `Helpdesk` (`READ` -- first-line support can see team state but
  not mutate it, mirroring its own `GUEST_USERS: READ` choice), `Guest
  Operator` (`OPERATE`). Every role whose *default* grant level already
  covers every module automatically (`Super Admin`/`Platform Admin`: `FULL`;
  `MSP Owner`/`MSP Admin`: `OPERATE`; `Organization Owner`: `FULL`;
  `Organization Admin`: `OPERATE`; `Read Only`/`Auditor`: `READ`) needed no
  explicit override -- the new module is simply included in their existing
  default the moment it exists, per `SystemRoleDefinition.grants()`'s own
  iterate-every-`MODULE_ACTIONS`-entry logic. `Network Administrator`,
  `Billing Manager` intentionally received **no** override (both already
  have `NONE`-by-default for every other guest-facing module too --
  network/billing roles have no plausible need to manage a guest roster).

No `docs/rbac/PERMISSION_MATRIX.md` regeneration was performed as part of
this change -- that file is regenerated by a manual command
(`generate_permission_matrix_markdown`) and lives outside this feature's
directory-rule boundary; it will read as stale until someone re-runs that
command, exactly as it would after any other domain's own additive RBAC
change landed without a follow-up regeneration.

## 11. Team join code: reused alphabet, not a new one

`constants.TEAM_CODE_ALPHABET` is `app.domains.voucher.constants
.VOUCHER_CODE_ALPHABET` imported directly (`ABCDEFGHJKLMNPQRSTUVWXYZ23456789`
-- uppercase letters and digits, excluding every character a person could
misread off a printed card or misdictate over a phone call: `0`/`O`,
`1`/`I`/`L`, and no lowercase at all), not a re-derived string literal --
so the two can never silently drift. A team join code solves the identical
problem a voucher code does (a short, print-friendly, verbally-communicable
code a person types into a form), and is, like a voucher code, a physical/
verbally-communicated artifact (announced to a delegation, printed on a
welcome card) -- the same "exclude every character a person could misread"
reasoning applies unchanged. Generation uses the same `secrets.choice`
in-memory-generate-then-DB-existence-check retry loop shape as
`VoucherService._generate_codes`, adapted to one code at a time (a team has
exactly one join code, never a bulk batch of them) -- see
`constants.TEAM_CODE_LENGTH`/`TEAM_CODE_GENERATION_MAX_ROUNDS`.

## 12. `location_id`'s `ondelete` policy: `SET NULL`, not `CASCADE`

`GuestTeam.location_id` uses `ondelete="SET NULL"`, mirroring
`app.domains.guest.models.Guest.location_id`'s reasoning, not
`app.domains.voucher.models.VoucherBatch.location_id`'s `CASCADE`. A guest
team's whole reason to exist is tracking a *group of people* as a durable
unit across a potentially long-lived event; losing precision about which
location record it was originally scoped to (falling back to org-wide) is a
much smaller, more honest consequence than silently deleting the team --
and, transitively, its entire membership/join-code history -- as a side
effect of an unrelated location housekeeping decision. A voucher batch, by
contrast, is inherently tied to *that* location's own printed-code
inventory, so cascading its deletion is the more honest choice there. See
`models.py`'s own docstring for the full write-up.
