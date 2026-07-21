# Campaigns: Design Write-Up

## 1. Friction-avoidance defaults

A post-login campaign sits between a guest and the internet access they
just authenticated for. Two fields default toward *not* getting in the
way:

* `Campaign.is_skippable` defaults `TRUE`.
* `Campaign.display_rule` defaults `ONCE_PER_N_DAYS` (7 days), not
  `EVERY_LOGIN`.

`DisplayRule.EVERY_LOGIN` combined with `is_skippable=False` is called
out explicitly, in both `__init__.py`'s module docstring and
`CampaignCreateRequest`'s own schema comment, as a guest-experience-
hostile combination -- shown on every single login with no way to
dismiss it. It is not forbidden outright (an admin may have a real
one-time-mandatory-survey reason), but it is never the default and never
silently arrived at.

## 2. Status: stored vs. effective

`Campaign.status` moves through `DRAFT -> SCHEDULED -> ACTIVE ->
PAUSED/ENDED` (see `CAMPAIGN_STATUS_TRANSITIONS` in `constants.py`).
Two things are true at once:

* A Celery Beat task (`tasks.sweep_campaign_status_transitions`, every
  `CAMPAIGN_STATUS_SWEEP_INTERVAL_SECONDS` = 300s) keeps the *stored*
  value reasonably fresh for admin dashboards, transitioning
  `SCHEDULED -> ACTIVE` once `starts_at` has passed and `* -> ENDED`
  once `ends_at` has passed.
* The guest-facing serving path (`get_next_campaign_for_session`) never
  trusts that stored value alone. It calls
  `validators.compute_effective_status(status, starts_at=, ends_at=,
  now=)` -- a pure function that re-derives the *real* status live from
  `starts_at`/`ends_at` -- on every candidate campaign, every request.

This means a campaign can never be served to a guest up to 5 minutes
late (the sweep's own cadence) just because the cron tick hasn't run
yet, while the stored field an admin's dashboard reads is still kept
reasonably current without every dashboard read re-deriving it itself.
`DRAFT`/`PAUSED`/`ENDED` are stable, admin-only states neither the sweep
nor `compute_effective_status` ever reinterprets -- only
`SCHEDULED`/`ACTIVE` are time-derived.

## 3. Guest eligibility: three rules, one join

`DisplayRule` has three values, each answering "should this guest see
this campaign again right now":

* `EVERY_LOGIN` -- always yes.
* `FIRST_LOGIN_ONLY` -- yes iff this guest has never been shown this
  campaign before (`repository.has_guest_been_shown_campaign`).
* `ONCE_PER_N_DAYS` -- yes iff this guest's last recorded impression for
  this campaign (`repository.get_last_shown_at_for_guest`) is `None` or
  older than `display_interval_days`.

`CampaignImpression` has no `guest_id` column of its own (see
`models.py`'s own docstring) -- both lookups join through
`guest_session_id -> GuestSession.guest_id`, mirroring
`app.domains.guest.repository`'s own established
`select(...).join(...)` precedent for cross-table guest lookups.

`CampaignResponse.guest_id` **is** a direct column (a survey response is
tied to the guest who answered, not just the session), so
`FIRST_LOGIN_ONLY` response-uniqueness (see `models.py`) is a plain
lookup, not a join.

## 4. `target_networks`: no "network" entity to reference

Research across this codebase found no VLAN/SSID/"network" entity ever
referenced by a `GuestSession` -- a session is tied directly to a
`Router`. `Campaign.target_networks` is therefore a JSONB array of real
`Router.id` values, **with no foreign key** -- mirroring
`QueueAssignment.target_id`'s identical loosely-coupled-reference
precedent elsewhere in this codebase. An empty array means "every router
in scope" (org-wide or location-wide, per `Campaign.location_id`); a
non-empty array is validated at creation time (every id must resolve to
a real router in the same organization) but is never a hard FK, since a
router deleted later should not cascade-delete or orphan a campaign
that merely mentions its id.

## 5. Masking in the results export

`campaign_responses.guest_id` links a survey answer to a real guest.
`GET /campaigns/{id}/results/export`'s CSV masks that guest's
`identifier`/`display_name` by default, exactly like every other
guest-PII surface in this codebase (see `app.common.masking`'s own
module docstring). Rather than hand-rolling a "check the masking flag,
call `mask_identifier()`" branch inside the CSV-building code (which
could silently drift from the JSON-response masking path's own
behavior, including its audit-on-bypass side effect), each export row is
built by round-tripping through a small internal-only Pydantic model
(`schemas._ResultsExportRow`, never returned from an endpoint) whose
fields are `MaskedIdentifier`/`MaskedName` -- the exact same
`PlainSerializer` mechanism every JSON response already uses. This
guarantees the two paths (JSON response, CSV export) can never disagree
about whether a given request should see raw or masked guest identity.

## 6. `submit_response`'s uniqueness check is service-layer, not a DB constraint

"One response per guest when `display_rule=FIRST_LOGIN_ONLY`" depends on
a *different* table's column (`Campaign.display_rule`) -- not
expressible as a partial unique index on `campaign_responses` alone (a
partial index's predicate can only reference columns of the table it is
declared on). `CampaignsService.submit_response` enforces this itself
via `repository.get_response_for_campaign_and_guest`, raising
`DuplicateFirstLoginResponseError` on a second attempt -- documented as
a real, honest gap in `models.py`'s own docstring, mirroring
`app.domains.dhcp.models.DhcpPool`'s identical precedent. The plain
(non-unique) `(campaign_id, guest_id)` index on `campaign_responses`
still exists purely for that check's own query performance.

## 7. Guest-facing endpoints carry zero auth

Research confirmed no "resolve the current guest session from a token"
mechanism exists anywhere in this codebase -- `app.domains.guest
.router`'s own `guest_router` carries no `RequirePermission`/
`CurrentUser`/session-resolver dependency at all; guest identity is
always an explicit `guest_session_id` body/query parameter. The three
Campaigns guest-facing endpoints (`/portal/campaigns/next`,
`/respond`, `/impression`) mirror this exactly, registered on their own
`guest_router` (no permission dependencies), separate from the
RBAC-gated admin `router`. `tests/unit/test_campaigns.py`'s own
`TestRoutePermissionStructure` asserts both halves of this contract
structurally: every admin route has a dependency, every guest-facing
route has none.
