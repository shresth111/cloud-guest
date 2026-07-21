"""Campaigns domain: post-login guest campaigns (survey/banner/redirect)
shown through the captive portal -- Dashboard -> Campaigns -> Guest
Session -> `campaigns`/`campaign_questions`/`campaign_responses`/
`campaign_assets`/`campaign_impressions`.

## Friction: a survey is a real interruption, not a free feature

Every guest who sees a campaign is a guest whose login just got slower.
`Campaign.is_skippable` defaults to `True` and `Campaign.display_rule`
defaults to `DisplayRule.ONCE_PER_N_DAYS` (7 days) -- see
`constants.py`'s own defaults -- specifically so the *easiest* way to
configure a campaign is also the least intrusive one.

**`DisplayRule.EVERY_LOGIN` combined with `Campaign.is_skippable=False`
is a guest-experience-hostile combination and should be avoided.** A
guest who cannot get online without completing a mandatory survey on
every single visit will not come back, and (for a paying hotel/hostel
guest specifically) is a real complaint, not just an inconvenience. This
domain does not forbid that combination outright -- an admin may have a
genuine, deliberate reason for a one-time mandatory consent/waiver
survey -- but it is never the default, and no code path in this domain
nudges an admin toward it.

## Runtime status, not just stored status

A Celery beat sweep (`tasks.sweep_campaign_status_transitions`, every
`constants.CAMPAIGN_STATUS_SWEEP_INTERVAL_SECONDS`) keeps
`Campaign.status` reasonably fresh for admin dashboards, but the
guest-facing "what should this guest see right now" read path
(`service.get_next_campaign_for_session`) never trusts that stored value
alone -- it always re-derives the effective status from `starts_at`/
`ends_at` at request time (`validators.compute_effective_status`), since
the stored value can lag up to that sweep interval behind reality and a
guest must never be shown a campaign that has already ended.

## PII: composed from `app.common.masking`, not reimplemented

`CampaignResponse` itself stores only `guest_id`/`guest_session_id`
(opaque UUIDs, nothing masking-shaped) and a JSONB `answers` blob -- there
is nothing to mask on that row directly. The real PII surface only
appears where a results export joins in the responding guest's own
identity (`Guest.identifier`/`display_name`) for a human-readable "who
answered" column -- exactly there, this domain reuses
`app.common.masking.MaskedIdentifier`/`MaskedName`, the same way
`app.domains.guest.schemas.GuestResponse` already does, rather than
inventing a second masking mechanism.

## What "network" means for `target_networks`

No distinct network/SSID entity exists anywhere in this codebase below
`app.domains.router.models.Router` (confirmed: `Vlan`/`HotspotProfile`
are router-scoped *config*, never referenced by a guest session; there
is no `GuestWifiConfig`/SSID model at all). `Campaign.target_networks`
is therefore a JSONB array of `Router.id` values with no foreign key
(mirroring `app.domains.queue_management.models.QueueAssignment`'s own
loosely-coupled `target_id` precedent) -- an empty array means "every
router in scope," never "no routers."
"""

from __future__ import annotations
