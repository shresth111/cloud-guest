# Campaigns Domain

The Campaigns domain is CloudGuest's post-login guest campaign engine:
Dashboard -> Campaigns -> `campaigns`/`campaign_questions`/
`campaign_responses`/`campaign_assets`/`campaign_impressions` -> served
on the captive portal after a guest logs in.

`PermissionModule.CAMPAIGNS` was already seeded (scope `LOCATION`, full
`(CREATE, READ, UPDATE, DELETE, APPROVE, EXPORT, MANAGE)` action set)
before this domain existed to claim it -- no RBAC enum/seed change was
needed to build this.

Three campaign types share one schema:

* **SURVEY** -- one or more questions (`SINGLE_CHOICE`/`MULTI_CHOICE`/
  `RATING_5`/`FREE_TEXT`), answered once per guest session.
* **BANNER** -- an image + optional click-through URL, shown post-login.
* **REDIRECT** -- a click-through URL only, no image.

See `FLOW.md` for the full design write-up and `DATABASE.md` for the
schema.

## Folder Structure

```text
backend/
  alembic/
    versions/
      0048_create_campaigns_tables.py
  app/
    core/
      celery_app.py          # beat_schedule gained campaigns-sweep-status-transitions
    domains/
      campaigns/
        __init__.py           # friction-avoidance + runtime-status design write-up
        constants.py           # CampaignType/Status/DisplayRule/AnswerType, sweep interval, task name
        models.py                # Campaign, CampaignQuestion, CampaignResponse, CampaignAsset, CampaignImpression
        exceptions.py             # CampaignsError subclasses (CloudGuestError)
        events.py                  # CampaignCreated/Updated/StatusChanged/Deleted/ResponseSubmitted/ImpressionRecorded
        validators.py                # pure status-transition/effective-status/question/asset/display-rule validation
        repository.py                 # CampaignsRepositoryProtocol/Repository (5 tables)
        service.py                     # CampaignsService: CRUD + lifecycle + clone + guest-facing serving + results
        schemas.py                      # Pydantic request/response DTOs (admin + guest-facing)
        dependencies.py                   # FastAPI DI wiring (composes org/location/router/guest DI)
        router.py                          # FastAPI routes: admin router + zero-auth guest_router
        tasks.py                            # Celery Beat task: sweep_campaign_status_transitions
      guest/                    # composed read-only (GuestRepository: sessions/guests), never modified
      organization/             # composed (get_organization), never modified
      location/                 # composed (get_location), never modified
      router/                   # composed (get_router, for target_networks validation), never modified
      rbac/
        enums.py               # AuditAction gained campaign_* values (module already fully seeded)
  docs/
    campaigns/
      README.md (this file)
      FLOW.md
      DATABASE.md
  tests/
    unit/
      test_campaigns.py       # validators/service/guest-serving/results/masking/API structural tests
      test_analytics.py       # beat_schedule structural assertion updated (13th entry)
```

## API Surface

Admin endpoints are registered under `/api/v1/campaigns` (see
`app/api/v1/router.py`), every one RBAC-gated by
`RequirePermission("campaigns.*")`:

* `POST/GET /campaigns`, `GET/PUT/DELETE /campaigns/{id}` -- CRUD.
* `POST /campaigns/{id}/clone` -- deep-copies a campaign's own fields
  plus its questions/assets into a new `DRAFT` campaign (never copies
  responses/impressions).
* `POST /campaigns/{id}/schedule|pause|resume|end` -- lifecycle
  transitions (see `FLOW.md` §2 for the legal transition graph).
* `POST/GET /campaigns/{id}/questions`, `PUT/DELETE
  /campaigns/questions/{id}` -- SURVEY question management.
* `POST/GET /campaigns/{id}/assets`, `PUT/DELETE
  /campaigns/assets/{id}` -- BANNER/REDIRECT asset management.
* `GET /campaigns/{id}/results` -- aggregated, per-question breakdown.
* `GET /campaigns/{id}/results/export` -- CSV export, guest identity
  masked by default (see `FLOW.md` §5).

Guest-facing endpoints are registered under `/api/v1/portal/campaigns`
via a **separate router with zero RBAC dependencies** -- mirrors
`app.domains.guest.router`'s own `guest_router`:

* `GET /portal/campaigns/next?session_id=...` -- resolves the one
  campaign (if any) this guest session should see right now.
* `POST /portal/campaigns/{id}/respond` -- submits SURVEY answers.
* `POST /portal/campaigns/{id}/impression` -- records that a campaign
  was shown (and whether it was skipped/clicked).

## What this domain deliberately does not do

* No live device push -- a campaign is served entirely by the captive
  portal calling the guest-facing endpoints above; nothing here talks to
  a router.
* No "network"/VLAN/SSID entity -- `Campaign.target_networks` is a JSONB
  array of `Router.id` values with no foreign key (see `FLOW.md` §4).
* No locale negotiation for `CampaignAsset` -- `get_next_campaign_for_session`
  returns the first asset row for a campaign; multi-locale asset
  selection is a real, documented gap, not a silent one.
