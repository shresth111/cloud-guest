# Campaigns Domain -- Database Schema

Migration: `alembic/versions/0048_create_campaigns_tables.py`. See
`FLOW.md` for the full design reasoning behind each decision below.

## `campaigns` (new table)

One row per campaign.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `organization_id` | `UUID` | No | FK -> `organizations.id`, `ondelete="CASCADE"`. |
| `location_id` | `UUID` | Yes | FK -> `locations.id`, `ondelete="CASCADE"`. `NULL` means org-wide -- mirrors `ConfigTemplate`'s own nullable-FK-means-platform/org-wide convention, one level down the hierarchy. |
| `name` | `VARCHAR(200)` | No | Admin-facing label. |
| `campaign_type` | `VARCHAR(20)` | No | `SURVEY`/`BANNER`/`REDIRECT` (`constants.CampaignType`). |
| `status` | `VARCHAR(20)` | No | `server_default 'draft'` -- see `FLOW.md` §2 for stored-vs-effective status. |
| `starts_at` / `ends_at` | `TIMESTAMPTZ` | Yes | Both nullable; `starts_at` is required to `schedule` a campaign (`CampaignNotSchedulableError` otherwise). |
| `display_rule` | `VARCHAR(20)` | No | `server_default 'once_per_n_days'` -- see `FLOW.md` §1/§3. |
| `display_interval_days` | `INTEGER` | Yes | `server_default 7`. Only meaningful when `display_rule='once_per_n_days'`; validated at the service layer (`validators.validate_display_rule_fields`), not a `CHECK` constraint. |
| `target_networks` | `JSONB` | No | `server_default '[]'`. Array of `Router.id` strings, **no foreign key** -- see `FLOW.md` §4. Empty means every router in scope. |
| `is_skippable` | `BOOLEAN` | No | `server_default true` -- see `FLOW.md` §1. |

Indexes: `ix_campaigns_organization_id`, `ix_campaigns_location_id`,
`ix_campaigns_status`, `ix_campaigns_campaign_type`.

## `campaign_questions` (new table)

One row per `SURVEY` question, ordered by `order_index`.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `campaign_id` | `UUID` | No | FK -> `campaigns.id`, `ondelete="CASCADE"`. |
| `order_index` | `INTEGER` | No | Display order within the campaign. |
| `question_text` | `TEXT` | No | |
| `answer_type` | `VARCHAR(20)` | No | `SINGLE_CHOICE`/`MULTI_CHOICE`/`RATING_5`/`FREE_TEXT` (`constants.AnswerType`). |
| `options` | `JSONB` | No | `server_default '[]'`. Populated only for `SINGLE_CHOICE`/`MULTI_CHOICE` -- validated at the service layer (`validators.validate_question_options`). |
| `is_required` | `BOOLEAN` | No | `server_default true`. |

Indexes: `ix_campaign_questions_campaign_id`,
`ix_campaign_questions_campaign_id_order_index` (composite, backs the
ordered read path).

## `campaign_responses` (new table)

One row per guest's completed SURVEY answers.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `campaign_id` | `UUID` | No | FK -> `campaigns.id`, `ondelete="CASCADE"`. |
| `guest_id` | `UUID` | No | FK -> `guests.id`, `ondelete="CASCADE"`. Direct column (unlike `campaign_impressions`, see below) -- a response is a first-class artifact tied to the guest who submitted it. |
| `guest_session_id` | `UUID` | No | FK -> `guest_sessions.id`, `ondelete="CASCADE"`. |
| `submitted_at` | `TIMESTAMPTZ` | No | |
| `answers` | `JSONB` | No | `server_default '{}'`. Keyed by the responding `CampaignQuestion.id` (string) -> the guest's raw answer. |

Indexes: `ix_campaign_responses_campaign_id`,
`ix_campaign_responses_guest_id`,
`ix_campaign_responses_guest_session_id`,
`ix_campaign_responses_campaign_id_guest_id` (composite, plain/
non-unique -- see `FLOW.md` §6 for why "one response per guest when
`display_rule=FIRST_LOGIN_ONLY`" is a service-layer check, not a
database constraint, and why this index exists purely for that check's
own query performance).

## `campaign_assets` (new table)

The visual/redirect content for a `BANNER`/`REDIRECT` campaign.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `campaign_id` | `UUID` | No | FK -> `campaigns.id`, `ondelete="CASCADE"`. |
| `image_url` | `VARCHAR(1000)` | Yes | |
| `click_url` | `VARCHAR(1000)` | Yes | |
| `alt_text` | `VARCHAR(300)` | Yes | |
| `locale` | `VARCHAR(10)` | Yes | No locale-negotiation logic in this pass -- see `README.md`'s own "what this domain deliberately does not do". |

Validated at the service layer that at least one of `image_url`/
`click_url` is set (`validators.validate_asset_urls`) -- a row with
neither would be inert.

Index: `ix_campaign_assets_campaign_id`.

## `campaign_impressions` (new table)

Append-only "this campaign was shown to this guest session" events --
no `update`/soft-delete method exists for this row anywhere in this
domain's own repository.

| Column | Type | Nullable | Notes |
|---|---|---|---|
| `campaign_id` | `UUID` | No | FK -> `campaigns.id`, `ondelete="CASCADE"`. |
| `guest_session_id` | `UUID` | No | FK -> `guest_sessions.id`, `ondelete="CASCADE"`. **No direct `guest_id` column** -- guest-level eligibility checks join through `GuestSession.guest_id` (see `FLOW.md` §3). |
| `shown_at` | `TIMESTAMPTZ` | No | |
| `was_skipped` | `BOOLEAN` | No | `server_default false`. |
| `was_clicked` | `BOOLEAN` | No | `server_default false`. |

Indexes: `ix_campaign_impressions_campaign_id`,
`ix_campaign_impressions_guest_session_id`,
`ix_campaign_impressions_shown_at`.

---

Every table above also has the standard `BaseModel` columns (`id`,
`created_at`, `updated_at`, `deleted_at`, `is_deleted`, `created_by`,
`updated_by`, `version`) and their own five standard indexes.

Table creation order in the migration respects FK dependencies:
`campaigns` first, then `campaign_questions`/`campaign_responses`/
`campaign_assets`/`campaign_impressions` (the latter two depending on
`campaigns` and `guest_sessions`/`guests`). `downgrade()` drops in
exact reverse order.

## RBAC schema change: none

`PermissionModule.CAMPAIGNS` (`rbac/enums.py`) was already seeded
(scope `LOCATION`, full `(CREATE, READ, UPDATE, DELETE, APPROVE,
EXPORT, MANAGE)` action set) before this domain existed to claim it --
zero enum/seed changes needed. Five additive `AuditAction` enum values
(`CAMPAIGN_CREATED`/`_UPDATED`/`_STATUS_CHANGED`/`_DELETED`/`_CLONED`)
were added. No migration needed for any of this, since
`permission_groups`/`permissions`/`permission_scopes`/`role_permissions`
rows are all seeded idempotently at application/CLI startup by
`seed_rbac`, never by a migration (see migration `0039`'s identical
note).
