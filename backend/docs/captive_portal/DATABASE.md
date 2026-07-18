# Captive Portal: Database Schema

Migration: `alembic/versions/0014_create_captive_portal_tables.py`
(revises `0013_create_voucher_tables`). One new table, extending
`app.database.base.BaseModel` (`id`, `created_at`, `updated_at`,
`deleted_at`/`is_deleted`, `created_by`/`updated_by`, `version`) -- no
changes to any existing table's columns.

## `captive_portal_configs`

One row per branding/content/enabled-login-methods configuration for a
guest WiFi captive portal -- either an organization-level default
(`location_id IS NULL`) or a location-specific override.

| Column | Type | Notes |
|---|---|---|
| `organization_id` | UUID, FK `organizations.id` (`CASCADE`), **not nullable** | A config always belongs to a tenant -- mirrors `voucher_batches.organization_id` (see `FLOW.md` §1) |
| `location_id` | UUID, FK `locations.id` (`CASCADE`), nullable | `NULL` means this organization's default; a specific location otherwise |
| `name` | String(200) | Admin-facing label for the config |
| `is_active` | Boolean, default `true` | Whether this config is currently usable/servable at all |
| `is_default` | Boolean, default `false` | Only meaningful when `location_id IS NULL` -- see below and `FLOW.md` §3 |
| `theme` | String(20), default `light` | `constants.PortalTheme` -- `light`/`dark`/`custom`; a selection the frontend renders against, not rendered here |
| `logo_url` | String(500), nullable | |
| `background_image_url` | String(500), nullable | |
| `primary_color` | String(7), default `#1A73E8` | Validated as a 6-digit hex color (`validators.validate_hex_color`) |
| `secondary_color` | String(7), default `#FFFFFF` | Same validation as `primary_color` |
| `default_language` | String(10), default `en` | |
| `supported_languages` | JSONB, default `["en"]` | List of language codes the portal renders in |
| `advertisement_banner_url` | String(500), nullable | |
| `advertisement_banner_link` | String(500), nullable | |
| `terms_and_conditions_text` | Text, nullable | Inline text variant -- at most one of this/`terms_and_conditions_url` set, never both (see `FLOW.md` §4) |
| `terms_and_conditions_url` | String(500), nullable | External URL variant |
| `privacy_policy_text` | Text, nullable | Same "at most one" pairing as terms and conditions |
| `privacy_policy_url` | String(500), nullable | |
| `splash_headline` | String(200), nullable | |
| `splash_welcome_message` | Text, nullable | |
| `redirect_url` | String(500), nullable | Where a guest is sent after a successful login -- consumed by the future `guest` module, never followed by this one |
| `otp_sms_enabled` | Boolean, default `true` | |
| `otp_email_enabled` | Boolean, default `false` | |
| `voucher_enabled` | Boolean, default `true` | |
| `username_password_enabled` | Boolean, default `false` | **Placeholder** -- no `Guest` model exists yet to authenticate against (`FLOW.md` §5) |
| `social_login_enabled` | Boolean, default `false` | **Schema-only placeholder** -- no real OAuth/social-login integration anywhere in this codebase (`FLOW.md` §5) |
| `social_login_providers` | JSONB, default `[]` | Forward-compatible extension point; stored/returned verbatim, never validated against a real provider registry |

Constraints: `ForeignKeyConstraint` on `organization_id` ->
`organizations.id` (`ondelete=CASCADE`), `ForeignKeyConstraint` on
`location_id` -> `locations.id` (`ondelete=CASCADE`).

Indexes: `organization_id`, `location_id`, `is_active`, `is_default`, plus
the standard `BaseModel` indexes, plus one **partial unique index**:

```text
uq_captive_portal_configs_org_default
  UNIQUE (organization_id) WHERE location_id IS NULL AND is_default = true
```

This is the database-layer backstop for "at most one `is_default=True`
organization-level config per organization" -- the service layer
(`CaptivePortalService._clear_existing_default`) is what actually maintains
this invariant on every write; the index exists so a bypass of that logic
(a direct script, a bug, a concurrent write race) fails loudly with a real
`IntegrityError` rather than silently producing two competing defaults.
Mirrors `app.domains.organization.models.OrganizationMember`'s identical
partial-unique-index convention for its own "at most one active membership
per (organization, user)" invariant.

## Why `is_default` is only meaningful when `location_id IS NULL`

A location-specific override's "is this the config actually served for
this location" question is already fully answered by `is_active` (see
`FLOW.md` §2's resolution lookup -- the highest-precedence tier simply
picks the most-recently-updated *active* config for the exact location,
deterministically, if more than one happens to be active). `is_default`
therefore only needs to disambiguate *which* organization-level
(`location_id IS NULL`) row is the one `resolve_portal_config` falls back
to -- an organization may keep several org-level rows (e.g. a draft being
iterated on alongside a currently-live one), and `is_default` marks the
live one. `validators.validate_default_scope` rejects
`is_default=True` outright when `location_id` is non-null.

## Why there is no dedicated single-active-per-location enforcement

Unlike `is_default` (which has a real, enforced uniqueness invariant),
this module does **not** prevent more than one config being marked
`is_active=True` for the same `(organization_id, location_id)` pair. An
admin iterating on a location's branding may reasonably keep a previous
"active" config around momentarily while testing a new one before
deactivating the old one. `CaptivePortalRepository.find_active_for_location`
picks the most-recently-updated active row deterministically as a
defensive tie-break, rather than raising or silently picking an arbitrary
row -- see that method's docstring.

## Facts genuinely new vs. reused from elsewhere

* **New** (no existing column anywhere): every column on
  `captive_portal_configs` -- nothing elsewhere in this codebase models a
  captive portal's branding/content/enabled-login-methods configuration.
* **Reused, not duplicated**: `organizations.id`/`locations.id` as FK
  targets (Modules 005/006, no schema change to either table);
  `audit_log_entries` (RBAC, Module 002) as the audit sink, via 5
  additive `AuditAction` values -- no new audit table.

## Entity-relationship summary

```text
organizations --< captive_portal_configs (organization_id, NOT NULL)
locations     --< captive_portal_configs (location_id, nullable)
```

No other existing table gained a new column or FK for this module --
unlike BE-008/BE-009's own follow-up migrations (0004/0006/0008 added FKs
to RBAC's scope tables), `captive_portal_configs` is not referenced by any
RBAC scope column, so no RBAC follow-up migration is needed here.
