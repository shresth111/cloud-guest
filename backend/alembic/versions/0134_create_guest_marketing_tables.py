# ruff: noqa: E501 -- frozen template copy (spec §6) has long literal lines.
"""Guest Marketing tables, portal consent columns, and the 10 system templates.

Contract: ``wyfy-specs/guest-marketing-campaigns.md`` §4 and §6.

Additive only:

* six new tables -- ``guest_marketing_consents`` (current consent, one live
  row per guest per channel), ``guest_marketing_consent_events``
  (append-only DPDP proof; never pruned), ``marketing_suppressions``,
  ``marketing_templates``, ``marketing_campaigns``,
  ``marketing_campaign_recipients`` (the delivery log);
* three columns on ``captive_portal_configs``: ``marketing_consent_enabled``
  (NOT NULL, server default false -- every venue starts with the opt-in
  off), ``marketing_consent_text`` and ``marketing_consent_text_version``;
* the 10 system templates (``organization_id IS NULL``), upserted on
  ``system_key`` so a later revision can ship new wording by re-running the
  same upsert. ``sms_dlt_template_id`` and ``whatsapp_content_sid`` start
  NULL and ``whatsapp_approval_status`` starts ``not_submitted``: nothing is
  sendable until ops registers each template with DLT / Meta.

No backfill; no guest has marketing consent, so the reachable audience at
launch is 0 by design (spec D6).

Numbered 0134 because open PRs #307/#308 already claim 0131/0132.

Revision ID: 0134_create_guest_marketing_tables
Revises: 0133_create_organization_feature_overrides
Create Date: 2026-09-25
"""

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0134_create_guest_marketing_tables"
down_revision = "0133_create_organization_feature_overrides"
branch_labels = None
depends_on = None

CONSENTS = "guest_marketing_consents"
CONSENT_EVENTS = "guest_marketing_consent_events"
SUPPRESSIONS = "marketing_suppressions"
TEMPLATES = "marketing_templates"
CAMPAIGNS = "marketing_campaigns"
RECIPIENTS = "marketing_campaign_recipients"
TABLES = (CONSENTS, CONSENT_EVENTS, SUPPRESSIONS, TEMPLATES, CAMPAIGNS, RECIPIENTS)

# Frozen copy of spec §6. SMS bodies are GSM-7 only (no emoji, no rupee sign,
# no Hindi) so they stay at 160 chars per segment.
SYSTEM_TEMPLATES: list[dict] = [
    {
        "system_key": "welcome_back",
        "name": "Welcome back",
        "category": "welcome",
        "sms_body": "Hi {{guest_name}}, thanks for visiting {{venue_name}} again! Show "
        "code {{offer_code}} on your next visit for a little treat. Opt out: "
        "{{unsubscribe_link}}",
        "whatsapp_body": "Hi {{guest_name}}, it was lovely to see you again at "
        "{{venue_name}}! 😊 As a thank-you, show the code *{{offer_code}}* "
        "on your next visit for a little treat on us. See you soon! Not "
        "interested? Unsubscribe: {{unsubscribe_link}}",
        "whatsapp_variable_order": [
            "guest_name",
            "venue_name",
            "offer_code",
            "unsubscribe_link",
        ],
        "email_subject": "Good to see you again, {{guest_name}}",
        "email_preheader": "A small thank-you from {{venue_name}}",
        "email_body_html": "<p>Hi {{guest_name}},</p><p>Thanks for coming back to "
        "{{venue_name}}. Regulars like you are the reason we do "
        "this.</p><p>Show the code <strong>{{offer_code}}</strong> on "
        "your next visit and we'll add a little something on the "
        "house.</p><p>See you soon,<br>Team "
        "{{venue_name}}</p><p><small>Don't want these emails? <a "
        'href="{{unsubscribe_link}}">Unsubscribe</a>.</small></p>',
        "description": "Thank returning guests and invite them back with a small treat.",
    },
    {
        "system_key": "celebrate_with_us",
        "name": "Birthdays & anniversaries",
        "category": "birthday",
        "sms_body": "Celebrating something, {{guest_name}}? Host your birthday or "
        "anniversary at {{venue_name}}. Code {{offer_code}} for a special "
        "deal. Opt out: {{unsubscribe_link}}",
        "whatsapp_body": "🎉 Got a birthday or anniversary coming up, {{guest_name}}? "
        "Celebrate it at {{venue_name}}! Use code *{{offer_code}}* when "
        "you book for a special celebration deal. Book here: "
        "{{booking_link}}. Unsubscribe: {{unsubscribe_link}}",
        "whatsapp_variable_order": [
            "guest_name",
            "venue_name",
            "offer_code",
            "booking_link",
            "unsubscribe_link",
        ],
        "email_subject": "Celebrate your special day at {{venue_name}}",
        "email_preheader": "A special deal for birthdays and anniversaries",
        "email_body_html": "<p>Hi {{guest_name}},</p><p>Birthday, anniversary or promotion "
        "coming up? Let {{venue_name}} host it.</p><p>Use "
        "<strong>{{offer_code}}</strong> when you book for a special "
        'celebration deal.</p><p><a href="{{booking_link}}">Book your '
        "table</a></p><p>Team {{venue_name}}</p><p><small><a "
        'href="{{unsubscribe_link}}">Unsubscribe</a></small></p>',
        "description": "Invite guests to host a birthday or anniversary at your venue.",
    },
    {
        "system_key": "weekend_offer",
        "name": "Weekend offer",
        "category": "offer",
        "sms_body": "Weekend plans, {{guest_name}}? Use {{offer_code}} at {{venue_name}} "
        "this weekend. Valid till {{offer_expiry}}. Opt out: "
        "{{unsubscribe_link}}",
        "whatsapp_body": "Weekend plans, {{guest_name}}? ☀️ Spend them at {{venue_name}}! "
        "Show code *{{offer_code}}* for this weekend's special offer. "
        "Valid till {{offer_expiry}}. Unsubscribe: {{unsubscribe_link}}",
        "whatsapp_variable_order": [
            "guest_name",
            "venue_name",
            "offer_code",
            "offer_expiry",
            "unsubscribe_link",
        ],
        "email_subject": "This weekend at {{venue_name}}: an offer for you",
        "email_preheader": "Code {{offer_code}}, valid till {{offer_expiry}}",
        "email_body_html": "<p>Hi {{guest_name}},</p><p>Make this weekend a good one. Drop "
        "by {{venue_name}} and show the code "
        "<strong>{{offer_code}}</strong> for our weekend "
        "special.</p><p>Valid till {{offer_expiry}}.</p><p>Team "
        "{{venue_name}}</p><p><small><a "
        'href="{{unsubscribe_link}}">Unsubscribe</a></small></p>',
        "description": "A weekend-only offer code with an expiry.",
    },
    {
        "system_key": "feedback_request",
        "name": "How was your visit?",
        "category": "feedback",
        "sms_body": "Hi {{guest_name}}, how was your visit to {{venue_name}}? Tell us in 1 "
        "min: {{review_link}} Opt out: {{unsubscribe_link}}",
        "whatsapp_body": "Hi {{guest_name}}, thanks for visiting {{venue_name}}! 🙏 How did "
        "we do? It takes one minute: {{review_link}}. Your feedback helps "
        "us get better. Unsubscribe: {{unsubscribe_link}}",
        "whatsapp_variable_order": [
            "guest_name",
            "venue_name",
            "review_link",
            "unsubscribe_link",
        ],
        "email_subject": "How was your visit to {{venue_name}}?",
        "email_preheader": "One minute, one favour",
        "email_body_html": "<p>Hi {{guest_name}},</p><p>Thanks for spending time at "
        "{{venue_name}}. We'd love to know how it went, good or "
        'bad.</p><p><a href="{{review_link}}">Share your feedback</a> '
        "(takes about a minute)</p><p>Team "
        "{{venue_name}}</p><p><small><a "
        'href="{{unsubscribe_link}}">Unsubscribe</a></small></p>',
        "description": "Ask recent guests how their visit went (uses your review link).",
    },
    {
        "system_key": "festival_diwali",
        "name": "Diwali greetings",
        "category": "festival",
        "sms_body": "Happy Diwali, {{guest_name}}! Celebrate with {{venue_name}}: use "
        "{{offer_code}} till {{offer_expiry}}. Opt out: {{unsubscribe_link}}",
        "whatsapp_body": "🪔 Happy Diwali, {{guest_name}}! Wishing you and your family "
        "light, joy and prosperity. Celebrate with us at {{venue_name}}: "
        "use code *{{offer_code}}* for a festive treat, valid till "
        "{{offer_expiry}}. Unsubscribe: {{unsubscribe_link}}",
        "whatsapp_variable_order": [
            "guest_name",
            "venue_name",
            "offer_code",
            "offer_expiry",
            "unsubscribe_link",
        ],
        "email_subject": "Happy Diwali from {{venue_name}} 🪔",
        "email_preheader": "A festive treat, valid till {{offer_expiry}}",
        "email_body_html": "<p>Dear {{guest_name}},</p><p>Wishing you and your loved ones "
        "a very happy Diwali, full of light, sweets and good "
        "company.</p><p>Celebrate with us at {{venue_name}}: use "
        "<strong>{{offer_code}}</strong> for a festive treat, valid "
        "till {{offer_expiry}}.</p><p>Warm wishes,<br>Team "
        "{{venue_name}}</p><p><small><a "
        'href="{{unsubscribe_link}}">Unsubscribe</a></small></p>',
        "description": "Diwali greetings with a festive offer. Duplicate it for other "
        "festivals.",
    },
    {
        "system_key": "happy_hour",
        "name": "Happy hour",
        "category": "offer",
        "sms_body": "Happy hour at {{venue_name}}, {{guest_name}}! Show {{offer_code}} "
        "today. Valid till {{offer_expiry}}. Opt out: {{unsubscribe_link}}",
        "whatsapp_body": "⏰ It's happy hour at {{venue_name}}, {{guest_name}}! Show code "
        "*{{offer_code}}* today for happy-hour prices. Valid till "
        "{{offer_expiry}}. Unsubscribe: {{unsubscribe_link}}",
        "whatsapp_variable_order": [
            "guest_name",
            "venue_name",
            "offer_code",
            "offer_expiry",
            "unsubscribe_link",
        ],
        "email_subject": "Happy hour is on at {{venue_name}}",
        "email_preheader": "Show {{offer_code}} today",
        "email_body_html": "<p>Hi {{guest_name}},</p><p>Happy hour is on at "
        "{{venue_name}}. Show <strong>{{offer_code}}</strong> for "
        "happy-hour prices, valid till {{offer_expiry}}.</p><p>Team "
        "{{venue_name}}</p><p><small><a "
        'href="{{unsubscribe_link}}">Unsubscribe</a></small></p>',
        "description": "Announce happy-hour prices for today.",
    },
    {
        "system_key": "loyalty_reward",
        "name": "Loyalty reward",
        "category": "loyalty",
        "sms_body": "Thank you for being a regular, {{guest_name}}! Your reward at "
        "{{venue_name}}: code {{offer_code}}, valid till {{offer_expiry}}. Opt "
        "out: {{unsubscribe_link}}",
        "whatsapp_body": "🌟 {{guest_name}}, you're one of our regulars at {{venue_name}}, "
        "and we noticed! Here's a reward just for you: code "
        "*{{offer_code}}*, valid till {{offer_expiry}}. Thank you for "
        "your loyalty! Unsubscribe: {{unsubscribe_link}}",
        "whatsapp_variable_order": [
            "guest_name",
            "venue_name",
            "offer_code",
            "offer_expiry",
            "unsubscribe_link",
        ],
        "email_subject": "A thank-you reward for you, {{guest_name}}",
        "email_preheader": "Because you keep coming back",
        "email_body_html": "<p>Hi {{guest_name}},</p><p>You've visited {{venue_name}} more "
        "than most, and that means a lot to us.</p><p>Here's a reward: "
        "<strong>{{offer_code}}</strong>, valid till "
        "{{offer_expiry}}.</p><p>Thank you,<br>Team "
        "{{venue_name}}</p><p><small><a "
        'href="{{unsubscribe_link}}">Unsubscribe</a></small></p>',
        "description": "Reward your regulars with a thank-you code.",
    },
    {
        "system_key": "event_invite",
        "name": "Event invitation",
        "category": "event",
        "sms_body": "{{guest_name}}, you're invited: {{event_name}} at {{venue_name}} on "
        "{{event_date}}. Book: {{booking_link}} Opt out: {{unsubscribe_link}}",
        "whatsapp_body": "📅 {{guest_name}}, you're invited! Join us for *{{event_name}}* "
        "at {{venue_name}} on {{event_date}}. Spots are limited. Reserve "
        "yours: {{booking_link}}. Unsubscribe: {{unsubscribe_link}}",
        "whatsapp_variable_order": [
            "guest_name",
            "event_name",
            "venue_name",
            "event_date",
            "booking_link",
            "unsubscribe_link",
        ],
        "email_subject": "You're invited: {{event_name}} at {{venue_name}}",
        "email_preheader": "{{event_date}}. Spots are limited",
        "email_body_html": "<p>Hi {{guest_name}},</p><p>We're hosting "
        "<strong>{{event_name}}</strong> at {{venue_name}} on "
        "{{event_date}}, and we'd love to see you there.</p><p><a "
        'href="{{booking_link}}">Reserve your spot</a></p><p>Team '
        "{{venue_name}}</p><p><small><a "
        'href="{{unsubscribe_link}}">Unsubscribe</a></small></p>',
        "description": "Invite guests to an event with a booking link.",
    },
    {
        "system_key": "win_back",
        "name": "We miss you",
        "category": "winback",
        "sms_body": "We miss you, {{guest_name}}! Come back to {{venue_name}} and use "
        "{{offer_code}} before {{offer_expiry}}. Opt out: {{unsubscribe_link}}",
        "whatsapp_body": "Hi {{guest_name}}, it's been a while! 👋 We miss having you at "
        "{{venue_name}}. Come back and use code *{{offer_code}}* for a "
        "welcome-back offer, valid till {{offer_expiry}}. Unsubscribe: "
        "{{unsubscribe_link}}",
        "whatsapp_variable_order": [
            "guest_name",
            "venue_name",
            "offer_code",
            "offer_expiry",
            "unsubscribe_link",
        ],
        "email_subject": "We miss you at {{venue_name}}",
        "email_preheader": "A welcome-back offer inside",
        "email_body_html": "<p>Hi {{guest_name}},</p><p>It's been a while since your last "
        "visit to {{venue_name}}, and we'd love to see you "
        "again.</p><p>Use <strong>{{offer_code}}</strong> for a "
        "welcome-back offer, valid till {{offer_expiry}}.</p><p>Team "
        "{{venue_name}}</p><p><small><a "
        'href="{{unsubscribe_link}}">Unsubscribe</a></small></p>',
        "description": "Bring back guests you have not seen in a while.",
    },
    {
        "system_key": "new_arrival",
        "name": "Something new",
        "category": "announcement",
        "sms_body": "Something new at {{venue_name}}, {{guest_name}}! Try it with code "
        "{{offer_code}} till {{offer_expiry}}. Opt out: {{unsubscribe_link}}",
        "whatsapp_body": "✨ Something new has arrived at {{venue_name}}, {{guest_name}}! "
        "Be among the first to try it. Show code *{{offer_code}}* for an "
        "introductory offer, valid till {{offer_expiry}}. Unsubscribe: "
        "{{unsubscribe_link}}",
        "whatsapp_variable_order": [
            "guest_name",
            "venue_name",
            "offer_code",
            "offer_expiry",
            "unsubscribe_link",
        ],
        "email_subject": "New at {{venue_name}}: be the first to try it",
        "email_preheader": "An introductory offer for our regulars",
        "email_body_html": "<p>Hi {{guest_name}},</p><p>We've just launched something new "
        "at {{venue_name}}, and you're among the first to hear about "
        "it.</p><p>Come try it and show <strong>{{offer_code}}</strong> "
        "for an introductory offer, valid till "
        "{{offer_expiry}}.</p><p>Team {{venue_name}}</p><p><small><a "
        'href="{{unsubscribe_link}}">Unsubscribe</a></small></p>',
        "description": "Announce something new with an introductory offer.",
    },
]


# House convention: base-model helpers are duplicated into each migration so
# it stays a frozen snapshot (see 0122's note).
def _base_model_columns() -> list[sa.Column]:
    return [
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _create_base_model_indexes(table_name: str) -> None:
    op.create_index(f"ix_{table_name}_created_at", table_name, ["created_at"])
    op.create_index(f"ix_{table_name}_deleted_at", table_name, ["deleted_at"])
    op.create_index(f"ix_{table_name}_is_deleted", table_name, ["is_deleted"])
    op.create_index(f"ix_{table_name}_created_by", table_name, ["created_by"])
    op.create_index(f"ix_{table_name}_updated_by", table_name, ["updated_by"])


def _drop_base_model_indexes(table_name: str) -> None:
    op.drop_index(f"ix_{table_name}_updated_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_is_deleted", table_name=table_name)
    op.drop_index(f"ix_{table_name}_deleted_at", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_at", table_name=table_name)


def _uuid(
    name: str,
    *,
    fk: str | None = None,
    ondelete: str | None = None,
    nullable: bool = True,
) -> sa.Column:
    args = [sa.ForeignKey(fk, ondelete=ondelete)] if fk else []
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, nullable=nullable)


def _ts(name: str, *, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        CONSENTS,
        *_base_model_columns(),
        _uuid(
            "organization_id", fk="organizations.id", ondelete="CASCADE", nullable=False
        ),
        _uuid("guest_id", fk="guests.id", ondelete="CASCADE", nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("consent_text_version", sa.String(50), nullable=True),
        _uuid("captured_at_location_id", fk="locations.id", ondelete="SET NULL"),
        sa.Column("ip_address", sa.String(45), nullable=True),
        _ts("status_changed_at", nullable=False),
    )
    op.create_index(
        "uq_gmc_guest_channel",
        CONSENTS,
        ["guest_id", "channel"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "ix_gmc_org_channel_status", CONSENTS, ["organization_id", "channel", "status"]
    )

    op.create_table(
        CONSENT_EVENTS,
        *_base_model_columns(),
        _uuid(
            "organization_id", fk="organizations.id", ondelete="CASCADE", nullable=False
        ),
        _uuid("guest_id", fk="guests.id", ondelete="CASCADE", nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("consent_text_version", sa.String(50), nullable=True),
        _uuid("actor_user_id"),
        sa.Column("ip_address", sa.String(45), nullable=True),
        _ts("occurred_at", nullable=False),
    )
    op.create_index(
        "ix_gmce_guest_occurred", CONSENT_EVENTS, ["guest_id", "occurred_at"]
    )

    op.create_table(
        SUPPRESSIONS,
        *_base_model_columns(),
        _uuid(
            "organization_id", fk="organizations.id", ondelete="CASCADE", nullable=False
        ),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("address_normalized", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(32), nullable=False),
        _uuid("source_recipient_id"),
    )
    op.create_index(
        "uq_ms_org_channel_address",
        SUPPRESSIONS,
        ["organization_id", "channel", "address_normalized"],
        unique=True,
    )

    op.create_table(
        TEMPLATES,
        *_base_model_columns(),
        _uuid("organization_id", fk="organizations.id", ondelete="CASCADE"),
        sa.Column("system_key", sa.String(50), nullable=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("description", sa.String(300), nullable=True),
        sa.Column("sms_body", sa.Text(), nullable=True),
        sa.Column("sms_dlt_template_id", sa.String(30), nullable=True),
        sa.Column("whatsapp_body", sa.Text(), nullable=True),
        sa.Column("whatsapp_content_sid", sa.String(40), nullable=True),
        sa.Column("whatsapp_variable_order", postgresql.JSONB(), nullable=True),
        sa.Column(
            "whatsapp_approval_status",
            sa.String(16),
            nullable=False,
            server_default="not_submitted",
        ),
        sa.Column("email_subject", sa.String(150), nullable=True),
        sa.Column("email_preheader", sa.String(150), nullable=True),
        sa.Column("email_body_html", sa.Text(), nullable=True),
    )
    op.create_index("ix_mt_org", TEMPLATES, ["organization_id"])
    op.create_index(
        "uq_mt_system_key",
        TEMPLATES,
        ["system_key"],
        unique=True,
        postgresql_where=sa.text("system_key IS NOT NULL"),
    )
    op.create_index(
        "uq_mt_org_name",
        TEMPLATES,
        ["organization_id", sa.text("lower(name)")],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL AND organization_id IS NOT NULL"),
    )

    op.create_table(
        CAMPAIGNS,
        *_base_model_columns(),
        _uuid(
            "organization_id", fk="organizations.id", ondelete="CASCADE", nullable=False
        ),
        _uuid("location_id", fk="locations.id", ondelete="SET NULL"),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        _uuid(
            "template_id",
            fk="marketing_templates.id",
            ondelete="RESTRICT",
            nullable=False,
        ),
        sa.Column("template_snapshot", postgresql.JSONB(), nullable=True),
        sa.Column(
            "variables",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("audience_filter", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="draft"),
        _ts("scheduled_at"),
        _ts("started_at"),
        _ts("completed_at"),
        _ts("cancelled_at"),
        sa.Column("cancel_reason", sa.String(32), nullable=True),
        _ts("paused_until"),
        *[
            sa.Column(name, sa.Integer(), nullable=False, server_default="0")
            for name in (
                "recipient_count",
                "count_pending",
                "count_submitted",
                "count_delivered",
                "count_failed",
                "count_skipped",
            )
        ],
        sa.Column("exclusion_counts", postgresql.JSONB(), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        _uuid("created_by_user_id"),
        sa.Column("schedule_idempotency_key", sa.String(64), nullable=True),
        _ts("schedule_idempotency_at"),
    )
    op.create_index("ix_mc_org_status", CAMPAIGNS, ["organization_id", "status"])
    op.create_index(
        "ix_mc_due",
        CAMPAIGNS,
        ["status", "scheduled_at"],
        postgresql_where=sa.text("status = 'scheduled'"),
    )
    op.create_index("ix_mc_location", CAMPAIGNS, ["location_id"])
    op.create_index(
        "uq_mc_org_idempotency_key",
        CAMPAIGNS,
        ["organization_id", "schedule_idempotency_key"],
        unique=True,
        postgresql_where=sa.text("schedule_idempotency_key IS NOT NULL"),
    )

    op.create_table(
        RECIPIENTS,
        *_base_model_columns(),
        _uuid(
            "organization_id", fk="organizations.id", ondelete="CASCADE", nullable=False
        ),
        _uuid(
            "campaign_id",
            fk="marketing_campaigns.id",
            ondelete="CASCADE",
            nullable=False,
        ),
        _uuid("guest_id", fk="guests.id", ondelete="SET NULL"),
        sa.Column("channel", sa.String(16), nullable=False),
        _uuid("location_id", fk="locations.id", ondelete="SET NULL"),
        sa.Column("address", sa.String(255), nullable=True),
        sa.Column("rendered_preview", sa.String(200), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("skip_reason", sa.String(32), nullable=True),
        sa.Column("provider", sa.String(20), nullable=True),
        sa.Column("provider_message_id", sa.String(100), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(500), nullable=True),
        sa.Column(
            "attempt_count", sa.SmallInteger(), nullable=False, server_default="0"
        ),
        sa.Column("unsubscribe_token", sa.String(32), nullable=False),
        _ts("sending_started_at"),
        _ts("next_attempt_at"),
        _ts("submitted_at"),
        _ts("delivered_at"),
        _ts("failed_at"),
    )
    op.create_index(
        "uq_mcr_campaign_guest", RECIPIENTS, ["campaign_id", "guest_id"], unique=True
    )
    op.create_index("ix_mcr_campaign_status", RECIPIENTS, ["campaign_id", "status"])
    op.create_index(
        "uq_mcr_unsub_token", RECIPIENTS, ["unsubscribe_token"], unique=True
    )
    op.create_index(
        "ix_mcr_provider_msg", RECIPIENTS, ["provider", "provider_message_id"]
    )
    op.create_index("ix_mcr_org_created", RECIPIENTS, ["organization_id", "created_at"])
    op.create_index(
        "ix_mcr_org_location", RECIPIENTS, ["organization_id", "location_id"]
    )

    for table in TABLES:
        _create_base_model_indexes(table)

    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "marketing_consent_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column("marketing_consent_text", sa.String(300), nullable=True),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column("marketing_consent_text_version", sa.String(50), nullable=True),
    )

    _seed_system_templates()


def _seed_system_templates() -> None:
    """Idempotent upsert on ``system_key`` (never touches ops-filled DLT ids,
    Content SIDs or approval state on re-run)."""
    table = sa.table(
        TEMPLATES,
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("organization_id", postgresql.UUID(as_uuid=True)),
        sa.column("system_key", sa.String),
        sa.column("name", sa.String),
        sa.column("category", sa.String),
        sa.column("description", sa.String),
        sa.column("sms_body", sa.Text),
        sa.column("whatsapp_body", sa.Text),
        sa.column("whatsapp_variable_order", postgresql.JSONB),
        sa.column("whatsapp_approval_status", sa.String),
        sa.column("email_subject", sa.String),
        sa.column("email_preheader", sa.String),
        sa.column("email_body_html", sa.Text),
    )
    for template in SYSTEM_TEMPLATES:
        values = {
            "id": uuid.uuid5(
                uuid.NAMESPACE_URL, f"wyfy:marketing:{template['system_key']}"
            ),
            "organization_id": None,
            "whatsapp_approval_status": "not_submitted",
            **template,
        }
        statement = postgresql.insert(table).values(**values)
        statement = statement.on_conflict_do_update(
            index_elements=["system_key"],
            index_where=sa.text("system_key IS NOT NULL"),
            set_={
                key: statement.excluded[key]
                for key in (
                    "name",
                    "category",
                    "description",
                    "sms_body",
                    "whatsapp_body",
                    "whatsapp_variable_order",
                    "email_subject",
                    "email_preheader",
                    "email_body_html",
                )
            },
        )
        op.execute(statement)


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "marketing_consent_text_version")
    op.drop_column("captive_portal_configs", "marketing_consent_text")
    op.drop_column("captive_portal_configs", "marketing_consent_enabled")
    for table in reversed(TABLES):
        _drop_base_model_indexes(table)
    op.drop_table(RECIPIENTS)
    op.drop_table(CAMPAIGNS)
    op.drop_table(TEMPLATES)
    op.drop_table(SUPPRESSIONS)
    op.drop_table(CONSENT_EVENTS)
    op.drop_table(CONSENTS)
