"""Firewall add-on: keep it on for organizations already using it.

``PlanFeatureKey.FIREWALL`` makes the customer Firewall section (firewall
rules, flood limit, guest isolation and Block Websites) a paid add-on that is
off by default and carried by no seeded plan. Without this backfill every
organization that already blocks websites or runs firewall rules would find
the section locked the day this deploys, and its rules would stay on the
router with no screen left to change or remove them.

So: every organization with evidence of use gets a live, enabled
``organization_feature_overrides`` row for ``firewall`` -- exactly the row the
Master console's add-on switch writes, so Master can still lock it later and
the panel shows it as an override with the reason below. Evidence of use is
any one of:

* a live ``firewall_rules`` row,
* a live ``content_filter_rules`` row (websites, apps, addresses),
* a live ``dns_filtering_policies`` or ``dns_filtering_router_locations`` row
  (Cloudflare categories set or switched on),
* an audit entry for any firewall, content-filter or DNS-filtering write --
  which catches the switches that live only on the router (flood limit, guest
  isolation, bypass hardening) and organizations that deleted every rule.

An organization that already has a live ``firewall`` override is left alone.
Nothing else is written: no plan, no license, no other key.

Downgrade removes only the rows this migration wrote (matched on the reason
text), live or not.

Numbered 0178, not 0172: open PRs #429-#447 already claim 0172-0177 for
other revision ids. ``down_revision`` is today's head (0171); whichever of
those merges first, re-point this file's ``down_revision`` at the new head
before merging, so there is still exactly one head.

Revision ID: 0178_grandfather_firewall_addon
Revises: 0171_create_monitored_device_health
Create Date: 2026-10-26
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0178_grandfather_firewall_addon"
down_revision = "0155_merge_guest_device_events_into_staging"  # staging head
branch_labels = None
depends_on = None

FEATURE_KEY = "firewall"
REASON = (
    "Grandfathered: already using Firewall or Block Websites when the add-on "
    "was introduced"
)

# Frozen copies of the AuditAction values (app.domains.rbac.enums) that are a
# customer, or Master on a customer's behalf, using the section.
AUDIT_ACTIONS = (
    "firewall_rule_created",
    "firewall_rule_updated",
    "firewall_rule_deleted",
    "firewall_rules_pushed",
    "firewall_band_installed",
    "firewall_flood_limit_changed",
    "firewall_guest_isolation_changed",
    "content_filter_rule_created",
    "content_filter_rule_updated",
    "content_filter_rule_deleted",
    "content_filter_rule_pushed",
    "dns_filtering_policy_updated",
    "dns_filtering_enabled",
    "dns_filtering_disabled",
    "dns_filtering_bypass_hardening_changed",
)


def upgrade() -> None:
    actions = ", ".join(f"'{action}'" for action in AUDIT_ACTIONS)
    op.get_bind().execute(
        sa.text(
            f"""
            INSERT INTO organization_feature_overrides
                (organization_id, feature_key, is_enabled, reason)
            SELECT o.id, :feature_key, true, :reason
            FROM organizations o
            WHERE o.deleted_at IS NULL
              AND (
                EXISTS (SELECT 1 FROM firewall_rules r
                        WHERE r.organization_id = o.id AND r.deleted_at IS NULL)
                OR EXISTS (SELECT 1 FROM content_filter_rules r
                           WHERE r.organization_id = o.id AND r.deleted_at IS NULL)
                OR EXISTS (SELECT 1 FROM dns_filtering_policies p
                           WHERE p.organization_id = o.id AND p.deleted_at IS NULL)
                OR EXISTS (SELECT 1 FROM dns_filtering_router_locations l
                           WHERE l.organization_id = o.id AND l.deleted_at IS NULL)
                OR EXISTS (SELECT 1 FROM audit_log_entries a
                           WHERE a.organization_id = o.id
                             AND a.action IN ({actions}))
              )
              AND NOT EXISTS (
                SELECT 1 FROM organization_feature_overrides f
                WHERE f.organization_id = o.id
                  AND f.feature_key = :feature_key
                  AND f.deleted_at IS NULL
              )
            """
        ),
        {"feature_key": FEATURE_KEY, "reason": REASON},
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text(
            "DELETE FROM organization_feature_overrides "
            "WHERE feature_key = :feature_key AND reason = :reason"
        ),
        {"feature_key": FEATURE_KEY, "reason": REASON},
    )
