"""Retire the system "Birthdays & anniversaries" marketing template.

Guests have no birthday or anniversary field, so a venue cannot tell who it is
for. Soft-deleted, not removed: ``marketing_campaigns.template_id`` may point at
it, and sent or scheduled campaigns keep working from their own snapshot. A draft
on it must pick another template before it can be scheduled.

Revision ID: 0179_retire_birthday_marketing_template
Revises: 0178_add_voucher_batch_session_timeout
"""

from __future__ import annotations

from alembic import op

revision = "0179_retire_birthday_marketing_template"
down_revision = "0178_add_voucher_batch_session_timeout"
branch_labels = None
depends_on = None


def _set_deleted(value: bool) -> None:
    deleted_at = "now()" if value else "NULL"
    op.execute(
        "UPDATE marketing_templates "
        f"SET is_deleted = {str(value).lower()}, deleted_at = {deleted_at} "
        "WHERE system_key = 'celebrate_with_us' AND organization_id IS NULL"
    )


def upgrade() -> None:
    _set_deleted(True)


def downgrade() -> None:
    _set_deleted(False)
