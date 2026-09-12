"""``post_login_html`` on ``captive_portal_configs``. Additive-only, one
column, one table.

The HTML a venue authors for the page a guest sees *after* a successful
sign-in. Until now that screen had exactly two possible shapes, neither of
them the venue's: a 5-second countdown to ``redirect_url`` if one was set,
or the product's built-in success screen if it was not.

**Nullable, no server_default, and that is the whole design.** Every other
recent column on this table (0088's ``guest_font_choice``/
``background_overlay_strength``, 0089's focal point, 0090's
``powered_by_enabled``) is NOT NULL with a default chosen to reproduce the
pre-migration render exactly. The same goal here produces the opposite
shape, because the value meaning "render as before" is the *absence* of a
page, not a particular page: NULL is read by the frontend as "fall back to
the redirect/success behaviour". So every existing row keeps rendering
byte-identically after this migration, with no backfill, no default to
pick, and no third state invented -- there is only "the venue wrote a page"
and "they did not".

``Text``, not a bounded ``String(n)``. The authoring ceiling
(``constants.POST_LOGIN_HTML_MAX_BYTES``, 64 KiB of submitted UTF-8) is
enforced in the service layer rather than by the column, deliberately: the
sanitizer can return slightly *more* bytes than it was handed -- it appends
``rel="noopener noreferrer" target="_blank"`` to every anchor -- so a
column capped at exactly the validated number would reject a payload that
had just passed validation. A ``String(n)`` here would be a constraint that
fires only on the pathological link-dense page, i.e. the worst possible
place to discover it.

**What is stored here is already sanitized.** Writes go through
``app.domains.captive_portal.html_sanitizer.sanitize_post_login_html``
(``nh3``/``ammonia`` allowlist, plus this codebase's own CSS pass) before
they reach this column, because the bytes are rendered to a guest on the
same origin that handles their OTP code and the author is a venue admin --
semi-trusted, and impersonable by anyone holding a stolen dashboard
session. This migration creates storage only; it cannot and does not
enforce that. Anything that inserts into this column outside the service
layer -- a backfill script, a data import, a psql session -- is
responsible for sanitizing first, and there is no read-path net to catch
it if it does not.

**Reversibility.** ``downgrade`` drops the column. That is lossless for
the guest-facing render: with the column gone every portal returns to the
pre-migration redirect/success behaviour, which is exactly what a NULL in
it already means. It does discard any page a venue had authored, and that
is the correct direction to lose data in for a rollback -- the alternative
failure (keeping the bytes but losing the sanitizer that vouches for them)
is the one with a security consequence.

Revision ID: 0101_add_post_login_html_to_captive_portal_configs
Revises: 0100_create_system_settings_table
Create Date: 2026-09-01
"""

import sqlalchemy as sa

from alembic import op

revision = "0101_add_post_login_html_to_captive_portal_configs"
down_revision = "0100_create_system_settings_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "captive_portal_configs",
        sa.Column("post_login_html", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "post_login_html")
