"""Backfill ``guest_consents.terms_version`` for the rows where it can be
established honestly, and leave the rest NULL.

## The defect

``guest_consents.terms_version`` has been a real column since the table was
created and is NULL in **every** production row. The only writer is the
portal's sign-in hook, which posts ``{guest_id, captive_portal_config_id}``
and nothing else, so the column was never given a value by anybody.

The platform can therefore prove *that* a guest consented and cannot say
*to what*. Under India's DPDP Act the burden of proof sits with the Data
Fiduciary -- the venue -- and a consent row with a null version discharges
none of it. The write path is fixed separately and **has already landed**
(``GuestService._resolve_terms_version`` derives one server-side, from
the config, on every new consent). This migration is only about the rows
already on disk, which is why it is its own change: it is independently
revertable, it blocks nothing, and -- see below -- it will cover very
few rows until the dashboard actually saves the terms text it displays.

## Which rows can be backfilled, and why only those

The version is a digest of the portal's terms and privacy text. The text
that matters is the text **as it was on the day the guest consented**, and
nothing in this schema stores history of it -- ``captive_portal_configs``
holds only the current value. So for most rows the honest answer is: we do
not know, and this migration must not invent one.

There is exactly one subset where the current value provably *is* the
historical value:

    the config row has not been written to at all since the consent
    was recorded  --  ``config.updated_at <= consent.consented_at``

``updated_at`` is bumped by ``TimestampMixin``'s ``onupdate`` on every ORM
write to the row, and every write to a portal config in this codebase goes
through ``CaptivePortalRepository``. If the config has not been touched
since the guest consented, the four content columns hold exactly the words
that guest was shown. Those rows get a real version.

Everything else stays NULL, deliberately:

* consents whose config has been edited since -- the text may or may not
  have changed, and "may or may not" is not evidence;
* consents whose ``captive_portal_config_id`` is NULL (the FK is
  ``ON DELETE SET NULL``, and the column is nullable to begin with);
* consents against a config with no terms and no privacy content, where
  whatever the guest saw came from the frontend's own hardcoded copy,
  which this layer has never been able to see.

**A NULL that means "we do not know" is worth more than a version that
means "we guessed".** The second is indistinguishable from evidence and is
worse than the gap it fills. Expect this backfill to cover a minority of
rows, and expect that number to be the honest one.

## Why the digest is computed here rather than imported

``app.domains.captive_portal.validators.compute_terms_version`` is the
runtime implementation and this is a byte-identical copy of it. Migrations
are frozen against the schema of their own moment and must not import
application code that will move underneath them -- but the two must agree,
or a row backfilled today would carry a different version string from a
row written tomorrow for the same unchanged text, which is the exact
failure this column exists to prevent.
``TestBackfillMigrationMatchesTheRuntime in
``tests/unit/test_guest_consent_terms_version.py`` loads this module by
path and asserts the copy and the original still agree on the same
inputs; if it fails, that test is the thing that noticed.

It is computed in Python rather than in SQL for the same reason: matching
``hashlib.sha256`` over a length-prefixed UTF-8 join in ``pgcrypto`` is
possible and is one ``octet_length``-versus-``char_length`` mistake away
from silently producing different strings on a database whose encoding is
not what the author assumed. The set of distinct configs is small -- one
statement per config, not per consent -- so there is nothing to gain.

``downgrade`` clears the versions this migration set. It cannot clear only
those, because nothing records which rows it touched, so it clears the
column wholesale -- which is where the column was before, and the write
path will refill it on the next consent.

Revision ID: 0116_backfill_guest_consent_terms_version
Revises: 0115_add_profile_prompt_declined_at_to_guests
Create Date: 2026-09-06
"""

import hashlib

import sqlalchemy as sa

from alembic import op

revision = "0116_backfill_guest_consent_terms_version"
down_revision = "0115_add_profile_prompt_declined_at_to_guests"
branch_labels = None
depends_on = None

# Frozen copy of app.domains.captive_portal.validators
# ._TERMS_VERSION_DIGEST_CHARS / compute_terms_version -- see the module
# docstring for why it is a copy and what keeps the two honest.
_TERMS_VERSION_DIGEST_CHARS = 16


def _compute_terms_version(
    terms_and_conditions_text: str | None,
    terms_and_conditions_url: str | None,
    privacy_policy_text: str | None,
    privacy_policy_url: str | None,
) -> str | None:
    parts = (
        terms_and_conditions_text,
        terms_and_conditions_url,
        privacy_policy_text,
        privacy_policy_url,
    )
    if not any(part and part.strip() for part in parts):
        return None
    digest = hashlib.sha256()
    for part in parts:
        value = (part or "").encode("utf-8")
        digest.update(str(len(value)).encode("ascii"))
        digest.update(b":")
        digest.update(value)
    return f"sha256:{digest.hexdigest()[:_TERMS_VERSION_DIGEST_CHARS]}"


def upgrade() -> None:
    connection = op.get_bind()

    # Only the configs some consent actually points at, and only the four
    # content columns plus the one timestamp the eligibility rule needs.
    configs = connection.execute(
        sa.text(
            """
            SELECT c.id,
                   c.updated_at,
                   c.terms_and_conditions_text,
                   c.terms_and_conditions_url,
                   c.privacy_policy_text,
                   c.privacy_policy_url
              FROM captive_portal_configs c
             WHERE EXISTS (
                       SELECT 1
                         FROM guest_consents g
                        WHERE g.captive_portal_config_id = c.id
                          AND g.terms_version IS NULL
                   )
            """
        )
    ).fetchall()

    for config in configs:
        version = _compute_terms_version(
            config.terms_and_conditions_text,
            config.terms_and_conditions_url,
            config.privacy_policy_text,
            config.privacy_policy_url,
        )
        if version is None:
            # No terms and no privacy content on the config: nothing this
            # layer can name. Left NULL rather than stamped -- see the
            # module docstring.
            continue
        connection.execute(
            sa.text(
                """
                UPDATE guest_consents
                   SET terms_version = :version
                 WHERE captive_portal_config_id = :config_id
                   AND terms_version IS NULL
                   AND consented_at >= :config_updated_at
                """
            ),
            {
                "version": version,
                "config_id": config.id,
                # The whole eligibility rule, in one comparison: the
                # config has not been written to since this consent, so
                # the text above is the text the guest was shown.
                "config_updated_at": config.updated_at,
            },
        )


def downgrade() -> None:
    op.execute("UPDATE guest_consents SET terms_version = NULL")
