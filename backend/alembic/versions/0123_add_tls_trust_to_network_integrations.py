"""Add per-integration TLS trust to ``network_integrations``.

Three columns -- ``tls_mode``, ``tls_pinned_sha256``, ``tls_trust_decided_at``
-- that make "which certificate do we accept from this controller" an
explicit, recorded, per-row decision instead of an unreachable constant.

## What was there before

Nothing on this table. The provider config dataclass carried a
``verify_tls: bool = True``, ``providers/omada.py`` read it, and no code in
``app/`` ever set it -- no column, no schema field, no service parameter. So
it was permanently ``True``, and a self-hosted Omada controller could not be
integrated at all: those ship a self-signed certificate (the software
controller this was verified against answers with ``CN=localhost``, issued by
itself), and strict verification refuses it. The failure was additionally
reported as ``OMADA_CONNECTION_FAILED`` -- "check that the controller URL and
port are correct" -- when the URL and the port were both fine.

## Why this migration changes nothing for any existing row

``tls_mode`` lands with ``server_default='strict'`` and ``NOT NULL``. Strict
is precisely what every existing row already did, because the old flag could
not be anything but ``True``. So the upgrade is behaviour-preserving by
construction: no integration that worked stops working, and no integration
that was refused starts being accepted until somebody explicitly chooses
``pinned`` or ``insecure`` for it.

The server default is kept on the column rather than backfilled and dropped.
A row inserted by anything that predates this change -- an older application
instance still running during a rolling deploy, a fixture, a hand-written
INSERT -- must land on strict rather than on NULL, and only a live server
default guarantees that during the window where both versions are writing.

## Why the fingerprint column is not encrypted

``tls_pinned_sha256`` is a SHA-256 of a certificate that the controller hands
to anybody who opens a socket to it. It is public by construction. Encrypting
it would buy nothing and would make it impossible to show an operator what
their integration is pinned to -- which is the mechanism that makes pinning a
decision rather than a ritual. Contrast ``credentials_encrypted`` on the same
table, which is Fernet ciphertext and stays that way.

## Why "who decided" is not a column here

``tls_trust_decided_at`` records *when*; the actor lives in the audit log,
which already carries an actor, a timestamp and the before/after values, and
which cannot be overwritten by the next decision the way a
``tls_trust_decided_by_user_id`` column would be. One column that answers
"is this decision stale?" on a list view, and the audit trail for everything
else.

Downgrade drops all three. That loses recorded pins, which is the honest
consequence of removing the feature -- and every integration reverts to
strict, i.e. to the behaviour on the other side of this migration.
"""

import sqlalchemy as sa

from alembic import op

revision = "0123_add_tls_trust_to_network_integrations"
down_revision = "0122_create_network_integration_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "network_integrations",
        sa.Column(
            "tls_mode",
            sa.String(length=20),
            nullable=False,
            server_default="strict",
        ),
    )
    op.add_column(
        "network_integrations",
        sa.Column("tls_pinned_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "network_integrations",
        sa.Column(
            "tls_trust_decided_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("network_integrations", "tls_trust_decided_at")
    op.drop_column("network_integrations", "tls_pinned_sha256")
    op.drop_column("network_integrations", "tls_mode")
