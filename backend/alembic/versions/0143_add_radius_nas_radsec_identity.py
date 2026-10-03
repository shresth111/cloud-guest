"""RadSec (RADIUS over TLS) identity on ``radius_nas_clients``.

A NAS-only venue behind CGNAT or a dynamic IP cannot be a UDP RADIUS client:
FreeRADIUS picks the client (and its secret) by source address. Over RadSec the
venue is identified by its TLS client certificate instead, so the row records
which certificate that is:

* ``transport`` -- ``udp`` (every existing row; keyed on ``ip_address``) or
  ``radsec`` (keyed on the certificate below, ``ip_address`` NULL).
* ``radsec_cert_cn`` / ``radsec_cert_issuer`` -- the leaf certificate's CN and
  its issuer DN in OpenSSL's one-line compat form, exactly as FreeRADIUS puts
  them in ``TLS-Client-Cert-Common-Name`` / ``TLS-Client-Cert-Issuer``. The
  hub binds CN to issuer, so a certificate from another trusted CA with the
  same CN cannot take the venue's identity.

Additive; every existing row becomes ``transport='udp'`` with NULL cert
columns, i.e. exactly today's behaviour. Downgrade drops the three columns.

Revision ID: 0143_add_radius_nas_radsec_identity
Revises: 0142_create_instant_on_poller_tables
Create Date: 2026-10-03
"""

import sqlalchemy as sa

from alembic import op

revision = "0143_add_radius_nas_radsec_identity"
down_revision = "0142_create_instant_on_poller_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "radius_nas_clients",
        sa.Column(
            "transport", sa.String(length=10), nullable=False, server_default="udp"
        ),
    )
    op.add_column(
        "radius_nas_clients",
        sa.Column("radsec_cert_cn", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "radius_nas_clients",
        sa.Column("radsec_cert_issuer", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("radius_nas_clients", "radsec_cert_issuer")
    op.drop_column("radius_nas_clients", "radsec_cert_cn")
    op.drop_column("radius_nas_clients", "transport")
