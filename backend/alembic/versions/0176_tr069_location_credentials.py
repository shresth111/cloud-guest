"""TR-069: per-location ACS credentials.

Additive and confined to the TR-069 domain's OWN table
(``tr069_acs_credentials``, created by 0172). No pre-ISP table is touched:

- ``tr069_acs_credentials``: + ``location_id`` (nullable FK to locations). A
  row with a location is that location's credential. Its
  ``customer_organization_id`` is the location's customer.
- The per-customer unique index now covers only rows without a location, and
  a new partial unique index allows one credential per (ISP, location).

Downgrade deletes the location credentials (detaching any device that named
one), then restores the 0172 index and drops the column. CPEs configured
with a location credential stop authenticating after a downgrade. Their
script has to be regenerated with the customer credential.

Revision ID: 0176_tr069_location_credentials
Revises: 0175_isp_subscriber_invoices
Create Date: 2026-10-23
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0176_tr069_location_credentials"
down_revision = "0175_isp_subscriber_invoices"
branch_labels = None
depends_on = None

_T = "tr069_acs_credentials"
_CUSTOMER_IDX = "uq_tr069_acs_credentials_isp_customer"
_LOCATION_IDX = "uq_tr069_acs_credentials_isp_location"


def upgrade() -> None:
    op.add_column(
        _T,
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", name="fk_tr069_acs_credentials_location_id"),
            nullable=True,
        ),
    )
    op.drop_index(_CUSTOMER_IDX, table_name=_T)
    op.create_index(
        _CUSTOMER_IDX,
        _T,
        ["isp_organization_id", "customer_organization_id"],
        unique=True,
        postgresql_where=sa.text(
            "customer_organization_id IS NOT NULL AND location_id IS NULL"
        ),
    )
    op.create_index(
        _LOCATION_IDX,
        _T,
        ["isp_organization_id", "location_id"],
        unique=True,
        postgresql_where=sa.text("location_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.execute(
        "UPDATE tr069_devices SET credential_id = NULL WHERE credential_id IN "
        "(SELECT id FROM tr069_acs_credentials WHERE location_id IS NOT NULL)"
    )
    op.execute("DELETE FROM tr069_acs_credentials WHERE location_id IS NOT NULL")
    op.drop_index(_LOCATION_IDX, table_name=_T)
    op.drop_index(_CUSTOMER_IDX, table_name=_T)
    op.create_index(
        _CUSTOMER_IDX,
        _T,
        ["isp_organization_id", "customer_organization_id"],
        unique=True,
        postgresql_where=sa.text("customer_organization_id IS NOT NULL"),
    )
    op.drop_column(_T, "location_id")
