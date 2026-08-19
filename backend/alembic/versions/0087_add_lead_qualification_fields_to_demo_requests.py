"""Add structured lead-qualification fields to demo_requests.

Additive-only schema change on the existing ``demo_requests`` table (no new
table) -- mirrors ``0085_add_portal_pin_login``'s identical
"nullable, opt-in, no backfill needed" shape:

* ``property_type`` -- the prospect's own vertical, one of
  ``app.domains.demo_request.constants.DemoRequestPropertyType`` (stored as
  a plain, unconstrained ``String``, never a native Postgres enum type --
  same reasoning as the existing ``status`` column: a new vertical never
  needs an ``ALTER TYPE`` migration, only a code change). Indexed: the
  Master console now filters its queue by it (see ``app.domains
  .demo_request.repository.DemoRequestRepository._list_filters``), the same
  justification the existing ``ix_demo_requests_status`` index documents
  for ``status``.
* ``location_count``/``router_count`` -- self-reported integers, both
  nullable/optional (``router_count`` is often less certain than
  ``location_count`` and may be genuinely unknown even when
  ``location_count`` isn't -- see ``models.py``'s own docstring). Not
  indexed: never filtered/sorted on directly, only read to compute
  ``lead_priority`` on the fly (``app.domains.demo_request.schemas
  .compute_lead_priority`` -- a derived value, deliberately never its own
  stored column, so it can never drift from these two fields).

Every row inserted before this feature shipped simply has all three
columns ``NULL`` ("unknown"/no signal) -- no backfill is needed or
attempted.

Revision ID: 0087_add_lead_qualification_fields_to_demo_requests
Revises: 0086_create_channel_partners_table
Create Date: 2026-08-19
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0087_add_lead_qualification_fields_to_demo_requests"
down_revision = "0086_create_channel_partners_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "demo_requests",
        sa.Column("property_type", sa.String(30), nullable=True),
    )
    op.add_column(
        "demo_requests",
        sa.Column("location_count", sa.Integer(), nullable=True),
    )
    op.add_column(
        "demo_requests",
        sa.Column("router_count", sa.Integer(), nullable=True),
    )
    op.create_index(
        "ix_demo_requests_property_type",
        "demo_requests",
        ["property_type"],
    )


def downgrade() -> None:
    op.drop_index("ix_demo_requests_property_type", table_name="demo_requests")
    op.drop_column("demo_requests", "router_count")
    op.drop_column("demo_requests", "location_count")
    op.drop_column("demo_requests", "property_type")
