"""Add ``portal_mode`` to ``network_integrations``.

One column that records **which of the controller's two captive-portal
contracts a venue is on**, so that the guest portal, the authorize path and
the disconnect path all dispatch on one stored answer instead of each
sniffing a redirect's query string and reaching its own conclusion.

## The two contracts, and why they are not variants of one thing

* ``external_portal`` -- TP-Link ``authType 4``, *External Portal Server*.
  The guest's browser posts its identity to us; this platform calls the
  controller's ``hotspot/extPortal/auth`` with a stored operator session.
  Every call is **outbound** from this platform, which is what makes it work
  through a venue's NAT with nothing exposed on our side. Proven end to end
  on real hardware (a real guest, a real EAP245, 2026-09-11).
* ``radius`` -- ``authType 2`` + *External Web Portal*. The guest's browser
  posts its identity to **the controller**, the controller becomes the RADIUS
  client, and it sends an **inbound** Access-Request to this platform's
  FreeRADIUS. This platform is not in the authorization path at all.

They send different redirect parameters, they submit to different endpoints,
and the direction of trust is reversed. Deriving one from the other's
symptoms is a guess, and the thing a wrong guess breaks is a guest's internet
access.

## Why this migration changes nothing for any existing row

``server_default='external_portal'`` and ``NOT NULL``: every row that
predates this column lands on exactly the behaviour it already had, and every
row inserted by an older application instance during a rolling deploy lands
there too -- which is why the server default stays on the column rather than
being backfilled and dropped (the identical argument ``0123``'s ``tls_mode``
makes for itself).

**No row is moved to ``radius`` by this migration or by any code path.**
RADIUS mode additionally requires an inbound UDP path to this platform's
FreeRADIUS that does not exist today, a NAS client keyed on the controller's
public address, and a certificate on the controller that a guest's browser
will accept. A column cannot arrange any of those, so the column alone never
turns anything on -- see ``ops/runbooks/omada-radius-mode.md``.

Downgrade drops the column. An integration deliberately placed in RADIUS mode
loses that fact and reverts to being treated as an External Portal Server
venue, which is the honest consequence of removing the feature: it is the
mode whose code path still exists on the other side of this migration.
"""

import sqlalchemy as sa

from alembic import op

revision = "0125_add_portal_mode_to_network_integrations"
down_revision = "0124_add_disconnect_enforced_to_guest_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "network_integrations",
        sa.Column(
            "portal_mode",
            sa.String(length=30),
            nullable=False,
            server_default="external_portal",
        ),
    )


def downgrade() -> None:
    op.drop_column("network_integrations", "portal_mode")
