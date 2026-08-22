"""Move the WireGuard hub endpoint from a literal IP to a DNS name.

Every provisioned MikroTik carries the hub's endpoint baked into its
``/interface wireguard peers`` entry as ``endpoint-address=``. That value is
interpolated from ``wireguard_servers.endpoint_host``, which today holds the
literal IP ``20.219.72.235``.

Baking a literal IP into the fleet is self-locking: the management path to a
router *is* the WireGuard tunnel, so if the hub's IP ever changes, every router
loses the tunnel and there is no remaining channel through which to push the
corrected address. Recovery would be a physical site visit per router. Worse,
the RouterOS WireGuard chunk the generators emit is add-if-missing with no
update branch, so re-pasting the setup script does **not** repair an existing
peer -- it silently skips it.

Switching to ``hub.wyfyguest.com`` makes a future hub move a one-record DNS
change instead of a fleet-wide brick.

Revision ID: 0095_wireguard_endpoint_host_to_dns_name
Revises: 0094_create_managed_router_resources_table
Create Date: 2026-08-22

**PRECONDITION -- this migration is inert and safe to run early, but do NOT
cut traffic over until the DNS record exists.** ``hub.wyfyguest.com`` must
have an A record pointing at the hub before any router is provisioned against
it. As of this commit the record does NOT exist (authoritative lookup against
``ns11.domaincontrol.com`` returns NXDOMAIN). The hub's
``wg-agent-preflight.sh`` refuses to start ``wg-agent`` until it resolves, so
the interlock is enforced on the hub side as well.

Only rows still holding the known old literal are updated, so this is
idempotent and will not clobber a value someone has already corrected by hand.
"""

from alembic import op

revision = "0095_wireguard_endpoint_host_to_dns_name"
down_revision = "0094_create_managed_router_resources_table"
branch_labels = None
depends_on = None

_OLD_ENDPOINT = "20.219.72.235"
_NEW_ENDPOINT = "hub.wyfyguest.com"


def upgrade() -> None:
    op.execute(
        f"""
        UPDATE wireguard_servers
           SET endpoint_host = '{_NEW_ENDPOINT}'
         WHERE endpoint_host = '{_OLD_ENDPOINT}'
        """
    )


def downgrade() -> None:
    op.execute(
        f"""
        UPDATE wireguard_servers
           SET endpoint_host = '{_OLD_ENDPOINT}'
         WHERE endpoint_host = '{_NEW_ENDPOINT}'
        """
    )
