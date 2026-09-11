"""Record whether a session's disconnect was actually enforced.

One nullable boolean on ``guest_sessions``: ``disconnect_enforced``.

## What was wrong

``GuestSession.status`` going to ``DISCONNECTED``/``TERMINATED``/``EXPIRED``
meant *"this platform wrote that down"*, not *"the guest's device was cut
off"*, and nothing anywhere recorded the difference.

The two are genuinely separate events. ``issue_live_disconnect``
(``app/domains/guest/service.py``) sends the RFC 5176 Disconnect-Request
**after** the status transition has already committed, and it never raises --
both deliberate, so that an unreachable or misconfigured NAS can never stop an
operator ending a session in our own records. That is the right call. The cost
of it was that a failed enforcement was indistinguishable from a successful
one, in the database and in the API response alike.

Measured on production 2026-09-11, that cost was being paid on every single
call: the app server has **no route to the WireGuard tunnel range**
(``ip route show`` carries no ``10.20.0.0/24``, there is no WireGuard
interface, ``ping 10.20.0.19`` is 100% loss), and ``nas_client.ip_address`` is
a tunnel address. So every Disconnect-Request left via the default gateway and
was dropped, and every session-ending path -- including the data-cap and
FUP-quota enforcement paths, and the operator's own "Terminate session" button
-- reported success for something that did not happen.

## Why a column rather than only a log line

A log line answers "did this one call work" for whoever is tailing at the
time. It cannot answer "which of these ended sessions were actually enforced",
which is the question an operator asks when a guest they terminated is still
using the WiFi, and the question anyone auditing quota enforcement has to ask
about the past. The row is where that belongs.

## Why nullable, and why nothing is backfilled

Tri-state, and NULL is the ordinary case rather than a missing value:

* ``NULL``  -- no live disconnect was attempted. Either the session is still
  running, or it ended because the NAS told *us* it ended (an Accounting-Stop
  carrying ``Lost-Service``/``Session-Timeout``/``Idle-Timeout``), which needs
  no packet from this side and is how most real sessions end.
* ``True``  -- a Disconnect-ACK came back.
* ``False`` -- a disconnect was attempted and did not land.

Every existing row therefore lands on NULL, which is accurate: we do not know
what happened for those, and inventing ``False`` for all of them would be a
guess dressed as data. Nothing is backfilled for exactly that reason -- see
``wyfy-omada/RADIUS-REMEDIATION.md`` for the same rule applied to the byte
fixtures.

No server default: unlike ``0123``'s ``tls_mode``, there is no "what every
existing row already did" value here, because the thing being recorded was
never observed. A row written by an older instance during a rolling deploy
should land on NULL, which is what ``nullable=True`` with no default gives.

Behaviour-preserving: nothing reads this column to make a decision. It is
written by ``issue_live_disconnect`` and surfaced in ``GuestSessionResponse``
so an operator can see it.
"""

import sqlalchemy as sa

from alembic import op

revision = "0124_add_disconnect_enforced_to_guest_sessions"
down_revision = "0123_add_tls_trust_to_network_integrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guest_sessions",
        sa.Column("disconnect_enforced", sa.Boolean(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("guest_sessions", "disconnect_enforced")
