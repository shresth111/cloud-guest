"""QoS & VOIP Priority: real device-push tracking for the paired
``/queue tree`` entry.

Closes the "marks traffic, never creates the paired queue" gap
documented in ``docs/qos/FLOW.md`` Section 2 and
``app.domains.network_config.renderers``' own module docstring: a
``QosTrafficRule``'s mangle *mark* was real (pushed via
``app.domains.network_config``'s own ``ConfigVersion``/``ProvisioningJob``
pipeline), but nothing ever created the ``/queue tree`` entry that
actually makes a mark do anything. ``app.domains.qos.device_adapters`` /
``service.QosService.push_rule_to_device`` now push that paired queue
directly -- these columns are this row's own record of that push's real,
current device state, mirroring
``app.domains.queue_management.models.QueueAssignment``'s own
``device_queue_id``/``error_message``/``applied_at`` columns exactly.

* ``device_queue_id`` -- the device-side ``/queue tree`` id (RouterOS's
  own e.g. ``"*1"``) once pushed, ``NULL`` until the first successful push.
* ``device_packet_mark`` -- the exact ``qos_packet_mark_identifier(rule)``
  string in effect when this queue was created, so a later re-push can
  detect a mark-identifier change (e.g. the rule was renamed) and
  remove-then-recreate rather than silently leaving a queue that
  references a mark nothing on the device sets anymore.
* ``device_push_status`` -- ``pending``/``active``/``failed``, see
  ``constants.QosDevicePushStatus``.
* ``device_push_error`` -- the real error detail from the most recent
  failed push attempt, if any.
* ``device_pushed_at`` -- when the current ``device_queue_id`` was last
  successfully (re-)applied.

All five are additive and nullable (or, for ``device_push_status``, a
real default of ``'pending'``) -- every pre-existing row backfills
correctly with no separate data migration, exactly the posture
``0071_add_isp_link_manual_status_override``'s own docstring already
establishes for an identically-shaped additive column set.

Revision ID: 0078_add_qos_traffic_rule_device_push
Revises: 0077_add_razorpay_checkout_fields_to_payments
Create Date: 2026-08-09
"""

import sqlalchemy as sa

from alembic import op

revision = "0078_add_qos_traffic_rule_device_push"
down_revision = "0077_add_razorpay_checkout_fields_to_payments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "qos_traffic_rules",
        sa.Column("device_queue_id", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "qos_traffic_rules",
        sa.Column("device_packet_mark", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "qos_traffic_rules",
        sa.Column(
            "device_push_status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        "qos_traffic_rules",
        sa.Column("device_push_error", sa.Text(), nullable=True),
    )
    op.add_column(
        "qos_traffic_rules",
        sa.Column("device_pushed_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("qos_traffic_rules", "device_pushed_at")
    op.drop_column("qos_traffic_rules", "device_push_error")
    op.drop_column("qos_traffic_rules", "device_push_status")
    op.drop_column("qos_traffic_rules", "device_packet_mark")
    op.drop_column("qos_traffic_rules", "device_queue_id")
