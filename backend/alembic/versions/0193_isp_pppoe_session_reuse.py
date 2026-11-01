"""ENFORCE-4 (BE review F5): a PPPoE Acct-Session-Id is unique only among open
sessions.

RouterOS restarts its Acct-Session-Id counter after a reboot, so a new
session can carry the id of an older, closed one. The all-time unique index
made the new Start match the closed row and stay "closed". It becomes a
partial unique index over ``status = 'active'``, plus a plain index on
(nas, id, started_at) for lookups and IPDR. ISP-owned table only.

``downgrade`` restores the all-time unique index. It refuses (with a clear
message) once two rows share an id on one NAS, rather than delete session
history (IPDR).

Revision ID: 0193_isp_pppoe_session_reuse
Revises: 0192_isp_referrals
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0193_isp_pppoe_session_reuse"
down_revision = "0192_isp_referrals"
branch_labels = None
depends_on = None

_T = "isp_pppoe_sessions"


def upgrade() -> None:
    op.drop_index("uq_isp_pppoe_sessions_nas_acct", table_name=_T)
    op.create_index(
        "uq_isp_pppoe_sessions_nas_acct_active",
        _T,
        ["nas_client_id", "acct_session_id"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ix_isp_pppoe_sessions_nas_acct_started",
        _T,
        ["nas_client_id", "acct_session_id", "started_at"],
    )


def downgrade() -> None:
    dup = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT 1 FROM isp_pppoe_sessions GROUP BY nas_client_id, "
                "acct_session_id HAVING count(*) > 1 LIMIT 1"
            )
        )
        .first()
    )
    if dup is not None:
        raise RuntimeError(
            "isp_pppoe_sessions has reused Acct-Session-Ids (one row per "
            "session after a router reboot); the all-time unique index cannot "
            "come back without deleting session history. Not downgrading."
        )
    op.drop_index("ix_isp_pppoe_sessions_nas_acct_started", table_name=_T)
    op.drop_index("uq_isp_pppoe_sessions_nas_acct_active", table_name=_T)
    op.create_index(
        "uq_isp_pppoe_sessions_nas_acct",
        _T,
        ["nas_client_id", "acct_session_id"],
        unique=True,
    )
