"""Propose (and, only when explicitly told to, apply) corrections to
``routers.vendor`` rows whose own data contradicts the label.

    NOTHING IN THIS SCRIPT MAY BE RUN AGAINST PRODUCTION WITHOUT THE
    OWNER'S EXPLICIT APPROVAL. It defaults to a dry run and refuses to
    write unless ``--apply`` and ``--i-have-owner-approval`` are BOTH
    given. Read the dry-run output first; that is what the approval is
    approval *of*.

## What happened

On 2026-09-10 all seven rows in the production fleet were set to
``vendor = "tplink_omada"`` through a dropdown with no confirmation step, on
an organization-scoped endpoint. Every one of them is MikroTik hardware.
``Office Guest`` is a ``MikroTik hEX lite (RB750r2)`` that last checked in at
``2026-09-10T08:20:27Z``, was demoted to ``offline`` / ``unhealthy`` by the
heartbeat sweep -- which reads ``status``, not ``vendor``, and was right to --
and was reported to nobody, because the alert evaluator's roster had been
filtered by the label.

The code change this script ships alongside removes the failure class:
``vendor_capabilities.is_controller_managed_row`` now weighs agent evidence
over the label, so those rows are already back inside monitoring, alerting,
readiness and the ZTP dashboard with no data change at all. **This script is
not what restores monitoring.** It exists so the column stops lying, and so
the next person to read it does not have to know the story.

## How a row is judged

In order, first match wins -- the determination the product engineer wrote
into ``FIX-PLAN.md`` under "Needs the owner's approval":

1. A router referenced by a live ``network_integrations`` row **is** a
   controller. Left alone. (At the time of writing zero integrations exist,
   so no row qualifies -- but the rule is first because it is the only one
   that can say "this really is a controller", and a row acquiring an
   integration between the dry run and the apply must not be corrected.)
2. Otherwise, agent evidence -- ``last_seen_at``, ``routeros_version``,
   ``last_health_check_at``, or RouterOS API credentials on file -- means
   agent-managed MikroTik.
3. Otherwise, a MikroTik model string means agent-managed MikroTik.
4. Otherwise: **left alone, and reported as undecidable.** A row with a
   controller label, no agent evidence and no MikroTik model is exactly what
   a legitimately onboarded controller looks like, and this script must never
   be the thing that turns a real controller into a MikroTik.

## What an apply writes

For each corrected row, one ``UPDATE routers SET vendor = 'mikrotik'`` and
one ``audit_log_entries`` row carrying the same ``{"changes": {...}}`` shape
``RouterService.change_router_vendor`` writes -- the old value, the new value,
the evidence that decided it, and the operator's ``--reason``. A corrective
write that leaves no better trail than the mistake did would be repeating it.

## Usage

    # 1. Read this. This is what gets approved.
    python -m scripts.remediate_mislabelled_router_vendors

    # 2. Only after a yes, and with the reason the owner agreed to:
    python -m scripts.remediate_mislabelled_router_vendors \\
        --apply --i-have-owner-approval \\
        --actor-user-id <uuid> \\
        --reason "Reverting the 2026-09-10 bulk relabel; approved by <name>"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.database.session import SessionLocal
from app.domains.network_integration.models import NetworkIntegration
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.models import AuditLogEntry
from app.domains.router.models import Router
from app.domains.router.vendor_capabilities import (
    AGENT_EVIDENCE_FIELDS,
    CONTROLLER_MANAGED_VENDORS,
    looks_like_mikrotik_hardware,
)

CORRECTED_VENDOR = "mikrotik"


def _verdict(router: Router, integration_count: int) -> tuple[str, str, list[str]]:
    """``(action, rule, evidence)`` for one row. ``action`` is ``"correct"``,
    ``"keep"`` or ``"undecidable"``."""
    if integration_count:
        return (
            "keep",
            "rule 1: a live network integration references this row",
            [f"{integration_count} integration(s)"],
        )

    evidence = [
        f"{field}={getattr(router, field)!r}"
        for field in AGENT_EVIDENCE_FIELDS
        if getattr(router, field, None) is not None
    ]
    if evidence:
        return ("correct", "rule 2: agent evidence", evidence)

    if looks_like_mikrotik_hardware(router.model):
        return ("correct", "rule 3: MikroTik model string", [f"model={router.model!r}"])

    return (
        "undecidable",
        "rule 4: indistinguishable from a genuine controller",
        [],
    )


async def _gather() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    async with SessionLocal() as session:
        result = await session.execute(
            select(Router).where(
                Router.is_deleted.is_(False),
                Router.vendor.in_(sorted(CONTROLLER_MANAGED_VENDORS)),
            )
        )
        for router in result.scalars():
            count = await session.scalar(
                select(NetworkIntegration.id)
                .where(
                    NetworkIntegration.router_id == router.id,
                    NetworkIntegration.is_deleted.is_(False),
                )
                .limit(1)
            )
            action, rule, evidence = _verdict(router, 1 if count else 0)
            rows.append(
                {
                    "id": str(router.id),
                    "name": router.name,
                    "model": router.model,
                    "vendor": router.vendor,
                    "status": router.status,
                    "health_status": router.health_status,
                    "last_seen_at": (
                        router.last_seen_at.isoformat() if router.last_seen_at else None
                    ),
                    "action": action,
                    "rule": rule,
                    "evidence": evidence,
                }
            )
    return rows


async def _apply(
    rows: list[dict[str, Any]], *, actor_user_id: uuid.UUID | None, reason: str
) -> int:
    written = 0
    async with SessionLocal() as session:
        for row in rows:
            if row["action"] != "correct":
                continue
            router = await session.get(Router, uuid.UUID(row["id"]))
            if router is None or router.vendor != row["vendor"]:
                # Re-read between the dry run and the apply: something else
                # moved this row. Skip rather than overwrite a change nobody
                # in this run has seen.
                print(f"  SKIP {row['name']}: row changed since the dry run")
                continue
            previous = router.vendor
            router.vendor = CORRECTED_VENDOR
            router.updated_by = actor_user_id
            router.updated_at = datetime.now(UTC)
            session.add(
                AuditLogEntry(
                    actor_user_id=actor_user_id,
                    action=AuditAction.ROUTER_UPDATED.value,
                    entity_type="router",
                    entity_id=router.id,
                    description=(
                        f"Router '{router.name}' device type changed: vendor "
                        f"{previous} -> {CORRECTED_VENDOR}. Reason: {reason}"
                    ),
                    event_metadata={
                        "changes": {
                            "vendor": {"from": previous, "to": CORRECTED_VENDOR},
                            "reason": reason,
                            "remediation_rule": row["rule"],
                            "remediation_evidence": row["evidence"],
                        }
                    },
                    organization_id=router.organization_id,
                    location_id=router.location_id,
                )
            )
            written += 1
        await session.commit()
    return written


def _report(rows: list[dict[str, Any]]) -> None:
    print(json.dumps(rows, indent=2, sort_keys=True))
    print()
    for action in ("correct", "keep", "undecidable"):
        names = [r["name"] for r in rows if r["action"] == action]
        print(f"{action:12} {len(names):3}  {', '.join(names) or '-'}")


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--i-have-owner-approval", action="store_true")
    parser.add_argument("--actor-user-id")
    parser.add_argument("--reason", default="")
    args = parser.parse_args()

    rows = await _gather()
    _report(rows)

    if not args.apply:
        print("\nDRY RUN. Nothing was written.")
        return 0
    if not args.i_have_owner_approval:
        print("\nREFUSED: --apply requires --i-have-owner-approval.", file=sys.stderr)
        return 2
    if len(args.reason) < 8:
        print("\nREFUSED: --reason is required and is recorded.", file=sys.stderr)
        return 2

    written = await _apply(
        rows,
        actor_user_id=uuid.UUID(args.actor_user_id) if args.actor_user_id else None,
        reason=args.reason,
    )
    print(f"\nCorrected {written} row(s), each with an audit entry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
