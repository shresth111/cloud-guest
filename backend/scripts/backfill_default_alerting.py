"""One-off, idempotent backfill of default alerting onto organizations that
already existed before it was created with them.

## Why this script has to exist

``app.domains.organization.router`` creates default alert rules with every
new organization, and always has. Its original docstring said, in as many
words, that organizations predating a rule simply do not get it and that an
operator can create one through ``POST /alert-rules``.

That is precisely the "a human has to hand-craft a rule first" step this
whole piece of work exists to remove, and the organization that needed it
most is the one that predates everything: on 2026-09-07 the platform's one
real customer -- "WyFy Guest", ``08ec098b-1fb0-4bd0-bcc2-fe489d01ec4c`` --
had **zero** alert rules, while all seven rules on the platform belonged to
demo or test organizations. A router at a real venue went down that night
and a fully working evaluator would still have emailed nobody.

Nothing else in this codebase seeds data: there is no data migration
anywhere in ``alembic/versions`` and a backfill Celery task would be a
second scheduled thing to reason about forever, for a job that needs to run
once. A script an operator runs deliberately, reads the output of, and then
forgets is the honest shape -- and it matches the existing
``scripts/backfill_background_images.py`` precedent exactly.

## What it does, and what it will never do

For every non-deleted organization it calls
``app.domains.monitoring.default_alerting.ensure_default_alerting``, which:

* creates any of the default rules the organization does not already have,
* creates an email notification channel from the organization's own
  ``contact_email`` if one is not already there, and
* links newly-created rules to that channel, so they can actually notify
  somebody.

It never touches a rule that already exists -- not its severity, not its
active flag, not its channel links. An operator who retuned or switched off
a default rule meant to, and re-running this must not argue with them. The
consequence is stated rather than hidden: a rule someone disabled stays
disabled, and this script will report it as already-present.

Organizations with no usable ``contact_email`` get their rules but no
channel, and are printed as **NOT NOTIFIABLE** so the gap is visible rather
than silently half-configured.

Run via::

    .venv/bin/python scripts/backfill_default_alerting.py --dry-run
    .venv/bin/python scripts/backfill_default_alerting.py
    .venv/bin/python scripts/backfill_default_alerting.py \\
        --organization-id 08ec098b-1fb0-4bd0-bcc2-fe489d01ec4c

``--dry-run`` opens the session and reads every organization, rule and
channel, prints exactly what it would create, and rolls back instead of
committing. Because ``ensure_default_alerting`` is idempotent, a dry run
followed by a real run is also a fair preview: the second pass sees the
same state the first one did.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.database.session import SessionLocal  # noqa: E402
from app.domains.monitoring.default_alerting import (  # noqa: E402
    DefaultAlertingReport,
    ensure_default_alerting,
)
from app.domains.monitoring.repository import MonitoringRepository  # noqa: E402
from app.domains.monitoring.service import (  # noqa: E402
    AlertService,
    NotificationService,
)
from app.domains.organization.models import Organization  # noqa: E402


def _render(name: str, report: DefaultAlertingReport) -> str:
    lines = [f"{name}  ({report.organization_id})"]
    if report.channel_created:
        lines.append("    channel:  created")
    elif report.channel_already_present:
        lines.append("    channel:  already present")
    else:
        lines.append(f"    channel:  NOT created -- {report.channel_skipped_reason}")
    for rule in report.rules_created:
        linked = (
            " (linked to channel)" if rule in report.rules_linked_to_channel else ""
        )
        lines.append(f"    rule:     created  {rule}{linked}")
    for rule in report.rules_already_present:
        lines.append(f"    rule:     present  {rule}")
    for rule in report.rules_failed:
        lines.append(f"    rule:     FAILED   {rule}")
    if not report.notifiable:
        lines.append("    >>> NOT NOTIFIABLE: an alert here would email nobody.")
    return "\n".join(lines)


async def _run(*, dry_run: bool, only: uuid.UUID | None) -> int:
    notifiable = 0
    total = 0
    async with httpx.AsyncClient() as http_client, SessionLocal() as session:
        repository = MonitoringRepository(session)
        # A real NotificationService, but nothing here ever dispatches a
        # notification -- only ``create_channel``/``list_channels`` are
        # called. The providers are left unset deliberately: constructing
        # the real ones would raise on a deployment whose SMTP settings are
        # incomplete, and this script's job is to fix the *configuration*
        # gap, which must not be blocked by the *delivery* gap.
        notification_service = NotificationService(repository, http_client)
        alert_service = AlertService(
            repository, notification_service=notification_service
        )

        statement = select(Organization).where(Organization.is_deleted.is_(False))
        if only is not None:
            statement = statement.where(Organization.id == only)
        organizations = list((await session.execute(statement)).scalars().all())

        for organization in organizations:
            total += 1
            report = await ensure_default_alerting(
                alert_service,
                notification_service,
                organization_id=organization.id,
                contact_email=organization.contact_email,
            )
            if report.notifiable:
                notifiable += 1
            print(_render(organization.name, report))

        if dry_run:
            await session.rollback()
            print("\n-- DRY RUN: rolled back, nothing was written. --")
        else:
            await session.commit()

    print(f"\n{notifiable}/{total} organizations can now receive an alert email.")
    if notifiable < total:
        print(
            "Organizations that cannot are listed above. The usual cause is a "
            "missing Organization.contact_email; set one and re-run."
        )
    # Non-zero exit when some organization still cannot be notified, so a
    # run wired into any kind of check fails loudly rather than looking
    # like a success that quietly configured nothing.
    return 0 if notifiable == total else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="read and report, then roll back without writing anything",
    )
    parser.add_argument(
        "--organization-id",
        type=uuid.UUID,
        default=None,
        help="restrict the backfill to a single organization",
    )
    args = parser.parse_args()
    return asyncio.run(_run(dry_run=args.dry_run, only=args.organization_id))


if __name__ == "__main__":
    raise SystemExit(main())
