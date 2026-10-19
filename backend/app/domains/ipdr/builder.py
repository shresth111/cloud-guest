"""The IPDR builder: flow records + session join for a time window, and the
nightly job that archives closed IST days.

* ``build`` -- the records of one location in ``[start, end)``, newest
  first (also used live for days not yet archived).
* ``build_day`` -- one IST day of one location -> gzip NDJSON in the
  archive + its ``ipdr_day_files`` row and hashed subjects.
* ``run_closed_days`` -- every closed IST day still inside flow-record
  retention, for every location with guest flow records that day, that has
  no day file yet. Flow records are deleted after
  ``traffic_flow_record_retention_days`` (7): a day not built by then is
  gone, and the list says ``missing``.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from app.core.config import Settings
from app.core.logging import get_logger

from .archive import IpdrArchive, encode_day, object_key
from .constants import (
    IST,
    SUBJECT_IP,
    SUBJECT_MAC,
    SUBJECT_PHONE,
    SUBJECT_USER,
    TRANSLATION_AMBIGUOUS,
    TRANSLATION_DERIVED,
)
from .formatting import normalize_ip, normalize_mac, phone_key
from .join import LeaseIndex, build_records
from .repository import IpdrRepository
from .translation import ExactOrRouterPublicIp

logger = get_logger(__name__)


def ist_day_bounds(day: date) -> tuple[datetime, datetime]:
    start = datetime.combine(day, time.min, tzinfo=IST).astimezone(UTC)
    end = datetime.combine(day + timedelta(days=1), time.min, tzinfo=IST)
    return start, end.astimezone(UTC)


def ist_day(moment: datetime) -> date:
    return moment.astimezone(IST).date()


def subject_value(kind: str, value: str | None) -> str | None:
    """The comparable form of one subject, or None."""
    if not value:
        return None
    if kind == SUBJECT_PHONE:
        return phone_key(value)
    if kind == SUBJECT_MAC:
        return normalize_mac(value)
    if kind == SUBJECT_IP:
        return normalize_ip(value)
    if kind == SUBJECT_USER:
        text = value.strip().lower()
        return text or None
    return None


def subject_digest(kind: str, value: str | None) -> str | None:
    normal = subject_value(kind, value)
    if normal is None:
        return None
    return hashlib.sha256(f"ipdr:{kind}:{normal}".encode()).hexdigest()


def subjects_of(records: list[dict[str, Any]]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for record in records:
        pairs = (
            (SUBJECT_PHONE, record.get("phone")),
            (SUBJECT_USER, record.get("user_id") if record.get("user_known") else None),
            (SUBJECT_MAC, record.get("mac")),
            (SUBJECT_IP, record.get("src_ip")),
            (SUBJECT_IP, record.get("nat_ip")),
        )
        for kind, value in pairs:
            digest = subject_digest(kind, value)
            if digest is not None:
                out.add((kind, digest))
    return out


class IpdrBuilder:
    def __init__(
        self,
        repository: IpdrRepository,
        settings: Settings,
        archive: IpdrArchive | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.archive = archive
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def grace(self) -> timedelta:
        return timedelta(seconds=int(self.settings.ipdr_session_grace_seconds))

    async def build(
        self,
        location_id: uuid.UUID,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> list[dict[str, Any]]:
        flows = await self.repository.flows(location_id, start, end)
        if not flows:
            return []
        routers = sorted({f.router_id for f in flows}, key=str)
        sessions = await self.repository.sessions(routers, start, end, grace=self.grace)
        public = await self.repository.router_public_ips(routers)
        leases = LeaseIndex(
            await self.repository.lease_events(routers, start, end),
            await self.repository.inventory_sightings(routers),
        )
        infrastructure = await self.repository.infrastructure(
            location_id, organization_id, routers
        )
        return build_records(
            flows,
            sessions,
            ExactOrRouterPublicIp(public),
            organization_id=organization_id,
            location_id=location_id,
            grace=self.grace,
            start=start,
            end=end,
            leases=leases,
            infrastructure=infrastructure,
        )

    async def build_day(
        self, location_id: uuid.UUID, organization_id: uuid.UUID, day: date
    ) -> dict[str, Any]:
        if self.archive is None:
            raise RuntimeError("build_day needs an archive")
        start, end = ist_day_bounds(day)
        records = await self.build(location_id, organization_id, start, end)
        built_at = self._clock()
        key = object_key(
            self.settings.ipdr_archive_prefix,
            organization_id,
            location_id,
            day,
            built_at,
        )
        stored = await self.archive.put(key, encode_day(records))
        derived = sum(
            1
            for r in records
            if r["nat_source"] in (TRANSLATION_DERIVED, TRANSLATION_AMBIGUOUS)
        )
        incomplete = await self.repository.records_incomplete(location_id, start, end)
        await self.repository.save_day_file(
            {
                "organization_id": organization_id,
                "location_id": location_id,
                "day": day,
                "store": stored.store,
                "object_key": stored.key,
                "sha256": stored.sha256,
                "row_count": len(records),
                "unknown_user_rows": sum(1 for r in records if not r["user_known"]),
                "derived_translation_rows": derived,
                "records_incomplete": incomplete,
                "built_at": built_at,
            },
            subjects_of(records),
        )
        return {"rows": len(records), "bytes": stored.size, "key": stored.key}

    def closed_days(self) -> list[date]:
        """Closed IST days whose every flow record is still retained."""
        now = self._clock()
        today = ist_day(now)
        retention = int(self.settings.traffic_flow_record_retention_days)
        oldest_kept = now - timedelta(days=retention)
        days = []
        day = today - timedelta(days=1)
        while ist_day_bounds(day)[0] >= oldest_kept:
            days.append(day)
            day -= timedelta(days=1)
        return sorted(days)

    async def run_closed_days(
        self,
        commit: Callable[[], Any] | None = None,
        rollback: Callable[[], Any] | None = None,
    ) -> dict[str, Any]:
        built = skipped = failed = rows = 0
        for day in self.closed_days():
            start, end = ist_day_bounds(day)
            for (
                location_id,
                organization_id,
            ) in await self.repository.locations_with_flows(start, end):
                if await self.repository.day_file(location_id, day) is not None:
                    skipped += 1
                    continue
                try:
                    result = await self.build_day(location_id, organization_id, day)
                except Exception:
                    failed += 1
                    if rollback is not None:
                        await rollback()
                    logger.exception(
                        "ipdr_day_build_failed",
                        extra={"location_id": str(location_id), "day": str(day)},
                    )
                    continue
                if commit is not None:
                    await commit()
                built += 1
                rows += result["rows"]
        return {"built": built, "skipped": skipped, "failed": failed, "rows": rows}
