"""One-off, idempotent backfill of already-stored captive-portal
background images through the v7 image pipeline.

Captive Portal v7 design spec, Part 4 ("Existing images"). Every
``brandings.background_image_key`` written before v7 points at the raw
bytes a customer uploaded -- typically a 1-5 MB gallery photo that CSS
``cover`` then upscales onto a phone. Running it through
``app.domains.branding.service._process_background_image`` produces the
same picture as a blurred, tinted, 2560px-long-edge WebP, usually
80-150 KB, and fills in the three measurements
(``background_luminance`` / ``background_top_luminance`` /
``background_entropy``) the guest-facing scrim logic reads.

Run via::

    .venv/bin/python scripts/backfill_background_images.py --dry-run
    .venv/bin/python scripts/backfill_background_images.py

Four properties this script is built around, all of them from the spec:

* **Idempotent.** A key already ending ``.webp`` is skipped outright, so
  a second run is a no-op and an interrupted run can simply be re-run.
  The check is on the stored extension rather than on a "processed" flag
  precisely so no new column has to exist for it -- the extension lives
  inside the existing ``String(1024)`` key, which is why Part 4 says no
  migration is needed for the images themselves.

* **Writes to a NEW key, and never deletes the old object.** Rollback is
  then one ``UPDATE brandings SET background_image_key = '<old key>'``
  per organization, with the bytes still sitting there -- as opposed to
  overwriting in place, where a bad blur constant discovered a week
  later is unrecoverable for every customer at once. The orphaned
  originals are small in number and can be swept later, deliberately by
  hand, once the new rendering has been looked at.

* **Not lazy-on-read.** The obvious alternative -- reprocess the first
  time a guest fetches the image -- puts an object-storage write and a
  DB write on ``GET /branding/{organization_id}/background-image/public``,
  which is unauthenticated and reachable by enumerating organization
  UUIDs. That is a write amplifier with no rate limit in front of it.

* **Failure is per-organization.** One unreadable object, one
  storage-side error, or one image the pipeline declines to process
  leaves that row exactly as it was and the run carries on. Nothing here
  needs to be all-or-nothing.

``--dry-run`` does every read and every computation and prints the same
per-organization before/after byte report, but performs no upload and no
database write.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.core.storage import (  # noqa: E402
    ObjectStorageError,
    ObjectStorageProtocol,
    get_object_storage,
)
from app.database.session import SessionLocal  # noqa: E402
from app.domains.branding.models import Branding  # noqa: E402
from app.domains.branding.service import (  # noqa: E402
    _process_background_image,
)


@dataclass
class Outcome:
    organization_id: uuid.UUID
    old_key: str
    new_key: str | None
    before_bytes: int
    after_bytes: int
    status: str
    detail: str = ""


def _new_key_for(organization_id: uuid.UUID) -> str:
    """Same shape ``BrandingService.upload_background_image`` writes --
    a fresh ``uuid4()`` per object, which is also what spec §5 S5 wants
    to derive a cache-busting token from later."""
    return f"branding/{organization_id}/background/{uuid.uuid4()}.webp"


async def _backfill_one(
    branding: Branding,
    storage: ObjectStorageProtocol,
    *,
    dry_run: bool,
) -> Outcome:
    old_key = branding.background_image_key or ""
    org_id = branding.organization_id

    if old_key.lower().endswith(".webp"):
        return Outcome(org_id, old_key, None, 0, 0, "skipped", "already webp")

    try:
        content = await storage.download(key=old_key)
    except ObjectStorageError as exc:
        return Outcome(org_id, old_key, None, 0, 0, "failed", f"download: {exc}")
    except KeyError as exc:
        # The in-memory fake used by tests raises KeyError for a key it
        # has never seen; a real deployment can hit the same shape if a
        # row points at an object somebody removed out of band.
        return Outcome(org_id, old_key, None, 0, 0, "failed", f"missing: {exc}")

    before = len(content)
    processed = _process_background_image(content)
    if processed is None:
        # The pipeline's own graceful path: unreadable, a decompression
        # bomb, or past the size guards. Leave the row untouched -- the
        # original object is still there and still serving.
        return Outcome(org_id, old_key, None, before, before, "unprocessable")

    new_content, content_type, _extension, metrics = processed
    after = len(new_content)
    new_key = _new_key_for(org_id)

    if dry_run:
        return Outcome(org_id, old_key, new_key, before, after, "would-write")

    try:
        await storage.upload(
            key=new_key, content=new_content, content_type=content_type
        )
    except ObjectStorageError as exc:
        return Outcome(
            org_id, old_key, new_key, before, after, "failed", f"upload: {exc}"
        )

    # Only after the new object is durably written -- so an interruption
    # between the two leaves an orphaned object (harmless, swept later)
    # rather than a row pointing at bytes that were never uploaded.
    branding.background_image_key = new_key
    branding.background_luminance = metrics.luminance
    branding.background_top_luminance = metrics.top_luminance
    branding.background_entropy = metrics.entropy
    return Outcome(org_id, old_key, new_key, before, after, "written")


def _fmt_kb(n: int) -> str:
    return f"{n / 1024:.1f} KB"


async def run(*, dry_run: bool) -> int:
    storage = get_object_storage()
    outcomes: list[Outcome] = []

    async with SessionLocal() as session:
        rows = (
            (
                await session.execute(
                    select(Branding).where(
                        Branding.background_image_key.is_not(None),
                        Branding.is_deleted == False,  # noqa: E712
                    )
                )
            )
            .scalars()
            .all()
        )

        for branding in rows:
            outcomes.append(await _backfill_one(branding, storage, dry_run=dry_run))

        if dry_run:
            await session.rollback()
        else:
            await session.commit()

    mode = "DRY RUN -- nothing written" if dry_run else "LIVE"
    print(f"\nBackground image backfill ({mode})")
    print(f"{len(outcomes)} organization(s) with a background image\n")

    total_before = total_after = 0
    for o in outcomes:
        if o.status in ("written", "would-write"):
            total_before += o.before_bytes
            total_after += o.after_bytes
            saved = 100 * (1 - o.after_bytes / o.before_bytes) if o.before_bytes else 0
            print(
                f"  {o.organization_id}  {o.status:<11} "
                f"{_fmt_kb(o.before_bytes):>10} -> {_fmt_kb(o.after_bytes):>10} "
                f"({saved:5.1f}% smaller)"
            )
            print(f"      {o.old_key}\n   -> {o.new_key}")
        else:
            print(f"  {o.organization_id}  {o.status:<11} {o.detail}")

    if total_before:
        saved = 100 * (1 - total_after / total_before)
        print(
            f"\n  TOTAL  {_fmt_kb(total_before)} -> {_fmt_kb(total_after)} "
            f"({saved:.1f}% smaller)"
        )

    failed = sum(1 for o in outcomes if o.status == "failed")
    if failed:
        print(f"\n  {failed} organization(s) failed -- rows left untouched.")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Read and process everything, report the per-organization "
        "before/after bytes, but write nothing to object storage or the "
        "database.",
    )
    args = parser.parse_args()
    return asyncio.run(run(dry_run=args.dry_run))


if __name__ == "__main__":
    raise SystemExit(main())
