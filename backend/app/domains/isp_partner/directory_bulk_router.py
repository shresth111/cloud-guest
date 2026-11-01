"""DIR-2 (ADDENDUM_06): directory export + bulk actions on subscribers.

Flag ``ISP_DIR2_ENABLED`` (default OFF -> 404). Paths sit outside
``/subscribers/{subscriber_id}/...`` on purpose (``/subscribers/bulk`` would be
read as a subscriber id).

* ``GET /subscriber-directory/export?format=csv|xlsx`` -- the directory with
  the same filters (state, search, customer, package, zone), every page, up to
  ``MAX_EXPORT_ROWS``. ``isp_subscribers.read`` + the caller's confinement,
  exactly like ``GET /subscribers/directory``.
* ``POST /subscriber-bulk/renew``   (``isp_invoices.create``, unpaid invoices)
* ``POST /subscriber-bulk/status``  (``isp_subscribers.update``: block
  temporary / unblock / freeze / unfreeze)
* ``POST /subscriber-bulk/move``    (``isp_subscribers.manage``)

Each bulk call takes a selection (explicit ``subscriber_ids`` or a directory
``filter``) and ``dry_run`` (default true): a dry run changes nothing and
returns ``{matched, eligible, skipped: [{id, reason}]}`` from the same guard
rules the single actions apply. A real run (``dry_run=false``) needs a
``bulk_key``; every subscriber goes through the existing single-action
service method in its own savepoint, so one refusal never undoes the others,
and renewals are idempotent per ``bulk_key`` + subscriber (a retried batch
renews nobody twice). Permanent blocks are not offered in bulk.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select

from .apps_export import csv_response, render_csv
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspError
from .http import ok
from .subscriber360_models import IspSubscriberProfile
from .subscriber360_router import get_subscriber360_service
from .subscriber360_service import _OWNERISH, IspSubscriber360Service

__all__ = ["directory_bulk_router"]

SUBS_READ = "isp_subscribers.read"
SUBS_UPDATE = "isp_subscribers.update"
SUBS_MANAGE = "isp_subscribers.manage"
INVOICES_CREATE = "isp_invoices.create"
MAX_BULK = 500
MAX_EXPORT_ROWS = 50_000
_PAGE = 100


class IspDir2Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_DIR2_", case_sensitive=False, extra="ignore"
    )

    enabled: bool = Field(default=False, description="ISP_DIR2_ENABLED")


@lru_cache(maxsize=1)
def get_dir2_settings() -> IspDir2Settings:
    return IspDir2Settings()


async def RequireDir2Enabled() -> None:
    if not get_dir2_settings().enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


directory_bulk_router = APIRouter(
    tags=["ISP Partner: subscriber directory bulk"],
    dependencies=[Depends(RequireDir2Enabled)],
)


# ---------------------------------------------------------------------------
# selection
# ---------------------------------------------------------------------------
class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class DirectoryFilter(_Body):
    state: str | None = Field(default=None, max_length=30)
    search: str | None = Field(default=None, max_length=100)
    isp_customer_id: uuid.UUID | None = None
    package_id: uuid.UUID | None = None
    zone_id: uuid.UUID | None = None


class _Selection(_Body):
    subscriber_ids: list[uuid.UUID] | None = Field(default=None, max_length=MAX_BULK)
    filter: DirectoryFilter | None = None
    dry_run: bool = True
    bulk_key: str | None = Field(default=None, min_length=8, max_length=48)

    @model_validator(mode="after")
    def _one_selection(self) -> _Selection:
        if (self.subscriber_ids is None) == (self.filter is None):
            raise ValueError("send either subscriber_ids or filter")
        if not self.dry_run and not self.bulk_key:
            raise ValueError("bulk_key is required to apply a bulk action")
        return self


class BulkRenewRequest(_Selection):
    package_id: uuid.UUID | None = None
    cycles: int = Field(default=1, ge=1, le=12)


class BulkStatusRequest(_Selection):
    action: Literal["block", "unblock", "freeze", "unfreeze"]
    reason: str | None = Field(default=None, max_length=255)


class BulkMoveRequest(_Selection):
    isp_customer_id: uuid.UUID
    reason: str | None = Field(default=None, max_length=255)


async def _directory_rows(
    svc: IspSubscriber360Service, isp: IspContext, f: DirectoryFilter, limit: int
) -> tuple[list[dict], int]:
    """Directory rows for ``f`` (scope + confinement as the directory), up to
    ``limit``; returns (rows, total)."""
    out: list[dict] = []
    page, total = 1, 0
    while len(out) < limit:
        d = await svc.directory(
            isp,
            state=f.state,
            search=f.search,
            isp_customer_id=f.isp_customer_id,
            package_id=f.package_id,
            zone_id=f.zone_id,
            page=page,
            page_size=_PAGE,
        )
        total = d["total"]
        out.extend(d["items"])
        if page >= (d["pages"] or 0):
            break
        page += 1
    return out[:limit], total


async def _selected_ids(
    svc: IspSubscriber360Service, isp: IspContext, body: _Selection
) -> list[uuid.UUID]:
    if body.subscriber_ids is not None:
        return list(dict.fromkeys(body.subscriber_ids))
    rows, total = await _directory_rows(svc, isp, body.filter, MAX_BULK + 1)
    if total > MAX_BULK:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"The filter matches {total} subscribers; "
                f"narrow it to {MAX_BULK} or fewer"
            ),
        )
    return [uuid.UUID(str(r["id"])) for r in rows]


async def _load(
    svc: IspSubscriber360Service, isp: IspContext, sid: uuid.UUID
) -> tuple[Any, Any] | None:
    """(subscriber, profile) inside the caller's scope, else None (404)."""
    try:
        s = await svc.plans.subscriber(isp, sid)
    except IspError:
        return None
    p = (
        await svc.session.execute(
            select(IspSubscriberProfile).where(
                IspSubscriberProfile.subscriber_id == s.id,
                IspSubscriberProfile.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    return s, p


# ---------------------------------------------------------------------------
# eligibility (the single actions' own guard clauses, read-only)
# ---------------------------------------------------------------------------
def renew_skip(s: Any, p: Any) -> str | None:
    if p is not None and p.block_kind:
        return "blocked"
    if p is not None and p.frozen_at is not None:
        return "frozen"
    if s.status == "disabled":
        return "disabled"
    if s.package_id is None:
        return "no_package"
    return None


def status_skip(
    action: str, s: Any, p: Any, *, role_slug: str, now: datetime
) -> str | None:
    blocked = p.block_kind if p is not None else None
    frozen = p is not None and p.frozen_at is not None
    if action == "block":
        return "already_blocked" if blocked else None
    if action == "unblock":
        if not blocked:
            return "not_blocked"
        if blocked == "permanent" and role_slug not in _OWNERISH:
            return "permanent_owner_only"
        return None
    if action == "freeze":
        if blocked:
            return "blocked"
        if frozen:
            return "already_frozen"
        if s.valid_until is None or s.valid_until <= now or s.status == "disabled":
            return "no_validity_left"
        return None
    if action == "unfreeze":
        return None if frozen else "not_frozen"
    return "unknown_action"


def move_skip(s: Any, target_id: uuid.UUID) -> str | None:
    return "already_there" if s.customer_organization_id == target_id else None


async def _run(
    svc: IspSubscriber360Service,
    isp: IspContext,
    body: _Selection,
    *,
    skip,  # noqa: ANN001 -- (s, p) -> reason | None
    apply,  # noqa: ANN001 -- async (sid) -> Any
) -> dict:
    ids = await _selected_ids(svc, isp, body)
    eligible: list[uuid.UUID] = []
    skipped: list[dict] = []
    for sid in ids:
        loaded = await _load(svc, isp, sid)
        if loaded is None:
            skipped.append({"id": str(sid), "reason": "not_found"})
            continue
        reason = skip(*loaded)
        if reason:
            skipped.append({"id": str(sid), "reason": reason})
        else:
            eligible.append(sid)
    out: dict[str, Any] = {
        "dry_run": body.dry_run,
        "matched": len(ids),
        "eligible": len(eligible),
        "skipped": skipped,
    }
    if body.dry_run:
        return out
    done: list[str] = []
    failed: list[dict] = []
    for sid in eligible:
        try:
            async with svc.session.begin_nested():
                await apply(sid)
            done.append(str(sid))
        except IspError as exc:
            failed.append(
                {
                    "id": str(sid),
                    "reason": getattr(exc, "code", "error"),
                    "message": str(exc)[:200],
                }
            )
    out.update(applied=len(done), applied_ids=done, failed=failed)
    return out


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
@directory_bulk_router.post(
    "/subscriber-bulk/renew", dependencies=isp_guards(INVOICES_CREATE)
)
async def bulk_renew(
    request: Request,
    payload: BulkRenewRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    async def apply(sid: uuid.UUID) -> Any:
        data: dict[str, Any] = {
            "paid_now": False,
            "idempotency_key": f"bulk-{payload.bulk_key}-{sid.hex[:12]}"[:64],
        }
        if payload.package_id:
            data["package_id"] = payload.package_id
        if payload.cycles > 1:
            data["cycles"] = payload.cycles
        return await svc.renew(isp, sid, data)

    res = await _run(svc, isp, payload, skip=renew_skip, apply=apply)
    return ok(request, res, "Bulk renew" + (" (dry run)" if payload.dry_run else ""))


@directory_bulk_router.post(
    "/subscriber-bulk/status", dependencies=isp_guards(SUBS_UPDATE)
)
async def bulk_status(
    request: Request,
    payload: BulkStatusRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    now = svc.now()

    async def apply(sid: uuid.UUID) -> Any:
        if payload.action == "block":
            return await svc.block(isp, sid, kind="temporary", reason=payload.reason)
        if payload.action == "unblock":
            return await svc.unblock(isp, sid)
        if payload.action == "freeze":
            return await svc.freeze(isp, sid, reason=payload.reason)
        return await svc.unfreeze(isp, sid)

    res = await _run(
        svc,
        isp,
        payload,
        skip=lambda s, p: status_skip(
            payload.action, s, p, role_slug=isp.role_slug, now=now
        ),
        apply=apply,
    )
    return ok(
        request,
        res,
        f"Bulk {payload.action}" + (" (dry run)" if payload.dry_run else ""),
    )


@directory_bulk_router.post(
    "/subscriber-bulk/move", dependencies=isp_guards(SUBS_MANAGE)
)
async def bulk_move(
    request: Request,
    payload: BulkMoveRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> dict:
    from .scoping import IspScope

    await IspScope.assert_customer(isp, payload.isp_customer_id)  # 404 outside scope

    async def apply(sid: uuid.UUID) -> Any:
        return await svc.move(
            isp, sid, isp_customer_id=payload.isp_customer_id, reason=payload.reason
        )

    res = await _run(
        svc,
        isp,
        payload,
        skip=lambda s, p: move_skip(s, payload.isp_customer_id),
        apply=apply,
    )
    return ok(request, res, "Bulk move" + (" (dry run)" if payload.dry_run else ""))


def _name(r: dict) -> str:
    return " ".join(x for x in (r.get("first_name"), r.get("last_name")) if x) or (
        r.get("display_name") or ""
    )


def _nested(r: dict, key: str) -> str:
    v = r.get(key)
    return (v or {}).get("name", "") if isinstance(v, dict) else (v or "")


_COLUMNS = (
    ("Subscriber ID", lambda r: r.get("identifier")),
    ("Circuit ID", lambda r: r.get("circuit_id")),
    ("Name", _name),
    ("Phone", lambda r: r.get("phone")),
    ("State", lambda r: r.get("display_state")),
    ("Package", lambda r: _nested(r, "package")),
    ("Valid until", lambda r: r.get("valid_until")),
    ("Customer", lambda r: r.get("customer_name")),
    ("Zone", lambda r: _nested(r, "zone")),
    ("User type", lambda r: r.get("user_type")),
    ("Last seen", lambda r: r.get("last_seen_at")),
)


@directory_bulk_router.get(
    "/subscriber-directory/export", dependencies=isp_guards(SUBS_READ)
)
async def export_directory(
    format: Literal["csv", "xlsx"] = "csv",
    state: str | None = Query(default=None, max_length=30),
    search: str | None = Query(default=None, max_length=100),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    package_id: uuid.UUID | None = Query(default=None),
    zone_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspSubscriber360Service = Depends(get_subscriber360_service),
) -> Response:
    rows, _ = await _directory_rows(
        svc,
        isp,
        DirectoryFilter(
            state=state,
            search=search,
            isp_customer_id=isp_customer_id,
            package_id=package_id,
            zone_id=zone_id,
        ),
        MAX_EXPORT_ROWS,
    )
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    if format == "csv":
        return csv_response(render_csv(_COLUMNS, rows), f"subscribers-{stamp}.csv")
    from app.domains.analytics.constants import ExportFormat
    from app.domains.analytics.export import render_report
    from app.domains.analytics.report_types import ReportPayload, ReportSection

    table = [
        {name: (get(r) if get(r) is not None else "") for name, get in _COLUMNS}
        for r in rows
    ]
    payload = ReportPayload(
        report_type="isp_subscribers",
        title=f"{isp.organization.name} subscribers",
        generated_at=datetime.now(UTC).isoformat(),
        organization_id=None,
        location_id=None,
        period_start=None,
        period_end=None,
        sections=[
            ReportSection(
                key="subscribers",
                title="Subscribers",
                data={
                    "subscribers": table
                    or [dict.fromkeys((c for c, _ in _COLUMNS), "")]
                },
            )
        ],
    )
    rendered = render_report(payload, ExportFormat.EXCEL)
    return Response(
        content=rendered.content,
        media_type=rendered.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="subscribers-{stamp}.xlsx"',
            "Cache-Control": "no-store",
        },
    )


@directory_bulk_router.get("/subscriber-bulk", dependencies=isp_guards(SUBS_READ))
async def bulk_capabilities(request: Request) -> dict:
    """Lets the FE show the bulk bar only when DIR-2 is on (404 otherwise)."""
    return ok(
        request,
        {
            "enabled": True,
            "max_subscribers": MAX_BULK,
            "max_export_rows": MAX_EXPORT_ROWS,
        },
        "Bulk actions",
    )
