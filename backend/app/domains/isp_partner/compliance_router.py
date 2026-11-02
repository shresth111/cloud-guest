"""``/isp/compliance/*`` (ADDENDUM_05, lane JAZE-3).

J4 counters + NAT-feed banner, J5 CGNAT lookup, J12 session dump, J6 KYC /
documents / CAF, J17 TRAI PMR + AGR + schedules, J18 report catalogue.

Same guard stack as every ``/isp`` route (``isp_guards``: flag, ISP partner,
permission pinned to the ISP org, no location/router headers). Path ids are
``subscriber_id`` / ``document_id`` / ``report_key`` -- never a scope-alias
name. Existing keys only (no RBAC seed change):

* reads: ``isp_partner.read``; KYC writes: ``isp_partner.update``;
  settings + schedules: ``isp_partner.manage``;
* CGNAT lookup: ``isp_ipdr.read``; its CSV + the session dump:
  ``isp_ipdr.export`` (unmasked, audited before the first byte);
* CAF PDF, KYC files, report CSVs: ``isp_partner.export`` (audited);
* AGR: ``isp_billing.read`` / ``isp_billing.export``.
"""

from __future__ import annotations

import csv
import io
import re
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Body, Depends, File, Form, Query, Request, UploadFile
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.ipdr.dependencies import get_ipdr_service
from app.domains.ipdr.formatting import csv_safe, mask_email, mask_phone
from app.domains.ipdr.service import IpdrService
from app.domains.organization.models import Organization
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from . import compliance_kyc as kyc_mod
from . import compliance_logic as logic
from .compliance_models import (
    IspComplianceSettings,
    IspReportSchedule,
    IspSubscriberDocument,
)
from .compliance_reports import CATALOGUE, IspComplianceReports, catalogue
from .compliance_service import (
    SESSION_DUMP_COLUMNS,
    SESSION_DUMP_MAX_DAYS,
    SESSION_DUMP_NOT_CAPTURED,
    IspComplianceService,
    compliance_settings,
)
from .constants import (
    ISP_BILLING_EXPORT,
    ISP_BILLING_READ,
    ISP_IPDR_EXPORT,
    ISP_IPDR_READ,
    ISP_PARTNER_EXPORT,
    ISP_PARTNER_MANAGE,
    ISP_PARTNER_READ,
    ISP_PARTNER_UPDATE,
    ISP_SUBSCRIBERS_KYC,  # RBAC-FIX
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspBadRequestError
from .http import ok
from .parity_settings import pii_unmasked_for, record_unmasked_view
from .scoping import IspScope

compliance_router = APIRouter(prefix="/compliance", tags=["ISP Partner: compliance"])

IST = ZoneInfo("Asia/Kolkata")
AUDIT_CGNAT_LOOKUP = "isp_cgnat_lookup"
AUDIT_CGNAT_EXPORT = "isp_cgnat_lookup_exported"
AUDIT_SESSION_DUMP = "isp_session_dump_exported"
AUDIT_CAF_PDF = "isp_caf_generated"
AUDIT_KYC_UPDATED = "isp_kyc_updated"
AUDIT_KYC_DOCUMENT = "isp_kyc_document"
AUDIT_COMPLIANCE_EXPORT = "isp_compliance_report_exported"
REPORT_SCHEDULE_KEYS = ("trai_pmr", "agr", "subscriber_details_status")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def get_compliance_service(
    db: AsyncSession = Depends(get_db_session),
) -> IspComplianceService:
    return IspComplianceService(db)


async def _audit(
    audit: RBACRepositoryProtocol,
    isp: IspContext,
    action: str,
    description: str,
    metadata: dict[str, Any],
    *,
    entity_id: uuid.UUID | None = None,
) -> None:
    await audit.create_audit_log_entry(
        actor_user_id=isp.user_id,
        action=action,
        entity_type="organization",
        entity_id=entity_id or isp.isp_org_id,
        description=description,
        event_metadata={"console": "isp", **metadata},
        organization_id=isp.isp_org_id,
        location_id=None,
    )


def _csv_line(writer: Any, buffer: io.StringIO, values: list[Any]) -> str:
    buffer.seek(0)
    buffer.truncate()
    writer.writerow([csv_safe("" if v is None else v) for v in values])
    return buffer.getvalue()


def _ist(value: Any) -> Any:
    if isinstance(value, datetime):
        aware = value if value.tzinfo else value.replace(tzinfo=UTC)
        return aware.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")
    return value


def _download(content: bytes, media: str, name: str) -> Response:
    return Response(
        content=content,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "no-store",
        },
    )


# ============================================================================
# J4
# ============================================================================


@compliance_router.get("/counters", dependencies=isp_guards(ISP_PARTNER_READ))
async def counters(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspComplianceService = Depends(get_compliance_service),
) -> dict:
    return ok(
        request,
        await service.counters(isp, isp_customer_id=isp_customer_id),
        "Subscriber counters",
    )


@compliance_router.get("/nat-feed", dependencies=isp_guards(ISP_PARTNER_READ))
async def nat_feed(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspComplianceService = Depends(get_compliance_service),
) -> dict:
    return ok(
        request,
        await service.nat_feed(isp, isp_customer_id=isp_customer_id),
        "NAT log feed",
    )


# ============================================================================
# J5: CGNAT lookup
# ============================================================================


def _lookup_query(
    public_ip: str = Query(..., max_length=64),
    public_port: int | None = Query(default=None, ge=0, le=65535),
    at: datetime = Query(...),
    tz: str = Query(default="Asia/Kolkata", max_length=64),
    tolerance_seconds: int = Query(default=60, ge=0, le=900),
    protocol: str | None = Query(default=None, pattern="^(tcp|udp|icmp|any)?$"),
    dst_ip: str | None = Query(default=None, max_length=64),
    dst_port: int | None = Query(default=None, ge=0, le=65535),
) -> logic.LookupQuery:
    try:
        zone = ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise IspBadRequestError(
            "Unknown time zone", field="tz", reason="ISP_QUERY_INVALID"
        ) from exc
    try:
        ip = logic.normalize_ip(public_ip)
        dst = logic.normalize_ip(dst_ip) if dst_ip else None
    except ValueError as exc:
        raise IspBadRequestError("Not an IP address", field="public_ip") from exc
    moment = at if at.tzinfo else at.replace(tzinfo=zone)
    proto = {"tcp": 6, "udp": 17, "icmp": 1}.get(protocol or "")
    return logic.LookupQuery(
        public_ip=ip,
        public_port=public_port,
        at=moment.astimezone(UTC),
        tolerance=timedelta(seconds=tolerance_seconds),
        protocol=proto,
        dst_ip=dst,
        dst_port=dst_port,
    )


async def _lookup(
    isp: IspContext,
    q: logic.LookupQuery,
    isp_customer_id: uuid.UUID | None,
    ipdr: IpdrService,
    service: IspComplianceService,
) -> dict[str, Any]:
    if isp_customer_id is not None:
        await IspScope.assert_customer(isp, isp_customer_id)
        org_ids = [isp_customer_id]
    else:
        org_ids = await isp.child_ids()
    routers = await service.routers_of(org_ids)
    owned_by_router = [
        {
            "isp_router_id": str(r.id),
            "router_name": r.name,
            "isp_customer_id": str(r.organization_id),
        }
        for r in routers
        if r.public_ip_address and r.public_ip_address == q.public_ip
    ]
    matches: list[dict[str, Any]] = []
    searched: list[str] = []
    for org_id in org_ids:
        filters = await ipdr.build_filters(
            organization_id=org_id,
            since=q.since,
            until=q.until + timedelta(seconds=1),
            ip=q.public_ip,
        )
        searched.append(str(org_id))
        async for record in ipdr.iter_records(filters):
            if logic.record_covers(record, q):
                matches.append(record)
    had_data = await service.had_nat_data([r.id for r in routers], q.since, q.until)
    keys = {
        (m["organization_id"], (m.get("user_id") or "").lower())
        for m in matches
        if m.get("user_known")
    }
    dossiers = await service.subscriber_dossiers(isp, keys)
    names = await isp.repository.names(Organization, org_ids)
    out = []
    for m in matches:
        key = (m["organization_id"], (m.get("user_id") or "").lower())
        out.append(
            {
                "record": m,
                "subscriber": dossiers.get(key),
                "customer_name": names.get(uuid.UUID(m["organization_id"])),
            }
        )
    return {
        "query": {
            "public_ip": q.public_ip,
            "public_port": q.public_port,
            "at_utc": q.at.isoformat(),
            "at_ist": q.at.astimezone(IST).isoformat(),
            "window_start": q.since.isoformat(),
            "window_end": q.until.isoformat(),
            "protocol": q.protocol,
            "dst_ip": q.dst_ip,
            "dst_port": q.dst_port,
        },
        "verdict": logic.verdict(matches, had_nat_data=had_data),
        "nat_data_in_window": had_data,
        "public_ip_is_router_wan": owned_by_router,
        "matches": out,
        "customers_searched": len(searched),
        "time_basis": (
            "Connection times come from the router's own flow timestamps when "
            "it sent them (ts_source=flow), otherwise from the collector "
            "window the record arrived in (ts_source=window). Compare with "
            "the requester's clock and zone; widen the tolerance if the "
            "requester's clock may be off."
        ),
        "evidence_notes": [
            "nat_source=nat_event: the router reported this translation.",
            "nat_source=derived: the router's public IP with the original "
            "port; valid only where the router does not rewrite ports.",
            "nat_source=ambiguous: several connections shared the address; "
            "do not attribute without more detail (destination, port).",
        ],
    }


def _masked_match(item: dict[str, Any]) -> dict[str, Any]:
    record = dict(item["record"])
    for key in ("phone", "alt_phone"):
        if record.get(key):
            record[key] = mask_phone(record[key])
    if record.get("email"):
        record["email"] = mask_email(record["email"])
    sub = dict(item["subscriber"]) if item["subscriber"] else None
    if sub:
        sub["phone"] = mask_phone(sub["phone"]) if sub.get("phone") else None
        sub["email"] = mask_email(sub["email"]) if sub.get("email") else None
    return {**item, "record": record, "subscriber": sub}


@compliance_router.get("/cgnat-lookup", dependencies=isp_guards(ISP_IPDR_READ))
async def cgnat_lookup(
    request: Request,
    q: logic.LookupQuery = Depends(_lookup_query),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    ipdr: IpdrService = Depends(get_ipdr_service),
    service: IspComplianceService = Depends(get_compliance_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    """Public IP (+ port) at an instant -> the subscriber who held it.
    Masked here; the CSV carries the full identity."""
    data = await _lookup(isp, q, isp_customer_id, ipdr, service)
    unmasked = await pii_unmasked_for(service.session, isp)
    if not unmasked:
        data["matches"] = [_masked_match(m) for m in data["matches"]]
    await _audit(
        audit,
        isp,
        AUDIT_CGNAT_LOOKUP,
        "CGNAT lookup",
        {
            "query": data["query"],
            "verdict": data["verdict"],
            "matches": len(data["matches"]),
            "unmasked": unmasked,
        },
    )
    return ok(request, data, "CGNAT lookup")


_LOOKUP_CSV = (
    "Verdict",
    "Customer",
    "Time Stamp (IST)",
    "Connection End (IST)",
    "Time Source",
    "Source IP",
    "Source Port",
    "Translated IP",
    "Translated Port",
    "Translation Source",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "User ID",
    "Name",
    "Phone",
    "Email",
    "MAC",
    "Circuit ID",
    "Subscriber Name",
    "Subscriber Phone",
    "Subscriber Email",
    "Installation Address",
    "CAF No.",
    "ID Proof",
    "ID Number (masked)",
    "Router ID",
)


@compliance_router.get(
    "/cgnat-lookup/export.csv", dependencies=isp_guards(ISP_IPDR_EXPORT)
)
async def cgnat_lookup_export(
    q: logic.LookupQuery = Depends(_lookup_query),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    ipdr: IpdrService = Depends(get_ipdr_service),
    service: IspComplianceService = Depends(get_compliance_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    data = await _lookup(isp, q, isp_customer_id, ipdr, service)
    await _audit(
        audit,
        isp,
        AUDIT_CGNAT_EXPORT,
        "CGNAT lookup exported",
        {
            "query": data["query"],
            "verdict": data["verdict"],
            "matches": len(data["matches"]),
        },
    )
    await db.commit()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    out = [
        _csv_line(
            writer,
            buffer,
            [
                f"# CGNAT lookup {data['query']['public_ip']}:"
                f"{data['query']['public_port'] or '*'} at "
                f"{data['query']['at_ist']} +/- window "
                f"{data['query']['window_start']} .. "
                f"{data['query']['window_end']} (UTC)"
            ],
        ),
        _csv_line(
            writer,
            buffer,
            [
                f"# verdict: {data['verdict']}; NAT data in "
                f"window: {data['nat_data_in_window']}"
            ],
        ),
        _csv_line(writer, buffer, list(_LOOKUP_CSV)),
    ]
    for item in data["matches"]:
        r, s = item["record"], item["subscriber"] or {}
        out.append(
            _csv_line(
                writer,
                buffer,
                [
                    data["verdict"],
                    item["customer_name"],
                    _ist(_dt(r.get("ts"))),
                    _ist(_dt(r.get("ts_end"))),
                    r.get("ts_source"),
                    r.get("src_ip"),
                    r.get("src_port"),
                    r.get("nat_ip"),
                    r.get("nat_port"),
                    r.get("nat_source"),
                    r.get("dst_ip"),
                    r.get("dst_port"),
                    r.get("protocol"),
                    r.get("user_id"),
                    r.get("name"),
                    r.get("phone"),
                    r.get("email"),
                    r.get("mac"),
                    s.get("circuit_id"),
                    s.get("name"),
                    s.get("phone"),
                    s.get("email"),
                    s.get("address"),
                    s.get("caf_number"),
                    s.get("id_proof_type"),
                    s.get("id_number_masked"),
                    r.get("router_id"),
                ],
            )
        )
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return _download(
        "".join(out).encode(), "text/csv; charset=utf-8", f"cgnat-lookup-{stamp}.csv"
    )


def _dt(value: Any) -> datetime | None:
    if value is None:
        return None
    return value if isinstance(value, datetime) else datetime.fromisoformat(str(value))


# ============================================================================
# J12: session dump
# ============================================================================


@compliance_router.get("/session-dump.csv", dependencies=isp_guards(ISP_IPDR_EXPORT))
async def session_dump(
    since: datetime = Query(...),
    until: datetime = Query(...),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspComplianceService = Depends(get_compliance_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
    db: AsyncSession = Depends(get_db_session),
) -> StreamingResponse:
    since = since if since.tzinfo else since.replace(tzinfo=IST)
    until = until if until.tzinfo else until.replace(tzinfo=IST)
    if since >= until:
        raise IspBadRequestError(
            "since must be before until", field="since", reason="ISP_DATE_RANGE_ORDER"
        )
    if until - since > timedelta(days=SESSION_DUMP_MAX_DAYS):
        raise IspBadRequestError(
            f"A session dump covers at most {SESSION_DUMP_MAX_DAYS} days",
            field="until",
            reason="ISP_DATE_RANGE_TOO_LONG",
            max_days=SESSION_DUMP_MAX_DAYS,
        )
    if isp_customer_id is not None:
        await IspScope.assert_customer(isp, isp_customer_id)
    await _audit(
        audit,
        isp,
        AUDIT_SESSION_DUMP,
        "Session dump exported",
        {
            "since": since.isoformat(),
            "until": until.isoformat(),
            "isp_customer_id": str(isp_customer_id) if isp_customer_id else None,
        },
    )
    await db.commit()

    async def stream() -> AsyncIterator[str]:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        yield _csv_line(
            writer,
            buffer,
            [
                f"# Sessions overlapping {_ist(since)} .. {_ist(until)} IST. "
                "Not captured by the platform (always empty): "
                f"{', '.join(SESSION_DUMP_NOT_CAPTURED)}."
            ],
        )
        yield _csv_line(writer, buffer, list(SESSION_DUMP_COLUMNS))
        async for row in service.session_rows(
            isp, since=since, until=until, isp_customer_id=isp_customer_id
        ):
            if "__truncated__" in row:
                yield _csv_line(
                    writer,
                    buffer,
                    [f"# truncated at {row['__truncated__']} rows; narrow the range"],
                )
                return
            yield _csv_line(
                writer, buffer, [_ist(row[c]) for c in SESSION_DUMP_COLUMNS]
            )

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return StreamingResponse(
        stream(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="session-dump-{stamp}.csv"',
            "Cache-Control": "no-store",
        },
    )


# ============================================================================
# settings
# ============================================================================

_SETTINGS_FIELDS = (
    "legal_name",
    "licence_number",
    "licence_category",
    "registered_address",
    "gstin",
    "compliance_email",
    "caf_prefix",
    "nat_feed_stale_minutes",
    "gigabit_threshold_mbps",
    "churn_after_days",
)
_GSTIN = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$")


def _settings_view(row: IspComplianceSettings) -> dict[str, Any]:
    return {name: getattr(row, name) for name in _SETTINGS_FIELDS} | {
        "caf_next_seq": row.caf_next_seq
    }


@compliance_router.get("/settings", dependencies=isp_guards(ISP_PARTNER_READ))
async def get_settings_(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(
        request,
        _settings_view(await compliance_settings(db, isp.isp_org_id)),
        "Compliance settings",
    )


@compliance_router.put("/settings", dependencies=isp_guards(ISP_PARTNER_MANAGE))
async def put_settings(
    request: Request,
    body: dict[str, Any] = Body(...),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    row = await compliance_settings(db, isp.isp_org_id)
    if row not in db:
        db.add(row)
    for name in _SETTINGS_FIELDS:
        if name not in body:
            continue
        value = body[name]
        if isinstance(value, str):
            value = value.strip() or None
        if name == "gstin" and value is not None:
            value = value.upper()
            if not _GSTIN.fullmatch(value):
                raise IspBadRequestError("GSTIN format is invalid", field="gstin")
        if (
            name == "compliance_email"
            and value is not None
            and not _EMAIL.fullmatch(value)
        ):
            raise IspBadRequestError("Not an email address", field=name)
        if name == "caf_prefix":
            value = (value or "CAF").upper()
            if not re.fullmatch(r"[A-Z0-9]{1,10}", value):
                raise IspBadRequestError(
                    "CAF prefix is 1-10 letters/digits", field=name
                )
        if name in (
            "nat_feed_stale_minutes",
            "gigabit_threshold_mbps",
            "churn_after_days",
        ):
            limits = {
                "nat_feed_stale_minutes": (5, 1440),
                "gigabit_threshold_mbps": (100, 100000),
                "churn_after_days": (7, 365),
            }[name]
            if not isinstance(value, int) or not limits[0] <= value <= limits[1]:
                raise IspBadRequestError(
                    f"{name} must be between {limits[0]} and {limits[1]}",
                    field=name,
                    reason="ISP_VALUE_OUT_OF_RANGE",
                    min=limits[0],
                    max=limits[1],
                )
        setattr(row, name, value)
    row.updated_by = isp.user_id
    await db.commit()
    return ok(request, _settings_view(row), "Compliance settings saved")


# ============================================================================
# J6: KYC, documents, CAF
# ============================================================================


async def _subscriber(
    db: AsyncSession, isp: IspContext, subscriber_id: uuid.UUID
) -> Any:
    from .billing_service import IspBillingService

    return await IspBillingService(session=db, audit=None).subscriber_in_scope(
        isp, subscriber_id
    )


async def _documents(db: AsyncSession, subscriber_id: uuid.UUID) -> list[Any]:
    return list(
        (
            await db.execute(
                select(IspSubscriberDocument)
                .where(
                    IspSubscriberDocument.subscriber_id == subscriber_id,
                    IspSubscriberDocument.is_deleted.is_(False),
                )
                .order_by(IspSubscriberDocument.created_at)
            )
        ).scalars()
    )


@compliance_router.get(
    "/subscribers/{subscriber_id}/kyc", dependencies=isp_guards(ISP_SUBSCRIBERS_KYC)
)
async def get_kyc(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    unmasked = await pii_unmasked_for(db, isp)
    kyc = await kyc_mod.kyc_of(db, sub.id)
    if unmasked and kyc is not None:
        await record_unmasked_view(
            db, isp, what="subscriber_kyc", customer_org_id=sub.customer_organization_id
        )
        await db.commit()
    return ok(
        request,
        {
            "subscriber_id": str(sub.id),
            "kyc": kyc_mod.kyc_view(kyc, unmasked=unmasked),
            "documents": [
                kyc_mod.document_view(d) for d in await _documents(db, sub.id)
            ],
            "id_types": list(logic.ID_TYPES),
            "document_kinds": list(logic.DOCUMENT_KINDS),
        },
        "Subscriber KYC",
    )


@compliance_router.put(
    "/subscribers/{subscriber_id}/kyc", dependencies=isp_guards(ISP_PARTNER_UPDATE)
)
async def put_kyc(
    request: Request,
    subscriber_id: uuid.UUID,
    body: dict[str, Any] = Body(...),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    kyc = await kyc_mod.upsert_kyc(
        db,
        isp_org_id=isp.isp_org_id,
        subscriber_id=sub.id,
        body=body,
        actor=isp.user_id,
    )
    # never put the submitted number in the audit row
    await _audit(
        audit,
        isp,
        AUDIT_KYC_UPDATED,
        "Subscriber KYC updated",
        {
            "subscriber_id": str(sub.id),
            "fields": sorted(k for k in body if k != "id_number"),
            "id_number_changed": "id_number" in body,
        },
        entity_id=sub.customer_organization_id,
    )
    await db.commit()
    return ok(
        request,
        kyc_mod.kyc_view(kyc, unmasked=await pii_unmasked_for(db, isp)),
        "Subscriber KYC saved",
    )


@compliance_router.post(
    "/subscribers/{subscriber_id}/documents",
    status_code=201,
    dependencies=isp_guards(ISP_PARTNER_UPDATE),
)
async def upload_document(
    request: Request,
    subscriber_id: uuid.UUID,
    kind: str = Form(...),
    file: UploadFile = File(...),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    from app.core.storage import get_object_storage

    sub = await _subscriber(db, isp, subscriber_id)
    content = await file.read(logic.MAX_DOCUMENT_BYTES + 1)
    content_type = kyc_mod.validate_document(kind, content)
    key = kyc_mod.storage_key(isp.isp_org_id, sub.id, kind)
    await get_object_storage().upload(
        key=key, content=content, content_type=content_type
    )
    if kind in ("photo", "signature"):
        # one current photo / signature: older ones are superseded
        for old in await _documents(db, sub.id):
            if old.kind == kind:
                old.is_deleted, old.deleted_at = True, datetime.now(UTC)
    doc = kyc_mod.new_document(
        isp_org_id=isp.isp_org_id,
        subscriber_id=sub.id,
        kind=kind,
        key=key,
        filename=file.filename or kind,
        content_type=content_type,
        content=content,
        actor=isp.user_id,
    )
    db.add(doc)
    await db.flush()
    await _audit(
        audit,
        isp,
        AUDIT_KYC_DOCUMENT,
        "KYC document uploaded",
        {
            "subscriber_id": str(sub.id),
            "kind": kind,
            "document_id": str(doc.id),
            "sha256": doc.sha256,
        },
        entity_id=sub.customer_organization_id,
    )
    await db.commit()
    return ok(request, kyc_mod.document_view(doc), "Document uploaded")


async def _document(db, sub, document_id) -> IspSubscriberDocument:
    doc = await db.get(IspSubscriberDocument, document_id)
    if doc is None or doc.is_deleted or doc.subscriber_id != sub.id:
        raise kyc_mod.IspDocumentNotFoundError()
    return doc


@compliance_router.get(
    "/subscribers/{subscriber_id}/documents/{document_id}",
    dependencies=isp_guards(ISP_SUBSCRIBERS_KYC),
)
async def download_document(
    subscriber_id: uuid.UUID,
    document_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> Response:
    from app.core.storage import get_object_storage

    sub = await _subscriber(db, isp, subscriber_id)
    doc = await _document(db, sub, document_id)
    content = await get_object_storage().download(key=doc.storage_key)
    await _audit(
        audit,
        isp,
        AUDIT_KYC_DOCUMENT,
        "KYC document downloaded",
        {
            "subscriber_id": str(sub.id),
            "kind": doc.kind,
            "document_id": str(doc.id),
            "op": "download",
        },
        entity_id=sub.customer_organization_id,
    )
    await db.commit()
    return Response(
        content=content,
        media_type=doc.content_type,
        headers={
            "Content-Disposition": f'inline; filename="{doc.filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@compliance_router.delete(
    "/subscribers/{subscriber_id}/documents/{document_id}",
    dependencies=isp_guards(ISP_PARTNER_UPDATE),
)
async def delete_document(
    request: Request,
    subscriber_id: uuid.UUID,
    document_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    doc = await _document(db, sub, document_id)
    # soft delete: the stored object stays (an audit may need it)
    doc.is_deleted, doc.deleted_at = True, datetime.now(UTC)
    await _audit(
        audit,
        isp,
        AUDIT_KYC_DOCUMENT,
        "KYC document removed",
        {
            "subscriber_id": str(sub.id),
            "kind": doc.kind,
            "document_id": str(doc.id),
            "op": "delete",
        },
        entity_id=sub.customer_organization_id,
    )
    await db.commit()
    return ok(request, {"id": str(doc.id), "deleted": True}, "Document removed")


@compliance_router.post(
    "/subscribers/{subscriber_id}/caf", dependencies=isp_guards(ISP_PARTNER_UPDATE)
)
async def assign_caf(
    request: Request,
    subscriber_id: uuid.UUID,
    body: dict[str, Any] = Body(default_factory=dict),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    sub = await _subscriber(db, isp, subscriber_id)
    kyc = await kyc_mod.kyc_of(db, sub.id) or await kyc_mod.upsert_kyc(
        db, isp_org_id=isp.isp_org_id, subscriber_id=sub.id, body={}, actor=isp.user_id
    )
    number = await kyc_mod.assign_caf_number(
        db,
        isp_org_id=isp.isp_org_id,
        kyc=kyc,
        custom=body.get("caf_number"),
        today=datetime.now(IST).date(),
    )
    await db.commit()
    return ok(
        request,
        {"caf_number": number, "source": kyc.caf_number_source},
        "CAF number assigned",
    )


@compliance_router.get(
    "/subscribers/{subscriber_id}/caf.pdf", dependencies=isp_guards(ISP_SUBSCRIBERS_KYC)
)
async def caf_pdf(
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> Response:
    from app.core.storage import get_object_storage

    from .plans_models import IspPackage

    sub = await _subscriber(db, isp, subscriber_id)
    kyc = await kyc_mod.kyc_of(db, sub.id)
    if kyc is None:
        raise IspBadRequestError("Fill in the subscriber's KYC first", field="kyc")
    if not kyc.caf_number:
        await kyc_mod.assign_caf_number(
            db,
            isp_org_id=isp.isp_org_id,
            kyc=kyc,
            custom=None,
            today=datetime.now(IST).date(),
        )
    kyc.caf_generated_at = datetime.now(UTC)
    settings = await compliance_settings(db, isp.isp_org_id)
    storage = get_object_storage()
    images: dict[str, bytes | None] = {"photo": None, "signature": None}
    for doc in await _documents(db, sub.id):
        if doc.kind in images and doc.content_type != "application/pdf":
            try:
                images[doc.kind] = await storage.download(key=doc.storage_key)
            except Exception:  # noqa: BLE001 -- render the form without it
                images[doc.kind] = None
    package = await db.get(IspPackage, sub.package_id) if sub.package_id else None
    customer = await isp.repository.get_organization(sub.customer_organization_id)
    view = kyc_mod.kyc_view(kyc, unmasked=False) or {}
    view["caf_date"] = datetime.now(IST).strftime("%d-%m-%Y")
    name = " ".join(p for p in (sub.first_name, sub.last_name) if p) or sub.display_name
    content = kyc_mod.render_caf_pdf(
        isp={
            "legal_name": settings.legal_name or isp.organization.name,
            "registered_address": settings.registered_address,
            "licence_number": settings.licence_number,
            "licence_category": settings.licence_category,
            "gstin": settings.gstin or getattr(isp.profile, "gstin", None),
        },
        subscriber={
            "username": sub.identifier,
            "circuit_id": sub.circuit_id,
            "name": name,
            "phone": sub.phone,
            "email": sub.email,
            "address": sub.address,
            "gstin": sub.gstin,
            "package_name": package.name if package else None,
            "customer_name": customer.name if customer else None,
        },
        kyc=view,
        photo=images["photo"],
        signature=images["signature"],
    )
    await _audit(
        audit,
        isp,
        AUDIT_CAF_PDF,
        "CAF PDF generated",
        {"subscriber_id": str(sub.id), "caf_number": kyc.caf_number},
        entity_id=sub.customer_organization_id,
    )
    await db.commit()
    safe = re.sub(r"[^A-Za-z0-9_-]", "-", kyc.caf_number or str(sub.id))
    return _download(content, "application/pdf", f"caf-{safe}.pdf")


# ============================================================================
# J17: TRAI PMR + AGR
# ============================================================================

TRAI_REPORTS = ("subscriptions", "hotspots", "gigabit", "data_usage")


@compliance_router.get("/trai-pmr", dependencies=isp_guards(ISP_PARTNER_READ))
async def trai_pmr(
    request: Request,
    period: str = Query(..., pattern=r"^\d{4}-\d{2}$"),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspComplianceService = Depends(get_compliance_service),
) -> dict:
    return ok(request, await service.trai_pmr(isp, period=period), "TRAI PMR")


def trai_csv(data: dict[str, Any], report: str) -> bytes:
    buffer = io.StringIO()
    w = csv.writer(buffer)
    w.writerow(
        [
            f"# TRAI PMR {data['period']} ({data['timezone']}); prepared by Wyfy, "
            "verify before filing"
        ]
    )
    if report == "subscriptions":
        w.writerow(["Speed Tier", "Subscribers"])
        for row in data["subscriptions_by_speed"]:
            w.writerow([row["tier"], row["subscribers"]])
        w.writerow(["Total", data["subscriptions_total"]])
    elif report == "hotspots":
        h = data["public_wifi_hotspots"]
        w.writerow(["Metric", "Value"])
        for k in (
            "venues",
            "nas_routers",
            "access_points",
            "registered_users",
            "users_active_in_period",
            "sessions_in_period",
            "download_bytes",
            "upload_bytes",
        ):
            w.writerow([k, "" if h[k] is None else h[k]])
        w.writerow(["note", h["access_points_note"]])
    elif report == "gigabit":
        w.writerow([f"# download >= {data['gigabit_threshold_mbps']} Mbps"])
        w.writerow(["Circuit ID", "Username", "Customer", "Download Mbps"])
        for row in data["gigabit_subscribers"]:
            w.writerow(
                [
                    row["circuit_id"],
                    csv_safe(row["username"]),
                    csv_safe(row["customer_name"] or ""),
                    row["download_mbps"],
                ]
            )
        w.writerow(["Total", len(data["gigabit_subscribers"])])
    else:
        u = data["data_usage"]
        w.writerow(["Metric", "Value"])
        for k in ("download_bytes", "upload_bytes", "download_tb", "upload_tb"):
            w.writerow([k, u[k]])
        w.writerow(["source", u["source"]])
    return buffer.getvalue().encode()


@compliance_router.get(
    "/trai-pmr/export.csv", dependencies=isp_guards(ISP_PARTNER_EXPORT)
)
async def trai_pmr_export(
    period: str = Query(..., pattern=r"^\d{4}-\d{2}$"),
    report: str = Query(..., pattern="^(subscriptions|hotspots|gigabit|data_usage)$"),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspComplianceService = Depends(get_compliance_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> Response:
    data = await service.trai_pmr(isp, period=period)
    await _audit(
        audit,
        isp,
        AUDIT_COMPLIANCE_EXPORT,
        "TRAI PMR exported",
        {"report": f"trai_pmr.{report}", "period": period},
    )
    return _download(
        trai_csv(data, report),
        "text/csv; charset=utf-8",
        f"trai-pmr-{report}-{period}.csv",
    )


def _agr_range(since: date | None, until: date | None) -> tuple[date, date]:
    today = datetime.now(IST).date()
    if since is None:
        start = today.year if today.month >= 4 else today.year - 1
        since = date(start, 4, 1)
    return since, until or today


@compliance_router.get("/agr", dependencies=isp_guards(ISP_BILLING_READ))
async def agr(
    request: Request,
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspComplianceService = Depends(get_compliance_service),
) -> dict:
    s, u = _agr_range(since, until)
    return ok(request, await service.agr(isp, since=s, until=u), "AGR")


def agr_csv(data: dict[str, Any]) -> bytes:
    buffer = io.StringIO()
    w = csv.writer(buffer)
    w.writerow([f"# AGR {data['since']} .. {data['until']} (taxable value, Rs)"])
    w.writerow(["Head", "Amount (Rs)"])
    for k, label in (
        ("telecom_taxable_paise", "Telecom revenue (SAC 9984)"),
        ("other_taxable_paise", "Other revenue"),
        ("gross_taxable_paise", "Gross revenue"),
        ("gst_collected_paise", "GST collected (excluded)"),
    ):
        w.writerow([label, f"{data[k] / 100:.2f}"])
    w.writerow([])
    w.writerow(["SAC", "Taxable (Rs)"])
    for row in data["by_sac"]:
        w.writerow([row["sac_code"], f"{row['taxable_paise'] / 100:.2f}"])
    for note in data["notes"]:
        w.writerow([f"# {note}"])
    return buffer.getvalue().encode()


@compliance_router.get("/agr/export.csv", dependencies=isp_guards(ISP_BILLING_EXPORT))
async def agr_export(
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    service: IspComplianceService = Depends(get_compliance_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> Response:
    s, u = _agr_range(since, until)
    data = await service.agr(isp, since=s, until=u)
    await _audit(
        audit,
        isp,
        AUDIT_COMPLIANCE_EXPORT,
        "AGR exported",
        {"report": "agr", "since": s.isoformat(), "until": u.isoformat()},
    )
    return _download(agr_csv(data), "text/csv; charset=utf-8", f"agr-{s}-{u}.csv")


# ============================================================================
# J17: schedules
# ============================================================================


def _schedule_view(row: IspReportSchedule) -> dict[str, Any]:
    return {
        "report_key": row.report_key,
        "day_of_month": row.day_of_month,
        "recipients": list(row.recipients or []),
        "enabled": row.enabled,
        "last_period_sent": row.last_period_sent,
        "last_sent_at": row.last_sent_at.isoformat() if row.last_sent_at else None,
        "last_status": row.last_status,
    }


@compliance_router.get("/report-schedules", dependencies=isp_guards(ISP_PARTNER_READ))
async def list_schedules(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .compliance_tasks import schedules_enabled

    rows = (
        await db.execute(
            select(IspReportSchedule).where(
                IspReportSchedule.isp_organization_id == isp.isp_org_id,
                IspReportSchedule.is_deleted.is_(False),
            )
        )
    ).scalars()
    return ok(
        request,
        {
            "schedules": [_schedule_view(r) for r in rows],
            "report_keys": list(REPORT_SCHEDULE_KEYS),
            "delivery_enabled": schedules_enabled(),
        },
        "Report schedules",
    )


@compliance_router.put(
    "/report-schedules/{report_key}", dependencies=isp_guards(ISP_PARTNER_MANAGE)
)
async def put_schedule(
    request: Request,
    report_key: str,
    body: dict[str, Any] = Body(...),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    if report_key not in REPORT_SCHEDULE_KEYS:
        raise IspBadRequestError(
            "Unknown report", field="report_key", reason="ISP_QUERY_INVALID"
        )
    day = body.get("day_of_month", 1)
    if not isinstance(day, int) or not 1 <= day <= 28:
        raise IspBadRequestError(
            "day_of_month is 1-28",
            field="day_of_month",
            reason="ISP_DAY_OF_MONTH_RANGE",
        )
    recipients = body.get("recipients") or []
    if (
        not isinstance(recipients, list)
        or not 1 <= len(recipients) <= 5
        or not all(
            isinstance(r, str) and _EMAIL.fullmatch(r.strip()) for r in recipients
        )
    ):
        raise IspBadRequestError("Give 1-5 email addresses", field="recipients")
    row = (
        await db.execute(
            select(IspReportSchedule).where(
                IspReportSchedule.isp_organization_id == isp.isp_org_id,
                IspReportSchedule.report_key == report_key,
                IspReportSchedule.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = IspReportSchedule(
            isp_organization_id=isp.isp_org_id,
            report_key=report_key,
            day_of_month=day,
            recipients=[],
            enabled=True,
        )
        db.add(row)
    row.day_of_month = day
    row.recipients = [r.strip() for r in recipients]
    row.enabled = bool(body.get("enabled", True))
    row.updated_by = isp.user_id
    await db.commit()
    return ok(request, _schedule_view(row), "Schedule saved")


# ============================================================================
# J18: report catalogue
# ============================================================================


def _report_range(
    since: datetime | None, until: datetime | None
) -> tuple[datetime, datetime]:
    now = datetime.now(UTC)
    until = until or now
    until = until if until.tzinfo else until.replace(tzinfo=IST)
    since = since or (until - timedelta(days=30))
    since = since if since.tzinfo else since.replace(tzinfo=IST)
    if since >= until:
        raise IspBadRequestError(
            "since must be before until", field="since", reason="ISP_DATE_RANGE_ORDER"
        )
    if until - since > timedelta(days=366):
        raise IspBadRequestError(
            "range is limited to 366 days",
            field="until",
            reason="ISP_DATE_RANGE_TOO_LONG",
            max_days=366,
        )
    return since, until


@compliance_router.get("/reports", dependencies=isp_guards(ISP_PARTNER_READ))
async def report_catalogue(request: Request) -> dict:
    return ok(request, {"reports": catalogue()}, "Compliance reports")


@compliance_router.get(
    "/reports/{report_key}", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def run_report(
    request: Request,
    report_key: str,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    if report_key not in CATALOGUE:
        raise IspBadRequestError(
            "Unknown report", field="report_key", reason="ISP_QUERY_INVALID"
        )
    s, u = _report_range(since, until)
    unmasked = await pii_unmasked_for(db, isp)
    data = await IspComplianceReports(db).run(
        isp, report_key, since=s, until=u, unmasked=unmasked
    )
    return ok(request, data, "Report")


@compliance_router.get(
    "/reports/{report_key}/export.csv", dependencies=isp_guards(ISP_PARTNER_EXPORT)
)
async def export_report(
    report_key: str,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> Response:
    if report_key not in CATALOGUE:
        raise IspBadRequestError(
            "Unknown report", field="report_key", reason="ISP_QUERY_INVALID"
        )
    s, u = _report_range(since, until)
    data = await IspComplianceReports(db).run(
        isp, report_key, since=s, until=u, unmasked=True
    )
    await _audit(
        audit,
        isp,
        AUDIT_COMPLIANCE_EXPORT,
        "Compliance report exported",
        {"report": report_key, "since": s.isoformat(), "until": u.isoformat()},
    )
    await db.commit()
    return _download(
        report_csv(data),
        "text/csv; charset=utf-8",
        f"{report_key}-{s:%Y%m%d}-{u:%Y%m%d}.csv",
    )


def report_csv(data: dict[str, Any]) -> bytes:
    buffer = io.StringIO()
    w = csv.writer(buffer)
    w.writerow([f"# {data['title']} ({data['since']} .. {data['until']})"])
    if not data.get("available"):
        w.writerow([f"# {data.get('pending')}"])
        return buffer.getvalue().encode()
    w.writerow(data["columns"])
    for row in data["rows"]:
        w.writerow([csv_safe("" if v is None else v) for v in row])
    if data.get("truncated"):
        w.writerow(["# truncated; narrow the date range"])
    return buffer.getvalue().encode()


__all__ = ["compliance_router"]
