"""J6: subscriber KYC, uploaded documents and the CAF PDF.

* The full Aadhaar number never reaches a model: ``compliance_logic.
  mask_id_number`` reduces it to the last four digits first.
* Files go to object storage under ``isp-kyc/<isp>/<subscriber>/``; the API
  streams them back only through these routes (no public URL is issued).
* CAF numbers: ``<prefix>/<FY>/<n>`` from a per-ISP counter (row-locked),
  or the paper form's own number ("custom").
"""

from __future__ import annotations

import hashlib
import io
import uuid
from datetime import UTC, date, datetime
from typing import Any
from xml.sax.saxutils import escape

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import compliance_logic as logic
from .compliance_models import (
    IspComplianceSettings,
    IspSubscriberDocument,
    IspSubscriberKyc,
)
from .exceptions import IspBadRequestError, IspError

KYC_FIELDS = (
    "applicant_type",
    "full_name",
    "father_or_spouse_name",
    "gender",
    "date_of_birth",
    "nationality",
    "alternate_phone",
    "permanent_address",
    "installation_address",
    "installation_pincode",
    "address_proof_type",
    "address_proof_same_as_id",
    "installed_at",
    "notes",
)
APPLICANT_TYPES = ("individual", "organization")
GENDERS = ("male", "female", "other", "undisclosed")


class IspDocumentNotFoundError(IspError):
    code = "ISP_DOCUMENT_NOT_FOUND"
    status_code_default = 404
    default_message = "Document not found"


class IspCafNumberTakenError(IspError):
    code = "ISP_CAF_NUMBER_TAKEN"
    status_code_default = 409
    default_message = "That CAF number is already used by another subscriber"


def fy_of(day: date) -> str:
    start = day.year if day.month >= 4 else day.year - 1
    return f"{start % 100:02d}-{(start + 1) % 100:02d}"


async def kyc_of(
    session: AsyncSession, subscriber_id: uuid.UUID
) -> IspSubscriberKyc | None:
    return (
        await session.execute(
            select(IspSubscriberKyc).where(
                IspSubscriberKyc.subscriber_id == subscriber_id,
                IspSubscriberKyc.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()


def kyc_view(kyc: IspSubscriberKyc | None, *, unmasked: bool) -> dict[str, Any] | None:
    if kyc is None:
        return None
    out: dict[str, Any] = {}
    for name in KYC_FIELDS:
        value = getattr(kyc, name)
        out[name] = value.isoformat() if isinstance(value, date | datetime) else value
    out.update(
        {
            "id_proof_type": kyc.id_proof_type,
            "id_number": logic.display_id_number(
                kyc.id_number_masked, unmasked=unmasked
            ),
            "id_number_last4": kyc.id_number_last4,
            "caf_number": kyc.caf_number,
            "caf_number_source": kyc.caf_number_source,
            "caf_generated_at": kyc.caf_generated_at.isoformat()
            if kyc.caf_generated_at
            else None,
            "verified_at": kyc.verified_at.isoformat() if kyc.verified_at else None,
            "verified_by": str(kyc.verified_by) if kyc.verified_by else None,
        }
    )
    return out


def _clean(body: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in KYC_FIELDS:
        if name not in body:
            continue
        value = body[name]
        if isinstance(value, str):
            value = value.strip() or None
        out[name] = value
    if (
        out.get("applicant_type") is not None
        and out["applicant_type"] not in APPLICANT_TYPES
    ):
        raise IspBadRequestError(
            "applicant_type is individual or organization",
            field="applicant_type",
            reason="ISP_CHOICE_INVALID",
        )
    if out.get("gender") is not None and out["gender"] not in GENDERS:
        raise IspBadRequestError(
            "gender is male, female, other or undisclosed",
            field="gender",
            reason="ISP_CHOICE_INVALID",
        )
    for name in ("address_proof_type",):
        if out.get(name) is not None and out[name] not in logic.ID_TYPES:
            raise IspBadRequestError(
                f"{name} must be one of {', '.join(logic.ID_TYPES)}",
                field=name,
                reason="ISP_CHOICE_INVALID",
            )
    pin = out.get("installation_pincode")
    if pin is not None and not (pin.isdigit() and len(pin) == 6):
        raise IspBadRequestError("PIN code is 6 digits", field="installation_pincode")
    if "date_of_birth" in out and isinstance(out["date_of_birth"], str):
        try:
            out["date_of_birth"] = date.fromisoformat(out["date_of_birth"])
        except ValueError as exc:
            raise IspBadRequestError(
                "date_of_birth is YYYY-MM-DD",
                field="date_of_birth",
                reason="ISP_DATE_FORMAT",
            ) from exc
    if "installed_at" in out and isinstance(out["installed_at"], str):
        try:
            out["installed_at"] = datetime.fromisoformat(out["installed_at"])
        except ValueError as exc:
            raise IspBadRequestError(
                "installed_at is an ISO date-time",
                field="installed_at",
                reason="ISP_DATE_FORMAT",
            ) from exc
    if (
        out.get("address_proof_same_as_id") is None
        and "address_proof_same_as_id" in out
    ):
        out["address_proof_same_as_id"] = True
    return out


async def upsert_kyc(
    session: AsyncSession,
    *,
    isp_org_id: uuid.UUID,
    subscriber_id: uuid.UUID,
    body: dict[str, Any],
    actor: uuid.UUID | None,
) -> IspSubscriberKyc:
    """Partial update. ``id_number`` with ``id_proof_type`` is masked here;
    sending ``id_number`` without a type is refused (we must know whether
    it is Aadhaar before storing anything)."""
    values = _clean(body)
    kyc = await kyc_of(session, subscriber_id)
    if kyc is None:
        kyc = IspSubscriberKyc(
            isp_organization_id=isp_org_id,
            subscriber_id=subscriber_id,
            applicant_type="individual",
            nationality="Indian",
            address_proof_same_as_id=True,
        )
        session.add(kyc)
    for name, value in values.items():
        setattr(kyc, name, value)
    if "id_proof_type" in body or "id_number" in body:
        id_type = body.get("id_proof_type", kyc.id_proof_type)
        if id_type is not None and id_type not in logic.ID_TYPES:
            raise IspBadRequestError(
                f"id_proof_type must be one of {', '.join(logic.ID_TYPES)}",
                field="id_proof_type",
                reason="ISP_CHOICE_INVALID",
            )
        if "id_number" in body:
            if id_type is None:
                raise IspBadRequestError(
                    "Pick the ID proof type first", field="id_proof_type"
                )
            try:
                masked, last4 = logic.mask_id_number(id_type, body.get("id_number"))
            except logic.IdNumberError as exc:
                raise IspBadRequestError(str(exc), field="id_number") from exc
            kyc.id_number_masked, kyc.id_number_last4 = masked, last4
        elif id_type != kyc.id_proof_type:
            # type changed without a number: the old number no longer applies
            kyc.id_number_masked = kyc.id_number_last4 = None
        kyc.id_proof_type = id_type
    if body.get("verified") is True:
        kyc.verified_by, kyc.verified_at = actor, datetime.now(UTC)
    elif body.get("verified") is False:
        kyc.verified_by = kyc.verified_at = None
    kyc.updated_by = actor
    await session.flush()
    return kyc


async def assign_caf_number(
    session: AsyncSession,
    *,
    isp_org_id: uuid.UUID,
    kyc: IspSubscriberKyc,
    custom: str | None,
    today: date,
) -> str:
    if kyc.caf_number and not custom:
        return kyc.caf_number
    if custom:
        number = custom.strip().upper()
        if not number or len(number) > 40:
            raise IspBadRequestError(
                "CAF number is 1-40 characters", field="caf_number"
            )
        clash = (
            await session.execute(
                select(IspSubscriberKyc.id).where(
                    IspSubscriberKyc.isp_organization_id == isp_org_id,
                    IspSubscriberKyc.caf_number == number,
                    IspSubscriberKyc.id != kyc.id,
                    IspSubscriberKyc.deleted_at.is_(None),
                )
            )
        ).first()
        if clash:
            raise IspCafNumberTakenError()
        kyc.caf_number, kyc.caf_number_source = number, "custom"
    else:
        settings = (
            await session.execute(
                select(IspComplianceSettings)
                .where(
                    IspComplianceSettings.isp_organization_id == isp_org_id,
                    IspComplianceSettings.deleted_at.is_(None),
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if settings is None:
            settings = IspComplianceSettings(
                isp_organization_id=isp_org_id,
                caf_prefix="CAF",
                caf_next_seq=1,
                nat_feed_stale_minutes=60,
                gigabit_threshold_mbps=1000,
                churn_after_days=60,
            )
            session.add(settings)
            await session.flush()
        seq = settings.caf_next_seq or 1
        settings.caf_next_seq = seq + 1
        kyc.caf_number = f"{settings.caf_prefix}/{fy_of(today)}/{seq}"
        kyc.caf_number_source = "auto"
    await session.flush()
    return kyc.caf_number


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------


def sniff_type(content: bytes) -> str | None:
    if content.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return "image/webp"
    if content.startswith(b"%PDF-"):
        return "application/pdf"
    return None


def validate_document(kind: str, content: bytes) -> str:
    if kind not in logic.DOCUMENT_KINDS:
        raise IspBadRequestError(
            f"kind must be one of {', '.join(logic.DOCUMENT_KINDS)}",
            field="kind",
            reason="ISP_CHOICE_INVALID",
        )
    if not content:
        raise IspBadRequestError("The file is empty", field="file")
    if len(content) > logic.MAX_DOCUMENT_BYTES:
        raise IspBadRequestError("Files are limited to 5 MB", field="file")
    content_type = sniff_type(content)
    if content_type is None:
        raise IspBadRequestError("Upload a JPEG, PNG, WebP or PDF", field="file")
    if kind in ("photo", "signature") and content_type == "application/pdf":
        raise IspBadRequestError("Photo and signature must be images", field="file")
    return content_type


def storage_key(isp_org_id: uuid.UUID, subscriber_id: uuid.UUID, kind: str) -> str:
    return f"isp-kyc/{isp_org_id}/{subscriber_id}/{kind}-{uuid.uuid4().hex}"


def document_view(doc: IspSubscriberDocument) -> dict[str, Any]:
    return {
        "id": str(doc.id),
        "kind": doc.kind,
        "filename": doc.filename,
        "content_type": doc.content_type,
        "size_bytes": doc.size_bytes,
        "sha256": doc.sha256,
        "uploaded_at": doc.created_at.isoformat() if doc.created_at else None,
    }


def new_document(
    *,
    isp_org_id: uuid.UUID,
    subscriber_id: uuid.UUID,
    kind: str,
    key: str,
    filename: str,
    content_type: str,
    content: bytes,
    actor: uuid.UUID | None,
) -> IspSubscriberDocument:
    safe = "".join(c for c in (filename or kind) if c.isalnum() or c in "._- ")[:200]
    return IspSubscriberDocument(
        isp_organization_id=isp_org_id,
        subscriber_id=subscriber_id,
        kind=kind,
        storage_key=key,
        filename=safe or kind,
        content_type=content_type,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        uploaded_by=actor,
    )


# ---------------------------------------------------------------------------
# CAF PDF
# ---------------------------------------------------------------------------


def _p(value: Any) -> str:
    return escape(str(value)) if value not in (None, "") else "&nbsp;"


def render_caf_pdf(
    *,
    isp: dict[str, Any],
    subscriber: dict[str, Any],
    kyc: dict[str, Any],
    photo: bytes | None = None,
    signature: bytes | None = None,
) -> bytes:
    """Our own CAF layout (not a copy of any vendor's form): licensee block,
    applicant, addresses, ID proof (masked), connection, declaration, photo
    and signature boxes."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        Image,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    styles = getSampleStyleSheet()
    small = styles["BodyText"].clone("small", fontSize=8.5, leading=11)
    head = styles["Heading2"].clone("head", spaceAfter=4)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.4 * cm,
        bottomMargin=1.4 * cm,
        title=f"CAF {kyc.get('caf_number') or ''}",
    )

    def image_or_box(content: bytes | None, w: float, h: float, label: str) -> Any:
        if content:
            try:
                img = Image(io.BytesIO(content), width=w, height=h, kind="proportional")
                return img
            except Exception:  # noqa: BLE001 -- a bad upload must not break the form
                pass
        return Paragraph(f"<para alignment='center'>{label}</para>", small)

    licensee = (
        f"<b>{_p(isp.get('legal_name'))}</b><br/>{_p(isp.get('registered_address'))}"
        f"<br/>Licence No.: {_p(isp.get('licence_number'))}"
        + (
            f" ({_p(isp.get('licence_category'))})"
            if isp.get("licence_category")
            else ""
        )
        + f"<br/>GSTIN: {_p(isp.get('gstin'))}"
    )
    top = Table(
        [
            [
                Paragraph(licensee, small),
                image_or_box(photo, 3.2 * cm, 4 * cm, "Affix / upload<br/>photograph"),
            ]
        ],
        colWidths=[13.4 * cm, 3.6 * cm],
        rowHeights=[4.2 * cm],
    )
    top.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (1, 0), (1, 0), 0.6, colors.grey),
            ]
        )
    )

    def grid(rows: list[tuple[str, Any]]) -> Table:
        t = Table(
            [
                [Paragraph(f"<b>{_p(k)}</b>", small), Paragraph(_p(v), small)]
                for k, v in rows
            ],
            colWidths=[5 * cm, 12 * cm],
        )
        t.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                ]
            )
        )
        return t

    id_type = (kyc.get("id_proof_type") or "").replace("_", " ").title()
    story = [
        top,
        Spacer(1, 6),
        Paragraph("Customer Application Form (Internet Service)", head),
        grid(
            [
                ("CAF No.", kyc.get("caf_number")),
                ("Date", kyc.get("caf_date")),
                ("Customer ID / Username", subscriber.get("username")),
                ("Circuit ID", subscriber.get("circuit_id")),
            ]
        ),
        Spacer(1, 8),
        Paragraph("Applicant", head),
        grid(
            [
                (
                    "Type of applicant",
                    (kyc.get("applicant_type") or "individual").title(),
                ),
                ("Name", kyc.get("full_name") or subscriber.get("name")),
                ("Father's / spouse's name", kyc.get("father_or_spouse_name")),
                ("Gender", (kyc.get("gender") or "").title()),
                ("Date of birth", kyc.get("date_of_birth")),
                ("Nationality", kyc.get("nationality")),
                ("Mobile", subscriber.get("phone")),
                ("Alternate mobile", kyc.get("alternate_phone")),
                ("Email", subscriber.get("email")),
                ("GSTIN (if any)", subscriber.get("gstin")),
            ]
        ),
        Spacer(1, 8),
        Paragraph("Addresses", head),
        grid(
            [
                (
                    "Permanent / billing address",
                    kyc.get("permanent_address") or subscriber.get("address"),
                ),
                ("Installation address", kyc.get("installation_address")),
                ("Installation PIN code", kyc.get("installation_pincode")),
                ("Installed on", kyc.get("installed_at")),
            ]
        ),
        Spacer(1, 8),
        Paragraph("Proof of identity and address", head),
        grid(
            [
                ("Proof of identity", id_type),
                ("Document number", kyc.get("id_number")),
                (
                    "Proof of address",
                    "Same as identity proof"
                    if kyc.get("address_proof_same_as_id")
                    else (kyc.get("address_proof_type") or "")
                    .replace("_", " ")
                    .title(),
                ),
                ("Verified on", kyc.get("verified_at")),
            ]
        ),
        Spacer(1, 8),
        Paragraph("Connection", head),
        grid(
            [
                ("Package", subscriber.get("package_name")),
                ("Customer (venue)", subscriber.get("customer_name")),
            ]
        ),
        Spacer(1, 10),
        Paragraph(
            "I declare that the particulars given above are correct and that the "
            "connection will be used only at the installation address stated. I "
            "understand that usage records are retained as required by law.",
            small,
        ),
        Spacer(1, 14),
    ]
    sig = Table(
        [
            [
                image_or_box(signature, 5 * cm, 1.8 * cm, "Signature of applicant"),
                Paragraph(
                    "<para alignment='center'>Signature and seal of the licensee's "
                    "authorised person</para>",
                    small,
                ),
            ]
        ],
        colWidths=[8.5 * cm, 8.5 * cm],
        rowHeights=[2.2 * cm],
    )
    sig.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (0, 0), 0.6, colors.grey),
                ("BOX", (1, 0), (1, 0), 0.6, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
            ]
        )
    )
    story.append(sig)
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "Aadhaar numbers are shown masked; the full number is never "
            "stored by this system.",
            small,
        )
    )
    doc.build(story)
    return buffer.getvalue()
