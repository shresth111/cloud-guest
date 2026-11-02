"""CAF-2 workbench logic. Reuses, unchanged:

* JAZE-3 ``compliance_kyc`` (``kyc_of``, ``kyc_view`` masked, ``upsert_kyc``,
  ``assign_caf_number`` -- auto ``PREFIX/FY/seq`` or a custom number unique
  per ISP) and its document table (photo / signature);
* JAZE-1 subscriber profile (addresses) and typeahead (zone-scoped through
  ``isp.child_ids()``);
* JAZE-5 ``LeadService`` (lead lookup with its confinement rules, list,
  ``convert``).

Scoping: every subscriber goes through ``IspBillingService.
subscriber_in_scope`` (other ISP or outside the caller's confinement -> 404)
and every list through ``isp.child_ids()``, which ZONE-1 narrows to the
selected zone.
"""

from __future__ import annotations

import io
import uuid
import zipfile
from datetime import UTC, date, datetime, time, timedelta
from functools import lru_cache
from typing import Any
from zoneinfo import ZoneInfo

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select

from . import compliance_kyc as kyc_mod
from .caf_models import APPLICANT_CATEGORIES, IspCafExtras, IspCafProfile
from .caf_pdf import fit_image, render_caf2_pdf
from .compliance_models import IspSubscriberDocument, IspSubscriberKyc
from .compliance_service import compliance_settings
from .exceptions import IspBadRequestError, IspFeatureDisabledError
from .plans_models import IspPackage, IspSubscriber

__all__ = [
    "EXPORT_MAX",
    "IspCafService",
    "RequireIspCafEnabled",
    "get_isp_caf_settings",
]

IST = ZoneInfo("Asia/Kolkata")
EXPORT_MAX = 200
EXTRAS_FIELDS = (
    "applicant_category",
    "applicant_category_other",
    "father_or_spouse_name",
    "plot_no",
    "locality",
    "district",
)
AUDIT_GENERATED = "isp_caf2_generated"
AUDIT_EXPORTED = "isp_caf2_exported"
AUDIT_EXTRAS = "isp_caf2_extras_saved"
AUDIT_NUMBER = "isp_caf2_number_assigned"
AUDIT_PROFILE = "isp_caf2_profile_saved"
AUDIT_LEAD_CONVERTED = "isp_caf2_lead_converted"


class IspCafSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ISP_CAF_WORKBENCH_",
        case_sensitive=False,
        extra="ignore",
    )

    enabled: bool = Field(default=False, description="ISP_CAF_WORKBENCH_ENABLED")


@lru_cache(maxsize=1)
def get_isp_caf_settings() -> IspCafSettings:
    return IspCafSettings()


async def RequireIspCafEnabled() -> None:
    if not get_isp_caf_settings().enabled:
        raise IspFeatureDisabledError()


def _iso(v: Any) -> Any:
    return v.isoformat() if isinstance(v, datetime | date) else v


def extras_view(row: IspCafExtras | None) -> dict[str, Any]:
    if row is None:
        return {"applicant_category": "individual"}
    return {k: getattr(row, k) for k in EXTRAS_FIELDS}


class IspCafService:
    def __init__(self, session: Any, audit: Any = None) -> None:
        self.session = session
        self.audit = audit

    # -- lookups -------------------------------------------------------------
    async def subscriber(self, isp: Any, subscriber_id: uuid.UUID) -> IspSubscriber:
        from .billing_service import IspBillingService

        return await IspBillingService(
            session=self.session, audit=None
        ).subscriber_in_scope(isp, subscriber_id)

    async def lead(self, isp: Any, lead_id: uuid.UUID) -> Any:
        from .apps_leads import LeadService

        return await LeadService(self.session)._lead(isp, lead_id)

    async def extras_row(
        self,
        *,
        subscriber_id: uuid.UUID | None = None,
        lead_id: uuid.UUID | None = None,
    ) -> IspCafExtras | None:
        q = select(IspCafExtras).where(IspCafExtras.is_deleted.is_(False))
        if subscriber_id is not None:
            q = q.where(IspCafExtras.subscriber_id == subscriber_id)
        else:
            q = q.where(
                IspCafExtras.lead_id == lead_id, IspCafExtras.subscriber_id.is_(None)
            )
        return (await self.session.execute(q)).scalars().first()

    async def _documents(
        self, subscriber_id: uuid.UUID
    ) -> dict[str, IspSubscriberDocument]:
        rows = (
            (
                await self.session.execute(
                    select(IspSubscriberDocument)
                    .where(
                        IspSubscriberDocument.subscriber_id == subscriber_id,
                        IspSubscriberDocument.is_deleted.is_(False),
                        IspSubscriberDocument.kind.in_(("photo", "signature")),
                    )
                    .order_by(IspSubscriberDocument.created_at)
                )
            )
            .scalars()
            .all()
        )
        return {d.kind: d for d in rows}  # newest wins

    async def profile_row(self, isp: Any) -> IspCafProfile | None:
        return (
            (
                await self.session.execute(
                    select(IspCafProfile).where(
                        IspCafProfile.isp_organization_id == isp.isp_org_id,
                        IspCafProfile.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )

    # -- prefill -------------------------------------------------------------
    async def _subscriber_block(self, isp: Any, s: IspSubscriber) -> dict[str, Any]:
        from app.domains.organization.models import Organization

        from .subscriber360_models import IspSubscriberProfile

        prof = (
            (
                await self.session.execute(
                    select(IspSubscriberProfile).where(
                        IspSubscriberProfile.subscriber_id == s.id,
                        IspSubscriberProfile.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )
        pkg = await self.session.get(IspPackage, s.package_id) if s.package_id else None
        cust = await self.session.get(Organization, s.customer_organization_id)
        same = prof is None or prof.install_same_as_billing
        install = None
        if prof is not None and not same:
            install = ", ".join(
                x
                for x in (
                    prof.install_building,
                    prof.install_address,
                    prof.install_area,
                )
                if x
            )
        return {
            "id": str(s.id),
            "circuit_id": s.circuit_id,
            "username": s.identifier,
            "name": " ".join(x for x in (s.first_name, s.last_name) if x)
            or s.display_name,
            "phone": s.phone,
            "email": s.email,
            "gstin": s.gstin,
            "address": s.address,
            "billing_city": prof.billing_city if prof else None,
            "billing_pincode": prof.billing_pincode if prof else None,
            "install_same_as_billing": same,
            "install_address": install,
            "install_city": prof.install_city if prof and not same else None,
            "install_pincode": prof.install_pincode if prof and not same else None,
            "package_name": pkg.name if pkg else None,
            "customer_name": cust.name if cust else None,
            "isp_customer_id": str(s.customer_organization_id),
        }

    async def prefill_subscriber(self, isp: Any, subscriber_id: uuid.UUID) -> dict:
        s = await self.subscriber(isp, subscriber_id)
        kyc = await kyc_mod.kyc_of(self.session, s.id)
        docs = await self._documents(s.id)
        settings = await compliance_settings(self.session, isp.isp_org_id)
        extras = await self.extras_row(subscriber_id=s.id)
        kyc_v = kyc_mod.kyc_view(kyc, unmasked=False)
        missing = []
        if kyc is None:
            missing.append("kyc")
        if "photo" not in docs:
            missing.append("photo")
        if "signature" not in docs:
            missing.append("signature")
        if not settings.licence_number:
            missing.append("licence_number")
        return {
            "source": "subscriber",
            "subscriber": await self._subscriber_block(isp, s),
            "kyc": kyc_v,
            "documents": {"photo": "photo" in docs, "signature": "signature" in docs},
            "extras": extras_view(extras)
            | (
                {"father_or_spouse_name": kyc.father_or_spouse_name}
                if extras is None and kyc is not None
                else {}
            ),
            "extras_saved": extras is not None,
            "caf_number": kyc.caf_number if kyc else None,
            "caf_generated_at": _iso(kyc.caf_generated_at) if kyc else None,
            "missing": missing,
        }

    async def prefill_lead(self, isp: Any, lead_id: uuid.UUID) -> dict:
        from .apps_leads import LeadService

        lead = await self.lead(isp, lead_id)
        view = (await LeadService(self.session).views([lead]))[0]
        extras = await self.extras_row(lead_id=lead.id)
        keep = (
            "id",
            "number",
            "name",
            "phone",
            "email",
            "address",
            "city",
            "status",
            "isp_customer_id",
            "customer_name",
            "interested_package_id",
            "converted_subscriber_id",
        )
        return {
            "source": "lead",
            "lead": {k: _iso(view.get(k)) for k in keep},
            "extras": extras_view(extras),
            "extras_saved": extras is not None,
        }

    # -- writes --------------------------------------------------------------
    @staticmethod
    def clean_extras(data: dict) -> dict:
        out: dict[str, Any] = {}
        for k in EXTRAS_FIELDS:
            if k not in data:
                continue
            v = data[k]
            out[k] = v.strip() or None if isinstance(v, str) else v
        cat = out.get("applicant_category")
        if "applicant_category" in out and cat not in APPLICANT_CATEGORIES:
            raise IspBadRequestError(
                "Applicant type must be one of " + ", ".join(APPLICANT_CATEGORIES),
                field="applicant_category",
                reason="ISP_CHOICE_INVALID",
            )
        if cat and cat != "other":
            out["applicant_category_other"] = None
        return out

    async def put_extras(
        self,
        isp: Any,
        *,
        subscriber_id: uuid.UUID | None = None,
        lead_id: uuid.UUID | None = None,
        data: dict,
    ) -> dict:
        values = self.clean_extras(data)
        if subscriber_id is not None:
            s = await self.subscriber(isp, subscriber_id)
            row, org = (
                await self.extras_row(subscriber_id=s.id),
                s.customer_organization_id,
            )
            entity = s.id
        else:
            lead = await self.lead(isp, lead_id)  # type: ignore[arg-type]
            row, org = (
                await self.extras_row(lead_id=lead.id),
                lead.customer_organization_id,
            )
            entity = lead.id
        if row is None:
            row = IspCafExtras(
                isp_organization_id=isp.isp_org_id,
                subscriber_id=subscriber_id,
                lead_id=lead_id,
                applicant_category="individual",
                created_by=isp.user_id,
            )
            self.session.add(row)
        for k, v in values.items():
            if k == "applicant_category" and v is None:
                continue
            setattr(row, k, v)
        row.updated_by = isp.user_id
        await self.session.flush()
        await self._audit(isp, AUDIT_EXTRAS, entity, org, fields=sorted(values))
        return extras_view(row)

    async def assign_number(
        self, isp: Any, subscriber_id: uuid.UUID, *, custom: str | None
    ) -> dict:
        s = await self.subscriber(isp, subscriber_id)
        kyc = await kyc_mod.kyc_of(self.session, s.id) or await kyc_mod.upsert_kyc(
            self.session,
            isp_org_id=isp.isp_org_id,
            subscriber_id=s.id,
            body={},
            actor=isp.user_id,
        )
        number = await kyc_mod.assign_caf_number(
            self.session,
            isp_org_id=isp.isp_org_id,
            kyc=kyc,
            custom=custom,
            today=datetime.now(IST).date(),
        )
        await self._audit(
            isp,
            AUDIT_NUMBER,
            s.id,
            s.customer_organization_id,
            caf_number=number,
            source=kyc.caf_number_source,
        )
        return {"caf_number": number, "source": kyc.caf_number_source}

    async def convert_lead(
        self, isp: Any, lead_id: uuid.UUID, plans: Any, data: dict
    ) -> dict:
        """JAZE-5 ``convert`` unchanged (it takes name/phone/email/address from
        the lead), then the lead's CAF extras move onto the new subscriber."""
        from .apps_leads import LeadService

        lead = await self.lead(isp, lead_id)
        payload = {k: v for k, v in data.items() if v is not None}
        payload.setdefault(
            "identifier", (lead.phone or "").strip() or f"lead-{lead.number}"
        )
        await LeadService(self.session, plans).convert(isp, lead.id, payload)
        await self.session.refresh(lead)
        sid = lead.converted_subscriber_id
        row = await self.extras_row(lead_id=lead.id)
        if row is not None and sid is not None:
            row.subscriber_id = sid
            row.updated_by = isp.user_id
            await self.session.flush()
        await self._audit(
            isp,
            AUDIT_LEAD_CONVERTED,
            sid,
            lead.customer_organization_id,
            lead_id=lead.id,
        )
        return await self.prefill_subscriber(isp, sid)

    # -- PDF -----------------------------------------------------------------
    async def _image(self, key: str | None) -> bytes | None:
        if not key:
            return None
        from app.core.storage import get_object_storage

        try:
            return await get_object_storage().download(key=key)
        except Exception:  # noqa: BLE001 -- render the form without it
            return None

    async def pdf_for(
        self, isp: Any, s: IspSubscriber, *, audit: bool = True
    ) -> tuple[bytes, str]:
        kyc = await kyc_mod.kyc_of(self.session, s.id)
        if kyc is None:
            raise IspBadRequestError("Fill in the subscriber's KYC first", field="kyc")
        if not kyc.caf_number:
            await kyc_mod.assign_caf_number(
                self.session,
                isp_org_id=isp.isp_org_id,
                kyc=kyc,
                custom=None,
                today=datetime.now(IST).date(),
            )
        kyc.caf_generated_at = datetime.now(UTC)
        settings = await compliance_settings(self.session, isp.isp_org_id)
        prof = await self.profile_row(isp)
        docs = await self._documents(s.id)
        view = kyc_mod.kyc_view(kyc, unmasked=False) or {}
        # The printed ID comes from the last four only; the stored masked
        # value is passed for non-Aadhaar types.
        view["id_number"] = (
            kyc.id_number_masked if kyc.id_proof_type != "aadhaar" else None
        )
        view["id_number_last4"] = kyc.id_number_last4
        view["caf_date"] = datetime.now(IST).strftime("%d-%m-%Y")
        content = render_caf2_pdf(
            isp={
                "legal_name": settings.legal_name or isp.organization.name,
                "registered_address": settings.registered_address,
                "licence_number": settings.licence_number,
                "licence_category": settings.licence_category,
                "gstin": settings.gstin or getattr(isp.profile, "gstin", None),
            },
            subscriber=await self._subscriber_block(isp, s),
            kyc=view,
            extras=extras_view(await self.extras_row(subscriber_id=s.id)),
            signatory={
                "name": prof.signatory_name if prof else None,
                "designation": prof.signatory_designation if prof else None,
            },
            photo=await self._image(docs["photo"].storage_key)
            if "photo" in docs
            else None,
            signature=await self._image(docs["signature"].storage_key)
            if "signature" in docs
            else None,
            stamp=await self._image(prof.stamp_storage_key) if prof else None,
        )
        if audit:
            await self._audit(
                isp,
                AUDIT_GENERATED,
                s.id,
                s.customer_organization_id,
                caf_number=kyc.caf_number,
            )
        safe = "".join(
            c if c.isalnum() or c in "-_" else "-" for c in kyc.caf_number or str(s.id)
        )
        return content, f"caf-{safe}.pdf"

    async def export_zip(
        self,
        isp: Any,
        *,
        subscriber_ids: list[uuid.UUID] | None,
        since: date | None,
        until: date | None,
    ) -> tuple[bytes, int, list[str]]:
        ids = await isp.child_ids()
        if subscriber_ids:
            subs = [await self.subscriber(isp, sid) for sid in subscriber_ids]
        else:
            if since is None or until is None:
                raise IspBadRequestError(
                    "Pick subscribers or a date range", field="since"
                )
            if until < since or (until - since).days > 366:
                raise IspBadRequestError(
                    "Range is 1 to 366 days",
                    field="until",
                    reason="ISP_DATE_RANGE_INVALID",
                    max_days=366,
                )
            start = datetime.combine(since, time.min, IST)
            end = datetime.combine(until + timedelta(days=1), time.min, IST)
            subs = list(
                (
                    await self.session.execute(
                        select(IspSubscriber)
                        .join(
                            IspSubscriberKyc,
                            IspSubscriberKyc.subscriber_id == IspSubscriber.id,
                        )
                        .where(
                            IspSubscriber.isp_organization_id == isp.isp_org_id,
                            IspSubscriber.customer_organization_id.in_(
                                ids or [uuid.UUID(int=0)]
                            ),
                            IspSubscriber.is_deleted.is_(False),
                            IspSubscriberKyc.deleted_at.is_(None),
                            IspSubscriber.created_at >= start,
                            IspSubscriber.created_at < end,
                        )
                        .order_by(IspSubscriber.circuit_id)
                        .limit(EXPORT_MAX + 1)
                    )
                )
                .scalars()
                .all()
            )
        if len(subs) > EXPORT_MAX:
            raise IspBadRequestError(
                f"At most {EXPORT_MAX} CAFs per file; narrow the range",
                field="until",
                reason="ISP_EXPORT_TOO_LARGE",
                max_rows=EXPORT_MAX,
            )
        buf = io.BytesIO()
        skipped: list[str] = []
        done = 0
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for s in subs:
                try:
                    content, name = await self.pdf_for(isp, s, audit=False)
                except IspBadRequestError as exc:
                    skipped.append(
                        f"circuit {s.circuit_id} ({s.identifier}): {exc.message}"
                    )
                    continue
                zf.writestr(f"{s.circuit_id:06d}-{name}", content)
                done += 1
            zf.writestr(
                "README.txt",
                f"CAF export {datetime.now(IST):%Y-%m-%d %H:%M} IST\n"
                f"{done} CAF(s)\n"
                + ("Skipped:\n" + "\n".join(skipped) + "\n" if skipped else ""),
            )
        await self._audit(
            isp,
            AUDIT_EXPORTED,
            isp.isp_org_id,
            isp.isp_org_id,
            count=done,
            skipped=len(skipped),
            subscriber_ids=[str(s.id) for s in subs][:EXPORT_MAX],
            since=_iso(since),
            until=_iso(until),
        )
        return buf.getvalue(), done, skipped

    # -- ISP profile (signatory + stamp) -------------------------------------
    async def profile_view(self, isp: Any) -> dict:
        prof = await self.profile_row(isp)
        settings = await compliance_settings(self.session, isp.isp_org_id)
        return {
            "signatory_name": prof.signatory_name if prof else None,
            "signatory_designation": prof.signatory_designation if prof else None,
            "stamp_set": bool(prof and prof.stamp_storage_key),
            "licence_number": settings.licence_number,
            "licence_category": settings.licence_category,
            "legal_name": settings.legal_name,
            "gstin": settings.gstin,
        }

    async def _profile_for_write(self, isp: Any) -> IspCafProfile:
        prof = await self.profile_row(isp)
        if prof is None:
            prof = IspCafProfile(
                isp_organization_id=isp.isp_org_id, created_by=isp.user_id
            )
            self.session.add(prof)
        prof.updated_by = isp.user_id
        return prof

    async def put_profile(self, isp: Any, data: dict) -> dict:
        prof = await self._profile_for_write(isp)
        for k in ("signatory_name", "signatory_designation"):
            if k in data:
                v = data[k]
                setattr(prof, k, (v or "").strip() or None)
        await self.session.flush()
        await self._audit(
            isp, AUDIT_PROFILE, isp.isp_org_id, isp.isp_org_id, fields=sorted(data)
        )
        return await self.profile_view(isp)

    async def set_stamp(self, isp: Any, content: bytes | None) -> dict:
        from app.core.storage import get_object_storage

        prof = await self._profile_for_write(isp)
        if content is None:
            prof.stamp_storage_key = prof.stamp_content_type = None
            prof.stamp_size_bytes = None
        else:
            jpeg = fit_image(content, max_px=800, max_bytes=250_000)
            if jpeg is None:
                raise IspBadRequestError(
                    "The stamp must be a JPEG, PNG or WebP image under 8 MB",
                    field="file",
                )
            key = f"isp/{isp.isp_org_id}/caf/stamp-{uuid.uuid4().hex}.jpg"
            await get_object_storage().upload(
                key=key, content=jpeg, content_type="image/jpeg"
            )
            prof.stamp_storage_key, prof.stamp_content_type = key, "image/jpeg"
            prof.stamp_size_bytes = len(jpeg)
        await self.session.flush()
        await self._audit(
            isp,
            AUDIT_PROFILE,
            isp.isp_org_id,
            isp.isp_org_id,
            stamp=content is not None,
        )
        return await self.profile_view(isp)

    # -- search ----------------------------------------------------------------
    async def caf_numbers(self, ids: list[uuid.UUID]) -> dict[uuid.UUID, str | None]:
        if not ids:
            return {}
        rows = await self.session.execute(
            select(IspSubscriberKyc.subscriber_id, IspSubscriberKyc.caf_number).where(
                IspSubscriberKyc.subscriber_id.in_(ids),
                IspSubscriberKyc.deleted_at.is_(None),
            )
        )
        return dict(rows.all())

    # -- audit -----------------------------------------------------------------
    async def _audit(
        self, isp: Any, action: str, entity_id: Any, org: Any, **meta: Any
    ) -> None:
        if self.audit is None:
            return
        await self.audit.create_audit_log_entry(
            actor_user_id=isp.user_id,
            action=action,
            entity_type="isp_subscriber",
            entity_id=entity_id,
            description=action.replace("_", " "),
            event_metadata={
                "console": "isp",
                **{
                    k: str(v) if isinstance(v, uuid.UUID) else v
                    for k, v in meta.items()
                },
            },
            organization_id=org or isp.isp_org_id,
            location_id=None,
        )
