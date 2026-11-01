"""CAF-2 PDF: the workbench layout, additive to JAZE-3's ``render_caf_pdf``
(which stays as it is and keeps serving ``/compliance/subscribers/{id}/
caf.pdf``). Our own layout and wording.

**Aadhaar is never printed in full.** Two independent guards:

1. ``id_number_for_caf`` builds the printed ID from what JAZE-3 stores --
   for Aadhaar only ``id_number_last4`` is used, giving ``XXXX XXXX 1234``;
   other ID types print JAZE-3's masked display value.
2. ``scrub`` runs over EVERY string that reaches the PDF and rewrites any
   12-digit run (spaces / dashes allowed between digits) to
   ``XXXX XXXX <last4>``, so even a 12-digit number typed into a free-text
   field (name, address, notes) cannot be printed whole.

Images (photo, signature, stamp) are decoded, flattened, downscaled and
re-encoded as JPEG under a byte cap before embedding; anything unreadable
or too large is replaced by an empty box.
"""

from __future__ import annotations

import io
import re
from typing import Any
from xml.sax.saxutils import escape

from .caf_models import APPLICANT_CATEGORIES
from .compliance_logic import ID_TYPES, display_id_number

__all__ = [
    "AADHAAR_RUN",
    "fit_image",
    "id_number_for_caf",
    "render_caf2_pdf",
    "scrub",
]

#: 12 digits, optionally separated by single spaces or dashes.
AADHAAR_RUN = re.compile(r"(?<!\d)(?:\d[ \-]?){11}\d(?!\d)")
MAX_IMAGE_INPUT_BYTES = 8 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000

CATEGORY_LABEL = {
    "individual": "Individual",
    "proprietor": "Proprietorship",
    "partnership": "Partnership",
    "pvt_ltd": "Private Ltd company",
    "public_ltd": "Public Ltd company",
    "other": "Other",
}
ID_LABEL = {
    "aadhaar": "Aadhaar",
    "voter_id": "Voter ID",
    "passport": "Passport",
    "pan": "PAN",
    "driving_licence": "Driving licence",
    "ration_card": "Ration card",
    "other": "Other",
}


def scrub(value: Any) -> str:
    """Text for the PDF with every 12-digit run masked to its last four."""
    if value is None:
        return ""
    text = str(value)

    def _mask(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        return f"XXXX XXXX {digits[-4:]}"

    return AADHAAR_RUN.sub(_mask, text)


def id_number_for_caf(
    id_type: str | None, stored: str | None, last4: str | None
) -> str | None:
    """The ID number box. Aadhaar: only the last four digits, ever."""
    if not id_type:
        return None
    if id_type == "aadhaar":
        tail = (
            re.sub(r"\D", "", last4 or "")[-4:] or re.sub(r"\D", "", stored or "")[-4:]
        )
        return f"XXXX XXXX {tail}" if len(tail) == 4 else None
    shown = display_id_number(stored, unmasked=False)
    return scrub(shown) if shown else None


def fit_image(
    content: bytes | None,
    *,
    max_px: int,
    max_bytes: int,
) -> bytes | None:
    """Decode, flatten onto white, downscale to ``max_px`` on the long side and
    re-encode as JPEG, stepping quality down until under ``max_bytes``.
    ``None`` for anything that is not a sane image."""
    if not content or len(content) > MAX_IMAGE_INPUT_BYTES:
        return None
    try:
        from PIL import Image

        Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
        with Image.open(io.BytesIO(content)) as im:
            im.load()
            if im.width * im.height > MAX_IMAGE_PIXELS:
                return None
            if im.mode in ("RGBA", "LA", "P"):
                rgba = im.convert("RGBA")
                flat = Image.new("RGB", rgba.size, (255, 255, 255))
                flat.paste(rgba, mask=rgba.split()[-1])
                im2 = flat
            else:
                im2 = im.convert("RGB")
            im2.thumbnail((max_px, max_px))
            for quality in (85, 75, 65, 55, 45):
                out = io.BytesIO()
                im2.save(out, format="JPEG", quality=quality, optimize=True)
                if out.tell() <= max_bytes:
                    return out.getvalue()
    except Exception:  # noqa: BLE001 -- a bad upload must never break the form
        return None
    return None


def _boxes(options: list[tuple[str, str]], chosen: str | None) -> str:
    return "&nbsp;&nbsp; ".join(
        f"[{'X' if key == chosen else '&nbsp;'}] {escape(label)}"
        for key, label in options
    )


def render_caf2_pdf(  # noqa: PLR0915 -- one form, top to bottom
    *,
    isp: dict[str, Any],
    subscriber: dict[str, Any],
    kyc: dict[str, Any],
    extras: dict[str, Any],
    signatory: dict[str, Any],
    photo: bytes | None = None,
    signature: bytes | None = None,
    stamp: bytes | None = None,
) -> bytes:
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

    def p(value: Any) -> str:
        text = scrub(value)
        return escape(text) if text else "&nbsp;"

    styles = getSampleStyleSheet()
    small = styles["BodyText"].clone("caf2small", fontSize=8.5, leading=11)
    tiny = styles["BodyText"].clone("caf2tiny", fontSize=7.5, leading=9.5)
    head = styles["Heading2"].clone("caf2head", fontSize=11.5, spaceAfter=3)
    title = styles["Heading1"].clone("caf2title", fontSize=14, spaceAfter=2)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.3 * cm,
        bottomMargin=1.3 * cm,
        title=f"CAF {scrub(kyc.get('caf_number'))}",
    )

    def picture(content: bytes | None, w: float, h: float, label: str, px: int) -> Any:
        jpeg = fit_image(content, max_px=px, max_bytes=180_000)
        if jpeg:
            return Image(io.BytesIO(jpeg), width=w, height=h, kind="proportional")
        return Paragraph(f"<para alignment='center'>{label}</para>", tiny)

    def grid(
        rows: list[tuple[str, Any]], widths: tuple[float, float] = (5, 13)
    ) -> Table:
        t = Table(
            [
                [Paragraph(f"<b>{escape(k)}</b>", small), Paragraph(p(v), small)]
                for k, v in rows
            ],
            colWidths=[widths[0] * cm, widths[1] * cm],
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

    licence = p(isp.get("licence_number"))
    if isp.get("licence_category"):
        licence += f" ({p(isp.get('licence_category'))})"
    header = Table(
        [
            [
                Paragraph(
                    f"<font size='12'><b>{p(isp.get('legal_name'))}</b></font><br/>"
                    f"{p(isp.get('registered_address'))}<br/>"
                    f"Licence No.: {licence}<br/>GSTIN: {p(isp.get('gstin'))}",
                    small,
                ),
                picture(photo, 3.0 * cm, 3.8 * cm, "Photograph", 600),
            ]
        ],
        colWidths=[14.4 * cm, 3.6 * cm],
        rowHeights=[4.0 * cm],
    )
    header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (1, 0), (1, 0), 0.6, colors.grey),
                ("LINEBELOW", (0, 0), (0, 0), 0.8, colors.black),
            ]
        )
    )

    category = extras.get("applicant_category") or (
        "individual"
        if (kyc.get("applicant_type") or "individual") == "individual"
        else "other"
    )
    category_text = _boxes(
        [(k, CATEGORY_LABEL[k]) for k in APPLICANT_CATEGORIES], category
    )
    if category == "other" and extras.get("applicant_category_other"):
        category_text += f" ({p(extras.get('applicant_category_other'))})"
    id_type = kyc.get("id_proof_type")
    id_text = _boxes([(k, ID_LABEL.get(k, k)) for k in ID_TYPES], id_type)
    id_number = id_number_for_caf(
        id_type, kyc.get("id_number"), kyc.get("id_number_last4")
    )
    name = kyc.get("full_name") or subscriber.get("name")
    install = ", ".join(
        x
        for x in (
            extras.get("plot_no") and f"Plot {extras['plot_no']}",
            subscriber.get("install_address"),
            extras.get("locality"),
            extras.get("district"),
            subscriber.get("install_city"),
            subscriber.get("install_pincode"),
        )
        if x
    )

    id_box = Table(
        [[Paragraph(f"<b>ID number</b>&nbsp;&nbsp;{p(id_number)}", small)]],
        colWidths=[18 * cm],
    )
    id_box.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.8, colors.black)]))

    signer = (
        f"{p(signatory.get('name'))}<br/>{p(signatory.get('designation'))}"
        if signatory.get("name") or signatory.get("designation")
        else "Authorised signatory"
    )
    sign_row = Table(
        [
            [
                picture(signature, 6 * cm, 2.2 * cm, "Customer signature", 900),
                Table(
                    [
                        [
                            picture(stamp, 3.2 * cm, 2.2 * cm, "Stamp", 600),
                            Paragraph(signer, tiny),
                        ]
                    ],
                    colWidths=[3.6 * cm, 4.8 * cm],
                ),
            ],
            [
                Paragraph("Signature of the applicant", tiny),
                Paragraph(f"For {p(isp.get('legal_name'))}", tiny),
            ],
        ],
        colWidths=[9 * cm, 9 * cm],
        rowHeights=[2.6 * cm, 0.6 * cm],
    )
    sign_row.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (0, 0), 0.6, colors.grey),
                ("BOX", (1, 0), (1, 0), 0.6, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    story = [
        header,
        Spacer(1, 6),
        Paragraph("Customer Application Form - Internet Service", title),
        grid(
            [
                ("CAF number", kyc.get("caf_number")),
                ("Date", kyc.get("caf_date")),
                ("Customer ID", subscriber.get("username")),
                ("Circuit ID", subscriber.get("circuit_id")),
            ]
        ),
        Spacer(1, 6),
        Paragraph("Applicant", head),
        Paragraph(category_text, tiny),
        Spacer(1, 3),
        grid(
            [
                ("Name", name),
                (
                    "Father's / spouse's name",
                    extras.get("father_or_spouse_name")
                    or kyc.get("father_or_spouse_name"),
                ),
                ("Date of birth", kyc.get("date_of_birth")),
                ("Mobile", subscriber.get("phone")),
                ("Email", subscriber.get("email")),
                ("GSTIN (if business)", subscriber.get("gstin")),
            ]
        ),
        Spacer(1, 6),
        Paragraph("Proof of identity", head),
        Paragraph(id_text, tiny),
        Spacer(1, 3),
        id_box,
        Spacer(1, 6),
        Paragraph("Addresses", head),
        grid(
            [
                (
                    "Billing / permanent",
                    kyc.get("permanent_address") or subscriber.get("address"),
                ),
                (
                    "Installation",
                    kyc.get("installation_address") or install or "Same as billing",
                ),
                ("Plot no.", extras.get("plot_no")),
                ("Locality", extras.get("locality")),
                ("District", extras.get("district")),
            ]
        ),
        Spacer(1, 6),
        Paragraph("Service", head),
        grid(
            [
                ("Plan", subscriber.get("package_name")),
                ("Venue / network", subscriber.get("customer_name")),
            ]
        ),
        Spacer(1, 6),
        Paragraph(
            "I confirm that the details above are true and that the identity and "
            "address documents I gave are mine. I will use the connection only "
            "for lawful purposes and keep my login details to myself.",
            tiny,
        ),
        Spacer(1, 8),
        sign_row,
    ]
    doc.build(story)
    return buffer.getvalue()
