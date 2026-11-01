"""CAF-2 without a database (runs in CI).

HARD RULE: no 12-digit Aadhaar string can reach the CAF PDF. The renderer is
fed full Aadhaar numbers in every field it prints (name, addresses, notes-
like fields, the ID number itself, the CAF number); every PDF content
stream is decompressed and searched for any 12-digit run, with or without
separators. Also: the printed ID box for Aadhaar is ``XXXX XXXX <last4>``,
images are downscaled and size-capped, and the flag is OFF by default.
"""

from __future__ import annotations

import base64
import io
import re
import zlib

import pytest
from fastapi import HTTPException

from app.domains.isp_partner import caf_pdf
from app.domains.isp_partner.caf_service import (
    IspCafService,
    RequireIspCafEnabled,
    get_isp_caf_settings,
)
from app.domains.isp_partner.exceptions import IspBadRequestError

# Synthetic Verhoeff-valid numbers (random, not anyone's).
FULL = "718190937865"
FULL_SPACED = "7181 9093 7865"
OTHER = "997543231948"
TWELVE = re.compile(r"(?:\d[\s\-]?){11}\d")


def _inflate(header: bytes, raw: bytes) -> bytes:
    """Undo the stream's filters (reportlab writes ``[/ASCII85Decode
    /FlateDecode]`` for page content)."""
    if b"ASCII85Decode" in header:
        data = re.sub(rb"\s", b"", raw)
        data = data.removeprefix(b"<~").removesuffix(b"~>")
        raw = base64.a85decode(data)
    if b"FlateDecode" in header:
        raw = zlib.decompress(raw)
    return raw


def pdf_text(content: bytes) -> str:
    """Every text string drawn in the PDF (every content stream decoded),
    plus the info dictionary's title."""
    out: list[str] = []
    for m in re.finditer(
        rb"<<((?:(?!>>).)*?)>>\s*stream\r?\n(.*?)\s*endstream", content, re.S
    ):
        try:
            raw = _inflate(m.group(1), m.group(2))
        except (ValueError, zlib.error):
            continue
        out.extend(
            s.decode("latin-1") for s in re.findall(rb"\(((?:\\.|[^\\)])*)\)", raw)
        )
    out.extend(
        s.decode("latin-1")
        for s in re.findall(rb"/Title \(((?:\\.|[^\\)])*)\)", content)
    )
    return "\n".join(out)


def _render(**over) -> bytes:
    kw = {
        "isp": {
            "legal_name": f"Net {FULL} Pvt Ltd",
            "registered_address": f"Plot {OTHER}, Sector 1",
            "licence_number": "UL-TEST-0001",
            "licence_category": "Category B",
            "gstin": "27AAPFU0939F1ZV",
        },
        "subscriber": {
            "username": FULL,
            "circuit_id": 12,
            "name": f"Applicant {FULL_SPACED}",
            "phone": "9876500001",
            "email": "a@example.com",
            "address": f"House {FULL}",
            "install_address": f"Flat {OTHER}",
            "package_name": "50 Mbps",
            "customer_name": "Cafe",
        },
        "kyc": {
            "caf_number": f"CAF/{FULL}",
            "caf_date": "01-11-2026",
            "full_name": f"Name {FULL}",
            "id_proof_type": "aadhaar",
            # even if a full number ever arrived here, it must not print
            "id_number": FULL,
            "id_number_last4": "7865",
            "permanent_address": f"Perm {FULL_SPACED}",
            "installation_address": None,
        },
        "extras": {
            "applicant_category": "proprietor",
            "father_or_spouse_name": f"Parent {FULL}",
            "plot_no": OTHER,
            "locality": f"Locality {FULL}",
            "district": "District",
        },
        "signatory": {"name": f"Signer {FULL}", "designation": "Director"},
    }
    kw.update(over)
    return caf_pdf.render_caf2_pdf(**kw)


def test_no_twelve_digit_aadhaar_reaches_the_pdf() -> None:
    content = _render()
    assert content.startswith(b"%PDF")
    text = pdf_text(content)
    # the body is really read (not just the title): body-only strings
    assert "Customer Application Form - Internet Service" in text
    assert "Proof of identity" in text
    assert "XXXX XXXX 7865" in text.replace("ID number", "")  # the ID box
    joined = re.sub(r"\s+", " ", text)
    assert not TWELVE.search(joined), TWELVE.search(joined)
    for n in (FULL, OTHER, FULL_SPACED):
        assert n not in text
    # digits only, every string concatenated per string: no 12-in-a-row
    for s in text.splitlines():
        assert not re.search(r"\d{12}", re.sub(r"[\s\-]", "", s)), s


def test_scrub_and_id_box() -> None:
    assert caf_pdf.scrub(f"call {FULL} now") == "call XXXX XXXX 7865 now"
    assert caf_pdf.scrub(FULL_SPACED) == "XXXX XXXX 7865"
    assert caf_pdf.scrub("7181-9093-7865") == "XXXX XXXX 7865"
    assert caf_pdf.scrub("phone 9876500001") == "phone 9876500001"  # 10 digits stay
    assert caf_pdf.scrub("1234567890123") == "1234567890123"  # 13 digits: not Aadhaar
    assert caf_pdf.scrub(None) == ""
    assert caf_pdf.id_number_for_caf("aadhaar", FULL, None) == "XXXX XXXX 7865"
    assert caf_pdf.id_number_for_caf("aadhaar", None, "7865") == "XXXX XXXX 7865"
    assert (
        caf_pdf.id_number_for_caf("aadhaar", "XXXX XXXX 7865", "7865")
        == "XXXX XXXX 7865"
    )
    assert caf_pdf.id_number_for_caf("aadhaar", None, None) is None
    assert caf_pdf.id_number_for_caf("pan", "ABCDE1234F", "234F") == "XXXXXX234F"
    assert caf_pdf.id_number_for_caf(None, FULL, "7865") is None


def test_images_downscaled_and_capped() -> None:
    from PIL import Image

    big = Image.new("RGB", (4000, 3000), (200, 30, 30))
    buf = io.BytesIO()
    big.save(buf, format="PNG")
    out = caf_pdf.fit_image(buf.getvalue(), max_px=600, max_bytes=60_000)
    assert out is not None and len(out) <= 60_000
    with Image.open(io.BytesIO(out)) as im:
        assert im.format == "JPEG" and max(im.size) <= 600
    rgba = Image.new("RGBA", (300, 300), (0, 0, 0, 0))
    buf = io.BytesIO()
    rgba.save(buf, format="PNG")
    assert caf_pdf.fit_image(buf.getvalue(), max_px=200, max_bytes=50_000)
    assert caf_pdf.fit_image(b"not an image", max_px=200, max_bytes=50_000) is None
    assert (
        caf_pdf.fit_image(b"x" * (9 * 1024 * 1024), max_px=200, max_bytes=50_000)
        is None
    )
    # a PDF with embedded images still renders and still never prints Aadhaar
    content = _render(photo=out, signature=out, stamp=out)
    assert not re.search(r"\d{12}", re.sub(r"[\s\-]", "", pdf_text(content)))


def test_extras_validation() -> None:
    assert IspCafService.clean_extras(
        {"applicant_category": "pvt_ltd", "plot_no": " 12 "}
    ) == {
        "applicant_category": "pvt_ltd",
        "plot_no": "12",
        "applicant_category_other": None,
    }
    with pytest.raises(IspBadRequestError):
        IspCafService.clean_extras({"applicant_category": "trust"})


async def test_flag_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ISP_CAF_WORKBENCH_ENABLED", raising=False)
    get_isp_caf_settings.cache_clear()
    try:
        with pytest.raises(HTTPException) as ei:
            await RequireIspCafEnabled()
        assert ei.value.status_code == 404
    finally:
        get_isp_caf_settings.cache_clear()


def test_the_aadhaar_check_would_catch_a_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative control: with the scrub switched off, the same extractor
    finds the planted full number, so the test above is not vacuous."""
    monkeypatch.setattr(caf_pdf, "scrub", lambda v: "" if v is None else str(v))
    text = pdf_text(_render())
    assert FULL in re.sub(r"[\s\-]", "", text)
