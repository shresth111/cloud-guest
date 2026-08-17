"""Renders every redesigned transactional email to a static HTML file with
representative sample data, for human visual review in a browser. Not a
test -- a preview generator. Run via:

    .venv/bin/python scripts/render_email_previews.py

Each email is composed the same way its real service code composes it
(same ``app.core.email_layout`` calls, same content shape) -- some are
imported directly from the real module-level render helpers
(``_render_otp_email``, ``_render_verify_email``,
``_render_password_reset_email``), others (still inline in their service
method, since that's where the real dynamic context -- ``location``,
``invoice``, ``plan`` ORM rows -- lives) are reproduced here with the exact
same ``app.core.email_layout`` calls the real code makes, populated with
representative sample data, so this script never drifts into inventing a
different design.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.email_layout import (  # noqa: E402
    button,
    callout,
    esc,
    heading,
    info_box,
    link_fallback,
    paragraph,
    render_email,
)

OUT_DIR = Path("/tmp/cgb-email-redesign/email-previews")


def _write(name: str, html: str) -> None:
    path = OUT_DIR / f"{name}.html"
    path.write_text(html, encoding="utf-8")
    print(f"wrote {path}")


def render_all() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # -- OTP (urgent/simple) -------------------------------------------------
    from app.domains.otp.service import _render_otp_email

    _write(
        "01_otp_guest_login",
        _render_otp_email(
            intro="Use this code to finish signing in.", code="482913", minutes=10
        ),
    )
    _write(
        "02_otp_data_masking",
        _render_otp_email(
            intro=(
                "Use this code to change your dashboard's guest-data "
                "masking setting. Ignore this message if you didn't "
                "request it."
            ),
            code="738204",
            minutes=10,
        ),
    )

    # -- Auth: verify email / password reset ---------------------------------
    from app.domains.auth.service import (
        _render_password_reset_email,
        _render_verify_email,
    )

    _write(
        "03_email_verification_warm",
        _render_verify_email(
            first_name="Priya",
            verify_url="https://app.wyfyguest.com/verify-email?token=8f1c2e9a-4b3d-4a7e-9c1f-2d6e8b0a5f3c",
            warm=True,
        ),
    )
    _write(
        "04_email_verification_resend",
        _render_verify_email(
            first_name="Priya",
            verify_url="https://app.wyfyguest.com/verify-email?token=8f1c2e9a-4b3d-4a7e-9c1f-2d6e8b0a5f3c",
            warm=False,
        ),
    )
    _write(
        "05_password_reset",
        _render_password_reset_email(
            first_name="Priya",
            reset_url="https://app.wyfyguest.com/reset-password?token=740f900f-31a0-414b-a8bd-6f600d0b1473",
        ),
    )

    # -- User invite (mirrors app.domains.user.service.invite_user) ---------
    content = (
        heading("You've been invited to Wyfy Guest")
        + paragraph(
            "Hi Jamie, an account has been created for you. Use the "
            "credentials below to sign in -- you'll be asked to set a new "
            "password the first time you log in."
        )
        + info_box(
            [("Username", esc("jamie")), ("Temporary password", esc("Xk9!mQ2pLr7v"))],
            mono_values=True,
        )
        + button("Log In to Wyfy Guest", "https://app.wyfyguest.com/login")
    )
    _write(
        "06_user_invited",
        render_email(
            preheader="An account has been created for you on Wyfy Guest.",
            content_html=content,
        ),
    )

    # -- Location welcome email (onboarding, warm/rich) ----------------------
    content = (
        heading("Welcome to Wyfy Guest, Priya!")
        + paragraph(
            "Your Wyfy Guest account for <strong>Grand Plaza Hotel &mdash; "
            "Downtown Branch</strong> is ready. Here's everything you need "
            "to log in for the first time."
        )
        + info_box(
            [
                ("Username", esc("priya.grandplaza")),
                ("Temporary password", esc("Tr8!kNw4qZs9")),
            ],
            mono_values=True,
        )
        + button("Log In to Wyfy Guest", "https://app.wyfyguest.com/login")
        + paragraph(
            "You'll be asked to set a new password the first time you log in.",
            muted=True,
        )
    )
    _write(
        "07_location_welcome_with_password",
        render_email(
            preheader="Your Wyfy Guest account for Grand Plaza Hotel is ready.",
            content_html=content,
        ),
    )

    content = (
        heading("Your Wyfy Guest account, Priya")
        + paragraph(
            "This is a reminder of your Wyfy Guest account for "
            "<strong>Grand Plaza Hotel &mdash; Downtown Branch</strong>."
        )
        + info_box([("Username", esc("priya.grandplaza"))])
        + button("Log In to Wyfy Guest", "https://app.wyfyguest.com/login")
        + paragraph(
            "If you no longer have your temporary password, use "
            "‘Forgot password’ on the login page to set a new one.",
            muted=True,
        )
    )
    _write(
        "08_location_welcome_reminder",
        render_email(
            preheader="A reminder of your Wyfy Guest account for Grand Plaza Hotel.",
            content_html=content,
        ),
    )

    # -- Voucher batch export (operator-facing) ------------------------------
    content = heading("Your voucher batch export") + paragraph(
        "The voucher batch export you requested is attached to this email "
        "as a PDF (batch <code>3f2a91d4-6b8e-4c1a-9f0d-7e5b2c8a1d3f</code>)."
    )
    _write(
        "09_voucher_batch_export",
        render_email(
            preheader="Your voucher batch export is attached.", content_html=content
        ),
    )

    # -- Demo request received (internal team notification) -----------------
    content = (
        heading("New demo request")
        + paragraph(
            "<strong>Alex Chen</strong> (alex@brewhousecafe.com) from "
            "<strong>Brew House Cafe</strong> requested a demo."
        )
        + info_box(
            [
                ("Phone", esc("+1 415-555-0132")),
                (
                    "Message",
                    esc("We run 4 locations and need guest wifi analytics."),
                ),
            ]
        )
        + paragraph("View it on the Master console under Demo Requests.", muted=True)
    )
    _write(
        "10_demo_request_received",
        render_email(
            preheader="Alex Chen from Brew House Cafe requested a demo.",
            content_html=content,
            accent="#6366f1",
        ),
    )

    # -- Subscription renewal reminder ---------------------------------------
    content = (
        heading("Your subscription renews soon")
        + paragraph(
            "Your Wyfy Guest subscription is scheduled to renew "
            "automatically on <strong>28 Aug 2026</strong>."
        )
        + info_box(
            [
                ("Plan", esc("Growth")),
                ("Amount", esc("USD 149.00")),
                ("Renews on", esc("28 Aug 2026")),
            ]
        )
        + paragraph(
            "No action is needed if your payment details are up to date. "
            "You can review or update your subscription anytime from your "
            "Wyfy Guest dashboard.",
            muted=True,
        )
    )
    _write(
        "11_subscription_renewal_reminder",
        render_email(
            preheader="Your subscription renews on 28 Aug 2026.",
            content_html=content,
        ),
    )

    # -- Subscription expiry reminder (urgent) -------------------------------
    content = (
        heading("Action needed: your license will expire soon")
        + paragraph(
            "Your most recent renewal attempt failed. Unless resolved, "
            "your Wyfy Guest license will expire on "
            "<strong>21 Aug 2026</strong>."
        )
        + info_box(
            [
                ("Plan", esc("Growth")),
                ("Amount due", esc("USD 149.00")),
                ("Expires on", esc("21 Aug 2026")),
            ]
        )
        + callout(
            "Please update your payment details before this date to avoid "
            "any interruption to your service.",
            tone="danger",
        )
    )
    _write(
        "12_subscription_expiry_reminder",
        render_email(
            preheader="Your license will expire on 21 Aug 2026 unless resolved.",
            content_html=content,
            accent="#dc2626",
        ),
    )

    # -- Invoice email --------------------------------------------------------
    content = (
        heading("Your invoice is ready")
        + paragraph("Your invoice <strong>INV-2026-000482</strong> from Wyfy Guest is ready.")
        + info_box(
            [
                ("Invoice number", esc("INV-2026-000482")),
                ("Amount due", esc("USD 149.00")),
                ("Due date", esc("31 Aug 2026")),
            ]
        )
        + paragraph(
            "The full invoice, including a detailed breakdown of charges "
            "and applicable taxes, is attached to this email as a PDF."
        )
        + paragraph(
            "If you have any questions about this invoice, please reach "
            "out to our support team.",
            muted=True,
        )
    )
    _write(
        "13_invoice_ready",
        render_email(
            preheader="Invoice INV-2026-000482: USD 149.00 due 31 Aug 2026.",
            content_html=content,
        ),
    )

    # -- Quotation email --------------------------------------------------------
    content = (
        heading("Your WyfyGuest quotation")
        + paragraph(
            "Hello Sam Rivera, please find attached your WyfyGuest "
            "quotation for <strong>Riverside Coworking</strong>."
        )
        + info_box(
            [
                ("Quotation number", esc("QUO-2026-A1B2C3D4")),
                ("Total", esc("USD 2,450.00")),
                ("Valid until", esc("15 Sep 2026")),
            ]
        )
        + paragraph("If you have any questions, just reply to this email.", muted=True)
        + paragraph("Thank you for considering WyfyGuest.", muted=True)
    )
    _write(
        "14_quotation",
        render_email(
            preheader="Your WyfyGuest quotation QUO-2026-A1B2C3D4, valid until 15 Sep 2026.",
            content_html=content,
        ),
    )

    # -- Scheduled analytics report -------------------------------------------
    content = heading("Weekly Guest Analytics Report") + paragraph(
        "Your scheduled guest_analytics report has been generated and is "
        "attached to this email."
    )
    _write(
        "15_scheduled_report",
        render_email(
            preheader="Your scheduled guest_analytics report is ready.",
            content_html=content,
        ),
    )

    # -- Monitoring alert (ops) -------------------------------------------------
    for label, sev, resolved, accent, msg in [
        ("critical", "critical", False, "#dc2626", "Router RTR-8821 is down"),
        ("warning", "warning", False, "#d97706", "ISP link latency exceeded threshold"),
        ("resolved", "critical", True, "#16a34a", "Router RTR-8821 is up"),
    ]:
        heading_text = "Alert resolved" if resolved else f"{sev.upper()} alert"
        content = heading(heading_text) + paragraph(esc(msg))
        _write(
            f"16_monitoring_alert_{label}",
            render_email(
                preheader=("[RESOLVED] " if resolved else f"[{sev.upper()}] ") + msg,
                content_html=content,
                accent=accent,
            ),
        )

    print(f"\n{len(list(OUT_DIR.glob('*.html')))} preview files written to {OUT_DIR}")


if __name__ == "__main__":
    render_all()
