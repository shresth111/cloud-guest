"""Shared HTML email design system: one branded table-based layout every
transactional email in this codebase renders through, plus the small set
of reusable content blocks (button, code block, info box, ...) each
domain's own email-composing code assembles into that layout.

## Why a Python-side helper, not Jinja2 template files

There is no templates directory anywhere in this backend (checked: no
``.html``/``.j2``/``.jinja`` files exist), and every transactional email
today is a plain Python f-string built inline in the service that sends it
(``app.domains.auth.service``, ``app.domains.user.service``,
``app.domains.location.provisioning_service``,
``app.domains.voucher.service``, ``app.domains.billing.renewal_service``,
``app.domains.billing.router``, ``app.domains.quotation.service``,
``app.domains.otp.service``, ``app.domains.monitoring.service``,
``app.domains.analytics.report_tasks``). This module keeps that exact
convention -- plain Python composing plain strings -- rather than
introducing a whole new templating dependency/mechanism for its own sake.
What it changes is *what* those f-strings build: real, table-based,
inline-styled HTML instead of bare plain text, assembled from this
module's shared shell + content-block functions so every email looks like
it came from the same product instead of each domain inventing its own
one-off copy.

## Brand source of truth

Colors/logotype mirror the real Wyfy Guest brand identity already shipped
in ``cloudguest-foundation`` (``public/brand/*.svg`` -- the icon's own
``linearGradient id="wyfyGuestIconGradient"`` runs ``#6366f1`` ->
``#7c3aed``; ``src/styles.css``'s ``--primary`` token is the same indigo
hue) and ``wyfy-guest-website`` (``src/styles/global.css`` spells out the
exact hex ramp: ``--color-indigo-600: #4f46e5`` is literally commented
"dashboard --primary", ``--color-indigo-500: #6366f1`` "dashboard --ring",
``--color-ink: #1e1b4b``, display font ``Poppins``, body font
``Open Sans``). This module does not invent a new palette -- it reuses
those exact values, with email-safe hex (not oklch -- effectively no email
client parses that) and a web-safe font *stack* (Poppins/Open Sans are
listed first for the handful of clients that do render linked/embedded
fonts, e.g. Apple Mail and some webmail; every client falls back to
Helvetica/Arial, which is why the logotype is a real HTML/CSS block, not an
image -- Outlook's Word rendering engine does not support ``data:`` image
URIs at all, and this brand mark needs to render identically with zero
external asset requests).

## Email-HTML constraints this module honors throughout

* Table-based layout only (``<table role="presentation">`` + ``<td>``),
  never flexbox/grid -- Outlook desktop's Word engine ignores both.
* Every visual style is inlined on the element (``style="..."``); the one
  ``<style>`` block only carries the responsive `@media` tweak and a couple
  of client resets, both widely supported no-ops where unsupported.
* Max content width 600px, with a `@media (max-width: 620px)` rule that
  drops horizontal padding for small screens -- the one place "responsive"
  meaningfully applies to a table-based email.
* No JavaScript, no external stylesheet, no web font as a hard requirement
  -- every block still reads correctly in the Helvetica/Arial fallback.
"""

from __future__ import annotations

import html
import re

# ============================================================================
# Brand tokens -- see module docstring for where each value comes from.
# ============================================================================

BRAND_INDIGO = "#4f46e5"  # wyfy-guest-website --color-indigo-600 ("dashboard --primary")
BRAND_INDIGO_LIGHT = "#6366f1"  # --color-indigo-500 ("dashboard --ring")
BRAND_VIOLET = "#7c3aed"  # --color-violet-600 (icon gradient's second stop)
BRAND_INK = "#1e1b4b"  # --color-ink
TEXT_BODY = "#44475b"
TEXT_MUTED = "#6b7280"
BG_CANVAS = "#f4f4fb"
BORDER = "#e6e6f2"
CARD_BG = "#ffffff"
DANGER = "#dc2626"
WARNING = "#d97706"
SUCCESS = "#16a34a"
CODE_BG = "#eef2ff"
CODE_BORDER = "#c7d2fe"

FONT_STACK = (
    "'Poppins','Helvetica Neue',Helvetica,Arial,sans-serif"
)
BODY_FONT_STACK = "'Open Sans','Helvetica Neue',Helvetica,Arial,sans-serif"

PRODUCT_NAME = "Wyfy Guest"


def esc(value: object) -> str:
    """HTML-escapes any dynamic value before it's interpolated into a
    template string -- every f-string below runs untrusted-ish user/guest-
    supplied strings (names, org names, messages) through this."""
    return html.escape(str(value), quote=True)


# ============================================================================
# Shell
# ============================================================================


def render_email(
    *,
    preheader: str,
    content_html: str,
    accent: str = BRAND_INDIGO,
) -> str:
    """Wraps ``content_html`` (built from the block helpers below) in the
    shared branded shell: hidden preheader, a thin brand-accent top bar,
    the wordmark header, a white content card, and a small muted footer.
    ``accent`` lets an urgent email (OTP, expiry warning) tint the top bar
    without forking the whole shell."""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>{PRODUCT_NAME}</title>
<style>
  body, table, td {{ -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }}
  table, td {{ mso-table-lspace: 0pt; mso-table-rspace: 0pt; }}
  img {{ -ms-interpolation-mode: bicubic; border: 0; }}
  body {{ margin: 0; padding: 0; width: 100% !important; background-color: {BG_CANVAS}; }}
  @media screen and (max-width: 620px) {{
    .wg-container {{ width: 100% !important; }}
    .wg-px {{ padding-left: 20px !important; padding-right: 20px !important; }}
  }}
</style>
</head>
<body style="margin:0;padding:0;background-color:{BG_CANVAS};">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all;font-size:1px;line-height:1px;color:{BG_CANVAS};">
    {esc(preheader)}&nbsp;&#8203;&nbsp;&#8203;&nbsp;&#8203;&nbsp;&#8203;&nbsp;&#8203;&nbsp;&#8203;
  </div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:{BG_CANVAS};">
    <tr>
      <td align="center" style="padding:32px 16px;">
        <table role="presentation" class="wg-container" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:600px;">
          <tr>
            <td style="height:4px;line-height:4px;font-size:0;background-color:{accent};border-radius:4px 4px 0 0;">&nbsp;</td>
          </tr>
          <tr>
            <td class="wg-px" style="background-color:{CARD_BG};padding:28px 40px 8px 40px;border-left:1px solid {BORDER};border-right:1px solid {BORDER};">
              {_logotype()}
            </td>
          </tr>
          <tr>
            <td class="wg-px" style="background-color:{CARD_BG};padding:8px 40px 40px 40px;border-left:1px solid {BORDER};border-right:1px solid {BORDER};border-bottom:1px solid {BORDER};border-radius:0 0 12px 12px;font-family:{BODY_FONT_STACK};color:{TEXT_BODY};">
              {content_html}
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:24px 16px 0 16px;font-family:{BODY_FONT_STACK};font-size:12px;line-height:18px;color:{TEXT_MUTED};">
              This is an automated message from {PRODUCT_NAME} &mdash; please don't reply directly to this email.<br>
              &copy; {PRODUCT_NAME}. All rights reserved.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _logotype() -> str:
    """A pure HTML/CSS wordmark (rounded indigo square + "Wyfy Guest" in
    the brand ink color) instead of an image -- see module docstring for
    why an ``<img>``/data-URI logo was deliberately avoided."""
    return f"""<table role="presentation" cellpadding="0" cellspacing="0" border="0">
        <tr>
          <td style="width:32px;height:32px;background-color:{BRAND_INDIGO};border-radius:8px;text-align:center;vertical-align:middle;font-family:{FONT_STACK};font-size:16px;font-weight:700;color:#ffffff;line-height:32px;">W</td>
          <td style="padding-left:10px;font-family:{FONT_STACK};font-size:19px;font-weight:700;color:{BRAND_INK};vertical-align:middle;">{PRODUCT_NAME}</td>
        </tr>
      </table>"""


# ============================================================================
# Content blocks -- callers compose these into ``content_html``.
# ============================================================================


def heading(text: str) -> str:
    return (
        f'<h1 style="margin:16px 0 12px 0;font-family:{FONT_STACK};'
        f'font-size:22px;line-height:28px;font-weight:700;color:{BRAND_INK};">'
        f"{text}</h1>"
    )


def paragraph(html_content: str, *, muted: bool = False) -> str:
    color = TEXT_MUTED if muted else TEXT_BODY
    return (
        f'<p style="margin:0 0 16px 0;font-family:{BODY_FONT_STACK};'
        f'font-size:15px;line-height:24px;color:{color};">{html_content}</p>'
    )


def button(label: str, url: str, *, color: str = BRAND_INDIGO) -> str:
    """A bulletproof, table-based CTA button -- degrades to a square-
    cornered solid-color button in Outlook (no VML round-trip needed for a
    rectangle this simple), a fully rounded one everywhere else."""
    safe_url = esc(url)
    return f"""<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:8px 0 20px 0;">
        <tr>
          <td style="border-radius:8px;background-color:{color};">
            <a href="{safe_url}" target="_blank" style="display:inline-block;padding:13px 32px;font-family:{FONT_STACK};font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:8px;">{esc(label)}</a>
          </td>
        </tr>
      </table>"""


def link_fallback(url: str) -> str:
    safe_url = esc(url)
    return (
        f'<p style="margin:0 0 20px 0;font-family:{BODY_FONT_STACK};font-size:13px;'
        f'line-height:20px;color:{TEXT_MUTED};">'
        f"If the button above doesn't work, copy and paste this link into your browser:<br>"
        f'<a href="{safe_url}" target="_blank" style="color:{BRAND_INDIGO};word-break:break-all;">{safe_url}</a></p>'
    )


def code_block(code: str, *, color: str = BRAND_INK) -> str:
    """The large, letter-spaced code display every OTP-style email uses."""
    return f"""<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:8px 0 20px 0;">
        <tr>
          <td align="center" style="background-color:{CODE_BG};border:1px solid {CODE_BORDER};border-radius:8px;padding:20px;">
            <span style="font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:32px;font-weight:700;letter-spacing:8px;color:{color};">{esc(code)}</span>
          </td>
        </tr>
      </table>"""


def info_box(rows: list[tuple[str, str]], *, mono_values: bool = False) -> str:
    """A bordered label/value table -- used for credentials, invoice/
    quotation summaries, demo-request details, etc."""
    value_font = (
        "font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;"
        if mono_values
        else f"font-family:{BODY_FONT_STACK};"
    )
    row_html = "".join(
        f"""<tr>
          <td style="padding:10px 16px;border-bottom:1px solid {BORDER};font-family:{BODY_FONT_STACK};font-size:13px;color:{TEXT_MUTED};white-space:nowrap;">{esc(label)}</td>
          <td style="padding:10px 16px;border-bottom:1px solid {BORDER};{value_font}font-size:14px;color:{BRAND_INK};text-align:right;word-break:break-word;">{value}</td>
        </tr>"""
        for label, value in rows
    )
    return f"""<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:4px 0 20px 0;border:1px solid {BORDER};border-radius:8px;overflow:hidden;">
        {row_html}
      </table>"""


def callout(text_html: str, *, tone: str = "info") -> str:
    """A tinted note box -- e.g. "this link expires in 1 hour" or an
    urgent expiry warning. ``tone`` picks the accent: info/warning/danger."""
    accent = {"info": BRAND_INDIGO_LIGHT, "warning": WARNING, "danger": DANGER}[tone]
    bg = {"info": "#eef2ff", "warning": "#fef3e2", "danger": "#fef2f2"}[tone]
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="margin:0 0 20px 0;"><tr><td style="background-color:{bg};'
        f"border-left:3px solid {accent};border-radius:4px;padding:12px 16px;"
        f'font-family:{BODY_FONT_STACK};font-size:13px;line-height:20px;color:{TEXT_BODY};">'
        f"{text_html}</td></tr></table>"
    )


def divider() -> str:
    return f'<hr style="border:none;border-top:1px solid {BORDER};margin:24px 0;">'


# ============================================================================
# Plain-text fallback (multipart/alternative)
# ============================================================================

_TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_BLOCK_BREAK_RE = re.compile(
    r"</(p|div|tr|table|h1|h2|h3|li)\s*>|<br\s*/?>", re.IGNORECASE
)
_ANY_TAG_RE = re.compile(r"<[^>]+>")
_BLANK_LINES_RE = re.compile(r"\n{3,}")


def html_to_plain_text(email_html: str) -> str:
    """Derives a reasonable plain-text ``multipart/alternative`` part from
    a rendered email's HTML: strips ``<script>``/``<style>`` blocks
    entirely, turns block-level closing tags/``<br>`` into newlines, drops
    every remaining tag, and decodes entities. Not a hand-authored plain-
    text edition of each template (this codebase has no separate plain-
    text copy to preserve -- every email body here was itself a single
    string before this redesign), but a real, readable fallback for the
    mail clients/scanners that prefer or require it."""
    text = _TAG_RE.sub("", email_html)
    text = _BLOCK_BREAK_RE.sub("\n", text)
    text = _ANY_TAG_RE.sub("", text)
    text = html.unescape(text)
    lines = [line.strip() for line in text.splitlines()]
    text = "\n".join(lines)
    text = _BLANK_LINES_RE.sub("\n\n", text)
    return text.strip() + "\n"


__all__ = [
    "PRODUCT_NAME",
    "BRAND_INDIGO",
    "BRAND_INDIGO_LIGHT",
    "BRAND_VIOLET",
    "BRAND_INK",
    "TEXT_BODY",
    "TEXT_MUTED",
    "DANGER",
    "WARNING",
    "SUCCESS",
    "esc",
    "render_email",
    "heading",
    "paragraph",
    "button",
    "link_fallback",
    "code_block",
    "info_box",
    "callout",
    "divider",
    "html_to_plain_text",
]
