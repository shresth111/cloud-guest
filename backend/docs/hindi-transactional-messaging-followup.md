# Hindi Transactional Messaging — Scoping Doc (Follow-Up)

Status: **scoping only, not implemented.** Deferred out of the current Hindi
rollout by `cloudguest-foundation/docs/hindi-language-rollout-spec.md`
(section "Top-line scope decision" + finding #7 + section 3c). This doc is
the promised follow-up investigation: every transactional
email/SMS/WhatsApp touchpoint in this backend, who receives it, whether a
language preference exists to key off, and what's actually required to add
a Hindi variant. Read this before picking up that ticket — it should save a
full rediscovery pass.

## TL;DR for whoever picks this up

- **No template files, no i18n layer.** Every message is a Python f-string
  built inline in the service that sends it, composed from
  `app/core/email_layout.py`'s shared HTML block helpers (`heading`,
  `paragraph`, `button`, `info_box`, `callout`, `code_block`,
  `render_email`). A Hindi variant means adding `if language == "hi":`
  branches inside these composing functions, not swapping a template file.
- **15 real send call sites across 10 files.** 4 of them (email
  verification ×2, password reset, user invite, location welcome
  email+SMS) go to a `User` row, which already has a `.language` column —
  the cheapest slice. The rest go to recipients with **no addressable
  language preference at all** today (guests, `Organization.contact_email`,
  arbitrary operator-typed addresses, external sales prospects).
- **Guests have zero language mechanism for OTP.** `Guest` has no
  `preferred_language` column (checked `app/domains/guest/models.py` in
  full) and OTP is pre-auth — no `Guest` row even exists yet when an OTP is
  requested. `GuestSession.accept_language` exists but is a raw,
  write-only, analytics-only capture (`app.domains.analytics.repository
  .AnalyticsRepository.get_language_breakdown`), never read back for
  delivery.
- **Real blockers, not just code:** WhatsApp OTP needs a *new*
  Meta-approved Twilio Content Template for Hindi copy (external approval
  process); SMS via Exotel needs a *new* TRAI DLT-registered template for
  Hindi copy (external regulatory process, India-specific). Both are
  currently moot in practice — `whatsapp_delivery_provider`/
  `sms_delivery_provider` default to `"logging"` (no real provider
  configured on this deployment today), so neither blocker bites until a
  real provider is turned on.
- **Two send paths bypass the notification outbox entirely** (invoice,
  quotation — call `email_provider.send()` directly). Any Hindi mechanism
  built on top of `NotificationService` won't reach them without separately
  wiring them in.
- There's an existing-but-**unused** `NotificationTemplate` DB table with
  `{{variable}}`-substitution rendering (`render_and_enqueue`) — zero real
  call sites use it (all 9 `NotificationService.enqueue` callers pass a
  pre-rendered body). It has no `language` column either. A candidate
  foundation to extend, not a working mechanism today.

---

## 1. Full touchpoint inventory

| # | Message | File / function | Trigger | Channel | Recipient identity |
|---|---|---|---|---|---|
| 1 | OTP code (login) | `app/domains/otp/service.py::_render_otp_email` / `_dispatch` | Guest requests OTP (`OtpPurpose.GUEST_LOGIN`) | Email / SMS / WhatsApp | Guest (unauthenticated, pre-`Guest`-row) |
| 2 | OTP code (data-masking change) | same file/functions, `OtpPurpose.ACCOUNT_DATA_MASKING` branch | Dashboard user changes guest-data masking setting | Email / SMS / WhatsApp | **User** (staff, has `.language`) — note: this purpose's OTP actually goes to a *staff* identifier, not a guest, despite living in the same OTP module |
| 3 | Email verification | `app/domains/auth/service.py::_render_verify_email` (called from `register`, `resend_verification`) | Signup / resend | Email | User |
| 4 | Password reset | `app/domains/auth/service.py::_render_password_reset_email` | Forgot-password request | Email | User |
| 5 | User invite (temp password) | `app/domains/user/service.py` inline, `invite_user` (~line 545) | Admin invites a new staff user | Email | User (the *new* invitee — `language` param already threaded through `invite_user`'s signature today, just unused for content selection) |
| 6 | Location welcome email | `app/domains/location/provisioning_service.py::_send_welcome_email` | New location provisioned | Email | User (the location owner) |
| 7 | Location welcome SMS | same file, inline in `provision_location` (~line 1085) | Same event, if `send_welcome_sms` + phone present | SMS | Same location owner |
| 8 | Voucher batch export | `app/domains/voucher/service.py::email_batch_pdf` | Staff clicks "email this export" | Email (PDF attachment) | Arbitrary operator-typed address — **no `User` row guaranteed** |
| 9 | Subscription renewal reminder | `app/domains/billing/renewal_service.py::send_renewal_reminders` | Scheduled task, N days before renewal | Email | `Organization.contact_email` |
| 10 | Subscription expiry reminder | same file, `send_expiry_reminders` | Scheduled task, past-due grace period | Email | `Organization.contact_email` |
| 11 | Invoice email | `app/domains/billing/router.py::_send_invoice_email_and_build_response` | Manual or subscription-triggered invoice send | Email (PDF attachment) | `Organization.contact_email` — **bypasses `NotificationService`, calls `email_provider.send()` directly** |
| 12 | Quotation email | `app/domains/quotation/service.py::_send_quotation_email` | Sales sends a quotation | Email (PDF attachment) | `quotation.client_email` — external prospect, no account in this system at all — **also bypasses the outbox** |
| 13 | Monitoring/device alert | `app/domains/monitoring/service.py::EmailNotifier.send` / `SmsNotifier.send` | Router/device health alert fires | Email / SMS | Ops-configured `config["email"]` / `config["phone_number"]` on an alert channel — internal ops, not a platform account |
| 14 | Scheduled analytics report | `app/domains/analytics/report_tasks.py` (~line 200) | Scheduled report task | Email (attachment) | `schedule.recipient_emails` — arbitrary admin-configured list |
| 15 | Demo request notification | `app/domains/demo_request/service.py` (~line 100) | Public "request a demo" form submitted | Email | Internal Wyfy Guest sales staff (`Settings.demo_request_notify_email`) — **not guest/customer-facing at all** |

**Provider dispatch classes** (all in `app/domains/otp/service.py`, reused
by `NotificationService` and `monitoring`'s notifiers by composition):
`LoggingEmailProvider`/`SmtpEmailProvider`/`SesEmailProvider`,
`LoggingSmsProvider`/`TwilioSmsProvider`/`ExotelSmsProvider`,
`LoggingWhatsAppProvider`/`TwilioWhatsAppProvider`. **Every
`*_delivery_provider` setting defaults to `"logging"`** (`app/core/config.py`)
— confirmed no real email/SMS/WhatsApp provider is configured on this
codebase today; every message currently only reaches structured logs.

---

## 2. Recipient identity vs. language mechanism

### Group A — `User` row exists, `.language` already there (cheapest slice)
Touchpoints: **3, 4, 5, 6, 7**, and touchpoint 2's OTP.

`User.language` (`app/domains/auth/models.py` line 62, default `"en"`) is a
real column, already accepted as an updatable field via `PUT /users/me`
(confirmed by the FE spec, still true). `invite_user` in
`app/domains/user/service.py` even already accepts a `language` parameter
in its signature — it's just never read when composing the invite email's
content. **This is the group where the work is genuinely just "add Hindi
copy + branch on `user.language`" — no schema change needed.**

Caveat: `language` is validated as free text (`str | None, max_length=10`,
`app/domains/user/schemas.py`), no enum constraint — same gap the FE spec
already flagged for the dashboard slice. Before branching content on it,
either tighten it to an allowed-locale enum or make every call site
fall back to English on any unrecognized value (never raise).

### Group B — Guest, no identity/preference mechanism at all
Touchpoints: **1** (OTP login, all 3 channels).

`app/domains/guest/models.py`'s `Guest` model has no `preferred_language`
column (read the full file to confirm — checked). And structurally, OTP
request happens *before* any `Guest` row exists (OTP is the pre-auth
identity-verification step; `Guest` is created/looked-up after
verification succeeds in `app.domains.auth`'s guest-login flow) — so even
adding the column doesn't give `OtpService.request_otp` anything to read
without a new parameter arriving from the request itself.

The only existing signal is `GuestSession.accept_language` — the raw
`Accept-Language` HTTP header, captured at login-history time, **write-only
and analytics-only** (read exclusively by
`AnalyticsRepository.get_language_breakdown` for dashboard stats). It is
never parsed into a usable locale and never available at OTP-request time
regardless (no session exists yet).

**Open question 1 (needs a decision, not just code):** how does OTP learn
which language to send in? Two real options:
- **(a) Pass the portal's already-selected UI language as a request
  parameter** on `/otp/request` (the captive portal already knows this —
  `PortalRuntimeContext`'s `language` state, per the FE spec's section 1a).
  No schema change, no cross-device persistence, matches the FE spec's own
  already-stated position that guest language is deliberately
  client-side-only (section 3b: "no reliable account to key a backend
  preference off"). **Recommended** — cheapest, consistent with the
  decision already made for the portal.
- **(b) Add `Guest.preferred_language`.** Explicitly rejected by the FE
  spec for this reason (section 3b) — would need its own rollout decision
  to revisit, not assumed here.

### Group C — No `User`, no per-recipient identity at all
Touchpoints: **8, 9, 10, 11, 12, 14**.

`Organization` has no `contact_email`-adjacent language field (checked
`app/domains/organization/models.py` — only `contact_email` itself exists,
no `preferred_language`/`locale`). Touchpoints 9, 10, 11 send to
`organization.contact_email`, an address with no owner-account tie at all.

**Open question 2:** would need a new `Organization.preferred_language`
(or similarly-scoped) column plus an admin-facing setting to populate it —
this is genuinely new schema/product work, not present anywhere today.
Touchpoints 8 (voucher export) and 14 (scheduled report) go to
free-typed/admin-configured email addresses with no account tie whatsoever
— even `Organization.preferred_language` wouldn't cleanly cover these (an
export could be emailed to a personal Gmail address that isn't the org's
contact). Likely needs its own separate design call (e.g. a `language`
query param on those specific send actions, chosen manually by the staff
member triggering the send) rather than trying to force everything through
one org-level field.

Touchpoint 12 (quotation) is a special case: `quotation.client_email` is an
**external sales prospect with no account in this system at all.** No
existing field anywhere could carry their language preference. If ever
prioritized, this would most naturally be a manual dropdown on the
quotation-creation form (sales rep picks the language per-quotation), not
an automatic lookup.

### Group D — Recommend excluding from scope entirely
Touchpoints: **13, 15**.

Both are internal/ops-facing, never seen by a guest or a customer-org
admin: monitoring alerts go to an ops-configured contact on an alert
channel (infra jargon — router down/up, DHCP pool exhaustion, etc. — not
the kind of content a Hindi-language rollout is meant to reach), and the
demo-request notification goes to Wyfy Guest's own internal sales inbox.
Recommend explicitly scoping these out rather than silently leaving them
English — same "say so plainly" posture the FE spec's section on dashboard
coverage already establishes.

---

## 3. Templating mechanism — what "adding a Hindi variant" actually means here

Confirmed (matches `email_layout.py`'s own module docstring, still
accurate): **no templates directory anywhere in this backend** — no
`.html`/`.j2`/`.jinja` files. Every message is composed by a Python
function that calls `email_layout.py`'s block helpers
(`heading()`, `paragraph()`, `button()`, `info_box()`, `callout()`,
`code_block()`, `render_email()`) and interpolates dynamic values via
f-strings, HTML-escaped through `esc()`.

This matters for effort sizing in a specific way: **the copy is
interleaved with real Python control flow, not sitting in an isolated
template file.** Examples already in the code today:
- `_render_otp_email`/`_dispatch` (otp/service.py) branch on
  `OtpPurpose` to pick a different `intro`/`subject`, and pluralize
  `"minute" + ("s" if minutes != 1 else "")` — English pluralization
  rules that don't transfer to Hindi as a flat find-and-replace.
- `_send_welcome_email` (location/provisioning_service.py) branches on
  whether `temporary_password is not None` to compose an entirely
  different paragraph/heading.
- `_render_verify_email` (auth/service.py) branches on `warm: bool` for
  first-touch vs. resend copy.

So a Hindi variant isn't "translate N strings in a dictionary" the way
the portal's `portal-i18n.ts` `HI` dict is (per the FE spec, section 1) —
it's "add a parallel Hindi branch inside each composing function,"
because the branching logic itself (which intro, which pluralization,
which heading) needs to exist in both languages, and Hindi grammar
(no direct plural-suffix equivalent, different word order for a phrase
like "expires in N minutes") won't reuse the English branch's structure
as-is. Budget copywriting/review time accordingly — this is closer to
writing N×2 functions than filling in N dictionary values.

### The unused `NotificationTemplate` mechanism
`app/domains/notification/models.py`'s `NotificationTemplate` (org-scoped
or platform-wide `subject_template`/`body_template` with `{{var}}`
placeholders, rendered via
`app.domains.router_provisioning.service.render_template`) plus
`NotificationService.render_and_enqueue()` is real, working code — **but
grep confirms zero production call sites use `render_and_enqueue`.** Every
real caller (`auth`, `user`, `location`, `voucher`, `billing.renewal_service`,
`analytics.report_tasks`, `demo_request`) calls plain `enqueue()` with a
body it already rendered itself via `email_layout.py`. `NotificationTemplate`
has no `language` column today either.

This table is a plausible foundation to build on (add a `language` column,
key lookup by `(event_type, channel, language)`, migrate the 9
`enqueue()` callers over to `render_and_enqueue()`) — but that's a
meaningfully bigger lift than it first looks: it means *also* migrating
every composing function's branching logic (see above) into the
`{{var}}`-substitution model, which has no conditionals/pluralization of
its own. Flag this as a real architectural choice to make explicitly
before starting, not an assumed default.

---

## 4. Genuine blockers / open questions (decisions needed before implementation)

1. **WhatsApp OTP needs a new Meta-approved Content Template for Hindi.**
   `TwilioWhatsAppProvider` (otp/service.py) requires a pre-registered,
   Meta-approved `ContentSid` — WhatsApp Business API rejects freeform
   business-initiated messages. A Hindi OTP template is a *different*
   template needing its own approval cycle in the Twilio Console (external,
   typically multi-day turnaround), not a code change. Currently moot:
   `whatsapp_delivery_provider` defaults to `"logging"`, so no real
   WhatsApp sending happens on this deployment yet — confirm whether
   WhatsApp OTP is even planned for production before prioritizing this.

2. **SMS via Exotel needs a new TRAI DLT-registered template for Hindi.**
   `ExotelSmsProvider`'s own docstring is explicit: a body that doesn't
   match the DLT-registered template text is silently dropped by Indian
   carriers. A Hindi SMS body is a different template registration, an
   external regulatory process, not a backend change. (Twilio SMS has no
   such constraint — freeform body — but note Exotel is the India-specific
   provider in this codebase, suggesting it's the intended path for
   production Indian-market SMS; confirm which provider this deployment
   actually intends to use before assuming Twilio's simpler path applies.)

3. **No `Guest.preferred_language` — how does OTP even learn the guest's
   language?** See Group B above. Needs an explicit decision: pass the
   portal's UI language as a request param on `/otp/request` (recommended,
   consistent with the FE spec's already-made call), or revisit the FE
   spec's decision not to add a `Guest.preferred_language` column.

4. **`Organization.contact_email`-addressed mail has no language signal.**
   Renewal/expiry reminders and invoice email (Group C) need either a new
   `Organization.preferred_language` column + admin setting, or a decision
   to leave these English-only for now (arguably lower-urgency than
   guest-facing/OTP content — these go to a billing contact, not
   necessarily someone who needs Hindi).

5. **Quotation email's recipient has no account in the system at all.**
   `quotation.client_email` is an external sales prospect — no field
   anywhere could carry a language preference automatically. If
   prioritized, likely a manual per-quotation language choice on the
   creation form, a product decision, not purely a backend one.

6. **Invoice and quotation sends bypass `NotificationService` entirely** —
   both call `email_provider.send()` directly rather than going through
   the outbox. Any Hindi mechanism that hooks into `NotificationService`
   (e.g. extending `NotificationTemplate`) needs these two call sites
   wired in separately, or refactored onto the outbox first as a
   prerequisite.

7. **`User.language` has no format constraint today** (`max_length=10`,
   free text) — tighten to an allowed-locale enum, or every content-branch
   site needs an explicit "unrecognized value → fall back to English"
   guard rather than assuming only `"en"`/`"hi"` ever arrive.

8. **Pre-existing branding bug, unrelated to Hindi but touches the same
   file:** the location-welcome SMS body (`location/provisioning_service.py`
   ~line 1088) still reads `"Welcome to CloudGuest!"` — the old,
   pre-rebrand product name (see `project_rebrand_wyfy_guest` — CloudGuest
   → Wyfy Guest, 2026-08-01). Worth fixing in the same PR that touches this
   file for Hindi variants, since it's a one-line change in a file already
   being edited — but call it out as a separate commit/reason, not silently
   folded into the Hindi diff.

---

## 5. Rough sizing (for planning only — not a commitment)

Scoped to **Group A + Group B via the recommended "pass portal language as
a request param" option** (i.e., excluding new `Organization.preferred_language`
schema work, excluding quotation, excluding Groups D):

- Design spike: how content-branching works per composing function (not a
  flat dictionary — see section 3) — **0.5–1 day**, should land before any
  Hindi copywriting starts so all 6 functions follow one agreed pattern.
- Group A (5 files: `auth/service.py` ×2 functions, `user/service.py`,
  `location/provisioning_service.py` ×2 functions) — add `language`
  branch + Hindi copy + review, per function — **~2–3 days** including
  copy review.
- Group B (OTP, 3 channels × 2 purposes in `otp/service.py`) — add the
  request-param plumbing through `/otp/request` → `OtpService.request_otp`
  → `_dispatch`, plus Hindi copy for email/SMS/WhatsApp bodies —
  **~2 days** for email+SMS. WhatsApp is copy-ready but **blocked on the
  external Meta template approval** (item 1) before it can actually be
  used — don't count that wait time as engineering effort, but it does
  block "done" on a calendar, not just a sprint.
- Fix the free-text `User.language` validation gap (item 7) — **~0.5 day**,
  small and worth doing regardless of what else ships.

**Total engineering effort for the recommended first slice: roughly
1–1.5 engineer-weeks**, plus unavoidable external-approval calendar time
if WhatsApp is in scope. Group C (`Organization.preferred_language` +
migrating renewal/expiry/invoice/voucher-export/report emails) and the
quotation special case are each their own separately-sized follow-up on
top of this — don't fold them into the same estimate without a product
decision on Organization-level language first (item 4).

---

## 6. File/touchpoint summary (for the engineer who picks this up)

- `app/domains/otp/service.py` — `_render_otp_email`, `_dispatch`,
  provider classes (`TwilioWhatsAppProvider`, `ExotelSmsProvider` —
  read their docstrings, they document the template-approval constraints
  referenced above in detail)
- `app/domains/auth/service.py` — `_render_verify_email`,
  `_render_password_reset_email`, and the 3 call sites in `register`/
  `initiate_password_reset`/`resend_verification`
- `app/domains/user/service.py` — `invite_user` (~line 520-570)
- `app/domains/location/provisioning_service.py` — `_send_welcome_email`,
  and the inline SMS send in `provision_location` (~line 1085) — also
  where the stale "CloudGuest" branding string lives
- `app/domains/voucher/service.py` — `email_batch_pdf`
- `app/domains/billing/renewal_service.py` — `send_renewal_reminders`,
  `send_expiry_reminders`, `_send_reminder_email`
- `app/domains/billing/router.py` — `_send_invoice_email_and_build_response`
  (bypasses the outbox — see item 6)
- `app/domains/quotation/service.py` — `_send_quotation_email` (bypasses
  the outbox — see item 6; also the external-prospect special case)
- `app/domains/monitoring/service.py` — `EmailNotifier`, `SmsNotifier`
  (recommend excluding — Group D)
- `app/domains/analytics/report_tasks.py` — scheduled report email
  composition (~line 200)
- `app/domains/demo_request/service.py` — demo request notification
  (recommend excluding — Group D)
- `app/core/email_layout.py` — the shared block-helper module every
  composing function above builds on; any shared "branch on language"
  helper (e.g. a `t(en=..., hi=...)` convenience) would live here
- `app/domains/notification/models.py`,
  `app/domains/notification/service.py` — the unused
  `NotificationTemplate`/`render_and_enqueue` mechanism (section 3) —
  read before deciding whether to build on it or route around it
- `app/domains/auth/models.py` (`User.language`, line 62),
  `app/domains/user/schemas.py` (validation gap, item 7),
  `app/domains/guest/models.py` (confirmed: no language field),
  `app/domains/organization/models.py` (confirmed: no language field)
- `app/core/config.py` — `email_delivery_provider`/`sms_delivery_provider`/
  `whatsapp_delivery_provider` and related settings (all default
  `"logging"` — confirm what's actually configured in production before
  assuming Twilio/Exotel/SES/SMTP specifics apply)
