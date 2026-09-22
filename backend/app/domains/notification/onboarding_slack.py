"""Master-console customer-onboarding status, posted to one internal Slack
channel through the existing ``notification_deliveries`` outbox.

## What the onboarding flow actually is (and what it is not)

The Master console does not run one long staged job with a progress bar.
It makes **three separate requests**, and that is the whole of it:

1. ``POST /customers/onboard``
   (``app.domains.customer_provisioning.router``) -- "Add Customer".
   Creates the organization, grants the operator ``organization-admin``
   on it, optionally creates a first location, seeds default alert rules.

   **The shipped Master console does not call this.** Checked against
   cloudguest-foundation ``origin/main``: the only ``onboard`` path
   anywhere in ``src/services`` is ``/network-integrations/platform/
   onboard``. ``master.customers.tsx``'s "Add Customer" button opens
   ``PlatformLocationWizard`` (titled "Smart location provisioning"),
   which goes straight to (2) -- its org step creates the organization
   inside that same transaction. This endpoint is still real, still
   GLOBAL-gated on ``organizations.create``, and still reachable by an
   API client, so it is hooked; just do not expect traffic on it from
   the wizard.
2. ``POST /locations/provision``
   (``app.domains.location.router`` ->
   ``LocationProvisioningService.provision_location``) -- "Smart location
   provisioning". Organization (new or reused), location, owner user,
   subscription/plan, feature flags, default settings, captive-portal
   config, optional MikroTik router + config template + WireGuard peer,
   audit entry, welcome email, activation.
3. ``POST /network-integrations/platform/onboard``
   (``app.domains.network_integration.router``) -- only for a venue whose
   equipment is a TP-Link Omada controller rather than a MikroTik.
   Registers the controller and the synthetic fleet ``Router`` row a
   guest session needs.

So there are exactly four honest events, and they are the four members of
``ONBOARDING_SLACK_EVENT_TYPES``.

**There is deliberately no "onboarding started" event, and no
per-sub-step event** ("location created", "portal ready", "router
configured"). Step 2 is a *single database transaction* -- see
``provisioning_service``'s own "The real single-transaction guarantee"
docstring. Every sub-step inside it is a ``session.flush()`` on one
request-scoped session, and any failure rolls all of them back together.
An outbox row written mid-flight is rolled back with everything else, so
a "started" or "portal ready" notice could only ever reach Slack for a
run that also succeeded -- it would be pure duplication of the completion
notice, and it would read as progress the system cannot actually observe.
Reporting stages that do not exist is how a Slack channel stops being
read.

## Why success rides the transaction and failure rides Celery

Success is enqueued **inside the request's own transaction**, at the
router layer, right after the service call returns. That is what makes it
impossible to announce a customer who was then rolled back: the outbox
row and the customer commit together or not at all.

Failure cannot work that way, for the same reason. By the time a
provisioning call raises, ``app.database.session.get_db_session`` is
about to roll the session back -- a row written there would vanish with
the half-built customer, and a silently failed onboarding is precisely
the thing worth paging about. So the failure notice is handed to Celery
(``tasks.record_onboarding_failure``), which opens its own session in
another process and writes the row there.

Both paths converge on the same single sending path: a ``PENDING`` row
that ``run_notification_dispatch_sweep`` drains, with the outbox's
existing retry/backoff. Nothing in this module ever performs a network
call on a request thread.

## What is deliberately NOT in a message

Everything in a message is assembled field-by-field by the builders
below. There is no ``model_dump()``, no ``**kwargs``, no dict merge and
no exception ``str()`` anywhere on this path, and that is the design, not
an accident -- it is the only construction under which "what could leak
into Slack?" has a bounded answer that a reader can check.

Excluded on purpose:

* **The webhook URL.** Not in the payload, not in the ``recipient``
  column, not in a log line (see ``slack.py``'s ``_redact``).
* **Credentials of any kind.** The owner's generated temporary password
  (``ProvisionLocationResult.owner_temporary_password``), the router's
  ``api_secret``, the controller's ``client_secret``/``password``, the
  RADIUS shared secret, the WireGuard keys.
* **WiFi passwords.** This codebase has a live defect where the Omada v2
  SSID *list* call returns ``securityKey`` in plaintext. No SSID object,
  and nothing derived from one, is reachable from any builder here --
  the controller builder takes a controller name, a vendor string and a
  site label, all of them typed by the operator.
* **Guest PII.** No guest, no MAC, no device, no session ever appears in
  an onboarding message; none of these three endpoints has one to hand.
* **Personal contact details.** The owner's name, email address and
  phone number are left out although the provisioning result carries all
  three. "Who the venue contact is" is not information an ops channel
  needs to know an onboarding landed, and an internal Slack channel is a
  worse place to keep it than the database already is.
* **Raw exception text.** A failure reports the exception's *class name*
  and HTTP status plus the request id, never ``str(exc)`` -- a message
  built by an arbitrary layer below (SQLAlchemy echoing a conflicting
  row, a validator echoing the address it rejected) is exactly the
  uncontrolled string this module exists to avoid. The request id is the
  correlation handle; the detail stays in the logs, where access is
  already governed.

What IS included: the organization name, the location name and code, the
plan name, the property type, the controller/router *name* and vendor,
whether a tunnel was allocated, the acting operator's user id (an opaque
UUID, not a name or address), a UTC timestamp and a deep link back into
the Master console.

## Scope

These messages are Master/GLOBAL scope. One event produces exactly one
row and exactly one POST to one channel; nothing here iterates
organizations, and no code path turns "the caller has no organization"
(which is what a GLOBAL operator resolves to) into "every organization".
The organization is always the concrete one the request just created or
named.

The row is written with ``organization_id=None``. That is deliberate and
it is a scoping decision, not laziness:
``NotificationRepository.list_deliveries`` filters org-scoped callers by
strict equality on ``organization_id``, so a ``NULL`` row is invisible to
every tenant's ``GET /notifications/deliveries`` and visible to a GLOBAL
Master caller. Tagging these internal ops rows with the customer's own
organization id would have published them straight into that customer's
notification list. The organization id is kept in ``context`` instead,
where ops can still query it and no tenant-scoped listing reads it.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import quote

from app.core.config import Settings
from app.core.logging import get_logger

from .constants import (
    SLACK_ONBOARDING_RECIPIENT,
    NotificationChannelType,
    NotificationEventType,
)

logger = get_logger(__name__)

# One field's value is truncated at this many characters. Names in this
# platform are already length-capped by their own columns; this is a
# backstop against a long free-text field ever reaching a message, not the
# primary defence (the field allowlist is).
MAX_FIELD_LENGTH = 200

# Slack renders at most ~3000 characters of a `text` block usefully. A
# message built from the allowlist below comes in well under this; the cap
# exists so that no future field can make a message unbounded.
MAX_MESSAGE_LENGTH = 2800

# Characters removed from every value before it is rendered, and the list
# is short on purpose.
#
# `<` and `>` are the load-bearing pair: every Slack construct that does
# something rather than merely look like something needs them -- `<!channel>`,
# `<!here>`, `<@U123>`, `<#C123>`, and the `<url|label>` link form that can
# show one destination and go to another. Removing these two is what stops a
# venue name from paging the channel or smuggling a link.
#
# Backtick and asterisk are cosmetic: a stray one would corrupt the layout of
# the message around it, so they go too.
#
# `_`, `~` and `|` are deliberately NOT stripped, and that is a correction.
# They were, and it was wrong: Organization slugs are normalised by nothing
# but `strip().lower()` (see `organization.service._normalize_slug`), so
# `grand_hotel_andheri` is a legal slug, and stripping underscores rendered it
# as `grandhotelandheri` -- a mangled identifier that an operator might copy
# out of the message and not find. Once `<`/`>` are gone none of the three can
# escape into a mention or a link; the worst any of them can now do is render
# a word in italics. A correct identifier is worth more than that.
_STRIPPED_CHARACTERS = frozenset("`*<>\r\n\t")

_OUTCOME_SUCCESS = "succeeded"
_OUTCOME_FAILURE = "failed"


def _clean(value: object) -> str:
    """Render one already-allowlisted value as a bounded, markup-safe
    string. This is the last line of defence, never the first -- it makes
    a value that reached here harmless, and the builders below are what
    decide which values reach here at all."""
    text = "" if value is None else str(value)
    text = "".join(ch for ch in text if ch not in _STRIPPED_CHARACTERS)
    text = " ".join(text.split())
    if len(text) > MAX_FIELD_LENGTH:
        text = text[: MAX_FIELD_LENGTH - 1] + "…"
    return text


@dataclass(frozen=True, slots=True)
class OnboardingNotice:
    """One onboarding event, reduced to exactly the fields that may be
    published. Built only by the module-level builders below -- the
    constructor is not a general-purpose escape hatch, and nothing
    outside this module should assemble ``details`` by hand.

    ``organization_id`` is carried for ``context`` and for the deep link;
    it is never used to select or fan out over organizations.
    """

    event_type: NotificationEventType
    stage: str
    organization_name: str
    organization_id: uuid.UUID | None
    occurred_at: datetime
    actor_user_id: uuid.UUID | None = None
    details: tuple[tuple[str, str], ...] = ()
    link_path: str | None = None
    failure_summary: str | None = None
    # The two halves `failure_summary` is rendered from, kept separately so
    # `build_context` can carry them across the Celery boundary without
    # `notice_from_context` having to parse a display string back apart.
    error_type: str | None = None
    status_code: int | None = None
    request_id: str | None = None

    @property
    def outcome(self) -> str:
        return (
            _OUTCOME_FAILURE
            if self.event_type is NotificationEventType.ONBOARDING_FAILED
            else _OUTCOME_SUCCESS
        )


def _notice(
    *,
    event_type: NotificationEventType,
    stage: str,
    organization_name: str,
    organization_id: uuid.UUID | None,
    actor_user_id: uuid.UUID | None,
    details: Sequence[tuple[str, object | None]],
    link_path: str | None,
    failure_summary: str | None = None,
    error_type: str | None = None,
    status_code: int | None = None,
    request_id: str | None = None,
) -> OnboardingNotice:
    return OnboardingNotice(
        event_type=event_type,
        stage=stage,
        organization_name=_clean(organization_name) or "(unnamed)",
        organization_id=organization_id,
        occurred_at=datetime.now(UTC),
        actor_user_id=actor_user_id,
        details=tuple(
            (label, _clean(value)) for label, value in details if value is not None
        ),
        link_path=link_path,
        failure_summary=failure_summary,
        error_type=error_type,
        status_code=status_code,
        request_id=request_id,
    )


# ============================================================================
# Builders -- one per event. Every argument is named; nothing takes a model,
# a schema, a response object or a mapping.
# ============================================================================


def customer_created_notice(
    *,
    organization_id: uuid.UUID,
    organization_name: str,
    organization_slug: str,
    location_created: bool,
    actor_user_id: uuid.UUID | None,
) -> OnboardingNotice:
    """``POST /customers/onboard`` succeeded.

    ``admin_email`` is on the request and is left out -- see the module
    docstring's exclusion list.
    """
    return _notice(
        event_type=NotificationEventType.ONBOARDING_CUSTOMER_CREATED,
        stage="Customer created",
        organization_name=organization_name,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        details=[
            ("Slug", organization_slug),
            ("First location", "created" if location_created else "not yet"),
        ],
        link_path=_organization_path(organization_id),
    )


def location_provisioned_notice(
    *,
    organization_id: uuid.UUID,
    organization_name: str,
    location_name: str,
    location_code: str,
    property_type: str | None,
    plan_name: str,
    router_name: str | None,
    tunnel_allocated: bool,
    actor_user_id: uuid.UUID | None,
) -> OnboardingNotice:
    """``POST /locations/provision`` succeeded -- the whole transaction,
    which is the only granularity that exists (module docstring).

    Takes ``tunnel_allocated: bool``, not the tunnel IP address. The
    address is hub-internal network topology and adds nothing an ops
    channel acts on; whether a tunnel exists at all does.

    ``owner_temporary_password``, ``owner_email``, ``owner_name`` and
    ``login_url`` are all on ``ProvisionLocationResult`` and none of them
    is a parameter here.
    """
    return _notice(
        event_type=NotificationEventType.ONBOARDING_LOCATION_PROVISIONED,
        stage="Location provisioned",
        organization_name=organization_name,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        details=[
            ("Location", location_name),
            ("Code", location_code),
            ("Property type", property_type),
            ("Plan", plan_name),
            ("Router", router_name or "none (controller venue)"),
            ("Tunnel", "allocated" if tunnel_allocated else "not required"),
        ],
        link_path=_location_search_path(location_code),
    )


def controller_onboarded_notice(
    *,
    organization_id: uuid.UUID,
    organization_name: str,
    controller_name: str,
    provider: str,
    site_name: str | None,
    synthetic_identity: bool,
    actor_user_id: uuid.UUID | None,
) -> OnboardingNotice:
    """``POST /network-integrations/platform/onboard`` succeeded.

    Takes a controller *name*, a provider string and a site label. It
    deliberately does not take the integration object, a credentials
    block, or anything SSID-shaped: the Omada v2 SSID list call returns
    ``securityKey`` in plaintext, so an SSID object is the one thing that
    must never become reachable from a notification payload. ``base_url``
    is also excluded -- it is a customer's internal controller address.
    """
    return _notice(
        event_type=NotificationEventType.ONBOARDING_CONTROLLER_ONBOARDED,
        stage="Controller onboarded",
        organization_name=organization_name,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        details=[
            ("Controller", controller_name),
            ("Vendor", provider),
            ("Site", site_name),
            (
                "Fleet device",
                "synthetic identity" if synthetic_identity else "real identity",
            ),
        ],
        # The Master console's own page for controllers. It takes no id
        # param, so this is the list, not a detail view -- see the route
        # comment above.
        link_path=_MASTER_INTEGRATIONS_PATH,
    )


def onboarding_failed_notice(
    *,
    stage: str,
    organization_name: str,
    organization_id: uuid.UUID | None,
    error_type: str,
    status_code: int | None,
    actor_user_id: uuid.UUID | None,
    request_id: str | None,
    details: Sequence[tuple[str, object | None]] = (),
) -> OnboardingNotice:
    """An onboarding request raised.

    ``error_type`` is the exception's class name and nothing else.
    ``str(exc)`` is never published -- see the module docstring. The
    request id is what turns this message into something actionable: it
    is the key into ``app.core.logging``'s structured logs, where the real
    message already is.
    """
    summary = _clean(error_type) or "Exception"
    if status_code is not None:
        summary = f"{summary} (HTTP {status_code})"
    return _notice(
        event_type=NotificationEventType.ONBOARDING_FAILED,
        stage=stage,
        organization_name=organization_name,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        details=details,
        link_path=None,
        failure_summary=summary,
        error_type=_clean(error_type) or "Exception",
        status_code=status_code,
        request_id=_clean(request_id) or None,
    )


# ============================================================================
# Rendering
# ============================================================================

# Master console route paths, as cloudguest-foundation actually registers
# them. Read off `origin/main` rather than assumed, because the obvious
# guesses are all wrong:
#
# * There is no `/master/customers/$id`. `master.customers.tsx` declares
#   `validateSearch: z.object({ open: z.string().optional() })`, where
#   `open` is an ORGANIZATION id; the page opens that customer's detail
#   drawer once the list loads and then strips the param. Its own comment
#   says the page "has no URL-addressable customer detail route".
# * There is no `/master/locations/$id` and no per-location drawer at all.
#   `master.locations.tsx` accepts `?q=`, which only prefills the search
#   box -- so the honest link is a pre-filtered list, not a detail view.
# * Tenant routes `/organizations/$orgId` and `/locations/$locationId` DO
#   exist, and are useless here: `_authenticated.tsx` redirects any path
#   not starting with `/master` back to `/master` on the master host.
#
# A link that 404s or bounces is worse than no link, which is why these
# are the paths and not the prettier ones.
_MASTER_CUSTOMERS_PATH = "/master/customers"
_MASTER_LOCATIONS_PATH = "/master/locations"
_MASTER_INTEGRATIONS_PATH = "/master/integrations"


def _organization_path(organization_id: uuid.UUID) -> str:
    return f"{_MASTER_CUSTOMERS_PATH}?open={organization_id}"


def _location_search_path(location_code: str) -> str:
    return f"{_MASTER_LOCATIONS_PATH}?q={quote(location_code, safe='')}"


def build_slack_text(notice: OnboardingNotice, *, master_base_url: str = "") -> str:
    """Render one notice as Slack's documented incoming-webhook ``text``.

    Reads only ``notice``'s own fields. ``master_base_url`` is a
    deployment origin from ``Settings``; when it is empty the message
    simply carries no link, because a relative path in Slack is not a
    link and a fabricated host is worse than none.
    """
    icon = "✅" if notice.outcome == _OUTCOME_SUCCESS else "\U0001f6a8"
    headline = (
        f"{icon} *Onboarding {notice.outcome}* — "
        f"{notice.stage}: {notice.organization_name}"
    )
    lines = [headline]

    if notice.failure_summary:
        lines.append(f"Error: {notice.failure_summary}")
        if notice.request_id:
            lines.append(f"Request id: {notice.request_id}")

    lines.extend(f"{label}: {value}" for label, value in notice.details if value)

    if notice.actor_user_id is not None:
        lines.append(f"Operator: {notice.actor_user_id}")
    lines.append(f"At: {notice.occurred_at.isoformat(timespec='seconds')}")

    base = master_base_url.strip().rstrip("/")
    if base and notice.link_path:
        lines.append(f"Open in Master: {base}{notice.link_path}")

    text = "\n".join(lines)
    if len(text) > MAX_MESSAGE_LENGTH:
        text = text[: MAX_MESSAGE_LENGTH - 1] + "…"
    return text


def build_context(notice: OnboardingNotice) -> dict[str, object]:
    """The structured twin of the rendered text, stored on
    ``NotificationDelivery.context``.

    Same allowlist, same values -- it holds nothing the message does not
    already say, which is what makes "is the outbox row safe?" the same
    question as "is the message safe?" rather than a second one. The
    organization id lives here because the row itself is written with
    ``organization_id=None``; see the module docstring's Scope section.
    """
    return {
        "event_type": notice.event_type.value,
        "stage": notice.stage,
        "outcome": notice.outcome,
        "organization_name": notice.organization_name,
        "organization_id": (
            str(notice.organization_id) if notice.organization_id else None
        ),
        "actor_user_id": (
            str(notice.actor_user_id) if notice.actor_user_id else None
        ),
        "occurred_at": notice.occurred_at.isoformat(),
        "failure_summary": notice.failure_summary,
        "error_type": notice.error_type,
        "status_code": notice.status_code,
        "request_id": notice.request_id,
        "details": {label: value for label, value in notice.details},
    }


# `Settings.frontend_base_url`'s committed default. It is a documented
# placeholder ("not a real host", per its own description), so falling
# back to it would put a link into Slack that resolves nowhere. A message
# with no link is honest; a message with a dead link is not.
_PLACEHOLDER_FRONTEND_BASE_URL = "https://app.cloudguest.example"


def resolve_master_console_base_url(settings: Settings) -> str:
    """Origin for the "Open in Master" link, or ``""`` for no link.

    ``master_console_base_url`` wins; ``frontend_base_url`` is the
    fallback, because today the Master console and the customer dashboard
    are the same cloudguest-foundation build. The placeholder default is
    treated as unset.
    """
    base = settings.master_console_base_url.strip()
    if base:
        return base
    fallback = settings.frontend_base_url.strip()
    if fallback == _PLACEHOLDER_FRONTEND_BASE_URL:
        return ""
    return fallback


# ============================================================================
# The enqueue seam
# ============================================================================


class OutboxEnqueueProtocol(Protocol):
    """The one method this module needs from
    ``app.domains.notification.service.NotificationService`` -- the same
    narrow, duck-typed shape ``location.provisioning_service
    .NotificationSenderProtocol`` and ``auth.service
    .NotificationSenderProtocol`` already use."""

    async def enqueue(
        self,
        *,
        event_type: NotificationEventType,
        channel: NotificationChannelType,
        recipient: str,
        body: str,
        organization_id: uuid.UUID | None,
        subject: str | None = None,
        context: dict[str, object] | None = None,
    ) -> object: ...


@dataclass(slots=True)
class OnboardingSlackNotifier:
    """Writes one Slack outbox row per onboarding event, or does nothing.

    ``enabled=False`` (no webhook configured) is the default state of
    every local checkout, every test run and any deployment that has not
    been given a webhook. In that state ``notify`` returns immediately
    having written nothing -- no row, no log at warning level, no error.

    ``notify`` never raises. It is called from request handlers that must
    succeed regardless, so every exception is logged and swallowed. The
    one thing it cannot protect against is the surrounding transaction
    being poisoned by a failed ``flush``, and that case is not special:
    it means the database rejected an insert, which would have failed the
    onboarding's own writes too.
    """

    notification_service: OutboxEnqueueProtocol
    enabled: bool = False
    master_base_url: str = ""

    async def notify(self, notice: OnboardingNotice) -> None:
        if not self.enabled:
            logger.debug(
                "onboarding_slack_disabled",
                extra={"event_type": notice.event_type.value},
            )
            return
        try:
            await self.notification_service.enqueue(
                event_type=notice.event_type,
                channel=NotificationChannelType.SLACK,
                # A constant label, never the webhook and never an address.
                recipient=SLACK_ONBOARDING_RECIPIENT,
                subject=None,
                body=build_slack_text(
                    notice, master_base_url=self.master_base_url
                ),
                # NULL on purpose -- see the module docstring's Scope
                # section. The organization id is in `context`.
                organization_id=None,
                context=build_context(notice),
            )
        except Exception:  # noqa: BLE001 -- an onboarding must never fail
            # over its own announcement. The delivery is lost, loudly.
            logger.exception(
                "onboarding_slack_enqueue_failed",
                extra={"event_type": notice.event_type.value},
            )


def notice_from_context(payload: Mapping[str, object]) -> OnboardingNotice:
    """Rebuild a failure notice from the JSON a Celery task was handed.

    Only ever used by ``tasks.record_onboarding_failure``, and only for
    ``ONBOARDING_FAILED`` -- the failure path is the one that crosses a
    process boundary (module docstring). Every field is read by name and
    re-cleaned; an unexpected key is ignored rather than rendered, so the
    allowlist still holds on the far side of the broker.
    """
    raw_org_id = payload.get("organization_id")
    raw_actor_id = payload.get("actor_user_id")
    raw_details = payload.get("details")
    details: list[tuple[str, object | None]] = []
    if isinstance(raw_details, Mapping):
        details = [(str(k), v) for k, v in raw_details.items()]
    return onboarding_failed_notice(
        stage=str(payload.get("stage") or "Onboarding"),
        organization_name=str(payload.get("organization_name") or "(unnamed)"),
        organization_id=uuid.UUID(str(raw_org_id)) if raw_org_id else None,
        error_type=str(payload.get("error_type") or "Exception"),
        status_code=(
            int(payload["status_code"])
            if isinstance(payload.get("status_code"), int)
            else None
        ),
        actor_user_id=uuid.UUID(str(raw_actor_id)) if raw_actor_id else None,
        request_id=(
            str(payload.get("request_id")) if payload.get("request_id") else None
        ),
        details=details,
    )


__all__ = [
    "MAX_FIELD_LENGTH",
    "MAX_MESSAGE_LENGTH",
    "OnboardingNotice",
    "OnboardingSlackNotifier",
    "OutboxEnqueueProtocol",
    "build_context",
    "build_slack_text",
    "resolve_master_console_base_url",
    "controller_onboarded_notice",
    "customer_created_notice",
    "location_provisioned_notice",
    "notice_from_context",
    "onboarding_failed_notice",
]
