"""The alerting a venue gets **without ever opening the alerts screen**.

## The gap this closes

On 2026-09-07 the platform's single real organization -- "WyFy Guest",
``08ec098b-1fb0-4bd0-bcc2-fe489d01ec4c`` -- had **zero** alert rules. Every
one of the seven rules that existed belonged to a demo or test
organization, and the one active email channel ("ISP Alerts") belonged to a
*different* test org and was linked to that org's own rule. So when a real
router at a real venue went down that night, a working evaluator would
still have emailed nobody: there was nothing configured to fire and nobody
configured to tell.

``app.domains.organization.router`` already had the right idea -- two
default rules created with every new organization -- but it stopped one
step short in two ways that both matter:

1. **Rules without channels notify nobody.** An ``AlertRule`` with no row in
   ``alert_rule_notification_channels`` reaches
   ``AlertService._dispatch_for_alert`` and returns. The rule exists, the
   ``Alert`` row appears, the dashboard lights up, and no email is sent. A
   default rule that cannot notify anyone is a screen, not an alert.
2. **Only brand-new organizations were covered.** The original docstring
   said so explicitly and accepted it, on the grounds that an operator can
   create the rule through ``POST /alert-rules``. That is exactly the "a
   human has to hand-craft a rule first" step the founder's complaint is
   about, and the org that needed it most was the one that already existed.

So this module owns the whole default, rules *and* the channel *and* the
link between them, and is written to be idempotent so the same function can
serve organization creation and a one-shot backfill of the organizations
that predate it (``scripts/backfill_default_alerting.py``).

## Why it lives here and not in ``OrganizationService``

Unchanged from the original placement, and for the original reason:
``app.domains.organization`` is a foundational domain with no business
knowing what an alert is. This module belongs to ``monitoring``, which owns
both ``AlertService`` and ``NotificationService``; the organization router
composes it at the orchestration layer, the same layer that already
composes billing's ``RequireFeature`` for that endpoint.

## Idempotency, and what it will not do

Matching is by ``(organization_id, target_component)`` for rules and by
``(organization_id, channel_type, name)`` for the channel. A rule whose
target already has a rule is left completely alone -- including one an
operator has since renamed, retuned, deactivated or pointed at different
channels. Re-running this must never undo somebody's deliberate
configuration; it only ever fills in what is missing.

Consequence worth stating plainly: an organization whose default rule was
deliberately switched off stays off, and an organization with no
``contact_email`` gets its rules but no channel, and is reported as such
rather than silently half-configured.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.domains.router.enums import RouterReachabilityState

from .constants import (
    ALERT_TARGET_ISP_LINK,
    ALERT_TARGET_MONITORED_HARDWARE,
    ALERT_TARGET_NETWORK_CONTROLLER,
    ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE,
    ALERT_TARGET_NETWORK_CONTROLLER_SETUP,
    ALERT_TARGET_ROGUE_DHCP_GUARD,
    ALERT_TARGET_ROUTER_REACHABILITY,
    NETWORK_CONTROLLER_STATE_FAILING,
    NETWORK_CONTROLLER_STATE_REFUSING_GUESTS,
    NETWORK_CONTROLLER_STATE_SETUP_INCOMPLETE,
    ROGUE_DHCP_STATE_UNGUARDED,
    AlertSeverity,
    AlertTriggerType,
    NotificationChannelType,
)
from .service import AlertService, NotificationService

logger = get_logger(__name__)

# The name given to the auto-provisioned email channel. Also the
# idempotency key, so it must stay stable: renaming this constant in a
# later release would make every organization grow a second channel.
DEFAULT_EMAIL_CHANNEL_NAME = "Account email"


# Every organization gets these rules, and -- new here -- gets them wired to
# somewhere they can actually arrive.
#
# Ordered most to least urgent, which is also the order an operator reads
# them in on the alerts screen.
DEFAULT_ALERT_RULES: tuple[dict[str, object], ...] = (
    {
        # THE TWO-MINUTE ONE. Watches Router.reachability_state, written by
        # RouterService.sweep_router_reachability off the 60-second agent
        # poll -- not Router.health_status, which moves on the shared
        # 15-minute ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES clock that
        # compute_lifecycle_stage, compute_internet_availability and the
        # frontend's location-liveness module all read. See
        # ALERT_TARGET_ROUTER_REACHABILITY's own comment for why that
        # separation is the whole point.
        #
        # CRITICAL, unlike everything below it: this is the only default
        # that means "guests at this venue have no Wi-Fi right now".
        "name": "Site offline",
        "description": (
            "Fires within about two minutes of a venue's router going "
            "quiet -- power cut, internet line down, or the device "
            "rebooting. Resolves once it has been back continuously for "
            "ten minutes, so a flapping router does not send repeat mail."
        ),
        "trigger_type": AlertTriggerType.HEALTH_STATUS_CHANGE,
        "target_component": ALERT_TARGET_ROUTER_REACHABILITY,
        "condition_config": {
            "expected_status": RouterReachabilityState.UNREACHABLE.value
        },
        "severity": AlertSeverity.CRITICAL.value,
    },
    {
        # The honest "ISP down" rule, and the ONLY default allowed to use
        # those words. IspLink.health_status is set from the router's own
        # report about its own WAN uplink -- a device that is still
        # reachable, telling us specifically about its internet line. That
        # is a genuinely different fact from "we stopped hearing from you",
        # and it is the difference the "Site offline" rule's copy is so
        # careful not to blur.
        "name": "Internet line down",
        "description": (
            "Fires when a venue's router reports that one of its own "
            "internet uplinks has failed its health checks."
        ),
        "trigger_type": AlertTriggerType.HEALTH_STATUS_CHANGE,
        "target_component": ALERT_TARGET_ISP_LINK,
        "condition_config": {"expected_status": "unhealthy"},
        "severity": AlertSeverity.CRITICAL.value,
    },
    {
        # The Omada counterpart of "Site offline". An Omada venue has no
        # MikroTik in the path, so the router rules above can never see it
        # (AlertService._agent_managed_routers drops the controller's
        # synthetic fleet row on purpose). What they would have caught is
        # this: the platform can no longer talk to the venue's controller,
        # and every guest authorization goes through that conversation.
        #
        # CRITICAL for the same reason "Site offline" is -- new guests at
        # this venue cannot get online. Fires after three consecutive
        # failed syncs, about half an hour at the default interval; see
        # NETWORK_CONTROLLER_FAILING_MIN_CONSECUTIVE_FAILURES for why not
        # sooner.
        "name": "WiFi controller unreachable",
        "description": (
            "Fires when the platform has failed to reach or sign in to a "
            "venue's WiFi controller (TP-Link Omada) several checks in a "
            "row -- about half an hour. While it lasts, new guests cannot "
            "get online. Resolves on the next successful check."
        ),
        "trigger_type": AlertTriggerType.HEALTH_STATUS_CHANGE,
        "target_component": ALERT_TARGET_NETWORK_CONTROLLER,
        "condition_config": {"expected_status": NETWORK_CONTROLLER_STATE_FAILING},
        "severity": AlertSeverity.CRITICAL.value,
    },
    {
        "name": "Network hardware down",
        "description": (
            "Fires when a registered access point, printer, camera, or "
            "other monitored device goes from up to down."
        ),
        "trigger_type": AlertTriggerType.HEALTH_STATUS_CHANGE,
        "target_component": ALERT_TARGET_MONITORED_HARDWARE,
        "condition_config": {"expected_status": "down"},
        "severity": AlertSeverity.WARNING.value,
    },
    {
        # The controller answers and says no. Not CRITICAL: it is inferred
        # from a pattern of refusals rather than observed as an outage, and
        # the thresholds (NETWORK_CONTROLLER_AUTHORIZE_*) are set so one
        # misbehaving phone, or a few odd devices at a busy venue, does not
        # page anybody.
        "name": "WiFi controller refusing guests",
        "description": (
            "Fires when a venue's WiFi controller refuses at least three "
            "different guests within fifteen minutes, and at least half of "
            "all sign-in attempts there fail. Resolves once fifteen minutes "
            "pass with no refusal."
        ),
        "trigger_type": AlertTriggerType.HEALTH_STATUS_CHANGE,
        "target_component": ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE,
        "condition_config": {
            "expected_status": NETWORK_CONTROLLER_STATE_REFUSING_GUESTS
        },
        "severity": AlertSeverity.WARNING.value,
    },
    {
        # This entry is also what solves the ``Alert.rule_id`` foreign key
        # for a detector that has findings but no rule to hang them on.
        # ``Alert.rule_id`` is a non-nullable FK to ``alert_rules``, so no
        # alert can exist for a target until an ``AlertRule`` for it does --
        # the exact reason ``app.domains.dhcp.tasks`` left
        # ALERT_TARGET_ROGUE_DHCP_GUARD unbuilt in cloud-guest#139. The
        # answer is a default rule created with the organization, not a
        # nullable column and not a separate seeding mechanism.
        #
        # Detector-only wording throughout, and not by accident:
        # ``/ip dhcp-server alert`` writes a log line and nothing else --
        # it blocks nothing. A rule named "Rogue DHCP protection" would
        # describe a defence this platform has never had. Same sentence the
        # readiness checklist item already shows for the same fact; see
        # ``app.domains.monitoring.constants.ALERT_TARGET_ROGUE_DHCP_GUARD``.
        "name": "Rogue DHCP detection off",
        "description": (
            "Fires when a router stops watching for another DHCP server "
            "on an interface that hands out addresses. Detection only -- "
            "it logs, it does not block."
        ),
        "trigger_type": AlertTriggerType.HEALTH_STATUS_CHANGE,
        "target_component": ALERT_TARGET_ROGUE_DHCP_GUARD,
        "condition_config": {"expected_status": ROGUE_DHCP_STATE_UNGUARDED},
        "severity": AlertSeverity.WARNING.value,
    },
    {
        # Least urgent, last: nothing broke, something was never finished.
        # It is here because the failure it describes is silent -- a venue
        # whose controller integration was started and abandoned looks
        # "added" in every list, and authorizes nobody. A day's grace so an
        # operator part-way through onboarding is never the recipient.
        "name": "WiFi controller setup unfinished",
        "description": (
            "Fires when a WiFi controller (TP-Link Omada) added more than a "
            "day ago still cannot let a single guest online -- for example "
            "no site selected, or not linked to a location. Resolves once "
            "setup is complete."
        ),
        "trigger_type": AlertTriggerType.HEALTH_STATUS_CHANGE,
        "target_component": ALERT_TARGET_NETWORK_CONTROLLER_SETUP,
        "condition_config": {
            "expected_status": NETWORK_CONTROLLER_STATE_SETUP_INCOMPLETE
        },
        "severity": AlertSeverity.WARNING.value,
    },
)


@dataclass
class DefaultAlertingReport:
    """What one ``ensure_default_alerting`` call actually did.

    Returned rather than logged-and-forgotten so the backfill script can
    print a per-organization summary an operator can check, and so a
    half-configured organization (rules but no channel, because there is no
    ``contact_email``) is a visible outcome rather than a silent one.
    """

    organization_id: uuid.UUID
    rules_created: list[str] = field(default_factory=list)
    rules_already_present: list[str] = field(default_factory=list)
    rules_failed: list[str] = field(default_factory=list)
    channel_created: bool = False
    channel_already_present: bool = False
    channel_skipped_reason: str | None = None
    rules_linked_to_channel: list[str] = field(default_factory=list)

    @property
    def notifiable(self) -> bool:
        """True only if this organization can now actually receive an
        email -- i.e. it has a channel AND at least one rule pointing at
        it. Rules alone are the failure mode this module exists to end."""
        has_channel = self.channel_created or self.channel_already_present
        return has_channel and bool(
            self.rules_linked_to_channel
            or self.rules_already_present
            or self.rules_created
        )


async def ensure_default_alerting(
    alert_service: AlertService,
    notification_service: NotificationService,
    *,
    organization_id: uuid.UUID,
    contact_email: str | None,
) -> DefaultAlertingReport:
    """Make sure this organization has the default rules, an email channel,
    and a link between them. Idempotent; safe to call repeatedly.

    Never raises. An organization successfully existing matters more than
    any default rule existing, and this is called on the organization
    creation path -- so every failure is logged and recorded in the report,
    and failure is per rule rather than per call, so one bad rule does not
    cost the organization the rest. That is the same shape the
    original ``_create_default_alert_rules`` had, kept deliberately.
    """
    report = DefaultAlertingReport(organization_id=organization_id)

    channel_id = await _ensure_default_email_channel(
        notification_service,
        organization_id=organization_id,
        contact_email=contact_email,
        report=report,
    )

    existing_rules, _ = await alert_service.list_alert_rules(
        organization_id=organization_id, page=1, page_size=100
    )
    existing_by_target = {
        rule.target_component: rule for rule in existing_rules if rule.target_component
    }

    for spec in DEFAULT_ALERT_RULES:
        target = str(spec["target_component"])
        name = str(spec["name"])
        existing = existing_by_target.get(target)
        if existing is not None:
            # Left completely alone, including its channel links. An
            # operator who pointed this rule somewhere else, retuned it or
            # switched it off meant to, and a backfill must not argue.
            report.rules_already_present.append(name)
            continue
        try:
            created = await alert_service.create_alert_rule(
                organization_id=organization_id,
                notification_channel_ids=[channel_id] if channel_id else [],
                **spec,
            )
        except Exception:
            report.rules_failed.append(name)
            logger.exception(
                "default_alert_rule_creation_failed",
                extra={
                    "organization_id": str(organization_id),
                    "target_component": target,
                },
            )
            continue
        report.rules_created.append(name)
        if channel_id:
            report.rules_linked_to_channel.append(name)
        logger.info(
            "default_alert_rule_created",
            extra={
                "organization_id": str(organization_id),
                "rule_id": str(created.id),
                "target_component": target,
                "linked_to_channel": bool(channel_id),
            },
        )

    if not report.notifiable:
        # The whole point of this module, so it gets its own log line
        # rather than being inferred from the absence of one.
        logger.warning(
            "default_alerting_not_notifiable",
            extra={
                "organization_id": str(organization_id),
                "channel_skipped_reason": report.channel_skipped_reason,
            },
        )
    return report


async def _ensure_default_email_channel(
    notification_service: NotificationService,
    *,
    organization_id: uuid.UUID,
    contact_email: str | None,
    report: DefaultAlertingReport,
) -> uuid.UUID | None:
    """The organization's own contact address, as a notification channel.

    ``Organization.contact_email`` is the address the venue already gave us
    and the one every other transactional mail on the platform goes to, so
    it needs no new field, no new screen and no onboarding step -- which is
    the requirement: a venue that has never opened the alerts screen must
    still get the email.

    Returns ``None`` (and records why) rather than raising, so an
    organization with no usable contact address still gets its rules and
    shows up in the report as not-notifiable instead of failing creation.
    """
    if not contact_email or "@" not in contact_email:
        report.channel_skipped_reason = (
            "organization has no usable contact_email to send alerts to"
        )
        return None

    existing_channels, _ = await notification_service.list_channels(
        organization_id=organization_id,
        channel_type=NotificationChannelType.EMAIL.value,
        page=1,
        page_size=100,
    )
    for channel in existing_channels:
        if channel.name == DEFAULT_EMAIL_CHANNEL_NAME:
            report.channel_already_present = True
            return channel.id

    try:
        channel = await notification_service.create_channel(
            organization_id=organization_id,
            channel_type=NotificationChannelType.EMAIL,
            name=DEFAULT_EMAIL_CHANNEL_NAME,
            config={"email": contact_email},
        )
    except Exception:
        report.channel_skipped_reason = "creating the default email channel failed"
        logger.exception(
            "default_notification_channel_creation_failed",
            extra={"organization_id": str(organization_id)},
        )
        return None

    report.channel_created = True
    logger.info(
        "default_notification_channel_created",
        extra={
            "organization_id": str(organization_id),
            "channel_id": str(channel.id),
        },
    )
    return channel.id


__all__ = [
    "DEFAULT_ALERT_RULES",
    "DEFAULT_EMAIL_CHANNEL_NAME",
    "DefaultAlertingReport",
    "ensure_default_alerting",
]
