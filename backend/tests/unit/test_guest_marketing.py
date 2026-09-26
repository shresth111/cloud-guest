"""Guest Marketing: security properties, the send path, templates and seeds.

Contract: ``wyfy-specs/guest-marketing-campaigns.md``. What is covered here,
and why each is a *security* test rather than a happy path:

* cross-tenant: organization B cannot read organization A's campaigns,
  custom templates or audience -- every read goes through the tenant filter;
* location isolation: a location-scoped caller's null location is rewritten
  to their own (never "all"), a foreign location is 403 ``cross_location``,
  and an org-wide campaign is a 404 to them;
* a locked add-on refuses every mounted ``/marketing`` route with 402
  ``feature_not_entitled`` before any permission or data work -- parametrized
  over the live route table, so a new route is covered by construction;
* the Master add-on routes are pinned to GLOBAL, so an organization-scoped
  holder of ``billing.manage`` is refused;
* opted-out / suppressed guests are excluded, including a guest who opts out
  mid-campaign (per-recipient re-check);
* no fake success: an unconfigured or logging-mode channel is a 409, never a
  pretend send.

The service runs against an in-memory fake of ``MarketingRepository`` that
applies the same tenant/location filters as the SQL; the SQL itself was
exercised end to end against a real Postgres while building (see the PR).
"""

from __future__ import annotations

import importlib.util
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import Settings
from app.domains.marketing.constants import (
    CampaignStatus,
    Channel,
    ChannelMode,
    ConsentStatus,
    RecipientStatus,
)
from app.domains.marketing.exceptions import (
    ChannelNotConfiguredError,
    CrossLocationError,
    MarketingNotFoundError,
    TemplateNotFoundError,
    UnknownVariableError,
    UnsubscribeLinkMissingError,
)
from app.domains.marketing.repository import AudienceCandidate, AudienceCounts
from app.domains.marketing.schemas import (
    AudienceFilter,
    CampaignCreate,
    EmailContent,
    SmsContent,
    TemplateCreate,
)
from app.domains.marketing.senders import (
    ChannelStatus,
    MarketingSenders,
    ProviderResult,
    SendError,
    resolve_marketing_senders,
)
from app.domains.marketing.service import CallerScope, MarketingService
from app.domains.marketing.validators import (
    TemplateVariableError,
    clean_email_html,
    derive_address,
    extract_variables,
    mask_email_address,
    mask_phone,
    normalize_phone,
    render,
    sms_body_problems,
    sms_stats,
)

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
LOC_A1 = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
LOC_A2 = uuid.UUID("00000000-0000-0000-0000-0000000000a2")
LOC_B1 = uuid.UUID("00000000-0000-0000-0000-0000000000b1")
NOW = datetime(2026, 9, 25, 6, 0, tzinfo=UTC)  # 11:30 IST, outside quiet hours


# ============================================================================
# Fakes
# ============================================================================


def _row(**fields: Any) -> SimpleNamespace:
    base = {
        "id": uuid.uuid4(),
        "created_at": NOW,
        "updated_at": NOW,
        "is_deleted": False,
        "version": 1,
    }
    base.update(fields)
    return SimpleNamespace(**base)


@dataclass
class FakeRepo:
    """Mirrors ``MarketingRepository``'s filters: every read is keyed on
    organization, campaigns additionally on the caller's location."""

    organizations: dict[uuid.UUID, Any] = field(default_factory=dict)
    locations: dict[uuid.UUID, Any] = field(default_factory=dict)
    guests: dict[uuid.UUID, Any] = field(default_factory=dict)
    visits: set[tuple[uuid.UUID, uuid.UUID]] = field(default_factory=set)
    consents: dict[tuple[uuid.UUID, str], Any] = field(default_factory=dict)
    suppressions: set[tuple[uuid.UUID, str, str]] = field(default_factory=set)
    templates: dict[uuid.UUID, Any] = field(default_factory=dict)
    campaigns: dict[uuid.UUID, Any] = field(default_factory=dict)
    recipients: dict[uuid.UUID, Any] = field(default_factory=dict)
    commits: int = 0

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, instance: Any) -> None:
        return None

    providers: dict[Any, Any] = field(default_factory=dict)

    async def list_providers(self, organization_id):
        return {
            channel: row
            for (org, channel), row in self.providers.items()
            if org == organization_id and not row.is_deleted
        }

    async def get_provider_by_id(self, organization_id, provider_id):
        return next(
            (
                row
                for (org, _c), row in self.providers.items()
                if org == organization_id and row.id == provider_id
            ),
            None,
        )

    async def get_organization(self, organization_id):
        return self.organizations.get(organization_id)

    async def get_location(self, organization_id, location_id):
        loc = self.locations.get(location_id)
        return loc if loc and loc.organization_id == organization_id else None

    portal_configs: dict[Any, Any] = field(default_factory=dict)

    async def get_portal_config(self, organization_id, location_id):
        return self.portal_configs.get(
            (organization_id, location_id)
        ) or self.portal_configs.get((organization_id, None))

    async def update_portal_config(self, config, data):
        for key, value in data.items():
            setattr(config, key, value)
        return config

    async def get_user_names(self, ids):
        return {}

    async def template_names(self, ids):
        return {i: self.templates[i] for i in ids if i in self.templates}

    async def get_template(self, organization_id, template_id):
        t = self.templates.get(template_id)
        if t is None or t.is_deleted:
            return None
        if t.organization_id not in (None, organization_id):
            return None
        return t

    async def list_templates(self, *, organization_id, include_system, **_):
        rows = [
            t
            for t in self.templates.values()
            if t.organization_id == organization_id
            or (include_system and t.organization_id is None)
        ]
        return rows, SimpleNamespace(total_items=len(rows))

    async def template_name_taken(self, organization_id, name, *, exclude_id=None):
        return any(
            t.organization_id == organization_id
            and t.name.lower() == name.lower()
            and t.id != exclude_id
            for t in self.templates.values()
        )

    async def create_template(self, **fields):
        fields.setdefault("whatsapp_body", None)
        fields.setdefault("whatsapp_content_sid", None)
        fields.setdefault("whatsapp_variable_order", None)
        fields.setdefault("sms_body", None)
        fields.setdefault("sms_dlt_template_id", None)
        fields.setdefault("email_subject", None)
        fields.setdefault("email_preheader", None)
        fields.setdefault("email_body_html", None)
        t = _row(**fields)
        self.templates[t.id] = t
        return t

    async def template_in_use(self, template_id):
        return False

    async def create_campaign(self, **fields):
        c = _row(
            scheduled_at=None,
            started_at=None,
            completed_at=None,
            cancelled_at=None,
            cancel_reason=None,
            paused_until=None,
            recipient_count=0,
            count_pending=0,
            count_submitted=0,
            count_delivered=0,
            count_failed=0,
            count_skipped=0,
            exclusion_counts=None,
            last_error=None,
            template_snapshot=None,
            schedule_idempotency_key=None,
            schedule_idempotency_at=None,
            **fields,
        )
        self.campaigns[c.id] = c
        return c

    async def get_campaign(self, organization_id, campaign_id, *, scope_location_id):
        c = self.campaigns.get(campaign_id)
        if c is None or c.is_deleted or c.organization_id != organization_id:
            return None
        if scope_location_id is not None and c.location_id != scope_location_id:
            return None
        return c

    async def get_campaign_for_worker(self, campaign_id):
        return self.campaigns.get(campaign_id)

    async def list_campaigns(
        self, *, organization_id, scope_location_id, venue_location_id=None, **_
    ):
        self.last_venue_filter = venue_location_id
        rows = [
            c
            for c in self.campaigns.values()
            if c.organization_id == organization_id
            and (scope_location_id is None or c.location_id == scope_location_id)
            and (
                venue_location_id is None
                or c.location_id == venue_location_id
                or str(venue_location_id)
                in (c.audience_filter.get("location_ids") or [])
            )
        ]
        return rows, SimpleNamespace(total_items=len(rows))

    async def list_recipients(
        self, *, organization_id, scope_location_id, venue_location_id=None, **_
    ):
        self.last_venue_filter = venue_location_id
        rows = []
        for r in self.recipients.values():
            c = self.campaigns[r.campaign_id]
            if c.organization_id != organization_id:
                continue
            if scope_location_id is not None and c.location_id != scope_location_id:
                continue
            if venue_location_id is not None and r.location_id != venue_location_id:
                continue
            name = self.locations[r.location_id].name if r.location_id else None
            rows.append((r, c, None, name))
        return rows, SimpleNamespace(total_items=len(rows))

    async def attribute_locations(self, *, guest_ids, location_ids, **_):
        attributed = {}
        for guest_id in guest_ids:
            visited = [
                loc for (g, loc) in sorted(self.visits, key=str) if g == guest_id
            ]
            if location_ids is not None:
                visited = [loc for loc in visited if loc in location_ids]
            if visited:
                attributed[guest_id] = visited[0]
        return attributed

    async def update_campaign_cas(
        self, campaign, *, expected_status, data, expected_version=None
    ):
        statuses = (
            [expected_status] if isinstance(expected_status, str) else expected_status
        )
        if campaign.status not in statuses:
            return False
        for key, value in data.items():
            setattr(campaign, key, value)
        campaign.version += 1
        return True

    async def find_campaign_by_idempotency_key(self, organization_id, key):
        return next(
            (
                c
                for c in self.campaigns.values()
                if c.organization_id == organization_id
                and c.schedule_idempotency_key == key
            ),
            None,
        )

    async def get_guest(self, organization_id, guest_id):
        g = self.guests.get(guest_id)
        return g if g and g.organization_id == organization_id else None

    async def guest_visited_location(self, guest_id, location_id):
        return (guest_id, location_id) in self.visits

    async def get_consents(self, guest_id):
        return {
            channel: row
            for (gid, channel), row in self.consents.items()
            if gid == guest_id
        }

    async def upsert_consent(self, *, guest_id, channel, status, **_):
        existing = self.consents.get((guest_id, channel))
        if existing and existing.status == status:
            return False
        self.consents[(guest_id, channel)] = _row(status=status, source=_["source"])
        return True

    async def add_suppression(
        self, *, organization_id, channel, address_normalized, **_
    ):
        self.suppressions.add((organization_id, channel, address_normalized))

    async def suppressed_addresses(self, organization_id, channel, addresses):
        return {
            a for a in addresses if (organization_id, channel, a) in self.suppressions
        }

    async def is_suppressed(self, organization_id, channel, address):
        return (organization_id, channel, address) in self.suppressions

    async def consent_counts(self, organization_id, location_ids):
        return {}

    async def audience(self, criteria):
        matched = [
            g
            for g in self.guests.values()
            if g.organization_id == criteria.organization_id
            and (
                criteria.location_ids is None
                or any((g.id, loc) in self.visits for loc in criteria.location_ids)
            )
        ]
        no_consent = opted_out = 0
        opted_in = []
        for g in sorted(matched, key=lambda g: g.last_seen_at, reverse=True):
            consent = self.consents.get((g.id, criteria.channel))
            if consent is None:
                no_consent += 1
            elif consent.status == ConsentStatus.OPTED_OUT.value:
                opted_out += 1
            else:
                opted_in.append(
                    AudienceCandidate(
                        guest_id=g.id,
                        identifier=g.identifier,
                        email=g.email,
                        display_name=g.display_name,
                        is_blocked=g.is_blocked,
                        last_seen_at=g.last_seen_at,
                        total_visit_count=g.total_visit_count,
                    )
                )
        return AudienceCounts(len(matched), no_consent, opted_out, opted_in)

    async def insert_recipients(self, rows):
        inserted = 0
        for row in rows:
            if any(
                r.campaign_id == row["campaign_id"] and r.guest_id == row["guest_id"]
                for r in self.recipients.values()
            ):
                continue
            r = _row(
                status=RecipientStatus.PENDING.value,
                attempt_count=0,
                skip_reason=None,
                error_code=None,
                error_message=None,
                provider_message_id=None,
                next_attempt_at=None,
                submitted_at=None,
                delivered_at=None,
                failed_at=None,
                **row,
            )
            self.recipients[r.id] = r
            inserted += 1
        return inserted

    async def claim_batch(self, campaign_id, limit, now):
        claimed = []
        for r in self.recipients.values():
            if (
                r.campaign_id == campaign_id
                and r.status == RecipientStatus.PENDING.value
            ):
                r.status = RecipientStatus.SENDING.value
                r.attempt_count += 1
                claimed.append(r)
        return claimed[:limit]

    async def update_recipient(self, recipient_id, **values):
        for key, value in values.items():
            setattr(self.recipients[recipient_id], key, value)

    async def adjust_counters(self, campaign_id, **deltas):
        c = self.campaigns[campaign_id]
        for name, delta in deltas.items():
            setattr(c, f"count_{name}", getattr(c, f"count_{name}") + delta)

    async def count_pending(self, campaign_id):
        return sum(
            1
            for r in self.recipients.values()
            if r.campaign_id == campaign_id
            and r.status == RecipientStatus.PENDING.value
        )

    async def skip_pending_recipients(self, campaign_id, reason):
        return 0


class FakeEmailSender:
    provider = "ses"

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, email, *, subject, html_body, from_name, headers):
        self.sent.append(email)
        return ProviderResult(provider="ses", message_id=f"m-{len(self.sent)}")


def _senders(email=None, *, email_live: bool = True) -> MarketingSenders:
    def status(channel: Channel, live: bool) -> ChannelStatus:
        return ChannelStatus(
            channel,
            live,
            "ses" if live else None,
            ChannelMode.LIVE if live else ChannelMode.LOGGING,
            None if live else "logging mode",
        )

    return MarketingSenders(
        sms=None,
        whatsapp=None,
        email=email if email_live else None,
        statuses={
            Channel.SMS: status(Channel.SMS, False),
            Channel.WHATSAPP: status(Channel.WHATSAPP, False),
            Channel.EMAIL: status(Channel.EMAIL, email_live),
        },
    )


def _settings(**overrides: Any) -> Settings:
    return Settings(**overrides)


@dataclass
class World:
    repo: FakeRepo
    email: FakeEmailSender
    guest_ids: dict[str, uuid.UUID]
    template_a: Any
    system_template: Any

    def service(self, *, email_live: bool = True, confinement=None) -> MarketingService:
        return MarketingService(
            self.repo,
            settings=_settings(),
            senders=_senders(self.email, email_live=email_live),
            now=lambda: NOW,
            caller_location_scope=confinement,
        )


def _world() -> World:
    repo = FakeRepo()
    for org_id, name in ((ORG_A, "Cafe A"), (ORG_B, "Cafe B")):
        repo.organizations[org_id] = _row(
            id=org_id, name=name, timezone="Asia/Kolkata", contact_email="o@x.in"
        )
    for loc_id, org_id in ((LOC_A1, ORG_A), (LOC_A2, ORG_A), (LOC_B1, ORG_B)):
        repo.locations[loc_id] = _row(
            id=loc_id,
            organization_id=org_id,
            name=str(loc_id)[-2:],
            address_line1="1 Rd",
            address_line2=None,
            city="Blr",
            state_province="KA",
        )
    guest_ids = {}
    specs = [
        ("a1_in", ORG_A, LOC_A1, "opted_in"),
        ("a1_out", ORG_A, LOC_A1, "opted_out"),
        ("a2_in", ORG_A, LOC_A2, "opted_in"),
        ("a2_none", ORG_A, LOC_A2, None),
        ("b1_in", ORG_B, LOC_B1, "opted_in"),
    ]
    for index, (key, org_id, loc_id, consent) in enumerate(specs):
        guest = _row(
            organization_id=org_id,
            identifier=f"{key}@guest.in",
            email=None,
            display_name=key,
            is_blocked=False,
            last_seen_at=NOW - timedelta(days=index),
            total_visit_count=index + 1,
        )
        repo.guests[guest.id] = guest
        repo.visits.add((guest.id, loc_id))
        guest_ids[key] = guest.id
        if consent:
            repo.consents[(guest.id, "email")] = _row(
                status=consent, source="captive_portal"
            )
    system = _row(
        organization_id=None,
        system_key="weekend_offer",
        name="Weekend offer",
        category="offer",
        description=None,
        sms_body="Hi {{guest_name}} {{unsubscribe_link}}",
        sms_dlt_template_id=None,
        whatsapp_body=None,
        whatsapp_content_sid=None,
        whatsapp_variable_order=None,
        whatsapp_approval_status="not_submitted",
        email_subject="Hi {{guest_name}}",
        email_preheader=None,
        email_body_html='<p>Hi {{guest_name}} <a href="{{unsubscribe_link}}">u</a></p>',
    )
    repo.templates[system.id] = system
    template_a = _row(
        organization_id=ORG_A,
        system_key=None,
        name="A only",
        category="offer",
        description=None,
        sms_body=None,
        sms_dlt_template_id=None,
        whatsapp_body=None,
        whatsapp_content_sid=None,
        whatsapp_variable_order=None,
        whatsapp_approval_status="not_submitted",
        email_subject="Offer",
        email_preheader=None,
        email_body_html='<p>{{guest_name}} <a href="{{unsubscribe_link}}">u</a></p>',
    )
    repo.templates[template_a.id] = template_a
    return World(repo, FakeEmailSender(), guest_ids, template_a, system)


def _scope(org=ORG_A, loc=None) -> CallerScope:
    return CallerScope(organization_id=org, location_id=loc, actor_user_id=uuid.uuid4())


async def _campaign(world: World, scope: CallerScope, *, location_id=None, locs=None):
    service = world.service()
    return await service.create_campaign(
        scope,
        CampaignCreate(
            name="Weekend",
            channel=Channel.EMAIL,
            template_id=world.template_a.id,
            location_id=location_id,
            audience_filter=AudienceFilter(channel=Channel.EMAIL, location_ids=locs),
        ),
    )


# ============================================================================
# Cross-tenant
# ============================================================================


class TestCrossTenant:
    async def test_org_b_cannot_read_org_a_campaign(self) -> None:
        world = _world()
        created = await _campaign(world, _scope(ORG_A))
        service = world.service()
        with pytest.raises(MarketingNotFoundError):
            await service.get_campaign(_scope(ORG_B), uuid.UUID(created["id"]))
        items, _ = await service.list_campaigns(
            _scope(ORG_B),
            statuses=None,
            channel=None,
            search=None,
            page=1,
            page_size=25,
        )
        assert items == []

    async def test_org_b_cannot_read_or_use_org_a_custom_template(self) -> None:
        world = _world()
        service = world.service()
        with pytest.raises(TemplateNotFoundError):
            await service.get_template(_scope(ORG_B), world.template_a.id)
        with pytest.raises(TemplateNotFoundError):
            await service.create_campaign(
                _scope(ORG_B),
                CampaignCreate(
                    name="steal",
                    channel=Channel.EMAIL,
                    template_id=world.template_a.id,
                    audience_filter=AudienceFilter(channel=Channel.EMAIL),
                ),
            )
        listed, _ = await service.list_templates(
            _scope(ORG_B),
            channel=None,
            category=None,
            include_system=True,
            page=1,
            page_size=50,
        )
        assert {t["id"] for t in listed} == {str(world.system_template.id)}

    async def test_org_b_audience_never_contains_org_a_guests(self) -> None:
        world = _world()
        preview = await world.service().audience_preview(
            _scope(ORG_B), AudienceFilter(channel=Channel.EMAIL)
        )
        assert preview["matched_guests"] == 1
        assert [s["guest_id"] for s in preview["sample"]] == [
            str(world.guest_ids["b1_in"])
        ]

    async def test_org_b_cannot_name_org_a_location(self) -> None:
        world = _world()
        with pytest.raises(Exception) as excinfo:
            await world.service().audience_preview(
                _scope(ORG_B),
                AudienceFilter(channel=Channel.EMAIL, location_ids=[LOC_A1]),
            )
        assert excinfo.value.data["error_code"] == "location_not_found"

    async def test_staff_opt_out_of_foreign_guest_is_404(self) -> None:
        world = _world()
        with pytest.raises(MarketingNotFoundError):
            await world.service().staff_opt_out(
                _scope(ORG_B), world.guest_ids["a1_in"], [Channel.EMAIL], None
            )
        consent = world.repo.consents[(world.guest_ids["a1_in"], "email")]
        assert consent.status == "opted_in"

    def test_no_request_schema_accepts_organization_id(self) -> None:
        from app.domains.marketing import schemas

        for name in dir(schemas):
            model = getattr(schemas, name)
            fields = getattr(model, "model_fields", None)
            if isinstance(fields, dict) and model.__module__ == schemas.__name__:
                assert "organization_id" not in fields, name
                assert model.model_config.get("extra") == "forbid", name


# ============================================================================
# Location isolation
# ============================================================================


class TestLocationScope:
    async def test_null_location_is_rewritten_to_callers_own_never_all(self) -> None:
        world = _world()
        service = world.service()
        assert await service.resolve_location_ids(_scope(ORG_A, LOC_A1), None) == [
            LOC_A1
        ]
        preview = await service.audience_preview(
            _scope(ORG_A, LOC_A1), AudienceFilter(channel=Channel.EMAIL)
        )
        assert preview["matched_guests"] == 2  # a1_in + a1_out, not LOC_A2's guests
        assert [s["guest_id"] for s in preview["sample"]] == [
            str(world.guest_ids["a1_in"])
        ]

    async def test_foreign_location_is_cross_location(self) -> None:
        world = _world()
        with pytest.raises(CrossLocationError):
            await world.service().resolve_location_ids(_scope(ORG_A, LOC_A1), [LOC_A2])
        with pytest.raises(CrossLocationError):
            await _campaign(world, _scope(ORG_A, LOC_A1), location_id=LOC_A2)

    async def test_location_scoped_caller_cannot_see_org_wide_or_other_location(
        self,
    ) -> None:
        world = _world()
        org_wide = await _campaign(world, _scope(ORG_A))
        other = await _campaign(world, _scope(ORG_A), location_id=LOC_A2, locs=[LOC_A2])
        own = await _campaign(world, _scope(ORG_A, LOC_A1))
        service = world.service()
        for campaign in (org_wide, other):
            with pytest.raises(MarketingNotFoundError):
                await service.get_campaign(
                    _scope(ORG_A, LOC_A1), uuid.UUID(campaign["id"])
                )
        listed, _ = await service.list_campaigns(
            _scope(ORG_A, LOC_A1),
            statuses=None,
            channel=None,
            search=None,
            page=1,
            page_size=25,
        )
        assert [c["id"] for c in listed] == [own["id"]]
        # A location-scoped caller's campaign is pinned to their location, and
        # its stored audience names only that location.
        assert own["location_id"] == str(LOC_A1)
        assert own["audience_filter"]["location_ids"] == [str(LOC_A1)]

    async def test_location_scoped_staff_cannot_opt_out_guest_of_other_location(
        self,
    ) -> None:
        world = _world()
        with pytest.raises(MarketingNotFoundError):
            await world.service().staff_opt_out(
                _scope(ORG_A, LOC_A1), world.guest_ids["a2_in"], [Channel.EMAIL], None
            )

    async def test_grant_confinement_is_enforced_even_if_scope_says_otherwise(
        self,
    ) -> None:
        world = _world()
        service = world.service(confinement=frozenset({LOC_A1}))
        with pytest.raises(CrossLocationError):
            await service.list_campaigns(
                _scope(ORG_A, None),
                statuses=None,
                channel=None,
                search=None,
                page=1,
                page_size=25,
            )

    async def test_caller_scope_dependency_pins_confined_callers(self) -> None:
        from app.domains.marketing.dependencies import get_caller_scope

        user = SimpleNamespace(id=str(uuid.uuid4()))
        pinned = await get_caller_scope(ORG_A, None, frozenset({LOC_A1}), user)
        assert pinned.location_id == LOC_A1
        with pytest.raises(CrossLocationError):
            await get_caller_scope(ORG_A, LOC_A2, frozenset({LOC_A1}), user)
        with pytest.raises(CrossLocationError):
            await get_caller_scope(ORG_A, None, frozenset({LOC_A1, LOC_A2}), user)
        org_admin = await get_caller_scope(ORG_A, None, None, user)
        assert org_admin.location_id is None


# ============================================================================
# Portal consent wording integrity (DPDP consent record)
# ============================================================================


def _portal(location_id=None, *, text=None, version=None, enabled=False):
    return _row(
        organization_id=ORG_A,
        location_id=location_id,
        marketing_consent_enabled=enabled,
        marketing_consent_text=text,
        marketing_consent_text_version=version,
        review_url=None,
    )


class TestPortalConsent:
    async def test_toggle_without_text_keeps_wording_and_version(self) -> None:
        from app.domains.marketing.schemas import PortalConsentUpdate

        world = _world()
        config = _portal(LOC_A1, text="Custom wording", version="v3", enabled=True)
        world.repo.portal_configs[(ORG_A, LOC_A1)] = config
        result = await world.service().update_portal_consent(
            _scope(), PortalConsentUpdate(location_id=LOC_A1, enabled=False)
        )
        assert config.marketing_consent_text == "Custom wording"
        assert config.marketing_consent_text_version == "v3"
        assert result["enabled"] is False and result["text_version"] == "v3"

    async def test_text_change_bumps_version_and_null_resets_to_default(self) -> None:
        from app.domains.marketing.schemas import PortalConsentUpdate

        world = _world()
        config = _portal(LOC_A1)
        world.repo.portal_configs[(ORG_A, LOC_A1)] = config
        service = world.service()
        first = await service.update_portal_consent(
            _scope(), PortalConsentUpdate(location_id=LOC_A1, enabled=True)
        )
        assert first["text_version"] == "v1"  # default wording
        custom = await service.update_portal_consent(
            _scope(),
            PortalConsentUpdate(location_id=LOC_A1, enabled=True, text="Deals from us"),
        )
        assert custom["text_version"] == "v2" and custom["text"] == "Deals from us"
        reset = await service.update_portal_consent(
            _scope(), PortalConsentUpdate(location_id=LOC_A1, enabled=True, text=None)
        )
        assert reset["text_version"] == "v3"
        assert config.marketing_consent_text is None

    async def test_location_scoped_caller_cannot_change_the_shared_org_portal(
        self,
    ) -> None:
        from app.domains.marketing.exceptions import PortalConfigMissingError
        from app.domains.marketing.schemas import PortalConsentUpdate

        world = _world()
        shared = _portal(None)
        world.repo.portal_configs[(ORG_A, None)] = shared
        with pytest.raises(PortalConfigMissingError):
            await world.service().update_portal_consent(
                _scope(ORG_A, LOC_A1),
                PortalConsentUpdate(location_id=LOC_A1, enabled=True),
            )
        assert shared.marketing_consent_enabled is False

    async def test_status_exposes_the_sms_unsubscribe_link_budget(self) -> None:
        world = _world()
        service = world.service()
        status = await service.status(_scope())
        link = service._unsubscribe_link("x" * 22)
        assert status["sms_unsubscribe_link_budget"] == max(30, len(link))


# ============================================================================
# Org-wide campaigns across venues (founder decision: a primary use case)
# ============================================================================


class TestOrgWideCampaigns:
    async def test_org_scoped_caller_creates_org_wide_campaign(self) -> None:
        world = _world()
        created = await _campaign(world, _scope(ORG_A))
        assert created["location_id"] is None
        assert created["audience_filter"]["location_ids"] is None  # all org locations

    async def test_org_scoped_caller_targets_a_subset_of_locations(self) -> None:
        world = _world()
        created = await _campaign(world, _scope(ORG_A), locs=[LOC_A1, LOC_A2])
        assert created["location_id"] is None
        assert created["audience_filter"]["location_ids"] == [str(LOC_A1), str(LOC_A2)]
        with pytest.raises(Exception) as excinfo:
            await _campaign(world, _scope(ORG_A), locs=[LOC_A1, LOC_B1])
        assert excinfo.value.data["error_code"] == "location_not_found"

    async def test_multi_venue_guest_is_counted_and_messaged_once(self) -> None:
        world = _world()
        # a1_in also visited the second venue.
        world.repo.visits.add((world.guest_ids["a1_in"], LOC_A2))
        service = world.service()
        preview = await service.audience_preview(
            _scope(ORG_A),
            AudienceFilter(channel=Channel.EMAIL, location_ids=[LOC_A1, LOC_A2]),
        )
        assert preview["matched_guests"] == 4
        assert preview["reachable"] == 2
        created = await _campaign(world, _scope(ORG_A), locs=[LOC_A1, LOC_A2])
        result = await service.schedule(
            _scope(ORG_A),
            uuid.UUID(created["id"]),
            scheduled_at=None,
            idempotency_key="idem-multi-venue",
        )
        await service.send_batch(uuid.UUID(result["id"]))
        assert sorted(world.email.sent) == ["a1_in@guest.in", "a2_in@guest.in"]

    async def test_venue_filter_on_campaigns(self) -> None:
        world = _world()
        owned = await _campaign(world, _scope(ORG_A), location_id=LOC_A1, locs=[LOC_A1])
        targeting = await _campaign(world, _scope(ORG_A), locs=[LOC_A1, LOC_A2])
        other = await _campaign(world, _scope(ORG_A), locs=[LOC_A2])
        all_venues = await _campaign(world, _scope(ORG_A))
        service = world.service()
        listed, meta = await service.list_campaigns(
            _scope(ORG_A),
            statuses=None,
            channel=None,
            search=None,
            page=1,
            page_size=25,
            location_id=LOC_A1,
        )
        ids = {c["id"] for c in listed}
        assert ids == {owned["id"], targeting["id"]}
        assert other["id"] not in ids and all_venues["id"] not in ids
        assert meta.total_items == 2
        unfiltered, meta = await service.list_campaigns(
            _scope(ORG_A),
            statuses=None,
            channel=None,
            search=None,
            page=1,
            page_size=25,
        )
        assert meta.total_items == 4

    async def test_venue_filter_is_locscoped(self) -> None:
        world = _world()
        service = world.service()
        for call in (
            lambda loc: service.list_campaigns(
                _scope(ORG_A, LOC_A1),
                statuses=None,
                channel=None,
                search=None,
                page=1,
                page_size=25,
                location_id=loc,
            ),
            lambda loc: service.list_deliveries(
                _scope(ORG_A, LOC_A1),
                channel=None,
                statuses=None,
                campaign_id=None,
                date_from=None,
                date_to=None,
                page=1,
                page_size=25,
                location_id=loc,
            ),
        ):
            with pytest.raises(CrossLocationError):
                await call(LOC_A2)
            # Omitted means the caller's own venue -- never "unfiltered".
            await call(None)
            assert world.repo.last_venue_filter == LOC_A1
        # An org-scoped caller naming another tenant's venue is refused.
        with pytest.raises(Exception) as excinfo:
            await service.list_deliveries(
                _scope(ORG_A),
                channel=None,
                statuses=None,
                campaign_id=None,
                date_from=None,
                date_to=None,
                page=1,
                page_size=25,
                location_id=LOC_B1,
            )
        assert excinfo.value.data["error_code"] == "location_not_found"

    async def test_deliveries_are_attributed_to_a_venue_and_filterable(self) -> None:
        world = _world()
        world.repo.visits.add((world.guest_ids["a1_in"], LOC_A2))
        service = world.service()
        created = await _campaign(world, _scope(ORG_A), locs=[LOC_A1, LOC_A2])
        await service.schedule(
            _scope(ORG_A),
            uuid.UUID(created["id"]),
            scheduled_at=None,
            idempotency_key="idem-attribution",
        )
        items, meta = await service.list_deliveries(
            _scope(ORG_A),
            channel=None,
            statuses=None,
            campaign_id=None,
            date_from=None,
            date_to=None,
            page=1,
            page_size=25,
        )
        assert meta.total_items == 2
        assert all(item["location_id"] and item["location_name"] for item in items)
        only_a2, meta = await service.list_deliveries(
            _scope(ORG_A),
            channel=None,
            statuses=None,
            campaign_id=None,
            date_from=None,
            date_to=None,
            page=1,
            page_size=25,
            location_id=LOC_A2,
        )
        assert meta.total_items == len(only_a2)
        assert {item["location_id"] for item in only_a2} == {str(LOC_A2)}

    async def test_repository_count_uses_the_same_venue_filter_as_the_page(
        self,
    ) -> None:
        """Pagination totals must match the filter: the COUNT and the page
        query are built from one statement. Checked on the real repository
        SQL, not on the fake."""
        from sqlalchemy.dialects import postgresql

        from app.domains.marketing.repository import MarketingRepository

        captured: list[Any] = []

        class Result:
            def scalar_one(self):
                return 0

            def all(self):
                return []

            def scalars(self):
                return iter(())

        class Session:
            async def execute(self, statement):
                captured.append(statement)
                return Result()

        repo = MarketingRepository(Session())  # type: ignore[arg-type]
        await repo.list_recipients(
            organization_id=ORG_A,
            campaign_id=None,
            scope_location_id=None,
            statuses=None,
            channel=None,
            created_from=None,
            created_before=None,
            page=1,
            page_size=25,
            venue_location_id=LOC_A2,
        )
        await repo.list_campaigns(
            organization_id=ORG_A,
            scope_location_id=None,
            statuses=None,
            channel=None,
            search=None,
            page=1,
            page_size=25,
            venue_location_id=LOC_A2,
        )
        compiled = [
            str(stmt.compile(dialect=postgresql.dialect())) for stmt in captured
        ]
        count_recipients, page_recipients, count_campaigns, page_campaigns = compiled
        for sql in (count_recipients, page_recipients):
            assert "marketing_campaign_recipients.location_id = " in sql
        for sql in (count_campaigns, page_campaigns):
            assert "marketing_campaigns.location_id = " in sql
            assert "@>" in sql  # audience_filter -> 'location_ids' @> [venue]

    def test_audience_sql_filters_venues_with_exists_never_a_join(self) -> None:
        """A JOIN on guest_sessions would return one row per session (a guest
        who visited three venues would be counted, and messaged, three
        times). The venue/date filter must be a correlated EXISTS."""
        from sqlalchemy.dialects import postgresql

        from app.domains.marketing.repository import (
            AudienceCriteria,
            MarketingRepository,
        )

        statement = MarketingRepository(None)._audience_statement(  # type: ignore[arg-type]
            AudienceCriteria(
                organization_id=ORG_A,
                channel="sms",
                location_ids=[LOC_A1, LOC_A2],
                visited_from=NOW - timedelta(days=30),
                visited_before=NOW,
                min_visits=2,
                max_visits=None,
                last_seen_before=None,
                require_name=False,
            )
        )
        sql = str(statement.compile(dialect=postgresql.dialect())).upper()
        assert "EXISTS (SELECT GUEST_SESSIONS.ID" in sql
        assert "JOIN GUEST_SESSIONS" not in sql
        assert (
            "GUESTS.ORGANIZATION_ID" in sql and "GUEST_SESSIONS.ORGANIZATION_ID" in sql
        )


# ============================================================================
# Sending: consent, suppression, no fake success
# ============================================================================


class TestSending:
    async def _send_now(self, world: World, service: MarketingService) -> dict:
        created = await _campaign(world, _scope(ORG_A))
        return await service.schedule(
            _scope(ORG_A),
            uuid.UUID(created["id"]),
            scheduled_at=None,
            idempotency_key="idem-" + uuid.uuid4().hex,
        )

    async def test_opted_out_and_unconsented_guests_are_never_recipients(self) -> None:
        world = _world()
        service = world.service()
        result = await self._send_now(world, service)
        assert result["status"] == CampaignStatus.SENDING.value
        await service.send_batch(uuid.UUID(result["id"]))
        sent = set(world.email.sent)
        assert sent == {"a1_in@guest.in", "a2_in@guest.in"}
        assert "a1_out@guest.in" not in sent and "a2_none@guest.in" not in sent
        campaign = world.repo.campaigns[uuid.UUID(result["id"])]
        assert campaign.status == CampaignStatus.SENT.value
        assert campaign.exclusion_counts["opted_out"] == 1
        assert campaign.exclusion_counts["no_consent"] == 1

    async def test_suppressed_address_is_excluded(self) -> None:
        world = _world()
        world.repo.suppressions.add((ORG_A, "email", "a2_in@guest.in"))
        service = world.service()
        result = await self._send_now(world, service)
        await service.send_batch(uuid.UUID(result["id"]))
        assert world.email.sent == ["a1_in@guest.in"]

    async def test_guest_who_opts_out_mid_campaign_is_skipped(self) -> None:
        world = _world()
        service = world.service()
        result = await self._send_now(world, service)
        # Opt-out lands after materialization, before the batch runs.
        world.repo.consents[(world.guest_ids["a2_in"], "email")] = _row(
            status="opted_out", source="unsubscribe_link"
        )
        await service.send_batch(uuid.UUID(result["id"]))
        assert world.email.sent == ["a1_in@guest.in"]
        skipped = [
            r
            for r in world.repo.recipients.values()
            if r.status == RecipientStatus.SKIPPED.value
        ]
        assert [r.skip_reason for r in skipped] == ["opted_out"]

    async def test_unconfigured_channel_is_409_never_a_pretend_send(self) -> None:
        world = _world()
        service = world.service(email_live=False)
        created = await _campaign(world, _scope(ORG_A))
        with pytest.raises(ChannelNotConfiguredError) as excinfo:
            await service.schedule(
                _scope(ORG_A),
                uuid.UUID(created["id"]),
                scheduled_at=None,
                idempotency_key="idem-xyz12345",
            )
        assert excinfo.value.data["channel_status"]["configured"] is False
        with pytest.raises(ChannelNotConfiguredError):
            await service.test_send(
                _scope(ORG_A), uuid.UUID(created["id"]), ["x@y.in"], None
            )
        assert world.email.sent == []
        assert world.repo.recipients == {}

    async def test_provider_failure_is_recorded_failed_not_submitted(self) -> None:
        world = _world()

        class Failing(FakeEmailSender):
            async def send(self, email, **_):
                raise SendError("provider_rejected", "nope", permanent=True)

        world.email = Failing()
        service = world.service()
        result = await self._send_now(world, service)
        await service.send_batch(uuid.UUID(result["id"]))
        statuses = {r.status for r in world.repo.recipients.values()}
        assert statuses == {RecipientStatus.FAILED.value}
        assert all(
            r.provider_message_id is None
            for r in world.repo.recipients.values()
            if hasattr(r, "provider_message_id")
        )
        assert (
            world.repo.campaigns[uuid.UUID(result["id"])].status
            == CampaignStatus.FAILED.value
        )

    async def test_schedule_is_idempotent_on_key(self) -> None:
        world = _world()
        service = world.service()
        created = await _campaign(world, _scope(ORG_A))
        kwargs = dict(
            scheduled_at=NOW + timedelta(hours=2), idempotency_key="same-key-123"
        )
        first = await service.schedule(
            _scope(ORG_A), uuid.UUID(created["id"]), **kwargs
        )
        second = await service.schedule(
            _scope(ORG_A), uuid.UUID(created["id"]), **kwargs
        )
        assert first["status"] == second["status"] == CampaignStatus.SCHEDULED.value

    async def test_materialization_never_duplicates_a_guest(self) -> None:
        world = _world()
        service = world.service()
        result = await self._send_now(world, service)
        campaign = world.repo.campaigns[uuid.UUID(result["id"])]
        assert await service.materialize(campaign) == 0
        assert len(world.repo.recipients) == 2


# ============================================================================
# Locked add-on -> 402 on every marketing route
# ============================================================================


_APP = None


def _app():
    """One app for the whole module: building it is the slow part."""
    global _APP
    if _APP is None:
        from app.main import create_app

        _APP = create_app()
    _APP.dependency_overrides.clear()
    return _APP


def _marketing_routes():
    app = _app()
    routes = []
    for route in app.routes:
        path = getattr(route, "path", "")
        # /marketing/credits is billing's (spec §13); its own guards are
        # asserted in tests/unit/test_marketing_credits.py.
        if path.startswith("/api/v1/marketing") and not path.startswith(
            "/api/v1/marketing/credits"
        ):
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                routes.append((method, path))
    return routes


MARKETING_ROUTES = _marketing_routes()


def test_route_table_is_the_contract() -> None:
    assert len(MARKETING_ROUTES) == 29, MARKETING_ROUTES  # 23 + 6 BYO provider routes


@pytest.mark.parametrize(("method", "path"), MARKETING_ROUTES)
def test_locked_addon_refuses_every_marketing_route(method: str, path: str) -> None:
    from fastapi.testclient import TestClient

    from app.domains.auth.models import AuthUser
    from app.domains.billing.dependencies import get_entitlement_checker
    from app.domains.billing.service import EntitlementSnapshot
    from app.domains.rbac.dependencies import CurrentOrganizationScope, CurrentUser
    from app.domains.rbac.organization_scope import OrganizationScope

    class LockedChecker:
        async def get_snapshot(self, organization_id):
            return EntitlementSnapshot(
                organization_id=organization_id,
                plan_id=uuid.uuid4(),
                license_status="active",
                expires_at=None,
                enabled_features=frozenset({"campaigns"}),
                limits={},
                tiers={},
            )

    app = _app()
    app.dependency_overrides[get_entitlement_checker] = lambda: LockedChecker()
    app.dependency_overrides[CurrentOrganizationScope] = lambda: (
        OrganizationScope.for_organization(ORG_A)
    )
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(uuid.uuid4()), email="owner@a.in"
    )
    concrete = (
        path.replace("{template_id}", str(uuid.uuid4()))
        .replace("{campaign_id}", str(uuid.uuid4()))
        .replace("{guest_id}", str(uuid.uuid4()))
    )
    client = TestClient(app, raise_server_exceptions=False)
    response = client.request(
        method, concrete, json={}, headers={"X-Organization-Id": str(ORG_A)}
    )
    assert response.status_code == 402, (
        method,
        path,
        response.status_code,
        response.text,
    )
    assert response.json()["data"]["error_code"] == "feature_not_entitled"


@pytest.mark.parametrize(("method", "path"), MARKETING_ROUTES)
def test_every_marketing_route_declares_the_guards_with_pinned_scope(
    method: str, path: str
) -> None:
    """Structural half: RequireOrganization, RequireFeature(guest_marketing)
    and a RequirePermission pinned to LOCATION, in that order."""
    from app.domains.rbac.dependencies import RequireOrganization

    app = _app()
    route = next(
        r for r in app.routes if getattr(r, "path", "") == path and method in r.methods
    )
    calls = [d.call for d in route.dependant.dependencies]
    names = [getattr(c, "__qualname__", "") for c in calls]
    org_index = calls.index(RequireOrganization)
    feature_index = next(
        i for i, n in enumerate(names) if n.startswith("RequireFeature")
    )
    permission_index = next(
        i for i, n in enumerate(names) if n.startswith("RequirePermission")
    )
    assert org_index < feature_index < permission_index
    features = {
        str(cell.cell_contents)
        for i, n in enumerate(names)
        if n.startswith("RequireFeature")
        for cell in (calls[i].__closure__ or ())
    }
    assert "guest_marketing" in features
    permission_closure = {
        str(cell.cell_contents) for cell in (calls[permission_index].__closure__ or ())
    }
    if path.startswith("/api/v1/marketing/providers"):
        # BYO provider routes (spec §12.4): both add-ons, and a permission
        # pinned at ORGANIZATION -- never satisfiable by a location grant.
        assert "guest_marketing_byo" in features
        assert any(v.startswith("marketing_providers.") for v in permission_closure)
        assert "organization" in permission_closure
    else:
        assert any(v.startswith("marketing.") for v in permission_closure)
        assert "location" in permission_closure  # scope=ScopeType.LOCATION pinned


# ============================================================================
# Master add-on routes: pinned GLOBAL
# ============================================================================


ADDON_ROUTES = [
    ("GET", "/api/v1/platform/organizations/{organization_id}/addons", "billing.read"),
    (
        "PUT",
        "/api/v1/platform/organizations/{organization_id}/addons/{addon_key}",
        "billing.manage",
    ),
    (
        "DELETE",
        "/api/v1/platform/organizations/{organization_id}/addons/{addon_key}",
        "billing.manage",
    ),
]


@pytest.mark.parametrize(("method", "path", "permission"), ADDON_ROUTES)
def test_addon_routes_pin_global_scope(method: str, path: str, permission: str) -> None:
    app = _app()
    route = next(
        r for r in app.routes if getattr(r, "path", "") == path and method in r.methods
    )
    permission_dep = next(
        d.call
        for d in route.dependant.dependencies
        if getattr(d.call, "__qualname__", "").startswith("RequirePermission")
    )
    closure = {str(cell.cell_contents) for cell in permission_dep.__closure__}
    assert permission in closure
    assert "global" in closure


def test_org_scoped_billing_manage_cannot_satisfy_a_global_check() -> None:
    from app.domains.rbac.authorization import ScopeResolver
    from app.domains.rbac.context import GrantScope, ScopeContext
    from app.domains.rbac.enums import ScopeType

    requested = ScopeContext(organization_id=ORG_B)
    for grant in (
        GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=ORG_B),
        GrantScope(
            scope_type=ScopeType.LOCATION, organization_id=ORG_B, location_id=LOC_B1
        ),
    ):
        assert not ScopeResolver.satisfies(grant, ScopeType.GLOBAL, requested)
    assert ScopeResolver.satisfies(
        GrantScope(scope_type=ScopeType.GLOBAL), ScopeType.GLOBAL, requested
    )


def test_org_scoped_billing_manage_holder_gets_403_on_addon_put() -> None:
    """HTTP-level: an org-scoped user holding billing.manage is refused."""
    from fastapi.testclient import TestClient

    from app.domains.auth.models import AuthUser
    from app.domains.rbac.authorization import AccessValidator
    from app.domains.rbac.dependencies import CurrentUser, get_access_validator
    from app.domains.rbac.enums import ScopeType
    from app.domains.rbac.exceptions import PermissionDeniedError

    seen: list[ScopeType] = []

    class OrgScopedValidator(AccessValidator):
        def __init__(self) -> None:
            pass

        async def check(self, user_id, permission_key, *, scope_type, scope_context):
            seen.append(scope_type)
            # Holds billing.manage at ORGANIZATION scope only.
            if scope_type != ScopeType.ORGANIZATION:
                raise PermissionDeniedError(permission_key, str(scope_type))

    app = _app()
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(uuid.uuid4()), email="msp@x.in"
    )
    app.dependency_overrides[get_access_validator] = lambda: OrgScopedValidator()

    async def _no_db():
        yield None

    from app.database.session import get_db_session

    app.dependency_overrides[get_db_session] = _no_db
    client = TestClient(app, raise_server_exceptions=False)
    response = client.put(
        f"/api/v1/platform/organizations/{ORG_B}/addons/guest_marketing",
        json={"enabled": True},
        headers={"X-Organization-Id": str(ORG_B)},
    )
    assert response.status_code == 403, response.text
    assert response.json()["data"]["error_code"] == "permission_denied"
    assert seen == [ScopeType.GLOBAL]


# ============================================================================
# Add-on service: override merge, cancel on lock, cache after commit
# ============================================================================


class TestAddonService:
    def _service(self, *, plan_value: bool = False):
        from app.domains.feature_entitlement.addons import AddonService

        events: list[str] = []
        overrides: dict[tuple, Any] = {}

        class Orgs:
            async def get_organization(self, organization_id):
                if organization_id != ORG_A:
                    from app.domains.organization.exceptions import (
                        OrganizationNotFoundError,
                    )

                    raise OrganizationNotFoundError(organization_id)
                return object()

        class Plans:
            async def get_plan_feature_enabled(self, organization_id, key):
                return plan_value

        class Overrides:
            async def get_live(self, organization_id, key):
                return overrides.get((organization_id, key))

            async def create(self, **fields):
                row = _row(**fields)
                overrides[(fields["organization_id"], fields["feature_key"])] = row
                events.append("write")
                return row

            async def update(self, row, data):
                for k, v in data.items():
                    setattr(row, k, v)
                events.append("write")
                return row

            async def soft_delete(self, row):
                overrides.pop((row.organization_id, row.feature_key))
                events.append("clear")

        class Hook:
            async def count_active_campaigns(self, organization_id):
                return 2

            async def cancel_active_campaigns_for_lock(self, organization_id):
                events.append("cancel")
                return 2

        class Names:
            async def get_user_names(self, ids):
                return {}

        class Audit:
            async def create_audit_log_entry(self, **fields):
                events.append("audit:" + fields["action"])

        class Cache:
            async def invalidate(self, organization_id):
                events.append("invalidate")

        class Committer:
            async def commit(self):
                events.append("commit")

        service = AddonService(
            organizations=Orgs(),
            plan_features=Plans(),
            overrides=Overrides(),
            campaign_hooks={"guest_marketing": Hook()},
            user_names=Names(),
            audit_writer=Audit(),
            entitlement_cache=Cache(),
            committer=Committer(),
        )
        return service, events

    async def test_lock_cancels_campaigns_in_the_transaction_then_invalidates(
        self,
    ) -> None:
        service, events = self._service(plan_value=True)
        view, cancelled = await service.set_addon(
            ORG_A,
            "guest_marketing",
            enabled=False,
            reason="unpaid",
            actor_user_id=uuid.uuid4(),
        )
        assert cancelled == 2
        assert view.enabled is False and view.source == "override" and view.plan_value
        assert events == [
            "write",
            "cancel",
            "audit:organization_feature_override_set",
            "commit",
            "invalidate",
        ]

    async def test_unlock_does_not_cancel(self) -> None:
        service, events = self._service()
        view, cancelled = await service.set_addon(
            ORG_A,
            "guest_marketing",
            enabled=True,
            reason=None,
            actor_user_id=uuid.uuid4(),
        )
        assert cancelled == 0 and view.enabled
        assert "cancel" not in events

    async def test_unknown_addon_and_org_are_404(self) -> None:
        from app.domains.feature_entitlement.addons import (
            AddonNotFoundError,
            AddonOrganizationNotFoundError,
        )

        service, _ = self._service()
        with pytest.raises(AddonNotFoundError):
            await service.set_addon(
                ORG_A,
                "white_label",
                enabled=True,
                reason=None,
                actor_user_id=uuid.uuid4(),
            )
        with pytest.raises(AddonOrganizationNotFoundError):
            await service.list_addons(ORG_B)

    async def test_snapshot_merges_overrides(self) -> None:
        from app.domains.billing.service import LicenseService

        plan_id = uuid.uuid4()

        class Licenses:
            async def get_by_organization_id(self, organization_id):
                return SimpleNamespace(
                    plan_id=plan_id, status="active", expires_at=None
                )

        class Plans:
            async def list_plan_features(self, pid):
                return [
                    SimpleNamespace(
                        feature_key="campaigns",
                        feature_type="boolean",
                        is_enabled=True,
                        limit_value=None,
                        tier_value=None,
                    )
                ]

        class Overrides:
            def __init__(self, rows):
                self.rows = rows

            async def list_for_organization(self, organization_id):
                return self.rows

        unlocked = LicenseService(
            Licenses(),
            Plans(),
            feature_overrides=Overrides(
                [SimpleNamespace(feature_key="guest_marketing", is_enabled=True)]
            ),
        )
        snapshot = await unlocked.get_entitlement_snapshot(ORG_A)
        assert "guest_marketing" in snapshot.enabled_features
        locked = LicenseService(
            Licenses(),
            Plans(),
            feature_overrides=Overrides(
                [SimpleNamespace(feature_key="campaigns", is_enabled=False)]
            ),
        )
        assert (
            "campaigns"
            not in (await locked.get_entitlement_snapshot(ORG_A)).enabled_features
        )
        plain = LicenseService(Licenses(), Plans())
        assert (
            "guest_marketing"
            not in (await plain.get_entitlement_snapshot(ORG_A)).enabled_features
        )


# ============================================================================
# RBAC seed
# ============================================================================


class TestRbacSeed:
    def _grants(self, slug: str) -> set[str]:
        from app.domains.rbac.enums import PermissionModule
        from app.domains.rbac.seed import (
            MODULE_ACTIONS,
            SYSTEM_ROLES,
            expand_grant_level,
        )

        role = next(r for r in SYSTEM_ROLES if r.slug == slug)
        level = role.overrides.get(PermissionModule.MARKETING, role.default_level)
        return {
            action.value
            for action in expand_grant_level(
                level, MODULE_ACTIONS[PermissionModule.MARKETING]
            )
        }

    def test_module_seeded_with_every_action(self) -> None:
        from app.domains.rbac.enums import PermissionModule, ScopeType
        from app.domains.rbac.seed import MODULE_ACTIONS, MODULE_NARROWEST_SCOPE

        actions = {a.value for a in MODULE_ACTIONS[PermissionModule.MARKETING]}
        assert actions == {"create", "read", "update", "delete", "execute", "manage"}
        assert MODULE_NARROWEST_SCOPE[PermissionModule.MARKETING] == ScopeType.LOCATION

    @pytest.mark.parametrize(
        "slug", ["reception-staff", "helpdesk", "guest-operator", "office-admin"]
    )
    def test_front_desk_roles_cannot_send(self, slug: str) -> None:
        assert "execute" not in self._grants(slug)

    @pytest.mark.parametrize(
        "slug", ["organization-owner", "organization-admin", "location-manager"]
    )
    def test_managers_can_send(self, slug: str) -> None:
        assert "execute" in self._grants(slug)

    def test_every_route_permission_is_seeded(self) -> None:
        seeded = {f"marketing.{a}" for a in self._grants("organization-owner")}
        used = set()
        for route in _app().routes:
            if not getattr(route, "path", "").startswith("/api/v1/marketing"):
                continue
            for dep in route.dependant.dependencies:
                if getattr(dep.call, "__qualname__", "").startswith(
                    "RequirePermission"
                ):
                    used |= {
                        str(c.cell_contents)
                        for c in dep.call.__closure__
                        if str(c.cell_contents).startswith("marketing.")
                    }
        assert used and used <= seeded


# ============================================================================
# Templates: variables, rendering, SMS rules, seeds
# ============================================================================


class TestTemplateRules:
    def test_variables_extracted_in_order_and_unknown_rejected(self) -> None:
        assert extract_variables(
            "Hi {{guest_name}} at {{venue_name}} {{guest_name}}"
        ) == [
            "guest_name",
            "venue_name",
        ]
        with pytest.raises(TemplateVariableError) as excinfo:
            extract_variables("Hi {{first_name}}")
        assert excinfo.value.variables == ["first_name"]
        with pytest.raises(TemplateVariableError):
            extract_variables("Hi {{guest_name}")

    def test_render_substitutes_escapes_and_blanks_missing(self) -> None:
        assert (
            render("Hi {{guest_name}}, {{offer_code}}!", {"guest_name": "Riya"})
            == "Hi Riya, !"
        )
        assert (
            render(
                "<p>{{guest_name}}</p>", {"guest_name": "<b>x</b>"}, escape_html=True
            )
            == "<p>&lt;b&gt;x&lt;/b&gt;</p>"
        )

    def test_guest_name_falls_back_to_there(self) -> None:
        world = _world()
        values = world.service()._values({}, {}, guest_name="  ", token="t")
        assert values["guest_name"] == "there"

    def test_long_display_name_renders_within_worst_case_segments(self) -> None:
        """Rendering bound (contract change 2026-09-25): a 200-char
        display_name, and 200-char venue/location names, are truncated so
        the actual segments never exceed the §5.4 worst case."""
        from app.domains.marketing.validators import sms_worst_case_segments

        world = _world()
        service = world.service()
        body = (
            "Hi {{guest_name}}, {{venue_name}} ({{location_name}}) has "
            "{{offer_code}} till {{offer_expiry}}. Opt out: {{unsubscribe_link}}"
        )
        snapshot = {"venue_name": "V" * 200, "location_name": "L" * 200}
        token = "t" * 22
        values = service._values(
            snapshot,
            {"offer_code": "C" * 30, "offer_expiry": "E" * 30},
            guest_name="G" * 200,
            token=token,
        )
        assert len(values["guest_name"]) == 20
        assert len(values["venue_name"]) == 30 and len(values["location_name"]) == 30
        link_length = len(values["unsubscribe_link"])
        actual = sms_stats(render(body, values)).segments
        assert actual <= sms_worst_case_segments(
            body, unsubscribe_link_length=link_length
        )
        # Without the bound this body would have rendered longer.
        unbounded = render(body, {**values, "guest_name": "G" * 200})
        assert sms_stats(unbounded).segments > actual

    async def test_preview_applies_the_rendering_bound(self) -> None:
        from app.domains.marketing.schemas import PreviewContent, TemplatePreviewRequest

        world = _world()
        world.repo.organizations[ORG_A].name = "N" * 120
        preview = await world.service().preview_template(
            _scope(),
            TemplatePreviewRequest(
                channel=Channel.SMS,
                content=PreviewContent(
                    sms=SmsContent(body="{{venue_name}} {{unsubscribe_link}}")
                ),
            ),
        )
        assert preview["rendered"]["body"].startswith("N" * 30 + " ")

    def test_sms_segments_gsm7_and_ucs2(self) -> None:
        assert sms_stats("a" * 160).segments == 1
        assert sms_stats("a" * 161).segments == 2
        assert sms_stats("a" * 306).segments == 2
        unicode = sms_stats("₹" * 70)
        assert unicode.encoding == "ucs2" and unicode.segments == 1
        assert sms_stats("₹" * 71).segments == 2

    def test_sms_rules(self) -> None:
        assert sms_body_problems("Hi {{guest_name}}") == "unsubscribe_link_missing"
        long_body = " ".join(["{{booking_link}}"] * 3) + " {{unsubscribe_link}}"
        assert sms_body_problems(long_body) == "sms_too_long"
        assert sms_body_problems("Hi {{guest_name}} {{unsubscribe_link}}") is None

    async def test_create_template_rejects_unknown_variable_and_missing_unsubscribe(
        self,
    ) -> None:
        world = _world()
        service = world.service()
        with pytest.raises(UnknownVariableError):
            await service.create_template(
                _scope(),
                TemplateCreate(
                    name="x",
                    category="offer",
                    sms=SmsContent(body="Hi {{nickname}} {{unsubscribe_link}}"),
                ),
            )
        with pytest.raises(UnsubscribeLinkMissingError):
            await service.create_template(
                _scope(),
                TemplateCreate(
                    name="y",
                    category="offer",
                    email=EmailContent(subject="s", body_html="<p>{{guest_name}}</p>"),
                ),
            )

    def test_email_sanitizer_strips_script_and_handlers(self) -> None:
        cleaned = clean_email_html(
            '<p onclick="x()">Hi</p><script>alert(1)</script>'
            '<a href="javascript:alert(1)">bad</a><a href="{{unsubscribe_link}}">u</a>'
        )
        assert "script" not in cleaned and "onclick" not in cleaned
        assert "javascript:" not in cleaned
        assert 'href="{{unsubscribe_link}}"' in cleaned

    def test_addresses_and_masking(self) -> None:
        assert normalize_phone("98765 43210") == "+919876543210"
        assert normalize_phone("+44 7911 123456") == "+447911123456"
        assert normalize_phone("12345") is None
        assert mask_phone("+919876543210") == "+91******3210"
        assert mask_email_address("riya@gmail.com") == "r***@gmail.com"
        assert (
            derive_address(Channel.SMS, identifier="a@b.in", email=None).problem
            == "no_address"
        )
        assert (
            derive_address(Channel.EMAIL, identifier="9876543210", email=None).problem
            == "no_address"
        )
        assert (
            derive_address(Channel.EMAIL, identifier="x", email="bad@").problem
            == "invalid_address"
        )


def _load_migration():
    path = next(
        Path(__file__)
        .resolve()
        .parents[2]
        .glob("alembic/versions/*_create_guest_marketing_tables.py")
    )
    spec = importlib.util.spec_from_file_location("marketing_migration", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestSeededSystemTemplates:
    def test_exactly_ten_unique_system_templates(self) -> None:
        templates = _load_migration().SYSTEM_TEMPLATES
        assert len(templates) == 10
        assert len({t["system_key"] for t in templates}) == 10
        assert {t["system_key"] for t in templates} == {
            "welcome_back",
            "celebrate_with_us",
            "weekend_offer",
            "feedback_request",
            "festival_diwali",
            "happy_hour",
            "loyalty_reward",
            "event_invite",
            "win_back",
            "new_arrival",
        }

    @pytest.mark.parametrize(
        "template", _load_migration().SYSTEM_TEMPLATES, ids=lambda t: t["system_key"]
    )
    def test_each_system_template_passes_the_custom_rules(self, template: dict) -> None:
        assert sms_body_problems(template["sms_body"]) is None
        assert sms_stats(template["sms_body"]).encoding == "gsm7"
        for key in (
            "sms_body",
            "whatsapp_body",
            "email_subject",
            "email_preheader",
            "email_body_html",
        ):
            extract_variables(template[key])
        assert "{{unsubscribe_link}}" in template["email_body_html"]
        # The order maps our variables onto the Content template's {{1}}..{{n}}
        # and need not follow reading order (happy_hour names the venue
        # first); it must cover exactly the variables the body uses.
        assert set(extract_variables(template["whatsapp_body"])) == set(
            template["whatsapp_variable_order"]
        )
        assert clean_email_html(template["email_body_html"]).count("{{") == template[
            "email_body_html"
        ].count("{{")


# ============================================================================
# Senders: logging is not configured; OTP senders are never reused
# ============================================================================


class TestSenderResolution:
    def test_defaults_and_logging_are_not_configured(self) -> None:
        senders = resolve_marketing_senders(
            _settings(
                marketing_sms_provider="logging",
                marketing_whatsapp_provider="unconfigured",
                marketing_email_provider="logging",
            )
        )
        for channel in Channel:
            status = senders.status(channel)
            assert status.configured is False
        assert senders.status(Channel.SMS).mode is ChannelMode.LOGGING
        assert (
            senders.sms is None and senders.whatsapp is None and senders.email is None
        )

    def test_otp_sender_identities_are_refused(self) -> None:
        senders = resolve_marketing_senders(
            _settings(
                marketing_sms_provider="ping4sms",
                marketing_sms_sender_id="OTPHDR",
                ping4sms_sender_id="OTPHDR",
                ping4sms_api_key="k",
                marketing_ping4sms_route="2",
                marketing_whatsapp_provider="twilio",
                marketing_whatsapp_from_number="+14155550100",
                whatsapp_twilio_from_number="+14155550100",
                twilio_account_sid="AC",
                twilio_auth_token="t",
            )
        )
        assert not senders.status(Channel.SMS).configured
        assert not senders.status(Channel.WHATSAPP).configured

    async def test_ping4sms_marketing_sender_parses_provider_response(
        self, monkeypatch
    ) -> None:
        import httpx

        from app.domains.marketing import senders as senders_module

        responses = iter(["987654321", "103"])
        seen: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(dict(request.url.params))
            return httpx.Response(200, text=next(responses))

        real_client = httpx.AsyncClient
        monkeypatch.setattr(
            senders_module.httpx,
            "AsyncClient",
            lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw),
        )
        sender = senders_module.Ping4SmsMarketingSender(
            api_key="k", route="2", sender_id="PROMO", entity_id="E1"
        )
        result = await sender.send("+919876543210", "hi", dlt_template_id="1107")
        assert result.message_id == "987654321"
        assert seen[0]["templateid"] == "1107" and seen[0]["sender"] == "PROMO"
        with pytest.raises(SendError) as excinfo:
            await sender.send("+919876543210", "hi", dlt_template_id="1107")
        assert (
            excinfo.value.permanent
            and excinfo.value.suppress_reason == "invalid_number"
        )
