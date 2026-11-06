"""Master Console > Billing > Reminders "Send" (``POST /billing/reminders/send``).

The button used to resolve a client-side ``delay()`` and toast "Reminder
sent" with nothing sent. These tests pin the real behaviour: the email's
facts come from billing data, an unconfigured provider is reported as not
sent, nothing-to-remind is a 409, and every attempt is audited.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.billing.reminder_dispatch import (
    NO_PROVIDER_ERROR,
    NO_RECIPIENT_ERROR,
    BillingReminderService,
    NothingToRemindError,
    ReminderKind,
    ReminderRecentlySentError,
)
from app.domains.otp.service import LoggingEmailProvider
from app.domains.rbac.enums import AuditAction

ORG = uuid.uuid4()
OTHER_ORG = uuid.uuid4()
NOW = datetime(2026, 11, 6, tzinfo=UTC)


class FakeOrgs:
    def __init__(self, email: str | None = "owner@example.com") -> None:
        self.email = email

    async def get_organization(self, organization_id: uuid.UUID) -> Any:
        return SimpleNamespace(id=organization_id, contact_email=self.email)


@dataclass
class FakePayments:
    rows: list[Any] = field(default_factory=list)

    async def list_failed_payments(self, organization_id=None):
        return [p for p in self.rows if p.organization_id == organization_id]


@dataclass
class FakeInvoices:
    rows: list[Any] = field(default_factory=list)

    async def list_invoices(
        self, *, page, page_size, organization_id=None, status=None
    ):
        hits = [
            i
            for i in self.rows
            if i.organization_id == organization_id and i.status == status
        ]
        return hits, None


@dataclass
class FakeSubscriptions:
    rows: list[Any] = field(default_factory=list)

    async def get_by_organization_id(self, organization_id):
        return next(
            (s for s in self.rows if s.organization_id == organization_id), None
        )


class FakePlans:
    async def get_by_id(self, plan_id):
        return SimpleNamespace(id=plan_id, name="Starter")


class FakeAudit:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    async def create_audit_log_entry(self, **fields: Any) -> None:
        self.entries.append(fields)


class RecordingProvider:
    def __init__(self, fail: Exception | None = None) -> None:
        self.sent: list[tuple[str, str, str]] = []
        self.fail = fail

    async def send(self, email: str, subject: str, body: str, **_: Any) -> None:
        if self.fail is not None:
            raise self.fail
        self.sent.append((email, subject, body))


def _invoice(number: str, status: str, *, org: uuid.UUID = ORG, days: int = 3) -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=org,
        invoice_number=number,
        status=status,
        currency="INR",
        total_amount=Decimal("1180.00"),
        due_date=NOW + timedelta(days=days),
    )


def _service(
    *,
    orgs: FakeOrgs | None = None,
    payments: list[Any] | None = None,
    invoices: list[Any] | None = None,
    subscriptions: list[Any] | None = None,
    audit: FakeAudit | None = None,
) -> BillingReminderService:
    return BillingReminderService(
        organizations=orgs or FakeOrgs(),
        payments=FakePayments(payments or []),
        invoices=FakeInvoices(invoices or []),
        subscriptions=FakeSubscriptions(subscriptions or []),
        plans=FakePlans(),
        audit_writer=audit,
    )


async def test_invoice_due_lists_the_orgs_own_unpaid_invoices_and_audits() -> None:
    audit = FakeAudit()
    provider = RecordingProvider()
    svc = _service(
        invoices=[
            _invoice("INV-1", "issued"),
            _invoice("INV-2", "overdue", days=-5),
            _invoice("INV-3", "paid"),
            _invoice("INV-X", "issued", org=OTHER_ORG),
        ],
        audit=audit,
    )
    result = await svc.send(
        actor_user_id=uuid.uuid4(),
        organization_id=ORG,
        kind=ReminderKind.INVOICE_DUE,
        email_provider_factory=lambda: provider,
    )
    assert result.email_sent is True
    assert result.email_recipient == "owner@example.com"
    assert len(provider.sent) == 1
    to, subject, body = provider.sent[0]
    assert to == "owner@example.com"
    assert "2 unpaid" in subject
    assert "INV-1" in body and "INV-2" in body
    assert "INV-3" not in body and "INV-X" not in body
    [entry] = audit.entries
    assert entry["action"] == AuditAction.BILLING_REMINDER_EMAILED.value
    assert entry["organization_id"] == ORG
    assert entry["event_metadata"]["email_sent"] is True
    assert "emailed to owner@example.com" in entry["description"]


async def test_logging_provider_is_reported_as_not_sent_never_as_success() -> None:
    audit = FakeAudit()
    svc = _service(invoices=[_invoice("INV-1", "issued")], audit=audit)
    result = await svc.send(
        actor_user_id=None,
        organization_id=ORG,
        kind=ReminderKind.INVOICE_DUE,
        email_provider_factory=LoggingEmailProvider,
    )
    assert result.email_sent is False
    assert result.email_error == NO_PROVIDER_ERROR
    assert audit.entries[0]["event_metadata"]["email_sent"] is False
    assert "NOT sent" in audit.entries[0]["description"]


async def test_provider_failure_and_misconfiguration_are_reported_and_audited() -> None:
    for factory in (
        lambda: RecordingProvider(fail=RuntimeError("535 auth failed")),
        lambda: (_ for _ in ()).throw(RuntimeError("mailbox mismatch")),
    ):
        audit = FakeAudit()
        svc = _service(invoices=[_invoice("INV-1", "issued")], audit=audit)
        result = await svc.send(
            actor_user_id=None,
            organization_id=ORG,
            kind=ReminderKind.INVOICE_DUE,
            email_provider_factory=factory,
        )
        assert result.email_sent is False
        assert result.email_error
        assert len(audit.entries) == 1


async def test_no_contact_email_is_not_sent() -> None:
    provider = RecordingProvider()
    svc = _service(orgs=FakeOrgs(email=None), invoices=[_invoice("INV-1", "issued")])
    result = await svc.send(
        actor_user_id=None,
        organization_id=ORG,
        kind=ReminderKind.INVOICE_DUE,
        email_provider_factory=lambda: provider,
    )
    assert result.email_sent is False
    assert result.email_error == NO_RECIPIENT_ERROR
    assert provider.sent == []


@pytest.mark.parametrize("kind", list(ReminderKind))
async def test_nothing_to_remind_is_a_409_and_sends_nothing(kind: ReminderKind) -> None:
    provider = RecordingProvider()
    audit = FakeAudit()
    # Rows exist, but only for a different organization.
    svc = _service(
        payments=[SimpleNamespace(id=uuid.uuid4(), organization_id=OTHER_ORG)],
        invoices=[_invoice("INV-X", "issued", org=OTHER_ORG)],
        subscriptions=[SimpleNamespace(id=uuid.uuid4(), organization_id=OTHER_ORG)],
        audit=audit,
    )
    with pytest.raises(NothingToRemindError) as exc:
        await svc.send(
            actor_user_id=None,
            organization_id=ORG,
            kind=kind,
            email_provider_factory=lambda: provider,
        )
    assert exc.value.status_code == 409
    assert provider.sent == []
    assert audit.entries == []


async def test_payment_failed_uses_the_newest_failed_payment() -> None:
    provider = RecordingProvider()
    payment = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=ORG,
        amount=Decimal("999.00"),
        currency="INR",
        failure_reason="Card declined",
    )
    audit = FakeAudit()
    svc = _service(payments=[payment], audit=audit)
    result = await svc.send(
        actor_user_id=None,
        organization_id=ORG,
        kind=ReminderKind.PAYMENT_FAILED,
        email_provider_factory=lambda: provider,
    )
    assert result.email_sent is True
    _, subject, body = provider.sent[0]
    assert "payment failed" in subject
    assert "INR 999.00" in body and "Card declined" in body
    assert audit.entries[0]["entity_type"] == "payment"
    assert audit.entries[0]["entity_id"] == payment.id


async def test_expiry_states_the_real_period_end_and_renewal_setting() -> None:
    provider = RecordingProvider()
    sub = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=ORG,
        plan_id=uuid.uuid4(),
        current_period_end=datetime(2026, 11, 20, tzinfo=UTC),
        auto_renew=False,
    )
    svc = _service(subscriptions=[sub])
    await svc.send(
        actor_user_id=None,
        organization_id=ORG,
        kind=ReminderKind.EXPIRY,
        email_provider_factory=lambda: provider,
    )
    _, subject, body = provider.sent[0]
    assert "20 Nov 2026" in subject
    assert "Automatic renewal is off" in body


def test_route_is_registered_global_billing_manage() -> None:
    import inspect

    from app.domains.billing.router import router
    from app.domains.rbac.enums import ScopeType

    [route] = [
        r for r in router.routes if getattr(r, "path", "") == "/billing/reminders/send"
    ]
    assert route.methods == {"POST"}
    gates = [
        inspect.getclosurevars(d.dependency).nonlocals
        for d in route.dependencies
        if "permission_key" in inspect.getclosurevars(d.dependency).nonlocals
    ]
    assert gates == [{"permission_key": "billing.manage", "scope": ScopeType.GLOBAL}]


# ---------------------------------------------------------------------------
# Cooldown: an operator double-click must not mail a customer twice.
# ---------------------------------------------------------------------------


class FakeCooldownStore:
    """``SET NX EX`` / ``DEL`` semantics of the real Redis client."""

    def __init__(self, *, broken: bool = False) -> None:
        self.keys: dict[str, int] = {}
        self.broken = broken

    async def set(self, name: str, value: str, *, nx: bool, ex: int) -> bool | None:
        if self.broken:
            raise ConnectionError("redis down")
        if nx and name in self.keys:
            return None
        self.keys[name] = ex
        return True

    async def delete(self, *names: str) -> int:
        for name in names:
            self.keys.pop(name, None)
        return len(names)


def _cooled_service(store: FakeCooldownStore) -> BillingReminderService:
    svc = _service(invoices=[_invoice("INV-1", "issued")], audit=FakeAudit())
    svc.cooldown_store = store
    return svc


async def test_a_second_send_inside_the_cooldown_is_refused_and_not_sent() -> None:
    store = FakeCooldownStore()
    svc = _cooled_service(store)
    provider = RecordingProvider()
    kwargs = dict(
        actor_user_id=uuid.uuid4(),
        organization_id=ORG,
        kind=ReminderKind.INVOICE_DUE,
        email_provider_factory=lambda: provider,
    )
    assert (await svc.send(**kwargs)).email_sent is True
    with pytest.raises(ReminderRecentlySentError) as exc:
        await svc.send(**kwargs)
    assert exc.value.status_code == 409
    assert len(provider.sent) == 1
    # Another kind for the same org is a different reminder.
    with pytest.raises(NothingToRemindError):
        await svc.send(**{**kwargs, "kind": ReminderKind.PAYMENT_FAILED})


async def test_a_failed_send_releases_the_slot_so_the_operator_can_retry() -> None:
    store = FakeCooldownStore()
    svc = _cooled_service(store)
    failing = RecordingProvider(fail=RuntimeError("smtp 535"))
    first = await svc.send(
        actor_user_id=uuid.uuid4(),
        organization_id=ORG,
        kind=ReminderKind.INVOICE_DUE,
        email_provider_factory=lambda: failing,
    )
    assert first.email_sent is False
    assert store.keys == {}
    provider = RecordingProvider()
    second = await svc.send(
        actor_user_id=uuid.uuid4(),
        organization_id=ORG,
        kind=ReminderKind.INVOICE_DUE,
        email_provider_factory=lambda: provider,
    )
    assert second.email_sent is True


async def test_redis_down_does_not_block_the_send() -> None:
    svc = _cooled_service(FakeCooldownStore(broken=True))
    provider = RecordingProvider()
    result = await svc.send(
        actor_user_id=uuid.uuid4(),
        organization_id=ORG,
        kind=ReminderKind.INVOICE_DUE,
        email_provider_factory=lambda: provider,
    )
    assert result.email_sent is True
