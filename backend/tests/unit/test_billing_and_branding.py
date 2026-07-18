"""Unit tests for the new domains: Subscription, Billing, License, Payment, Invoice, Branding, Theme, Custom Domains, and Webhooks.

Uses the same pytest-driven native async pattern as existing tests.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
import pytest

from app.domains.subscription.constants import PlanCode, SubscriptionStatus
from app.domains.subscription.service import SubscriptionService
from app.domains.billing.service import BillingService
from app.domains.license.service import LicenseService
from app.domains.payment.service import PaymentService
from app.domains.invoice.service import InvoiceService
from app.domains.branding.service import BrandingService
from app.domains.theme.service import ThemeService
from app.domains.domain.service import CustomDomainService

# --- Mock Repositories ---

class FakeSubscriptionRepository:
    def __init__(self):
        self.plans = {}
        self.subs = {}
        self.history = []

    async def get_plan_by_id(self, plan_id):
        return self.plans.get(plan_id)

    async def get_plan_by_code(self, code):
        for p in self.plans.values():
            if p.code == code:
                return p
        return None

    async def list_active_plans(self):
        return list(self.plans.values())

    async def create_plan(self, data):
        from app.domains.subscription.models import SubscriptionPlan
        p = SubscriptionPlan(**data)
        p.id = uuid.uuid4()
        self.plans[p.id] = p
        return p

    async def get_subscription_by_org(self, organization_id):
        for s in self.subs.values():
            if s.organization_id == organization_id:
                return s
        return None

    async def create_subscription(self, data):
        from app.domains.subscription.models import Subscription
        s = Subscription(**data)
        s.id = uuid.uuid4()
        self.subs[s.id] = s
        return s

    async def update_subscription(self, subscription, data):
        for k, v in data.items():
            setattr(subscription, k, v)
        return subscription

    async def get_subscription_by_id(self, subscription_id):
        return self.subs.get(subscription_id)

    async def add_plan_change_history(self, data):
        from app.domains.subscription.models import PlanChangeHistory
        h = PlanChangeHistory(**data)
        h.id = uuid.uuid4()
        self.history.append(h)
        return h

    async def get_plan_change_history(self, organization_id):
        return [x for x in self.history if x.organization_id == organization_id]


class FakeBillingRepository:
    def __init__(self):
        self.profiles = {}

    async def get_by_org_id(self, organization_id):
        return self.profiles.get(organization_id)

    async def create_profile(self, data):
        from app.domains.billing.models import BillingProfile
        p = BillingProfile(**data)
        p.id = uuid.uuid4()
        self.profiles[p.organization_id] = p
        return p

    async def update_profile(self, profile, data):
        for k, v in data.items():
            setattr(profile, k, v)
        return profile


class FakeLicenseRepository:
    def __init__(self):
        self.licenses = {}

    async def get_by_key(self, key):
        for l in self.licenses.values():
            if l.license_key == key:
                return l
        return None

    async def get_by_id(self, license_id):
        return self.licenses.get(license_id)

    async def list_by_organization(self, organization_id):
        return [l for l in self.licenses.values() if l.organization_id == organization_id]

    async def create_license(self, data):
        from app.domains.license.models import License
        l = License(**data)
        l.id = uuid.uuid4()
        self.licenses[l.id] = l
        return l

    async def update_license(self, license_obj, data):
        for k, v in data.items():
            setattr(license_obj, k, v)
        return license_obj


class FakePaymentRepository:
    def __init__(self):
        self.payments = {}
        self.coupons = {}

    async def get_payment_by_id(self, payment_id):
        return self.payments.get(payment_id)

    async def get_payment_by_intent(self, intent_id):
        for p in self.payments.values():
            if p.gateway_payment_intent_id == intent_id:
                return p
        return None

    async def list_payments_by_org(self, organization_id):
        return [p for p in self.payments.values() if p.organization_id == organization_id]

    async def create_payment(self, data):
        from app.domains.payment.models import Payment
        p = Payment(**data)
        p.id = uuid.uuid4()
        self.payments[p.id] = p
        return p

    async def update_payment(self, payment, data):
        for k, v in data.items():
            setattr(payment, k, v)
        return payment

    async def get_coupon_by_code(self, code):
        for c in self.coupons.values():
            if c.code == code:
                return c
        return None

    async def create_coupon(self, data):
        from app.domains.payment.models import Coupon
        c = Coupon(**data)
        c.id = uuid.uuid4()
        self.coupons[c.id] = c
        return c

    async def update_coupon(self, coupon, data):
        for k, v in data.items():
            setattr(coupon, k, v)
        return coupon


class FakeInvoiceRepository:
    def __init__(self):
        self.invoices = {}
        self.credit_notes = {}

    async def get_by_id(self, invoice_id):
        return self.invoices.get(invoice_id)

    async def get_by_number(self, invoice_number):
        for i in self.invoices.values():
            if i.invoice_number == invoice_number:
                return i
        return None

    async def list_by_org(self, organization_id):
        return [i for i in self.invoices.values() if i.organization_id == organization_id]

    async def create_invoice(self, data):
        from app.domains.invoice.models import Invoice
        i = Invoice(**data)
        i.id = uuid.uuid4()
        self.invoices[i.id] = i
        return i

    async def update_invoice(self, invoice, data):
        for k, v in data.items():
            setattr(invoice, k, v)
        return invoice

    async def get_next_invoice_sequence(self):
        return len(self.invoices) + 1

    async def create_credit_note(self, data):
        from app.domains.invoice.models import CreditNote
        cn = CreditNote(**data)
        cn.id = uuid.uuid4()
        self.credit_notes[cn.id] = cn
        return cn

    async def list_credit_notes_by_org(self, organization_id):
        return [cn for cn in self.credit_notes.values() if cn.organization_id == organization_id]


class FakeBrandingRepository:
    def __init__(self):
        self.brandings = {}

    async def get_by_organization(self, organization_id):
        for b in self.brandings.values():
            if b.organization_id == organization_id and b.location_id is None:
                return b
        return None

    async def get_by_location(self, location_id):
        for b in self.brandings.values():
            if b.location_id == location_id:
                return b
        return None

    async def create_branding(self, data):
        from app.domains.branding.models import Branding
        b = Branding(**data)
        b.id = uuid.uuid4()
        self.brandings[b.id] = b
        return b

    async def update_branding(self, branding, data):
        for k, v in data.items():
            setattr(branding, k, v)
        return branding


class FakeThemeRepository:
    def __init__(self):
        self.themes = {}

    async def get_by_branding_id(self, branding_id):
        for t in self.themes.values():
            if t.branding_id == branding_id:
                return t
        return None

    async def create_theme(self, data):
        from app.domains.theme.models import Theme
        t = Theme(**data)
        t.id = uuid.uuid4()
        self.themes[t.id] = t
        return t

    async def update_theme(self, theme, data):
        for k, v in data.items():
            setattr(theme, k, v)
        return theme


class FakeCustomDomainRepository:
    def __init__(self):
        self.domains = {}

    async def get_by_id(self, domain_id):
        return self.domains.get(domain_id)

    async def get_by_name(self, domain_name):
        for d in self.domains.values():
            if d.domain_name == domain_name and not d.is_deleted:
                return d
        return None

    async def list_by_organization(self, organization_id):
        return [d for d in self.domains.values() if d.organization_id == organization_id and not d.is_deleted]

    async def create_domain(self, data):
        from app.domains.domain.models import CustomDomain
        d = CustomDomain(**data)
        d.id = uuid.uuid4()
        self.domains[d.id] = d
        return d

    async def update_domain(self, domain, data):
        for k, v in data.items():
            setattr(domain, k, v)
        return domain


# --- Pytest Cases ---

@pytest.mark.asyncio
async def test_subscription_and_plans():
    repo = FakeSubscriptionRepository()
    service = SubscriptionService(repo)

    # 1. Create a plan
    plan = await service.create_plan({
        "name": "Starter Plan",
        "code": "starter",
        "price_monthly": 19.99,
        "price_yearly": 199.99,
        "trial_days": 14,
        "limits": {}
    })
    assert plan.code == "starter"

    # 2. Subscribe organization
    org_id = uuid.uuid4()
    sub = await service.create_subscription(org_id, plan.id, "monthly")
    assert sub.status == SubscriptionStatus.TRIALING.value
    assert sub.organization_id == org_id


@pytest.mark.asyncio
async def test_billing_profile():
    repo = FakeBillingRepository()
    service = BillingService(repo)

    org_id = uuid.uuid4()
    profile = await service.get_or_create_profile(org_id)
    assert profile.organization_id == org_id
    assert profile.customer_id is not None


@pytest.mark.asyncio
async def test_license_lifecycle():
    repo = FakeLicenseRepository()
    service = LicenseService(repo)

    # 1. Generate license key
    org_id = uuid.uuid4()
    lic = await service.generate_license(org_id, "starter")
    assert len(lic.license_key) == 19  # XXXX-XXXX-XXXX-XXXX
    
    # 2. Activate on router
    router_id = uuid.uuid4()
    activated = await service.activate_license(lic.license_key, router_id)
    assert activated.status == "activated"
    assert activated.router_id == router_id


@pytest.mark.asyncio
async def test_payment_and_coupons():
    repo = FakePaymentRepository()
    service = PaymentService(repo)

    # 1. Coupon code creation
    coupon = await service.create_coupon({
        "code": "SAVE50",
        "discount_type": "percentage",
        "discount_value": 50.0,
        "currency": "USD",
        "active": True
    })
    assert coupon.code == "SAVE50"

    # 2. Verify discount application
    final_amt, _ = await service.apply_coupon("SAVE50", 100.0)
    assert final_amt == 50.0


@pytest.mark.asyncio
async def test_invoice_creation():
    repo = FakeInvoiceRepository()
    service = InvoiceService(repo)

    org_id = uuid.uuid4()
    invoice = await service.create_invoice(
        organization_id=org_id,
        subtotal=100.0,
        tax_rate=0.18,
        discount_amount=10.0
    )
    # subtotal 100.0 - discount 10.0 = 90.0. Tax is 18% of 90.0 = 16.20. Total = 106.20
    assert float(invoice.subtotal) == 100.0
    assert float(invoice.discount_amount) == 10.0
    assert float(invoice.tax_amount) == 16.20
    assert float(invoice.total) == 106.20


@pytest.mark.asyncio
async def test_branding_cascading():
    repo = FakeBrandingRepository()
    service = BrandingService(repo)

    org_id = uuid.uuid4()
    loc_id = uuid.uuid4()

    # Create Org branding
    await service.update_branding(org_id, None, {"company_name": "My Corp", "primary_color": "#FF0000"})
    
    # Get effective branding without location
    brand = await service.get_effective_branding(org_id, None)
    assert brand.company_name == "My Corp"
    assert brand.primary_color == "#FF0000"

    # Create Location override
    await service.update_branding(org_id, loc_id, {"company_name": "Local Shop", "primary_color": "#00FF00"})
    effective = await service.get_effective_branding(org_id, loc_id)
    assert effective.company_name == "Local Shop"
    assert effective.primary_color == "#00FF00"


@pytest.mark.asyncio
async def test_custom_domains():
    repo = FakeCustomDomainRepository()
    service = CustomDomainService(repo)

    org_id = uuid.uuid4()
    domain = await service.add_custom_domain(org_id, "portal.mycompany.com")
    assert domain.domain_name == "portal.mycompany.com"
    assert domain.is_verified is False

    # Verify
    verified = await service.verify_domain_dns(domain.id)
    assert verified.is_verified is True
