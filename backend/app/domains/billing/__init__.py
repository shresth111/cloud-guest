"""Billing domain (BE-013 Part 1: Plan + License + Usage Core).

This is the "reserved future Billing domain" that
``app.domains.organization``'s own module docstring has pointed at since
Module 005: ``Organization.subscription_tier`` was deliberately kept as a
lightweight, unpopulated, nullable *label* with "no pricing/entitlement
logic behind it" specifically so this module could arrive later and give it
real meaning. See ``docs/billing/FLOW.md`` §1 for the full write-up of how
this module resolves that reservation: ``License``/``Plan`` become the real
source of truth for what an organization is entitled to, and
``Organization.subscription_tier`` becomes a denormalized, best-effort
convenience label kept in sync by a narrow, additive hook on
``OrganizationService`` -- never re-derived ad hoc by any reader.

Part 1 scope: ``Plan``/``PlanFeature`` (the pricing/entitlement catalog),
``License``/``LicenseChangeLog`` (what an organization is actually entitled
to right now, and its full upgrade/downgrade/suspend/expire history), and
``UsageMetric`` (real, composed usage tracking against existing domains'
own data, plus limit validation against the organization's active license).
Later BE-013 parts (not built here) layer Subscription/Renewal/Coupon,
Payment/Stripe/Razorpay/webhooks, and Invoice/Tax on top of this
foundation.
"""
