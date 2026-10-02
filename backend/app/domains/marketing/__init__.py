"""Guest Marketing: WhatsApp / SMS / email campaigns to guests who opted in
on the WiFi portal.

Contract: ``wyfy-specs/guest-marketing-campaigns.md`` (§5 is the source of
truth). A paid add-on: every customer route is gated by
``RequireFeature(PlanFeatureKey.GUEST_MARKETING)``, which a Master-console
override (``billing.models.OrganizationFeatureOverride``) or a plan turns on.

Distinct from ``app.domains.campaigns`` (captive-portal surveys/banners shown
during login): outbound messaging has its own send lifecycle, per-recipient
delivery rows, consent, suppression and provider credentials.
"""
