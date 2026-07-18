"""Captive Portal domain (BE-010 Part 3): branding/content/enabled-login-
methods configuration for the guest WiFi login page a guest's device is
redirected to before getting internet access -- logo, colors, terms and
conditions, splash content, and which login methods (OTP SMS/email,
voucher, username/password, social login) are enabled.

This module does **not** implement guest authentication itself -- that is
``app.domains.otp``/``app.domains.voucher`` (already built). It is pure
configuration/branding data plus a guest-facing "give me the portal config
to render" read endpoint (``GET /api/v1/captive-portal/resolve``). The
future ``app.domains.guest`` module (the final BE-010 part) composes with
all three -- ``otp``/``voucher`` for actually authenticating a guest, this
module for what the login page should look like and which methods to
offer.

Resolution mirrors ``app.domains.router_provisioning.models
.ConfigVariable``'s own most-specific-wins precedent, narrowed to two
tiers: a location-specific override, else an organization-level default.
See ``docs/captive_portal/FLOW.md`` for the full design write-up.
"""
