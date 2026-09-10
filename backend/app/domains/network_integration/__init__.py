"""Network Integration domain: per-tenant connections to third-party network
controllers, and the captive-portal enforcement step that runs against them.

The first vendor is TP-Link Omada. It is the *first*, not the point --
"Omada is a pluggable provider, not a product" is the product owner's own
non-negotiable, and the shape of this domain is what enforces it:
``service.py`` talks only to ``providers/base.py::NetworkProvider``, and
``providers/omada.py`` is the single module in the entire backend permitted
to import ``wyfy_device_gateway.omada``. A second vendor is a new module
under ``providers/``, one line in that package's registry, and one member
in ``constants.NetworkProviderKind`` -- with no edit to ``service.py``,
``router.py`` or ``models.py``.

## What this domain is, and the four things it is not

It **is**: an inventory of controller connections (URL, auth mode,
encrypted credentials, selected site and guest SSID), a live read-through
to those controllers for sites/SSIDs/devices/clients, a background sync
that keeps a cached status honest, and one public endpoint that authorizes
a guest's device on the controller.

It is **not** an authentication system. ``POST /portal/authorize``
authenticates nobody. OTP, vouchers, consent capture and analytics stay
exactly where they are in ``app.domains.guest`` -- this endpoint's whole
job is the *network enforcement* step that happens after that domain has
already decided the guest may go online, and it is the Omada equivalent of
the existing MikroTik ``link-login-only`` POST. It proves the caller holds
a genuinely ``ACTIVE`` ``GuestSession`` whose organization and location
match the request, and then it calls the controller. Nothing more.

It is **not** a second tenant model. ``organizations``, ``locations``,
``guest_sessions``, ``audit_log_entries`` and RBAC are all reused as-is;
this domain adds exactly three tables.

It is **not** a second analytics stack. The device/client lists are live
read-throughs rendered by the existing table components, not a stored
time series.

It is **not** verified against hardware. Every line here was written
against the shared contract and TP-Link's published documentation, and
tested against mocks. Nothing in this domain has run against a physical
Omada controller. Where a field's meaning was inferred rather than
confirmed, the inference is marked ``# INFERRED, unverified`` at the site
-- see ``providers/omada.py``.

## Inert unless a row exists

Existing customers keep working with Omada absent. The migration is
additive; no existing table is touched; no existing code path consults
this domain. A tenant with no ``network_integrations`` row has exactly the
behaviour they had before, and the background sweep selects nothing.

## Where the sharp edges are

* **Tenant isolation is enforced in the service layer, on the loaded
  row.** This codebase has a known defect class -- the permission check
  reads the ``X-Organization-Id`` header while the handler reads a path id
  -- found live in fourteen endpoints. It is especially dangerous here: the
  ``base_url`` column is where this platform sends a tenant's controller
  credentials, so a cross-tenant *write* is a credential exfiltration
  primitive, not just a data leak. Every ``{integration_id}`` path
  re-verifies ``row.organization_id`` against the caller's organization
  inside ``service.py``. See ``exceptions
  .CrossOrganizationNetworkIntegrationAccessError``.
* **``CurrentOrganization`` is ``None`` for a GLOBAL caller, and ``None``
  means "no filter" downstream.** Customer paths refuse it outright;
  platform paths ask for the unscoped read by name. See
  ``service.NetworkIntegrationService.list_platform_integrations``.
* **The controller URL is hostile input reaching a server-side HTTP
  client.** Validated at write time and re-validated immediately before
  every outbound request, because DNS changes in between. See
  ``validators.py``, which is also honest about the one §6 rule this
  repository cannot enforce (cross-host redirects, which the gateway owns).
* **Credentials are write-only.** Fernet-encrypted under their own key, not
  the router fleet's; never returned by any endpoint (``has_credentials:
  bool`` only); never logged; rotated without the old value ever being
  read back to a caller. See ``crypto.py``.
"""

from __future__ import annotations
