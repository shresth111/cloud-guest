"""ISP Partner Dashboard (network.wyfyguest.com): the ISP-scoped API.

An ISP is an ``org_type="msp"`` organization marked by an active
``isp_partner_profiles`` row. Its customers are STANDARD child organizations
with no users of their own. Everything under ``/isp`` is additive: it only
*calls* existing services, for organizations whose parent holds an active ISP
profile, and every route is behind ``ISP_PARTNER_ENABLED`` (default off).

Spec: ``~/wyfy-ops/isp-network/{PRD,API_CONTRACT,TASKS}.md``.

Module map:

* ``config`` -- the feature flag (its own settings; ``core/config.py`` is not
  edited) and ``RequireIspFeatureEnabled``;
* ``models`` -- ``isp_partner_profiles``, ``isp_customer_profiles``,
  ``isp_staff_customer_scopes``;
* ``rbac_roles`` / ``seed`` -- the four permission groups, fourteen keys and
  five ``isp-*`` roles, seeded by ``python -m app.domains.isp_partner.seed``
  as new rows only;
* ``dependencies`` / ``scoping`` -- the guard stack (``RequireIspPartner``,
  ``IspContext``, ``IspScope``). ``IspScope`` is the only code allowed to
  turn a path id into a row;
* ``router`` -- ``/isp/*``; ``platform_router`` -- ``/platform/isp-partners``
  (Master, owned by the FULLSTACK lane).
"""
