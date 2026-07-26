"""Admin Logs: the customer dashboard's "Admin Logs" page.

Two real, organization-scoped log categories, composed entirely from
already-existing domains -- no new table, no new migration, the same
"composition, not duplication" posture ``app.domains.controller_logs``
already established:

* **Dashboard Logins** -- who logged into the customer dashboard and
  when, sourced from ``app.domains.auth``'s real ``login_attempts``
  table, filtered down to this organization's own active members (see
  ``service.py``'s own module docstring for why that filter has to live
  here rather than on ``LoginAttempt`` itself -- it has no
  ``organization_id`` column).
* **Router Logs** -- real ``router_events`` rows merged across every
  router at every one of the organization's own locations, tagged with
  which location/router each one came from.

**Owner-only**, deliberately stricter than the ``audit_logs.read``
permission alone grants (Organization Admin -- an "Agent"-invitable role
-- also holds that permission by default) -- see ``router.py``'s own
module docstring for the full RBAC gate.
"""

from __future__ import annotations
