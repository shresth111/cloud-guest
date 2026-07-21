# MAC Authorization -- Design Write-Up

## 1. Relationship to `app.domains.guest_access` -- a deliberate, explicit scoping decision

Before building this domain, research turned up that
`app.domains.guest_access.models.DeviceAccessRule` already implements
almost the entire schema this roadmap item describes: `mac_address`,
`organization_id`/`location_id` (NULL = org-wide) scope, a `rule_type`
(`WHITELIST`/`BLOCKLIST`/`TEMPORARY` with `expires_at`/`VIP`), a `reason`
comment field, and it is already wired into
`app.domains.guest.service.GuestService.login_via_otp` via an
`access_control_hook`.

**What that existing domain does *not* do** is real MAC Authentication
Bypass (MAB): a `WHITELIST`/`VIP` decision there only lets a login
*proceed* to normal OTP verification -- it never skips OTP entirely and
creates a session directly. Implementing genuine auth-bypass behavior
would mean modifying `login_via_otp`'s own control flow (a live,
security-sensitive path), not just adding a new table.

Given this, three paths were possible: (a) extend `DeviceAccessRule`/
`AccessRuleType` with a new bypass-capable rule type and change
`login_via_otp`'s body: (b) build this domain fully standalone, real
schema/field overlap with `DeviceAccessRule` notwithstanding; (c) skip
this roadmap item for now. **Option (b) was the explicit, deliberate
choice** -- this domain is intentionally independent of
`app.domains.guest_access`, not an oversight or an accidental
duplication. `is_mac_authorized` (see `service.py`) is the read-model
query a future integration pass would call to actually wire in the
bypass behavior against `GuestService`'s own login flow -- this build
stops short of making that live, security-sensitive control-flow change.

## 2. No router/device composition

Unlike `app.domains.vlan`/`app.domains.dhcp`/`app.domains.isp_routing`/
`app.domains.port_forwarding` (all scoped to one router), this domain has
no router concept at all -- a MAC address is authorized for an
organization (optionally a location), not tied to any particular device
a guest happens to connect through. It therefore composes nothing;
`requesting_organization_id` is trusted directly, the identical posture
`app.domains.policy` already establishes (RBAC's own `CurrentOrganization`
dependency has already validated real organization membership before a
request ever reaches this domain's service).

## 3. `organization_id` is required, unlike `Policy.organization_id`

`app.domains.policy.models.Policy.organization_id` is nullable ("`NULL`
means a platform-wide policy definition"). `MacAuthorizationEntry
.organization_id` is **not** nullable -- there is no "platform-wide MAC
whitelist" concept in this domain; every entry belongs to exactly one
organization. Since `CurrentOrganization` legitimately returns `None`
(whenever the caller omits the `X-Organization-Id` header, regardless of
scope), `create_entry`/`import_entries`/`export_entries_csv` each
explicitly check for this and raise a real, dedicated
`OrganizationRequiredError` rather than letting a `NULL` reach the
database's own `NOT NULL` constraint as an opaque integrity error.

## 4. `location_id`: filterable, not part of the uniqueness scope

`location_id` is nullable (organization-wide) and filterable via
`GET /entries?location_id=...`, but deliberately **not** part of the
uniqueness index -- Postgres treats every `NULL` in a unique index as
distinct from every other `NULL`, so including a nullable `location_id`
column in the uniqueness key would silently allow unlimited
organization-wide (`location_id = NULL`) duplicates for the same MAC
address. Uniqueness is scoped to `(organization_id, mac_address)` only --
see `models.py`'s own module docstring for this exact reasoning.

## 5. Bulk import: partial success, mirrors `app.domains.voucher`

`import_entries` mirrors
`app.domains.voucher.service.VoucherService.import_vouchers`'s own
"accepted rows are inserted, rejected rows are reported with a reason,
never an all-or-nothing failure" contract exactly -- each row is run
through the same `create_entry` logic individually, and any
`MacAuthorizationError`/`ValueError` (a malformed MAC, a bad
`authorization_type` string, a duplicate) is caught per-row and reported
in `rejected`, never aborting the rest of the batch. The one exception:
a missing `requesting_organization_id` is checked once, up front, before
the loop -- that is a request-level precondition failure, not a per-row
data problem, so it raises immediately rather than rejecting every row
individually with the same reason.

## 6. `is_mac_authorized`: never raises on a malformed MAC

A malformed MAC address queried via `is_mac_authorized` returns `False`
rather than propagating `InvalidMacAddressError` -- this method's whole
purpose is "should this device be trusted", and a request for a garbage
MAC address is definitionally "not trusted", not a caller error worth
crashing over. This is a real, intentional exception to
`normalize_mac_address`'s own default "always raise on invalid input"
behavior used everywhere else in this domain (create/update).
