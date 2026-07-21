# PII Masking Layer -- Design Notes

## 0. Not a domain, and nothing to reconcile with

A full-tree grep for "mask"/"masking"/"pii" before writing any code found
zero existing implementation -- every hit was an unrelated false positive
(RouterOS subnet masks, `FastAPIInstrumentor`'s name containing the
substring "pii"). `app.common.masking` and its Pydantic `Annotated`
types are the first of their kind in this codebase; there was no partial
implementation to extend.

## 1. Where the flag lives: per-user, not per-role

RBAC's own `UserRole` model lets a user hold multiple roles at multiple
scopes simultaneously -- there is no single "the user's role" to hang a
boolean off of without inventing a cross-role aggregation rule this
codebase's `PermissionResolver` doesn't already have. `User
.data_masking_enabled` was added as a plain per-user column instead,
mirroring `User.must_change_password`'s own identical precedent (a
narrow, additive boolean, `server_default` chosen for safety, resolved
once inside `get_current_user` with zero extra DB round trips since the
`User` row is already loaded there). The tradeoff: an administrator must
explicitly flip this per user rather than it being inherited from a
role -- accepted deliberately for simplicity over the alternative's
extra per-request role-resolution query and aggregation-rule design.

**Fail-closed default.** `server_default true` (masked) applies to every
pre-existing account and every new one -- a privileged user must be
explicitly, individually granted raw access, never the reverse. The same
`True` default is baked into `MaskingContext.masking_enabled` itself, so
any code path that somehow reads the masking context before
`get_current_user` has run (there is none today) still fails safe.

## 2. Why a plain `ContextVar`, never Pydantic's own `model_dump(context=...)`

Pydantic 2.10 (the pinned version) supports `SerializationInfo.context`/
`model_dump(context=...)` -- but a survey of every router in this
codebase confirmed `model_dump()` is *always* called with zero arguments
before being handed to `build_response(data=...)`. A `Masked*` serializer
relying on Pydantic's own `context=` parameter would silently never
receive it at any of these call sites unless every router were also
changed to pass one -- directly contradicting the goal of "writing
`mobile: MaskedMobile` in a schema is enough." The serializers therefore
read a plain, request-scoped `ContextVar` directly
(`app.middleware.request_context.masking_context`), exactly the same
pattern `request_id`/`user_id`/`organization_id` already use in
`app.core.logging`.

## 3. `MaskingContext` is mutable and request-scoped, not a single flag

Beyond the boolean, `MaskingContext` also needs an accumulator (
`accessed_kinds`) for the audit requirement (§5) and enough identity
(`user_id`, `organization_id`) to write a meaningful audit row. A single
scalar `ContextVar[bool]` couldn't carry that. The `ContextVar`'s own
`default=` is deliberately `None`, never a literal `MaskingContext()`
instance -- a mutable object as a `ContextVar` default would be the
*same shared instance* returned by every `.get()` call made before any
`.set()` in that context, which would leak `accessed_kinds` mutations
across unrelated requests. `RequestContextMiddleware.dispatch` `.set()`s
a brand-new `MaskingContext()` at the very top of every request (before
any dependency/serializer code can run), and `get_masking_context()`
hands back a fresh, never-stored, throwaway instance for the (currently
nonexistent) case of code reading the context genuinely outside a
request. `ruff`'s own `B039` rule flags exactly this hazard for a
literal `ContextVar(default=MaskingContext())` -- confirming the design
independently, not just this project's own reasoning.

## 4. Four masking rules, not one generic type

`MaskedStr` as one generic type can't know whether a given field should
be masked as a mobile number, an email, a name, or a MAC address --
each rule is structurally different. `MaskedMobile`/`MaskedEmail`/
`MaskedName`/`MaskedMac` are four distinct `Annotated[str | None, ...]`
aliases, each built from one shared internal factory
(`_make_serializer`) closing over its own pure mask function and a
`kind` name used purely for the audit bookkeeping (§5) -- never for
guessing a field's semantic type from its runtime shape.

**`MaskedIdentifier`: a real schema shape the original ask didn't
anticipate.** `app.domains.guest.models.Guest.identifier` (and
`GuestLoginHistory.identifier`) is a single column holding *either* a
phone number *or* an email address, whichever a guest presented at
login -- there is no separate, typed column to hang a static
`MaskedMobile`/`MaskedEmail` annotation off of. `mask_identifier`
dispatches at the value level (`"@" in value` -> email, else -> mobile)
-- a real, accurate test for this codebase's own two identifier shapes,
not a fragile heuristic guessing at unrelated formats.

## 5. Auditing a bypass: synchronous serializers, an async DB write

Pydantic serializers are synchronous and cannot `await` a database
write, and `audit_log_entries` needs a real session. Each `Masked*`
serializer, when masking is bypassed, appends its `kind` to
`MaskingContext.accessed_kinds` (mutated in place -- no new `.set()`
needed per field). `RequestContextMiddleware.dispatch` reads that list
once `call_next` returns (the response body, and therefore every
serializer call, has already run by then) and -- only if non-empty --
opens a fresh, short-lived session directly (mirroring how Celery tasks
already open ad-hoc sessions, e.g. `app.domains
.provisioning_engine.tasks`, since `BaseHTTPMiddleware.dispatch` runs
outside FastAPI's own per-route dependency injection and has no
request-scoped session to reuse) and writes **one** row summarizing
every distinct kind unmasked, not one row per field -- a single
guest-list page with 50 rows and 2 masked fields each would otherwise
write 100 audit rows per view. `AuditAction.PII_VIEWED_UNMASKED` is a
new, additive enum value; the field-building logic itself
(`_build_pii_audit_fields`) is deliberately split out as a pure function
so it can be unit-tested without a real database session -- the actual
`SessionLocal`/`RBACRepository` glue around it is accepted as thin,
uncovered wiring, the same testing boundary this codebase already draws
around its Celery task bodies.

## 6. A real bug caught before it shipped

The first implementation of `_make_serializer` had the masking condition
and the audit-recording condition inverted -- it recorded
`accessed_kinds` (and returned the *masked* value) when masking was
*enabled*, and silently returned the *raw* value with no audit record
when masking was *disabled* -- the exact opposite of the requirement.
Caught by an end-to-end smoke test (build a real Pydantic model, flip
the context, inspect `accessed_kinds`) before writing the test suite
proper. This is the reason `test_masking.py`'s own serialization tests
assert on `accessed_kinds` explicitly in both the masked and unmasked
branches, not just the returned string values.

## 7. Two deliberate non-applications: don't mask a caller's own just-submitted data

`GuestLoginResponse.identifier` (returned to a guest immediately after
*they* submit that same identifier to log in) and
`RejectedImportRowResponse.mac_address` (an admin's own just-submitted
MAC Authorization import row, echoed back as rejected) are both left as
plain `str`, not `Masked*`. Masking a caller's own, just-typed data back
to them in the same request/response cycle would be a confusing
regression, not a privacy improvement -- and `GuestLoginResponse`
specifically never goes through `CurrentUser`/JWT auth at all (guests
authenticate via OTP/voucher, not a platform `User` account), so
`MaskingContext` would otherwise sit at its fail-closed default and mask
it for *every* guest, not just privileged callers.
