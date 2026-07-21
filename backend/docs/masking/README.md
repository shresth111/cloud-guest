# PII Masking Layer

`app.common.masking` is a cross-cutting utility, not a domain: it masks
guest PII (mobile number, email, name) and device MAC addresses at the
HTTP response layer, so reception-style dashboard users see
`"XXXXXXX98647"` instead of a raw number while the database, search, and
filtering all continue to operate on real values unchanged.

See `FLOW.md` for the full design write-up (including why a plain
`ContextVar` read, not Pydantic's own `model_dump(context=...)`, is the
mechanism that makes this work with zero changes to any existing router
call site).

## Folder Structure

```text
backend/
  alembic/
    versions/
      0047_add_user_data_masking_enabled.py
  app/
    common/
      masking.py               # mask_mobile/mask_email/mask_name/mask_mac/mask_identifier
                                 # + MaskedMobile/MaskedEmail/MaskedName/MaskedMac/MaskedIdentifier
    middleware/
      request_context.py       # MaskingContext + masking_context ContextVar
                                 # + the one-row-per-request audit flush
    domains/
      auth/
        models.py             # User.data_masking_enabled (new column), AuthUser gained the same field
        dependencies.py        # get_current_user sets MaskingContext.masking_enabled/user_id
      rbac/
        dependencies.py       # CurrentOrganization opportunistically sets MaskingContext.organization_id
        enums.py               # AuditAction.PII_VIEWED_UNMASKED (new)
      user/
        service.py            # data_masking_enabled added to ADMIN_EDITABLE_FIELDS (not self-editable)
        schemas.py             # UserUpdateRequest/UserResponse gained the same field
      guest/
        schemas.py            # GuestResponse.identifier/display_name, GuestDeviceResponse.mac_address
      controller_logs/
        schemas.py            # GuestLoginHistoryLogResponse.identifier
      mac_authorization/
        schemas.py            # MacAuthorizationEntryResponse.mac_address
      connected_devices/
        schemas.py            # ConnectedDeviceResponse.mac_address
  docs/
    masking/
      README.md (this file)
      FLOW.md
  tests/
    unit/
      test_masking.py
```

## Usage

Writing a field into a response schema is enough -- no router changes:

```python
from app.common.masking import MaskedMobile, MaskedName

class GuestResponse(BaseModel):
    identifier: MaskedIdentifier   # phone-or-email, dispatches by shape
    display_name: MaskedName
```

Whether a given field actually renders masked or raw depends entirely on
the *caller's* `User.data_masking_enabled` flag (`True` = masked, the
default for every account) -- resolved once per request inside
`get_current_user` and read directly by the `Masked*` serializers via a
`ContextVar`, never via Pydantic's own `context=` mechanism (see
`FLOW.md` for why).

## Toggling masking for a user

There is no dedicated endpoint -- `data_masking_enabled` was added to
`app.domains.user.service.ADMIN_EDITABLE_FIELDS`, so an administrator
flips it via the existing `PUT /api/v1/users/{id}` endpoint, exactly like
`is_verified`. Deliberately **not** in `SELF_EDITABLE_FIELDS` -- a user
must never be able to un-mask themselves.

## Presentation layer only

Nothing in `app.common.masking` touches a repository, a query filter, or
a database column -- masking happens exclusively when a response schema
field is serialized. Search/filter continues to operate on real,
unmasked values everywhere in this codebase, because they were never
masked in the first place.

## Auditing masking bypass

Every request in which a masking-disabled caller actually caused a
`Masked*` field to serialize unmasked gets exactly one
`audit_log_entries` row (`action="pii_viewed_unmasked"`,
`entity_type="pii_access"`), written by `RequestContextMiddleware` itself
after the response body has been fully built -- summarizing every
distinct PII kind unmasked (`mobile`/`email`/`name`/`mac`/`identifier`)
rather than one row per field, to avoid a multi-hundred-row explosion on
a single guest-list page view.

## Testing

`tests/unit/test_masking.py` covers every mask function's edge cases
(`None`/empty/short strings/already-masked/non-ASCII names), the
`Masked*` types' flag-on/flag-off serialization paths (including that
masking is the fail-closed default), the `accessed_kinds` audit
bookkeeping, `get_masking_context()`'s shared-mutable-default-hazard
avoidance, and the pure `_build_pii_audit_fields` helper.
