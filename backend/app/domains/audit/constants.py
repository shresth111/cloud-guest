"""Shared constants for the audit domain."""

from __future__ import annotations

# Hard ceiling on how many rows one CSV export streams -- a plain module
# constant, not a new Settings field, mirroring
# app.domains.notification.constants.DISPATCH_SWEEP_BATCH_SIZE's own
# "narrow, single-purpose bound, not a new knob" precedent. An export
# hitting this cap is truncated, not silently incomplete -- see
# service.py's own docstring.
AUDIT_EXPORT_MAX_ROWS = 10_000
AUDIT_EXPORT_PAGE_SIZE = 500

CSV_EXPORT_HEADERS = (
    "created_at",
    "actor_user_id",
    "action",
    "entity_type",
    "entity_id",
    "organization_id",
    "location_id",
    "description",
    # Appended, never inserted. Every existing consumer of this export reads
    # by position or by a header row it already knows; a new column at the
    # end is additive for both, and one in the middle silently shifts every
    # field after it.
    "event_metadata",
)

__all__ = [
    "AUDIT_EXPORT_MAX_ROWS",
    "AUDIT_EXPORT_PAGE_SIZE",
    "CSV_EXPORT_HEADERS",
]
