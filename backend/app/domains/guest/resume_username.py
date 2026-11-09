"""A hotspot username for resuming a session without the guest's identifier.

``GET /guest/session/active`` needs no login: anyone with a router id and a
device MAC can call it. The portal uses its answer to post a hotspot login
for a device that already has a session, and that post used to need the
guest's real phone number or email as the username.

This module gives the portal an opaque username instead, signed so it cannot
be forged. RADIUS maps it back to the guest before doing anything else, so
Authorize and Accounting keep working on the real identifier.

It is not a credential. RADIUS still requires an ACTIVE session on that router
and applies the device binding.

``guest_resume_identifier_mode`` controls the rollout:

* ``off``: no alias, raw identifier (the behaviour before this module).
* ``alias``: alias offered, identifier still raw, so the alias can be proved
  on real routers while cached portal bundles keep working.
* ``masked``: alias offered and the identifier masked.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from typing import Protocol

from app.common.masking import mask_identifier
from app.core.config import get_settings

_SIGNING_PREFIX = b"wyfy-guest-resume-username:v1:"
_USERNAME_RE = re.compile(r"wr1-([0-9a-f]{32})-([0-9a-f]{16})")


class ResumeIdentityResponse(Protocol):
    identifier: str
    hotspot_username: str | None


def _signature(session_id: uuid.UUID) -> str:
    key = get_settings().jwt_secret_key.encode()
    digest = hmac.new(key, _SIGNING_PREFIX + session_id.bytes, hashlib.sha256)
    return digest.hexdigest()[:16]


def issue_resume_username(session_id: uuid.UUID) -> str:
    return f"wr1-{session_id.hex}-{_signature(session_id)}"


def session_id_from_resume_username(username: str | None) -> uuid.UUID | None:
    """The session a genuine alias names, or ``None``. Never raises."""
    match = _USERNAME_RE.fullmatch((username or "").strip())
    if match is None:
        return None
    session_id = uuid.UUID(hex=match.group(1))
    if not hmac.compare_digest(match.group(2), _signature(session_id)):
        return None
    return session_id


def apply_resume_identity(
    response: ResumeIdentityResponse, session_id: uuid.UUID
) -> None:
    """Apply ``guest_resume_identifier_mode`` to a ``/session/active`` answer."""
    mode = get_settings().guest_resume_identifier_mode
    if mode == "off":
        return
    response.hotspot_username = issue_resume_username(session_id)
    if mode == "masked":
        response.identifier = mask_identifier(response.identifier) or ""
