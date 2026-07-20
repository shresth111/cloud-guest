"""Real, collision-safe, concurrency-safe ``RadiusNasClient.nas_code``
generation, plus the RADIUS shared-secret generator ``RadiusService``
composes when an admin does not supply one explicitly.

## ``nas_code`` format: ``"NAS-<location_code>-<sequence>"``, not the module
## brief's imagined ``"NAS-HOTEL001-0001"``

The module brief this extension responds to assumed a short, human-chosen
per-site code (``"HOTEL001"``) that does not exist as a concept anywhere in
this codebase. This codebase's real, closest equivalent is
``app.domains.location.models.Location.location_code`` -- itself generated
by ``app.domains.location.number_generator.generate_location_code`` as
``"LOC-<year>-<6-digit sequence>"`` (e.g. ``"LOC-2026-000001"``), **not** a
short site mnemonic. Rather than inventing a second, fictional short-code
concept with no real data behind it, this generator embeds the location's
own *real* ``location_code`` value verbatim -- e.g.
``"NAS-LOC-2026-000001-0001"`` -- so every NAS code is traceable back to a
real, already-existing, already-unique location identifier rather than a
plausible-looking but fabricated one.

``Location.location_code`` is nullable (only populated for locations
provisioned through Smart Location Provisioning; older rows may have none)
-- ``_location_segment`` falls back to the first 8 characters of the
location's own UUID when ``location_code`` is ``None``, so generation never
fails outright for a location that predates that feature.

## Mechanism: mirrors ``app.domains.location.number_generator`` exactly

Same ``RadiusNasCodeCounter`` unique-``counter_key`` table, same single
atomic Postgres ``INSERT ... ON CONFLICT (counter_key) DO UPDATE SET
last_value = last_value + 1 ... RETURNING last_value`` statement -- see
that module's own docstring for the full concurrency-safety write-up this
one intentionally does not repeat. ``counter_key`` is ``"nas:<location_id>"``
(one row per location, unlike location's own per-year key), so the
sequence is "the Nth NAS ever registered at this location", independent of
every other location's own count -- this matches the module brief's own
examples (``NAS-HOTEL001-0001``, ``NAS-HOTEL001-0002``,
``NAS-HOTEL002-0001`` -- the sequence resets per site, not globally or per
year).

## Shared secret generation

``generate_shared_secret`` is a thin wrapper over ``secrets.token_urlsafe``
(the OS CSPRNG, the same trust boundary this codebase's other real
cryptographic material -- e.g. ``app.domains.wireguard``'s keypair
generation -- already relies on), producing a URL-safe string with
``length`` bytes of entropy before base64url-encoding. Deliberately not a
retry/collision-check loop like ``voucher``'s/``guest_teams``'s join-code
generators: a RADIUS shared secret has no human-facing uniqueness
requirement (it is never displayed on a portal or matched against a public
namespace) and, at
``constants.NAS_SHARED_SECRET_DEFAULT_LENGTH_BYTES`` (32) bytes of entropy,
a collision is not a real-world concern worth defending against with a
retry loop.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Protocol

from .constants import NAS_CODE_PREFIX, NAS_CODE_SEQUENCE_DIGITS


class NasCodeCounterRepositoryProtocol(Protocol):
    """The single method this module needs -- satisfied by
    ``repository.RadiusNasCodeCounterRepository`` (a real, atomic Postgres
    UPSERT) for production use, and by a small in-memory fake in this
    domain's own tests."""

    async def increment_and_get_next(self, counter_key: str) -> int: ...


def _counter_key(location_id: uuid.UUID) -> str:
    return f"nas:{location_id}"


def _location_segment(location_code: str | None, location_id: uuid.UUID) -> str:
    """The real ``Location.location_code`` if this location has one, else
    a short, stable fallback derived from its own id -- see module
    docstring."""
    return location_code if location_code is not None else str(location_id)[:8]


def _format_code(location_segment: str, sequence: int) -> str:
    return (
        f"{NAS_CODE_PREFIX}-{location_segment}-"
        f"{sequence:0{NAS_CODE_SEQUENCE_DIGITS}d}"
    )


async def generate_nas_code(
    repository: NasCodeCounterRepositoryProtocol,
    *,
    location_id: uuid.UUID,
    location_code: str | None,
) -> str:
    """Real, collision-safe -- see module docstring for the exact
    concurrency mechanism and code-shape reasoning."""
    sequence = await repository.increment_and_get_next(_counter_key(location_id))
    return _format_code(_location_segment(location_code, location_id), sequence)


def generate_shared_secret(length: int) -> str:
    """A cryptographically-random, URL-safe RADIUS shared secret with
    ``length`` bytes of entropy before base64url-encoding -- see module
    docstring."""
    return secrets.token_urlsafe(length)


__all__ = [
    "NasCodeCounterRepositoryProtocol",
    "generate_nas_code",
    "generate_shared_secret",
]
