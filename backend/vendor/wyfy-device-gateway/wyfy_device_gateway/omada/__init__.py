"""TP-Link Omada controller integration.

The backend imports ``OmadaControllerAdapter`` (usually via
``registry.get_controller_adapter``) and the error classes, and nothing else.
Everything below that -- HTTP, sessions, endpoint paths, response shapes --
is internal to this package and free to change.

## Read this before trusting anything here

**No code in this package has ever run against a physical Omada controller.**
It was written from TP-Link's published documentation, corroborated against
an open-source client, and tested exclusively against ``httpx.MockTransport``.
The tests prove this client behaves as we believe the API expects. They
cannot prove the API expects it.

Every factual claim in this package's docstrings is tagged:

* **VERIFIED** -- stated in a primary TP-Link document, URL given inline.
* **CORROBORATED** -- consistent across independent open-source clients or
  TP-Link forum threads, but absent from any primary document we could reach.
* **INFERRED, unverified** -- our reasoning, with the consequence of being
  wrong spelled out.

The reason so much is merely corroborated: the authoritative Open API
reference is the "Online API Document" that a controller serves from its own
web UI at ``/doc.html``. It ships with the product and is not published on
the web, so without a controller there is no primary source for most Open API
paths. The external-portal API, by contrast, *is* publicly documented, which
is why the guest-authorization path -- the part that matters most -- is the
best-sourced code here.

## The two APIs

Omada exposes two unrelated HTTP APIs, selected per-integration by
``ControllerAuthMode``:

``legacy`` -- the **external portal API**, ``/{omadacId}/api/v2/hotspot/...``,
authenticated with a *hotspot operator* account (created in the controller's
Hotspot Manager, explicitly not a controller admin account). Available on
v5.0.15+. It can authorize portal clients and nothing else.

``openapi`` -- the **Open API**, ``/openapi/v1/...``, authenticated with an
OAuth-style ``client_id``/``client_secret`` issued under Settings > Platform
Integration > Open API. Available on v5.13+. It can read inventory.

Neither is a superset of the other, which is why ``ControllerCredentials``
carries both credential pairs and why a real deployment will usually populate
both: Open API for the dashboard's device and client tables, an operator
account for the captive portal.

## Capability matrix

See ``adapter.py``'s module docstring for the full table. The short version:
inventory needs ``openapi``; guest authorization needs operator credentials
in either mode; **deauthorization needs exactly the same operator
credentials as authorization**, so anything this package can put on a
network it can also take off. The endpoint TP-Link does not document was
found on the controller and is implemented in ``deauth.py``;
``deauthorize_guest`` raises ``OmadaUnsupportedApiError`` only for an
integration with no operator account at all, which is the same
configuration that cannot authorize anybody either.

## The endpoint transposition (contract section 1a), resolved

Operator login is ``POST /{omadacId}/api/v2/hotspot/login``; client
authorization is ``POST /{omadacId}/api/v2/hotspot/extPortal/auth``. TP-Link's
own v5 and v6 documents contain PHP samples with these two swapped, which is
what produced the ambiguity. ``auth.py``'s module docstring lays out the
three-source resolution in full.
"""

from __future__ import annotations

from .adapter import OmadaControllerAdapter
from .errors import (
    ALL_ERRORS,
    OmadaAuthError,
    OmadaAuthorizationError,
    OmadaClientNotFoundError,
    OmadaConnectionError,
    OmadaError,
    OmadaInvalidControllerError,
    OmadaRateLimitedError,
    OmadaSessionExpiredError,
    OmadaSiteNotFoundError,
    OmadaTimeoutError,
    OmadaUnsupportedApiError,
)

__all__ = [
    "ALL_ERRORS",
    "OmadaAuthError",
    "OmadaAuthorizationError",
    "OmadaClientNotFoundError",
    "OmadaConnectionError",
    "OmadaControllerAdapter",
    "OmadaError",
    "OmadaInvalidControllerError",
    "OmadaRateLimitedError",
    "OmadaSessionExpiredError",
    "OmadaSiteNotFoundError",
    "OmadaTimeoutError",
    "OmadaUnsupportedApiError",
]
