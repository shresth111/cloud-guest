"""The two headers a venue twin resolves its target from.

They are named here, once, because both ends need them and they must agree: the
backend reads them in :mod:`~app.domains.isp_partner.twins`, and the partner
console's shim pins them on every venue request.

They are deliberately NOT ``X-Location-Id`` / ``X-Router-Id`` (which
``RejectLocationRouterHeaders`` refuses) and NOT ``X-Organization-Id`` (which
stays the ISP organization -- that is what the ``isp_*`` permission check runs
against). These are additive, ``X-Isp-``-prefixed, and mean "the venue the
partner console is currently acting on".
"""

from __future__ import annotations

#: The customer organization the workspace is acting on.
HEADER_CUSTOMER = "X-Isp-Customer-Id"
#: The location within it.
HEADER_LOCATION = "X-Isp-Location-Id"

__all__ = ["HEADER_CUSTOMER", "HEADER_LOCATION"]
