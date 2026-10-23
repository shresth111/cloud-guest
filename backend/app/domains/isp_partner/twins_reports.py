"""The customer Reports page's "Business Unit" picker, made to work for ISPs.

``UserReports`` (mounted unchanged in the partner console) lets the user pick
any location of the customer as the Business Unit, and "Bandwidth Usage By
Location" fetches every location's sessions in turn, each time sending
``location_id=<that location>``. The report twins inject the WORKSPACE
location from ``X-Isp-Location-Id`` -- so without this, every Business Unit
and every row of the by-location report would silently show the workspace
location's numbers under another location's name.

``with_report_location`` adds an optional ``isp_location_id`` query extra
(the shim already renames ``location_id`` -> ``isp_location_id``). It resolves
through ``IspScope.assert_location`` (ISP + confinement) and the twin pins it
to the SAME customer as the header target; it then feeds both the handler's
``location_id`` filter and any ``scope_location_id``/``header_location_id``,
so the original's own location-consistency check keeps passing. Left out, the
row keeps its injected workspace location -- never "every location".
"""

from __future__ import annotations

from dataclasses import replace

from .twins import Extra, TwinSpec

__all__ = ["REPORT_PATHS", "with_report_location"]

#: Report-catalogue reads whose location the Business Unit picker chooses.
REPORT_PATHS: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/venue/guest-sessions"),
        ("GET", "/venue/guests"),
        ("GET", "/venue/analytics/voucher-redemptions/log"),
        ("GET", "/venue/otp/requests"),
        ("GET", "/venue/guest-login-history"),
        ("GET", "/venue/campaigns"),
    }
)


def with_report_location(spec: TwinSpec) -> TwinSpec:
    if (spec.method, spec.path) not in REPORT_PATHS:
        return spec
    location_keys = [k for k, src in spec.inject.items() if src == ("location",)]
    if "location_id" not in location_keys:
        return spec
    also = tuple(k for k in location_keys if k != "location_id")
    extra = Extra(
        "isp_location_id",
        "query",
        "location",
        "location_id",
        forward_also=also,
    )
    return replace(spec, extras=spec.extras + (extra,))
