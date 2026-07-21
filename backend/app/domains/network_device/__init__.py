"""Network Device (NAC) domain: a device identity/compliance registry --
vendor, device type, and an admin-assessed compliance status -- distinct
from ``app.domains.guest_access.DeviceAccessRule`` (an allow/deny
*decision*, MAC-keyed with no device-identity concept of its own) and from
``app.domains.connected_devices`` (live/recent presence telemetry,
sync-driven, no compliance concept at all). See docs/ARCHITECTURE_DESIGN.md
§6.2 for the full "NAC vs. access-decision layer" distinction this domain
implements.

## Honesty note: "compliance status" is admin-assessed, not detected

There is no real posture-inspection/endpoint-agent mechanism anywhere in
this codebase (and none is fabricated here) -- ``compliance_status`` is a
plain, admin-set field (``UNKNOWN`` until someone reviews it), the same
"real, if manual, workflow" posture ``app.domains.mac_authorization``
already takes for its own allow-list. This intentionally renames the
ADD's own "OS fingerprint" concept to ``device_type`` (an admin-entered
free-text classification, e.g. "laptop"/"iot-camera") -- "OS fingerprint"
implies real packet-based detection (e.g. p0f-style TCP/IP stack
fingerprinting) this codebase has no mechanism for and should not imply.

## This domain does not (yet) feed ``guest_access``

The ADD describes this domain's compliance status "feeding `guest_access`
as an input signal" for block decisions. This pass builds a complete,
standalone, real NAC registry with its own CRUD and compliance-assessment
workflow -- ready for a future ``NetworkDeviceLookupProtocol`` consumer --
but deliberately does not modify ``app.domains.guest_access``'s own
``AccessDecisionResolver``/``GuestAccessService`` in this pass, mirroring
the identical, deliberate scope boundary this same work already drew
around ``app.domains.identity`` and guest login.
"""

from __future__ import annotations
