"""Network Diagnostics domain: real, on-demand ``ping``/``traceroute``
against a router, executed synchronously (an admin asks now, gets a real
result in the HTTP response), with every attempt -- successful or
failed -- recorded as an immutable ``DiagnosticRun`` row.

## A genuinely different shape from the "config resource" domains

Unlike DHCP/VLAN/Port Forwarding/Hotspot/QoS (static inventory tables,
realized onto a device later by ``app.domains.network_config``), this
domain is a real-time *execution* domain -- closer in shape to
``app.domains.device_sync``. It owns no config to render and is
therefore never composed into ``network_config``'s own pipeline.

## Composition, not duplication

``app.domains.isp.device_adapters.MikroTikIspHealthAdapter.ping`` is the
only pre-existing ping-shaped capability anywhere in this codebase (used
for WAN-uplink health checks). Its exact RouterOS command/reply-parsing
logic is mirrored here (not imported at runtime -- diagnostics is
router-generic, not WAN-link-specific, so a runtime dependency on the
ISP domain would be a real, if narrow, architectural mismatch) --
``docs/network_diagnostics/FLOW.md`` documents this choice. Traceroute
has zero precedent anywhere in this codebase and is genuinely new
adapter code.

``app.domains.router_agent``'s pull-model provisioning queue was
considered and rejected as the execution mechanism -- see that domain's
own docs and this domain's ``FLOW.md`` §1 for why a retryable,
attempts-tracked config-mutation job queue is the wrong shape for a
synchronous "run once, return the result now" diagnostic.
"""

from __future__ import annotations
