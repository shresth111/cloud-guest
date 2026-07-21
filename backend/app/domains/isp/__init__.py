"""ISP Management domain: per-router WAN/ISP uplink inventory (provider,
type, role, bandwidth, gateway/DNS, interface), real health monitoring
(RouterOS ``/tool/ping``-backed latency/packet-loss checks) with history,
and automatic primary/backup failover.

Composes with ``app.domains.router`` (a router's own connection
credentials -- ``RouterLookupProtocol.get_decrypted_api_secret``, reused
directly, never re-decrypted here) via the same narrow-Protocol
composition-over-duplication pattern every other domain in this codebase
establishes. See ``docs/isp/FLOW.md`` for the full design write-up.
"""

from __future__ import annotations
