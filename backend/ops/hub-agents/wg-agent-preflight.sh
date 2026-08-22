#!/bin/sh
# Refuse to start wg_agent unless it can allocate IPs safely and hand out a
# resolvable endpoint. Both failures are otherwise SILENT and unrepairable.
set -e
EXPECTED_MIN_PEERS=60
peers=$(wg show wg0 peers 2>/dev/null | wc -l)
if [ "$peers" -lt "$EXPECTED_MIN_PEERS" ]; then
    echo "PREFLIGHT FAIL: wg0 has $peers peers, expected >= $EXPECTED_MIN_PEERS." >&2
    echo "  next_free_ip() would re-issue 10.20.0.2 onward to already-live routers." >&2
    exit 1
fi
host=$(sed -n 's/^SERVER_ENDPOINT_HOST = "\(.*\)"/\1/p' /usr/local/sbin/wg_agent.py)
if ! getent hosts "$host" >/dev/null 2>&1; then
    echo "PREFLIGHT FAIL: SERVER_ENDPOINT_HOST '$host' does not resolve." >&2
    echo "  Every router provisioned would get an unreachable WireGuard endpoint." >&2
    exit 1
fi
echo "preflight OK: $peers peers, endpoint '$host' resolves"
