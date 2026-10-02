#!/bin/bash
# STAGING ONLY. Discovery capture for a RadSec client we have never seen (the
# Instant On AP). Run as root on wyfy-staging-server WHILE the device tries to
# connect, e.g. right after flipping enableRadiusOverTls on its RADIUS profile:
#   DURATION=900 ~/wyfy-ops/ssm-run-on.sh i-0a6a08bb87c6f0f84 deploy/staging-radius/radsec-capture.sh
# (ssm-run-on.sh polls ~180 s; for longer captures run it with nohup on the box
#  and read the report afterwards: OUT dir below.)
# Prints: every TCP connection to 2083 (source ip:port -- under CGNAT this is
# the carrier's address), the ClientHello (SNI, versions), whether the server
# accepted the client certificate, and the client's certificate chain (cleartext
# because the listener is pinned to TLS 1.2), saved as PEM for radsec-map.sh.
set -uo pipefail
DURATION=${DURATION:-170}
PORT=${PORT:-2083}
RD=/home/ubuntu/deploy/staging-radius/radsec
SRC=$(cd "$(dirname "$0")" && pwd)
[ -f "$SRC/radsec_pcap.py" ] || SRC=/home/ubuntu/deploy/staging-radius/src/deploy/staging-radius
OUT=$RD/captures/$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0750 "$OUT"
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "capturing tcp port $PORT on all interfaces for ${DURATION}s -> $OUT/radsec.pcap"
timeout "$DURATION" tcpdump -i any -s 0 -U -n -w "$OUT/radsec.pcap" "tcp port $PORT" 2>"$OUT/tcpdump.err"
echo "tcpdump: $(tail -2 "$OUT/tcpdump.err" | tr '\n' ' ')"
python3 "$SRC/radsec_pcap.py" "$OUT/radsec.pcap" "$OUT/certs" "$PORT" | tee "$OUT/report.txt"
echo; echo "== radsec container log since $START (TLS errors, connection open/close)"
docker logs --since "$START" wyfy-staging-radius-radsec-1 2>&1 | grep -vE 'Waking up|Ready to process' | tail -40
echo; echo "== connections.log since $START"
awk -v s="$(date -u -d "$START" '+%Y-%m-%d %H:%M:%S')" '$0 >= s' "$RD/state/connections.log" 2>/dev/null | tail -20
echo; echo "report: $OUT/report.txt  certs: $OUT/certs/"
