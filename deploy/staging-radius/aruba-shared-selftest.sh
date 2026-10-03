#!/bin/bash
# STAGING ONLY. Self-test of the shared Aruba Instant On listener (UDP
# 1912/1913), no AP needed. Run as root on wyfy-staging-server:
#   ~/wyfy-ops/ssm-run-on.sh i-0a6a08bb87c6f0f84 deploy/staging-radius/aruba-shared-selftest.sh
# Every packet is sent from 127.0.0.1, an address with NO client{} in
# clients.conf: the point is that identity comes from inside the packet.
#   S1  1812 from that unregistered source is still dropped (default listener
#       unchanged: "unknown client")
#   S2  1912 with a wrong secret -> dropped (Message-Authenticator invalid)
#   S3  1912 with no Message-Authenticator -> dropped
# With the real shared secret (read inside the container into a shell
# variable, never printed; skipped while the placeholder is still in place):
#   S4  right NAS-Identifier + right AP MAC -> reaches /radius/aruba-shared/
#       authorize and is NOT refused by the shared resolver (Access-Reject only
#       because no guest session exists for this test identifier)
#   S5  right NAS-Identifier + WRONG AP MAC -> Access-Reject, api logs
#       radius_aruba_shared_rejected reason=ap_mac_mismatch
#   S6  unknown NAS-Identifier -> Access-Reject, reason=nas_unknown
#   S7  Accounting-Request Start on 1913 -> Accounting-Response
# NAS_ID / AP_MAC default to the staging AP21.
set -uo pipefail
R=wyfy-staging-radius-radius-1
A=deploy-api-1
NAS_ID="${NAS_ID:-cg-aruba-9e6069de}"
AP_MAC="${AP_MAC:-54-F0-B1-C8-A9-0A}"
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PASS=0; FAIL=0; SKIP=0
res() { if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "PASS $2"; else FAIL=$((FAIL+1)); echo "FAIL $2"; fi; }
skip() { SKIP=$((SKIP+1)); echo "SKIP $1"; }
rc() { docker exec -i $R radclient -x -r 1 -t 6 127.0.0.1:$1 $2 "$3" 2>&1; }
pkt() {  # pkt <nas-id> <called-station-id> [with-MA]
  printf 'User-Name = "+919999900077"\nUser-Password = "wyfy-shared-selftest"\nCalling-Station-Id = "a4c3f0112277"\nNAS-Identifier = "%s"\nCalled-Station-Id = "%s"\nNAS-Port-Type = Wireless-802.11\nService-Type = Login-User\n' "$1" "$2"
  [ "${3:-1}" = 1 ] && printf 'Message-Authenticator = 0x00\n'
}
RANDOM_SECRET=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)

echo "== listeners"; ss -Hlnu '( sport = :1812 or sport = :1913 or sport = :1912 or sport = :1813 )' | awk '{print $5}' | sort -u | tr '\n' ' '; echo
! docker exec $R grep -q 'ipaddr = 127.0.0.1/32' /etc/freeradius/3.0/clients.conf; res $? "127.0.0.1 has no client{} in clients.conf"

o=$(pkt "$NAS_ID" "$AP_MAC:WYFY_ARUBA" | rc 1812 auth "$RANDOM_SECRET"); echo "$o" | grep -E 'Received|No reply'
echo "$o" | grep -q 'No reply'; res $? "S1 1812 from an unregistered source -> dropped (default listener unchanged)"
o=$(pkt "$NAS_ID" "$AP_MAC:WYFY_ARUBA" | rc 1912 auth "$RANDOM_SECRET"); echo "$o" | grep -E 'Received|No reply'
echo "$o" | grep -q 'No reply'; res $? "S2 1912 wrong secret -> dropped"

SHARED=$(docker exec $R sh -c "grep -q '^# PLACEHOLDER' /var/lib/wyfy-radius/wyfy-aruba-shared-clients.conf && exit 0; awk '/^[[:space:]]*secret = /{print \$3; exit}' /var/lib/wyfy-radius/wyfy-aruba-shared-clients.conf")
if [ -z "$SHARED" ]; then
  o=$(pkt "$NAS_ID" "$AP_MAC:WYFY_ARUBA" 0 | rc 1912 auth "$RANDOM_SECRET"); echo "$o" | grep -q 'No reply'; res $? "S3 1912 no Message-Authenticator -> dropped"
  for t in S4 S5 S6 S7; do skip "$t: shared secret is still the placeholder (set it in Master first)"; done
else
  echo "   shared secret fp $(printf '%s' "$SHARED" | sha256sum | cut -c1-12) (len ${#SHARED})"
  o=$(pkt "$NAS_ID" "$AP_MAC:WYFY_ARUBA" 0 | rc 1912 auth "$SHARED"); echo "$o" | grep -E 'Received|No reply'
  echo "$o" | grep -q 'No reply'; res $? "S3 1912 right secret but no Message-Authenticator -> dropped"
  o=$(pkt "$NAS_ID" "$AP_MAC:WYFY_ARUBA" | rc 1912 auth "$SHARED"); echo "$o" | grep -E 'Received|No reply'
  echo "$o" | grep -q 'Received Access-'; res $? "S4 right NAS-ID + AP MAC -> answered"
  o=$(pkt "$NAS_ID" "AA-BB-CC-00-00-01:WYFY_ARUBA" | rc 1912 auth "$SHARED"); echo "$o" | grep -E 'Received|No reply'
  echo "$o" | grep -q 'Received Access-Reject'; res $? "S5 wrong AP MAC -> Access-Reject"
  o=$(pkt "cg-aruba-00000000" "$AP_MAC:WYFY_ARUBA" | rc 1912 auth "$SHARED"); echo "$o" | grep -E 'Received|No reply'
  echo "$o" | grep -q 'Received Access-Reject'; res $? "S6 unknown NAS-ID -> Access-Reject"
  o=$(printf 'Acct-Status-Type = Start\nUser-Name = "+919999900077"\nCalling-Station-Id = "a4c3f0112277"\nAcct-Session-Id = "SHARED-SELFTEST-1"\nNAS-Identifier = "%s"\nCalled-Station-Id = "%s:WYFY_ARUBA"\nMessage-Authenticator = 0x00\n' "$NAS_ID" "$AP_MAC" | rc 1913 acct "$SHARED"); echo "$o" | grep -E 'Received|No reply'
  echo "$o" | grep -q 'Received Accounting-Response'; res $? "S7 1913 Accounting-Request -> Accounting-Response"
  sleep 1
  L=$(docker logs --since "$START" $A 2>&1)
  echo "$L" | grep -q '/radius/aruba-shared/authorize'; res $? "api received /radius/aruba-shared/authorize"
  echo "$L" | grep -q 'ap_mac_mismatch'; res $? "api logged reason ap_mac_mismatch (S5)"
  echo "$L" | grep -q 'nas_unknown'; res $? "api logged reason nas_unknown (S6)"
  echo "-- api shared-listener log lines"
  echo "$L" | grep -E 'radius_aruba_shared_rejected|/radius/aruba-shared/' | cut -c1-240 | tail -n 10
fi
unset SHARED
echo "-- freeradius log since start"
docker logs --since "$START" $R 2>&1 | grep -vE '^\s*$|Info: ' | tail -n 12
echo "== $PASS passed, $FAIL failed, $SKIP skipped"
[ $FAIL -eq 0 ]
