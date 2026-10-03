#!/bin/bash
# STAGING ONLY. RadSec container entrypoint: check the mounted certs, make sure
# the (possibly empty) enrolment map exists, validate the config, run radiusd.
set -euo pipefail
for f in server.pem server.key trust.pem; do
  [ -s "/etc/wyfy-radsec/$f" ] || { echo "missing /etc/wyfy-radsec/$f (run install.sh)" >&2; exit 1; }
done
case "${RADSEC_TLS_MAX:-}" in 1.2|1.3) ;; *) echo "RADSEC_TLS_MAX must be 1.2 or 1.3" >&2; exit 1;; esac
M=/var/lib/wyfy-radsec/radsec-map
[ -e "$M" ] || : > "$M"
chown root:freerad /var/lib/wyfy-radsec "$M"; chmod 0770 /var/lib/wyfy-radsec; chmod 0640 "$M"
touch /var/lib/wyfy-radsec/connections.log; chown freerad:freerad /var/lib/wyfy-radsec/connections.log
freeradius -C >/dev/null || { freeradius -CX 2>&1 | tail -20; exit 1; }
echo "radsec: $(grep -c . "$M" || true) enrolled certificate(s); trust.pem holds $(grep -c 'BEGIN CERTIFICATE' /etc/wyfy-radsec/trust.pem) CA(s); TLS max $RADSEC_TLS_MAX"
# rlm_passwd reads the map only at start-up. Whoever changes it (radsec-map.sh,
# or the hub agent's /radius/radsec-client once that ships to staging) only
# has to write the file: a change of mtime/size restarts radiusd here. Open
# TLS connections drop and the devices reconnect.
sig() { stat -c '%Y %s' "$M" 2>/dev/null; }
trap 'kill "$(cat /run/wyfy-radsecd.pid 2>/dev/null)" 2>/dev/null; exit 0' TERM INT
while true; do
  freeradius -f -l stdout &
  echo $! > /run/wyfy-radsecd.pid
  last=$(sig)
  while kill -0 "$(cat /run/wyfy-radsecd.pid)" 2>/dev/null; do
    sleep 3
    now=$(sig)
    if [ "$now" != "$last" ]; then
      if freeradius -C >/dev/null 2>&1; then
        echo "radsec: enrolment map changed ($(grep -c . "$M" || true) line(s)) -- restarting radiusd"
        kill "$(cat /run/wyfy-radsecd.pid)"; wait "$(cat /run/wyfy-radsecd.pid)" 2>/dev/null
        break
      fi
      echo "radsec: map changed but the config no longer validates -- keeping the running radiusd" >&2
      last=$now
    fi
  done
  sleep 1
done
