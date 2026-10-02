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
exec freeradius -f -l stdout
