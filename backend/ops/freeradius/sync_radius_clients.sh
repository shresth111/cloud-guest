#!/bin/bash
# Regenerates /etc/freeradius/3.0/clients.wyfy.conf from the real
# radius_nas_clients table (decrypting each NAS's shared secret via the
# same app.domains.router.crypto.decrypt_secret every other domain uses)
# and reloads FreeRADIUS only if the generated content actually changed --
# so a new/rotated NAS client is picked up automatically within one run
# of this timer, without ever needing another manual clients.conf edit.
set -euo pipefail

GEN_SCRIPT=/opt/wyfy/gen_clients_conf.py
TARGET=/etc/freeradius/3.0/clients.wyfy.conf
TMP=$(mktemp)

docker cp "$GEN_SCRIPT" deploy-api-1:/tmp/gen_clients_conf.py
docker exec deploy-api-1 python3 /tmp/gen_clients_conf.py > "$TMP" 2>/var/log/wyfy-radius-sync.err

if [ ! -s "$TMP" ]; then
    echo "$(date -u --iso-8601=seconds) sync produced empty output, keeping existing clients.wyfy.conf" >> /var/log/wyfy-radius-sync.log
    rm -f "$TMP"
    exit 0
fi

if ! diff -q "$TMP" "$TARGET" > /dev/null 2>&1; then
    cp "$TMP" "$TARGET"
    chown freerad:freerad "$TARGET"
    systemctl reload freeradius
    echo "$(date -u --iso-8601=seconds) clients.wyfy.conf changed, reloaded freeradius" >> /var/log/wyfy-radius-sync.log
fi

rm -f "$TMP"
