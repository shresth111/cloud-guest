#!/bin/bash
# STAGING ONLY. Runs radius_agent.py (HTTP :9092 on AGENT_BIND_ADDR) and
# supervises freeradius. The agent restarts freeradius with
# `systemctl restart freeradius`; /usr/local/bin/systemctl is a shim that
# kills the current radiusd so the loop below starts a fresh one.
set -u
: "${RADIUS_AGENT_SECRET:?RADIUS_AGENT_SECRET must be set}"
: "${AGENT_BIND_ADDR:?AGENT_BIND_ADDR must be set (the docker bridge gateway, never 0.0.0.0)}"
[ "$AGENT_BIND_ADDR" = "0.0.0.0" ] && { echo "refusing AGENT_BIND_ADDR=0.0.0.0" >&2; exit 1; }

# First start on an empty volume: the image's seeded file is hidden by the
# mount, so recreate it.
if [ ! -s /var/lib/wyfy-radius/clients.conf ]; then
  printf '# wyfy staging: stanzas below are written by radius_agent.py only\n' > /var/lib/wyfy-radius/clients.conf
fi
chown freerad:freerad /var/lib/wyfy-radius /var/lib/wyfy-radius/clients.conf
chmod 0640 /var/lib/wyfy-radius/clients.conf

python3 -u /opt/wyfy/radius_agent.py &
AGENT=$!
trap 'kill $AGENT $(cat /run/wyfy-radiusd.pid 2>/dev/null) 2>/dev/null; exit 0' TERM INT

while true; do
  kill -0 "$AGENT" 2>/dev/null || { echo "radius-agent exited" >&2; exit 1; }
  freeradius -f -l stdout &
  echo $! > /run/wyfy-radiusd.pid
  wait $!
  echo "freeradius exited rc=$? -- restarting in 1s" >&2
  sleep 1
done
