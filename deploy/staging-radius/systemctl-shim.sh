#!/bin/bash
# STAGING ONLY. Stand-in for `systemctl restart|reload freeradius` inside the
# staging RADIUS container (radius_agent.py calls it after every clients.conf
# write). Kills the supervised radiusd; entrypoint.sh starts a new one. Exits
# non-zero unless a NEW radiusd is still alive 2s after it started, so a
# config the server refuses makes the agent revert, exactly as on the hub.
set -u
[ "${2:-}" = "freeradius" ] || { echo "shim only handles freeradius" >&2; exit 1; }
case "${1:-}" in restart|reload) ;; *) echo "unsupported: $*" >&2; exit 1;; esac
PIDF=/run/wyfy-radiusd.pid
old=$(cat "$PIDF" 2>/dev/null || echo 0)
[ "$old" != 0 ] && kill -TERM "$old" 2>/dev/null
for _ in $(seq 1 50); do
  new=$(cat "$PIDF" 2>/dev/null || echo 0)
  [ "$new" != "$old" ] && [ "$new" != 0 ] && break
  sleep 0.2
done
[ "$new" = "$old" ] && { echo "freeradius did not come back" >&2; exit 1; }
sleep 2
kill -0 "$new" 2>/dev/null || { echo "freeradius exited right after restart" >&2; exit 1; }
exit 0
