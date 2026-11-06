#!/bin/sh
# Drop from root to the unprivileged `app` user (uid/gid 10001) before running
# the real command (uvicorn via run_api.sh, or a celery worker/beat).
#
# Why an entrypoint and not a bare `USER app` in the Dockerfile: the prod log
# volume (cloudguest_logs -> /var/log/cloudguest) was created by root images
# and its files are root-owned. A process that STARTS as uid 10001 cannot fix
# that, the app's RotatingFileHandler fails to open the log file, and the api
# never boots -- every guest login fails. Starting as root just long enough to
# chown the writable paths, then exec'ing as `app`, needs no box step.
#
# Fail-safe: if the log dir still is not writable by `app` after the chown
# (read-only mount, odd filesystem), or setpriv is missing, this logs a WARNING
# and runs the command as root exactly as before, rather than crash-looping.
# CLOUDGUEST_RUN_AS_ROOT=1 forces the old behaviour.
set -eu

APP_USER=app
LOG_DIR="${CLOUDGUEST_LOG_DIR:-logs}"
case "$LOG_DIR" in /*) ;; *) LOG_DIR="/app/$LOG_DIR" ;; esac

if [ "$(id -u)" = "0" ] && [ "${CLOUDGUEST_RUN_AS_ROOT:-0}" != "1" ]; then
  for d in "$LOG_DIR" /app/logs /app/var; do
    mkdir -p "$d" 2>/dev/null || true
    chown -R "$APP_USER:$APP_USER" "$d" 2>/dev/null || true
  done
  # shellcheck disable=SC2016  # $1 is expanded by the inner sh, on purpose
  if command -v setpriv >/dev/null 2>&1 \
     && setpriv --reuid="$APP_USER" --regid="$APP_USER" --init-groups \
          sh -c 'test -w "$1" && test -w /app' _ "$LOG_DIR" 2>/dev/null; then
    exec setpriv --reuid="$APP_USER" --regid="$APP_USER" --init-groups -- "$@"
  fi
  echo "WARNING: docker-entrypoint: $LOG_DIR or /app is not writable by $APP_USER (or setpriv is missing); running as root" >&2
fi
exec "$@"
