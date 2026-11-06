#!/usr/bin/env bash
# Days left on the hotspot fleet certificate, as an exit code an alarm can use.
#
#   check-hotspot-cert-expiry.sh [--pem PATH] [--connect HOST:PORT --servername NAME]
#                                [--warn-days N] [--metric NAMESPACE]
#
#   exit 0  more than --warn-days (default 21) left
#   exit 1  fewer than --warn-days left          -> someone must act this week
#   exit 2  expired, missing, or unreadable      -> guests are (or soon will be) broken
#
# Default source: the certbot lineage on this host,
# /etc/letsencrypt/live/wyfy-hotspot-fleet/fullchain.pem. A missing lineage is
# exit 2, not "nothing to check": on 2026-09-06 the lineage was found absent
# on the AWS box while routers served a hand-pushed cert due to expire
# 2026-11-16, and "no file, so no alert" is exactly how that went unnoticed.
#
# --connect checks a certificate as SERVED instead (openssl s_client), for any
# TLS endpoint this host can reach. Routers' hotspot HTTPS listens on their
# guest LAN, which the app box generally cannot reach; use --pem for the
# routine check and --connect from somewhere on a venue LAN when in doubt.
#
# --metric NAMESPACE also publishes HotspotCertDaysRemaining (Count) with
# `aws cloudwatch put-metric-data` (instance role needs cloudwatch:PutMetricData).
# Missing/unreadable publishes -1, so one "< 21" alarm covers every bad state.
# Alarm on: Minimum < 21 over 1 day, and treat missing data as breaching.
#
# Read-only. Never contacts a router's API, never changes anything.
set -uo pipefail

PEM="/etc/letsencrypt/live/wyfy-hotspot-fleet/fullchain.pem"
CONNECT=""
SERVERNAME="wifi.wyfyguest.com"
WARN_DAYS=21
NAMESPACE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pem)        PEM="$2"; shift 2 ;;
    --connect)    CONNECT="$2"; shift 2 ;;
    --servername) SERVERNAME="$2"; shift 2 ;;
    --warn-days)  WARN_DAYS="$2"; shift 2 ;;
    --metric)     NAMESPACE="$2"; shift 2 ;;
    -h|--help)    sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

publish() {
  [[ -n "$NAMESPACE" ]] || return 0
  aws cloudwatch put-metric-data --namespace "$NAMESPACE" \
    --metric-name HotspotCertDaysRemaining --unit Count --value "$1" \
    || echo "WARNING: could not publish the CloudWatch metric" >&2
}

crit() { echo "CRITICAL: $*"; logger -t wyfy-hotspot-cert-expiry -- "CRITICAL: $*" 2>/dev/null || true; publish -1; exit 2; }

if [[ -n "$CONNECT" ]]; then
  SRC="served by $CONNECT (SNI $SERVERNAME)"
  END="$(openssl s_client -connect "$CONNECT" -servername "$SERVERNAME" </dev/null 2>/dev/null \
         | openssl x509 -noout -enddate 2>/dev/null)" || true
else
  SRC="$PEM"
  [[ -r "$PEM" ]] || crit "$PEM does not exist or is not readable -- nothing on this host can renew the hotspot certificate"
  END="$(openssl x509 -in "$PEM" -noout -enddate 2>/dev/null)" || true
fi
END="${END#notAfter=}"
[[ -n "$END" ]] || crit "could not read a certificate from $SRC"

END_EPOCH="$(date -d "$END" +%s 2>/dev/null)" || crit "could not parse expiry '$END'"
DAYS=$(( (END_EPOCH - $(date +%s)) / 86400 ))

publish "$DAYS"
if (( END_EPOCH <= $(date +%s) )); then
  crit "hotspot certificate ($SRC) EXPIRED on $END"
elif (( DAYS < WARN_DAYS )); then
  echo "WARNING: hotspot certificate ($SRC) expires $END -- $DAYS day(s) left (< $WARN_DAYS)"
  logger -t wyfy-hotspot-cert-expiry -- "WARNING: $DAYS day(s) left, expires $END" 2>/dev/null || true
  exit 1
fi
echo "OK: hotspot certificate ($SRC) expires $END -- $DAYS day(s) left"
