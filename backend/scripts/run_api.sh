#!/usr/bin/env sh
set -eu

alembic upgrade head

# FORWARDED_ALLOW_IPS controls which peer IPs uvicorn trusts to set
# X-Forwarded-Proto/X-Forwarded-For (its own ProxyHeadersMiddleware,
# always active, defaults to trusting only a literal "127.0.0.1" peer).
# Behind a host-level nginx reverse proxy in front of a Docker container
# published port, a loopback connection from the host arrives inside the
# container NATed to the Docker bridge gateway IP, not literally
# "127.0.0.1" -- confirmed live: request.base_url (used to build the
# guest-facing public logo/background-image URL in
# app.domains.captive_portal.router) kept reporting "http://" even
# though every real request reaches this API over real HTTPS, because
# the default trust check silently never matched and the real
# X-Forwarded-Proto: https header was correctly-but-wrongly ignored.
# Defaults to uvicorn's own "127.0.0.1" default (safe, no behavior
# change) when unset -- set to this deployment's real Docker bridge
# subnet (e.g. "172.18.0.0/16") in its own .env for a reverse-proxied
# deployment like this one.
uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}"

