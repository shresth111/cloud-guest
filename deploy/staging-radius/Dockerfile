# STAGING ONLY. FreeRADIUS 3.2.1 + the hub's radius_agent.py in one container,
# built from THIS repo's backend/ops config so staging exercises the same
# rest.conf / site snippets / client-stanza writer as the prod hub.
# Build context: the repo root (see docker-compose.yml).
FROM freeradius/freeradius-server:3.2.1 AS stock

# --- stage 1: splice the repo's authorize/accounting snippets into the stock site
FROM python:3.12-slim AS gen
COPY --from=stock /etc/freeradius/sites-available/default /gen/stock-default
COPY backend/ops/freeradius/rest.conf                     /gen/rest.conf
COPY backend/ops/freeradius/sites-default.snippets.conf   /gen/snippets.conf
COPY deploy/staging-radius/gen_site.py                    /gen/gen_site.py
RUN python3 /gen/gen_site.py /gen

# --- stage 2: runtime
FROM freeradius/freeradius-server:3.2.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=gen /gen/out/default /etc/freeradius/sites-available/default
COPY --from=gen /gen/out/rest    /etc/freeradius/mods-available/rest
# The shared Aruba Instant On listener (UDP 1912/1913): its own server, its own
# client list (backend/ops/freeradius/sites-aruba-shared.conf), its own rest
# instance. Its client file lives on the volume beside clients.conf and is
# written only by the agent's POST /radius/shared-client.
COPY --from=gen /gen/out/rest_aruba /etc/freeradius/mods-available/rest_aruba
COPY backend/ops/freeradius/sites-aruba-shared.conf /etc/freeradius/sites-available/wyfy-aruba-shared
# The image is Ubuntu 20.04 (python 3.8); the agent uses PEP 604 `X | None`
# in signatures. Postponed annotations make that a no-op on 3.8 without
# touching the agent's logic; the import check below proves it loads.
COPY backend/ops/hub-agents/radius_agent.py /opt/wyfy/radius_agent.py
RUN sed -i '0,/^import /s//from __future__ import annotations\nimport /' /opt/wyfy/radius_agent.py \
 && cd /opt/wyfy && python3 -c 'import radius_agent; assert radius_agent.CLIENTS_CONF == "/etc/freeradius/3.0/clients.conf"'
COPY deploy/staging-radius/entrypoint.sh     /opt/wyfy/entrypoint.sh
COPY deploy/staging-radius/systemctl-shim.sh /usr/local/bin/systemctl
# clients.conf lives on a volume (stanzas are written at runtime by the agent).
# The agent hardcodes the Ubuntu-package path /etc/freeradius/3.0/clients.conf,
# so both that path and the image's own path point at the volume copy. The
# image's stock clients.conf (localhost/testing123) is NOT carried over.
COPY deploy/staging-radius/aruba-shared-placeholder.sh /opt/wyfy/aruba-shared-placeholder.sh
RUN ln -sf ../mods-available/rest /etc/freeradius/mods-enabled/rest \
 && ln -sf ../mods-available/rest_aruba /etc/freeradius/mods-enabled/rest_aruba \
 && ln -sf ../sites-available/wyfy-aruba-shared /etc/freeradius/sites-enabled/wyfy-aruba-shared \
 && mkdir -p /etc/freeradius/3.0 /var/lib/wyfy-radius \
 && printf '# wyfy staging: stanzas below are written by radius_agent.py only\n' > /var/lib/wyfy-radius/clients.conf \
 && ln -sf /var/lib/wyfy-radius/clients.conf /etc/freeradius/clients.conf \
 && ln -sf /var/lib/wyfy-radius/clients.conf /etc/freeradius/3.0/clients.conf \
 && chmod 0755 /opt/wyfy/aruba-shared-placeholder.sh \
 && /opt/wyfy/aruba-shared-placeholder.sh /var/lib/wyfy-radius/wyfy-aruba-shared-clients.conf \
 && ln -sf /var/lib/wyfy-radius/wyfy-aruba-shared-clients.conf /etc/freeradius/wyfy-aruba-shared-clients.conf \
 && ln -sf /var/lib/wyfy-radius/wyfy-aruba-shared-clients.conf /etc/freeradius/3.0/wyfy-aruba-shared-clients.conf \
 && chown -R freerad:freerad /etc/freeradius /var/lib/wyfy-radius \
 && chmod 0755 /opt/wyfy/entrypoint.sh /usr/local/bin/systemctl \
 && WYFY_RADIUS_API_URI=http://127.0.0.1:8000/api/v1 freeradius -CX | tail -1 | grep -q 'Configuration appears to be OK'
ENV WYFY_RADIUS_API_URI=http://127.0.0.1:8000/api/v1
ENTRYPOINT ["/opt/wyfy/entrypoint.sh"]
