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
COPY backend/ops/hub-agents/radius_agent.py /opt/wyfy/radius_agent.py
COPY deploy/staging-radius/entrypoint.sh     /opt/wyfy/entrypoint.sh
COPY deploy/staging-radius/systemctl-shim.sh /usr/local/bin/systemctl
# clients.conf lives on a volume (stanzas are written at runtime by the agent).
# The agent hardcodes the Ubuntu-package path /etc/freeradius/3.0/clients.conf,
# so both that path and the image's own path point at the volume copy. The
# image's stock clients.conf (localhost/testing123) is NOT carried over.
RUN ln -sf ../mods-available/rest /etc/freeradius/mods-enabled/rest \
 && mkdir -p /etc/freeradius/3.0 /var/lib/wyfy-radius \
 && printf '# wyfy staging: stanzas below are written by radius_agent.py only\n' > /var/lib/wyfy-radius/clients.conf \
 && ln -sf /var/lib/wyfy-radius/clients.conf /etc/freeradius/clients.conf \
 && ln -sf /var/lib/wyfy-radius/clients.conf /etc/freeradius/3.0/clients.conf \
 && chown -R freerad:freerad /etc/freeradius /var/lib/wyfy-radius \
 && chmod 0755 /opt/wyfy/entrypoint.sh /usr/local/bin/systemctl \
 && WYFY_RADIUS_API_URI=http://127.0.0.1:8000/api/v1 freeradius -CX | tail -1 | grep -q 'Configuration appears to be OK'
ENV WYFY_RADIUS_API_URI=http://127.0.0.1:8000/api/v1
ENTRYPOINT ["/opt/wyfy/entrypoint.sh"]
