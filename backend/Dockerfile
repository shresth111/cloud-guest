FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
COPY vendor ./vendor
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY alembic ./alembic
COPY alembic.ini .

# Traffic Lens "Geo Location" data: DB-IP Lite country + ASN (CC BY 4.0),
# about 18 MB, fetched here because it is not kept in the repository.
# Best effort on purpose: without the files the app starts and answers
# geo_available=false, so a db-ip.com outage must not fail a deploy.
# --build-arg FETCH_GEO_DATA=0 skips it.
ARG FETCH_GEO_DATA=1
RUN if [ "$FETCH_GEO_DATA" = "1" ]; then \
        python scripts/fetch_geo_data.py --dest /app/data/geo \
        || echo "WARNING: geo data not fetched; Geo Location will read 'not available'"; \
    fi

# Traffic Lens "known-bad destinations" list: Spamhaus DROP, about 110 kB.
# Free to use in a product, but its terms grant no right to redistribute, so
# it is fetched here and never kept in the (public) repository. Best effort
# on purpose: without the files the finding answers "could not be checked".
# --build-arg FETCH_THREAT_DATA=0 skips it.
ARG FETCH_THREAT_DATA=1
RUN if [ "$FETCH_THREAT_DATA" = "1" ]; then \
        python scripts/fetch_threat_data.py --dest /app/data/threat \
        || echo "WARNING: threat list not fetched; known-bad destinations will read 'could not be checked'"; \
    fi

# The processes run as a fixed non-root uid/gid (10001). The container starts
# as root only so scripts/docker-entrypoint.sh can chown the writable paths
# (the prod log volume is root-owned from earlier images) and then exec the
# command as `app` via setpriv; see that script for the fail-safe. Writable at
# runtime, and nothing else under /app:
#   /var/log/cloudguest  CLOUDGUEST_LOG_DIR in prod (named volume)
#   /app/logs            the log_dir default when CLOUDGUEST_LOG_DIR is unset
#   /app/var             ipdr_local_dir default (var/ipdr) when no IPDR bucket
#   /app (the directory itself, not its contents) -- celery beat writes its
#                        `celerybeat-schedule` file into the working directory
#   /tmp                 celery beat's pidfile
# Port 8000 is unprivileged, so binding needs no capability.
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --home-dir /app --no-create-home \
         --shell /usr/sbin/nologin app \
    && chmod +x /app/scripts/run_api.sh /app/scripts/docker-entrypoint.sh \
    && mkdir -p /var/log/cloudguest /app/logs /app/var \
    && chown app:app /app /var/log/cloudguest /app/logs /app/var

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/v1/health/live || exit 1

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD ["/app/scripts/run_api.sh"]

