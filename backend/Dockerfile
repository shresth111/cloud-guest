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

RUN chmod +x /app/scripts/run_api.sh \
    && mkdir -p /var/log/cloudguest

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/v1/health/live || exit 1

CMD ["/app/scripts/run_api.sh"]

