"""Analytics domain (BE-012 Part 1: Analytics Core Infrastructure).

Celery + Beat-scheduled aggregation over ``app.domains.guest``/
``app.domains.router``/``app.domains.organization``/``app.domains.location``
data into persisted ``AnalyticsSnapshot`` rollups
(``ORG_DAILY_SUMMARY``/``LOCATION_DAILY_SUMMARY``/``PLATFORM_DAILY_SUMMARY``).
See ``docs/analytics/README.md`` and ``docs/analytics/FLOW.md`` for the full
architecture write-up.
"""
