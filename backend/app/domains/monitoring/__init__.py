"""Monitoring domain (BE-011 Part 1): the Health Engine + Event Engine --
platform-wide/cross-domain health checks (database, redis, the API process
itself, auth, storage, an honestly-``UNKNOWN`` celery/websocket, and
FreeRADIUS/WireGuard proxy signals) and a unified, cross-domain event
timeline.

See ``service.py``'s module docstring for the full architectural write-up,
and ``docs/monitoring/FLOW.md`` for every design decision in detail.
"""
