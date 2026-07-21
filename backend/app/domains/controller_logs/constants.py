"""Constants for the Controller Logs domain."""

from __future__ import annotations

from app.database.constants import MAX_PAGE_SIZE

# Provision Logs are stored per-job, not per-router -- listing "provision
# logs for a router" means fetching this router's own most recent jobs
# first, then merging each job's own logs. Bounded to the N most recent
# jobs rather than every job the router has ever had, a real, documented
# limit (never a silent, unbounded fetch) -- see
# docs/controller_logs/FLOW.md for the full reasoning.
MAX_PROVISION_JOBS_FOR_LOG_MERGE = 20

# CSV export is bounded to the most recent N rows. Every category here
# except Provision Logs reads through some domain's own
# ``GenericRepository.paginate`` (directly, or via that domain's own
# service method), which itself clamps ``page_size`` to ``MAX_PAGE_SIZE``
# (see ``app.database.utils.pagination.PageParams.__post_init__``) -- so
# a larger "export" bound here would silently get truncated one layer
# down rather than actually exporting more rows. Set equal to that real,
# already-enforced ceiling instead of inventing a separate, larger
# number that can never actually be reached.
MAX_EXPORT_ROWS = MAX_PAGE_SIZE

__all__ = ["MAX_PROVISION_JOBS_FOR_LOG_MERGE", "MAX_EXPORT_ROWS"]
