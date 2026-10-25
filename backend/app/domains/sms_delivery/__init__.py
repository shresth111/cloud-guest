"""SMS delivery log: one row per real SMS send attempt, its provider outcome,
and the provider's delivery report (DLR) when one actually arrives.

See ``recorder`` (writing a row at every send site), ``dlr`` (turning a
provider answer into a status, or into nothing), ``service`` (forward-only
DLR application, the DLR poller, the day-wise report, retention) and
``router`` (the report endpoint and the inbound DLR callback).

"Delivered" is only ever written from a provider delivery report. A send the
provider accepted is ``sent``; nothing infers delivery from acceptance.
"""
