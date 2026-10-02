"""The Security domain -- venue security posture, and the honest record of
what this platform can and cannot enforce.

One read-only aggregation domain. It owns no tables, writes nothing to any
database, and never constructs a device adapter; every number it reports is
already stored by the domain that produced it. See ``constants``'s module
docstring for why owning no tables is the point rather than a first-pass
shortcut, and ``repository``'s for how the cross-domain reads are shaped.

The capability matrix in ``constants.SECURITY_FEATURES`` is the other half of
the domain, and the more important half: it is what lets the dashboard show a
feature as available only where it can actually be enforced. A feature this
platform cannot honour is returned as explicitly unavailable, with the missing
dependency named, rather than as a toggle that writes a row.
"""

__all__: list[str] = []
