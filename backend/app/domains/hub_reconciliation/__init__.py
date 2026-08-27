"""Reconciliation between this platform's record of the fleet and the two
things that are actually true about it: the WireGuard hub's live peer
table, and the FreeRADIUS ``clients.conf`` keyed on the addresses in it.

## Why this is its own package

Because the failure it exists to prevent is not inside either domain -- it
is in the seam between them, which nothing owned.

A router's WireGuard tunnel address and its FreeRADIUS ``client{}`` stanza
are two halves of one fact. ``app.domains.wireguard`` decides the first.
``app.domains.guest`` writes the second, once, at registration, from
``peer.tunnel_ip_address``. Neither is wrong on its own and neither can be
fixed on its own: on 2026-08-27 the hub held a stanza for ``10.20.0.8``
while the device was handshaking on ``10.20.0.6``, and every guest login at
that venue was dropped as an unknown client -- silently, because FreeRADIUS
does not reply to one.

The import direction settles where the fix can live. ``app.domains.guest``
already imports ``app.domains.wireguard``; making WireGuard call back into
RADIUS would close a cycle. So ``WireGuardService`` takes a narrow
``PeerAddressListener`` (see its own docstring) and this package -- which is
allowed to know about both -- supplies it. That keeps each domain's
dependencies one-way and puts the cross-domain invariant in exactly one
readable place instead of at every call site that happens to move a peer.
"""
