"""Guest Teams domain: grouped guest access -- a named group of guests (a
corporate delegation, a wedding party, a conference cohort) who share one
access grant, are tracked/managed together as a unit via a shareable join
code, and can have their whole team's access revoked at once rather than one
guest at a time.

An extension of ``app.domains.guest``, not a replacement for any part of it:
this module never reimplements guest identity resolution or session
lifecycle -- it composes ``app.domains.guest.service.GuestService`` (its
``_get_or_create_guest``/``get_guest_sessions``/``terminate_session``/
``get_or_create_device``) for every guest- and session-level operation, the
same "compose the real domain, add only what is genuinely new" discipline
every prior domain in this codebase follows. What is genuinely new here is
the team itself: its own status lifecycle (``ACTIVE``/``EXPIRED``/
``REVOKED``), its own join code (reusing ``app.domains.voucher.constants
.VOUCHER_CODE_ALPHABET``'s exact print-friendly alphabet and
``secrets.choice`` generation approach -- not a re-derived alphabet), an
optional member cap, an optional pooled/shared data quota distinct from any
individual guest's own per-session quota, and an optional expiry.

See ``service.py``'s module docstring for the full architectural write-up
and ``docs/guest_teams/FLOW.md`` for every design decision's full reasoning.
"""
