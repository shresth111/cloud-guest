"""Demo Booking domain -- the real calendar booking flow behind the public
"Book a Demo" call-to-action on wyfyguest.com.

See ``models.py`` for the data model (and why a booking is layered *on top
of* an ``app.domains.demo_request.models.DemoRequest`` rather than
replacing it), ``availability.py`` for the slot grid and its timezone
convention, and ``router.py`` for the public API contract.
"""
