"""Guest domain (BE-010 Part 4): the final domain in BE-010, composing
``app.domains.otp``/``app.domains.voucher``/``app.domains.captive_portal``/
``app.domains.router`` into a real guest WiFi login journey -- guest/device
identity, session lifecycle, a FreeRADIUS ``rlm_rest``-style HTTP
integration, and guest analytics.

See ``service.py``'s module docstring for the full architectural write-up.
"""
