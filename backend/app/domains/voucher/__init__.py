"""Voucher domain (BE-010 Part 2): admin-generated, printable access codes
that guests redeem at the captive portal for guest WiFi access -- no
username/password, no OTP round-trip.

Self-contained by design, like its sibling ``app.domains.otp`` (BE-010 Part
1): no ``Guest`` model exists yet (a later module in this same BE-010
sequence). ``Voucher.redeemed_identifier`` is a plain phone/email/device-MAC
string, not a foreign key -- the future ``guest`` domain composes with this
one purely through ``VoucherService.validate_voucher``/``redeem_voucher``'s
return values.

Unlike OTP codes (delivered by the platform to a verified phone/email, so a
hash is appropriate) or provisioning tokens (one-time, machine-presented),
a voucher code IS the thing physically handed to a person -- it is stored
in plaintext, not hashed, so it can be displayed/printed/exported. See
``models.py``'s module docstring for the full reasoning.

See ``docs/voucher/README.md`` for the full design write-up.
"""
