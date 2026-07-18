"""OTP domain (BE-010 Part 1): guest-facing one-time-passcode request and
verification, delivered via SMS or email, used to authenticate guest WiFi
captive-portal logins.

Self-contained by design: no ``Guest`` model exists yet (a later module in
this same BE-010 sequence). ``OtpRequest.identifier`` is a plain phone
number/email string, not a foreign key -- the future ``guest`` domain
composes with this one purely through ``OtpService.verify_otp``'s return
value.

See ``docs/otp/README.md`` for the full design write-up.
"""
