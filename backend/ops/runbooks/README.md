# Operator runbooks

Procedures an operator runs by hand against real hardware.

## Why these live in the repo now

`mikrotik-router-setup.rsc` spent its life as a loose file in one person's
home directory, in no git repository at all. No history, no review, and no way
to know which operators were holding which copy.

That is not a filing preference. On 2026-09-06 the file's **troubleshooting**
section — the part read precisely when someone is already fighting a broken
venue and is most likely to paste without thinking — was found to instruct:

```
login-by me http-pap nahi -> set [find name=hsprof1] login-by=https,http-pap
```

The same file creates a **self-signed** certificate. `https` in `login-by`
plus a certificate no guest device trusts is the exact combination the
generators had already been fixed to avoid, and it produces three symptoms at
once:

1. no sign-in page on Windows or macOS at all,
2. the captive-portal window never closing after login,
3. a certificate warning on Android.

Confirmed live on 2026-08-23 from a provisioned hEX, Windows and macOS both on
a LAN cable. The generators were corrected; this document was not, because
nothing connected the two. **A runbook that drifts from the code it describes
is a defect with no owner and no test**, and keeping it here at least gives it
a diff.

## The rule this file exists to enforce

**`login-by=http-pap`. Never `https`.** Both generators — the backend renderer
(`app/domains/network_config/renderers.py`) and the Master Console script
generator — write exactly that one value, and each says in its own comment why
there is exactly one writer of it. Any runbook, ticket or piece of tribal
knowledge that says otherwise is out of date and is actively breaking venues.

## If you hold an older copy

Copies of this file were circulated outside version control. If you have one:
delete it and use this. If you have *given* one to someone, tell them. There
is no way to enumerate who has what — that is the cost of the file having
lived outside a repository, and it is the reason it does not any more.
