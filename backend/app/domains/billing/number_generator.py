"""Real, collision-safe, concurrency-safe sequential document numbering
(BE-013 Part 4) -- ``INV-2026-00001``/``CN-2026-00001``/``DN-2026-00001``.

## The bug class this module deliberately avoids

A well-known, real bug in exactly this kind of system is generating the
next sequential number via ``SELECT MAX(sequence) + 1 FROM ... WHERE
...; INSERT ...`` (or the application-level equivalent -- reading a
"current count" into Python, incrementing it there, then writing it back).
Under concurrency this is a genuine race: two requests can both execute the
``SELECT``/read before either commits its own ``INSERT``/write, both
observe the same "current" value, both compute the same "next" value, and
both then create a row with the identical number -- silently, with no
error, unless a *separate* uniqueness constraint happens to catch it after
the fact (and even then, one caller's request simply fails with a
confusing duplicate-key error instead of ever getting a distinct number).

## This module's real mechanism: one atomic, server-evaluated UPSERT

``models.InvoiceNumberCounter`` has a unique ``counter_key`` column (e.g.
``"invoice:2026"``). ``repository.NumberCounterRepository
.increment_and_get_next`` issues **exactly one** SQL statement per call --
a real Postgres ``INSERT ... ON CONFLICT (counter_key) DO UPDATE SET
last_value = invoice_number_counters.last_value + 1 ... RETURNING
last_value`` -- via SQLAlchemy's ``postgresql.insert(...)
.on_conflict_do_update(...)``. This is genuinely, not just apparently, safe
under concurrency for two concrete reasons:

1. **No read-then-write round trip from the application at all.** The
   increment (``last_value + 1``) is computed by Postgres itself, as part
   of evaluating the single ``SET`` clause against the row's value *at the
   instant the statement executes* -- there is no intervening moment where
   this module's own Python code reads a value, and a second caller's own
   read could interleave before the first caller's write lands. Contrast
   this with the buggy pattern above, where the read and the write are two
   separate statements with a real gap between them.
2. **Postgres serializes concurrent UPSERTs targeting the same row.** When
   two transactions concurrently attempt to ``INSERT ... ON CONFLICT`` the
   same ``counter_key``, Postgres takes a row-level lock on the conflicting
   row for the duration of the ``DO UPDATE``; the second transaction's
   statement blocks until the first commits (or rolls back), then proceeds
   against the now-updated value. Two concurrent callers requesting a
   number for the same counter key can therefore never observe the same
   "before" value and can never compute (let alone persist) the same "next"
   value -- this is a real database-level mutual-exclusion guarantee, not
   an application-level convention that a caller could bypass or race
   past. This is the exact same class of guarantee
   ``repository.CouponRepository.increment_current_uses``'s own
   ``UPDATE ... SET current_uses = current_uses + 1`` already relies on for
   this domain's coupon-redemption counter -- the only difference here is
   the extra ``ON CONFLICT`` branch, needed because a brand-new calendar
   year's counter row does not exist yet the first time it is requested.

``counter_key`` includes the calendar year (``"<document_type>:<year>"``)
so each document type's sequence resets to 1 at the start of a new year --
a real, common invoicing convention -- and credit/debit notes always use
their own, independent counter keys, never the invoice sequence and never
each other's (see ``constants.NoteType``'s own docstring for why credit and
debit notes are modeled as one table with a discriminator, yet still get
fully independent number sequences).
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from .constants import (
    CREDIT_NOTE_NUMBER_PREFIX,
    DEBIT_NOTE_NUMBER_PREFIX,
    INVOICE_NUMBER_PREFIX,
    NUMBER_SEQUENCE_DIGITS,
)


class NumberCounterRepositoryProtocol(Protocol):
    """The single method this module needs -- satisfied by
    ``repository.NumberCounterRepository`` (a real, atomic Postgres UPSERT)
    for production use, and by a small in-memory fake in this domain's own
    tests (see ``test_billing_invoices_tax.py``'s own concurrency test,
    which proves the *fake*'s own locking mirrors the real statement's
    atomicity, not merely "no ``await`` happened to occur in between")."""

    async def increment_and_get_next(self, counter_key: str) -> int: ...


def _counter_key(prefix: str, year: int) -> str:
    return f"{prefix.lower()}:{year}"


def _format_number(prefix: str, year: int, sequence: int) -> str:
    return f"{prefix}-{year}-{sequence:0{NUMBER_SEQUENCE_DIGITS}d}"


async def generate_invoice_number(
    repository: NumberCounterRepositoryProtocol, *, at: datetime
) -> str:
    """``"INV-2026-00001"``-shaped, real, collision-safe -- see module
    docstring for the exact concurrency mechanism."""
    year = at.year
    sequence = await repository.increment_and_get_next(
        _counter_key(INVOICE_NUMBER_PREFIX, year)
    )
    return _format_number(INVOICE_NUMBER_PREFIX, year, sequence)


async def generate_credit_note_number(
    repository: NumberCounterRepositoryProtocol, *, at: datetime
) -> str:
    """``"CN-2026-00001"``-shaped -- its own independent sequence, never the
    invoice sequence."""
    year = at.year
    sequence = await repository.increment_and_get_next(
        _counter_key(CREDIT_NOTE_NUMBER_PREFIX, year)
    )
    return _format_number(CREDIT_NOTE_NUMBER_PREFIX, year, sequence)


async def generate_debit_note_number(
    repository: NumberCounterRepositoryProtocol, *, at: datetime
) -> str:
    """``"DN-2026-00001"``-shaped -- its own independent sequence, never the
    invoice sequence or the credit-note sequence."""
    year = at.year
    sequence = await repository.increment_and_get_next(
        _counter_key(DEBIT_NOTE_NUMBER_PREFIX, year)
    )
    return _format_number(DEBIT_NOTE_NUMBER_PREFIX, year, sequence)


__all__ = [
    "NumberCounterRepositoryProtocol",
    "generate_invoice_number",
    "generate_credit_note_number",
    "generate_debit_note_number",
]
