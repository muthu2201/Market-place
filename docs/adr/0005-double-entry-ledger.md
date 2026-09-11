# 0005. An immutable double-entry ledger, even holding no funds

Status: Accepted
Date: 2026-09-11

## Context

The platform never holds customer funds (ADR 0003), so it would be possible to
track the business with a few columns on the orders table: commission earned,
tax collected, amount settled.

That approach fails the moment something goes wrong. A provider reports a
payment we have no order for. A transfer is created twice. A refund lands for an
amount that does not match. With ad-hoc columns, each of those is discovered by
someone noticing; with a journal, each is an account that does not net to the
provider's record.

## Decision

Every economic event is recorded as balanced debits and credits in an
append-only journal: capture, commission, GST on that commission, TCS, TDS,
processing fee, transfer, settlement release, rolling reserve, refund, reversal,
chargeback, payout and tax remittance.

Three guarantees live in the database, not in the application:

1. **Entries balance.** A deferred constraint trigger refuses a commit where
   debits do not equal credits, per entry. A test proves the database refuses an
   unbalanced entry written by raw SQL that bypasses the Go layer entirely.
2. **History is immutable.** `UPDATE` and `DELETE` on the journal raise an
   exception. A correction is a new, compensating entry that references the one
   it reverses.
3. **Lines cannot cross currencies.** A line's currency must match both its
   account and its entry.

Posting is idempotent on a key, which is what makes webhook replay and
at-least-once outbox delivery safe. Twenty-four goroutines posting the same key
produce exactly one entry.

## Why balances are not materialised on write

The obvious implementation keeps a running balance per account and updates it on
every posting. That serialises every order behind one hot row: the platform
commission account.

Instead the journal is a pure append, and a balance is "the rolled-up total plus
the un-rolled tail". A worker advances a watermark periodically. Reads are
correct at every instant, writes never contend, and a test asserts the rollup
does not change the answer and a second rollup does not double-count.

The same shape was later applied to turnover counters after a load test showed a
single platform-wide row aborting transactions under concurrency.

## Consequences

More writes per order: a capture posts six or seven lines where a column update
would have been one. In exchange, reconciliation against the provider reduces to
a question with a yes-or-no answer, the trial balance is a continuously-checkable
invariant that the worker verifies every five minutes, and a seller statement can
be produced from the journal rather than assembled from application logic.

`ledger_trial_balance` must show a zero difference for every currency. A non-zero
row is an incident, not a discrepancy, because it means something bypassed a
constraint that should be impossible to bypass.
