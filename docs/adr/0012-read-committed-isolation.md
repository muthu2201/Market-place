# 0012. READ COMMITTED with explicit locking

Status: Accepted
Date: 2026-09-11

## Context

The system was first built on `REPEATABLE READ` for every transaction, on the
reasoning that stronger isolation is safer and PostgreSQL's snapshot isolation
makes most anomalies impossible.

The load test disproved it. Under concurrent checkout, 5.8% of requests returned
500. Every one was a `40001` serialization failure: two transactions touching the
same row, one aborted by the server. Retries existed, but under sustained
concurrency the retries collided too, and the failure rate scaled with load in
exactly the way a production incident does.

The lesson is that isolation level is not a safety dial. `REPEATABLE READ` does
not make concurrent code correct; it converts a class of correctness bugs into a
class of availability bugs, and a payment endpoint that fails 5.8% of the time is
not safe.

## Decision

`READ COMMITTED` is the default isolation level, with an explicit contract:
**every transaction that reads a value it intends to write must either take a row
lock or perform the update as a single atomic statement.**

In practice:

- `SELECT … FOR UPDATE` where a value is read, decided upon, and written.
- `UPDATE … SET x = x + n` where the read is only needed for the arithmetic.
- `INSERT … ON CONFLICT … DO UPDATE … RETURNING` where a row must exist exactly
  once, which is atomic and race-free in one statement.
- `FOR UPDATE SKIP LOCKED` for queue claiming, where contention should mean
  "take a different row", not "wait" and not "abort".
- `pg_advisory_xact_lock` where the invariant spans rows, as for the audit hash
  chain.

`InTx` still retries `40001` and `40P01`, because `READ COMMITTED` can deadlock,
and additionally retries `23505` on the **named idempotency constraints** so a
concurrent duplicate resolves to the winner's row rather than a 500.

Individual transactions may opt into a stronger level where the invariant
genuinely requires a stable snapshot — the gapless tax-invoice series is one.
That is a local decision with a comment explaining why, not a global default.

## What the load test actually found

The isolation change was one of six concurrency defects the stress test exposed.
The others are worth recording because each was invisible under single-threaded
testing and obvious under load:

1. Order numbers drawn from the gapless invoice allocator serialised every
   checkout behind one row. Split: orders take a plain sequence, tax invoices keep
   the gapless allocator because statute requires it.
2. A single platform-wide turnover row aborted transactions. Replaced with
   append-only `turnover_deltas` plus a periodic rollup — the same
   append-and-roll-up shape as ledger balances (ADR 0005).
3. `seller_ledger_account` did `INSERT … DO NOTHING` then `SELECT`, which returns
   nothing when a concurrent transaction inserted first. Replaced with
   `ON CONFLICT DO UPDATE … RETURNING`.
4. `/healthz`, `/readyz` and `/metrics` were rate-limited, so load shedding blinded
   monitoring at exactly the moment it was needed. Exempted.
5. The audit hash chain forked under concurrent writes. An advisory lock was not
   enough: `BIGSERIAL` defaults are evaluated while the tuple is built, *before*
   the `BEFORE` trigger fires, so rows acquired sequence numbers in one order and
   reached the locked section in another. Fixed by allocating `chain_pos` from a
   sequence *inside* the lock, with verification walking `chain_pos`.

None of these were found by reading code. All were found by running the system
hard enough to break it.

## Consequences

Every developer must know which pattern applies to the transaction they are
writing. This is a real cognitive cost and the alternative — a global level that
appears to remove the question — only hides it until load arrives.

Post-change measurement: 2,885 read requests/second at p99 55 ms, 53.9 completed
purchases/second, and zero errors on both paths.
