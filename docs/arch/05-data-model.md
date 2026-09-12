# Data model

71 tables across 12 migrations, 44 triggers, 26 functions, 6 domains. The
interesting part is not the shape of the tables — it is which invariants live in
the database rather than in Go, and why each one is there.

## The rule

**An invariant that must never be violated lives in the database.** Application
code can be bypassed by a migration script, a psql session, a future service, or
a bug. A constraint cannot.

A useful test for any rule: *could a correct-looking `INSERT` typed by hand break
it?* If yes, it belongs in the schema.

## Domains — types that carry their own rules

```sql
CREATE DOMAIN money_minor      AS BIGINT ...   -- never a float, anywhere
CREATE DOMAIN currency_code    AS CHAR(3) ...  -- ISO 4217, uppercase
CREATE DOMAIN basis_points     AS INTEGER ...  -- 0..10000
CREATE DOMAIN public_id        AS TEXT ...     -- prefixed Crockford base32
CREATE DOMAIN email_blind_index AS BYTEA ...   -- exactly 32 bytes
CREATE DOMAIN sha256_digest    AS BYTEA ...    -- exactly 32 bytes
```

`money_minor` is the important one. A `NUMERIC` column invites someone to divide
it; a domain over `BIGINT` named for what it holds does not. The type travels
with the column, so every money column in every table gets the constraint for
free, including tables written years from now.

## Migration map

| File | Contents |
|---|---|
| `0001_infrastructure` | Domains, `forbid_mutation()`, audit log + chain, outbox, jobs, idempotency keys, `rate_limit_allow()` |
| `0002_identity` | Accounts, credentials, sessions, roles, consents, `subject_keys` |
| `0003_sellers` | Seller profiles, KYC, GSTIN/PAN, payout accounts |
| `0004_ledger` | Accounts, journal entries, journal lines, the balance trigger |
| `0005_catalog` | Products, assets, taxonomy, provenance signals, moderation, publish guards |
| `0006_orders_payments` | Orders, order lines, payments, refunds, webhook de-duplication |
| `0007_delivery_tax_payouts` | Licences, download grants, tax invoices, gapless series, payouts |
| `0008_compliance_ranking` | Grievances, DSARs, takedowns, ranking inputs, fee schedules |
| `0009_chart_of_accounts` | The chart itself, and the per-seller subsidiary opener |
| `0010_settlement_accounts` | Settlement holds, reserves, offsets |
| `0011_contention` | `next_order_number`, `turnover_deltas` + rollup, race-free account opener, advisory-locked audit chain |
| `0012_audit_chain_order` | `chain_pos` allocated inside the lock; verification walks it |

Migrations `0011` and `0012` exist because of the load test, not because of a
feature. They are the schema half of
ADR [0012](../adr/0012-read-committed-isolation.md).

## Invariants the database enforces itself

### The ledger balances

```sql
-- Deferred: checked at COMMIT, not per statement, because an entry is written
-- as a header and then its lines.
CONSTRAINT TRIGGER journal_entry_must_balance
  AFTER INSERT ON journal_lines DEFERRABLE INITIALLY DEFERRED ...
```

A test writes an unbalanced entry with raw SQL, bypassing Go entirely, and
asserts the database refuses it.

The trigger branches on `TG_TABLE_NAME` because PL/pgSQL binds `NEW.<field>`
eagerly: a single function body referencing a column that exists on only one of
the two tables fails to load for the other, regardless of which branch runs.

### History is append-only

`forbid_mutation()` raises on `UPDATE` and `DELETE` for the journal, the audit
log, and every other table whose whole value is that it cannot be rewritten.
Corrections are compensating entries.

The one place it was deliberately suspended is migration `0012`, which backfills
`chain_pos` on existing audit rows: `DISABLE TRIGGER`, one statement, `ENABLE
TRIGGER`, with a comment recording that the guard behaved correctly by blocking
it in the first place.

### A published product is deliverable

```sql
CREATE FUNCTION products_publish_guard() ...
  -- refuses publication when a download product has no clean, non-preview
  -- asset, or when any asset is unscanned
```

This is the control that stops "pay and receive nothing" and "pay and receive
malware". It is a trigger because a control that a direct `UPDATE` can bypass is
not a control.

### Statuses carry their timestamps

`CHECK (status <> 'paid' OR paid_at IS NOT NULL)` and its siblings. This is why
`transitionStamped` writes the status and its timestamp in one `UPDATE` — two
statements would be transiently invalid.

### A fee schedule cannot break the covenant

```sql
CONSTRAINT fee_schedules_ninety_day_notice
  CHECK (effective_from >= announced_at + INTERVAL '90 days' OR code = 'launch')
```

The public promise of 90 days' notice is a constraint. A schedule that violates
it cannot be inserted, so abandoning the covenant requires a migration that
drops a named constraint — visible in a diff, which is the level of friction a
promise like this deserves
(ADR [0015](../adr/0015-flat-all-in-commission.md)).

### The tax-invoice series is gapless

Statute requires a consecutive serial number per financial year. That allocator
serialises by design, and it is the one place where serialisation is correct:
a gap in a tax invoice series is a compliance defect, whereas a gap in order
numbers is nothing at all.

Order numbers were originally drawn from the same allocator, which serialised
every checkout. `0011` split them: orders take `next_order_number`, a plain
sequence.

### Personal data is never in the clear

`subject_keys` holds each subject's wrapped DEK. Personal columns are ciphertext
with the subject ID and field name as AAD, so a ciphertext cannot be moved
between columns or between people. Lookup goes through a uniquely-indexed blind
index (ADR [0008](../adr/0008-crypto-shredding-for-erasure.md)).

### The audit chain cannot fork

Each entry hashes its predecessor. `chain_pos` comes from a sequence allocated
*inside* an advisory-locked section, because a `BIGSERIAL` default is evaluated
while the tuple is built — before the `BEFORE` trigger fires. Rows would
otherwise take sequence numbers in one order and reach the locked section in
another, and the chain would fork under concurrency. It did; the load test found
it. Verification walks `chain_pos` and detects both mutation and deletion.

## Two patterns worth copying

### Append-only delta plus rollup

Used for ledger balances *and* turnover counters, for the same reason: a single
hot row serialises every writer.

```
writes  → append a delta row (never contends)
reads   → rolled-up total + un-rolled tail (always correct)
worker  → periodically folds the tail into the total, advancing a watermark
```

Reads are correct at every instant, writes never contend, and a test asserts the
rollup does not change the answer and a second rollup does not double-count.

### Idempotency as a unique constraint

`journal_entries_idempotency_uq`, `idempotency_keys_unique_idx`,
`provider_webhook_events_uq`, `jobs_unique_key_idx`. The transaction helper knows
these names, so a concurrent duplicate surfaces as a retryable `23505` that
resolves to the winner's row rather than a 500. Only the *named* ones are treated
that way: a unique violation on a business constraint is still an error.

## Identifiers

Two kinds, deliberately:

- **Internal**: UUIDv7 primary keys. Time-ordered, so index locality is good and
  B-tree page splits behave, without exposing a guessable sequence.
- **External**: `prd_7ZK3…`, `ord_…` — a prefix plus 26 Crockford base32
  characters. The prefix makes a misrouted identifier obvious in a log or a
  support ticket; Crockford excludes `I`, `L`, `O` and `U`, so a person reading
  one aloud does not create a support case.

The UUIDv7 generator keeps a 12-bit monotonic counter and, on saturation within
a millisecond, borrows from the next — a bounded, self-correcting drift that is
documented where it is implemented rather than discovered later.

## Retention

| Data | Retained | Because |
|---|---|---|
| Ledger entries, tax invoices | 8 years | Income-tax and CGST record-keeping |
| Audit log | 8 years | Same, plus incident forensics |
| Personal data | Until erasure | DPDP; erasure destroys the key, not the row |
| Sessions | Until expiry, swept hourly | No value in keeping them |
| Login attempts | 6 hours, pruned | Rate limiting only |
| Idempotency keys | 24 hours, purged hourly | Long enough for any retry |
| Download grants | Window plus audit | The grant expires; the fact it existed does not |

Crypto-shredding is what makes the first two rows and the third row
simultaneously satisfiable.
