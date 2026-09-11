# 0007. A transactional outbox, and idempotent consumers

Status: Accepted
Date: 2026-09-11

## Context

A handler that changes state and then tells someone about it has two ways to be
wrong, and choosing the order only chooses which way:

- Publish first, then commit: the transaction rolls back and the world has been
  told about something that did not happen. A buyer receives "your download is
  ready" for an order that does not exist.
- Commit first, then publish: the process dies in between and the world is never
  told about something that did. A seller is never notified of a sale, a receipt
  is never sent, an entitlement e-mail never goes out.

No amount of care in the handler fixes this. It is the dual-write problem, and
it has exactly one correct answer.

## Decision

The *intent to publish* is written in the same transaction as the state change,
to `outbox_messages`. A separate dispatcher moves it outward afterwards.

Claiming uses `FOR UPDATE SKIP LOCKED`, so N dispatcher goroutines never collide
and a stuck handler never blocks the queue behind it. Failures increment an
attempt counter with exponential backoff; exhausted messages move to a
dead-letter state with the last error kept, and `Replay` puts them back after
the underlying cause is fixed.

Messages may carry an `OrderingKey`. Messages sharing one are delivered in
insertion order — two state changes to the same order cannot be observed
backwards — while messages with different keys, or none, proceed fully in
parallel.

## Delivery is at least once, and that is not negotiable

Exactly-once delivery does not exist across a process boundary. Every consumer
is therefore idempotent by construction, and the idempotency is enforced by the
database rather than by consumer discipline:

- Ledger posting is unique on its idempotency key, so a replayed capture posts
  once.
- `provider_webhook_events` is unique on `(provider, event_id)`, so a webhook
  Razorpay sends five times is processed once.
- `jobs` carries a unique key, so a duplicated schedule is one job.
- Download grants are counted against a quota inside the same transaction that
  issues them.

The transaction retry helper knows those constraint names. A concurrent
duplicate surfaces as `23505` on a *named idempotency constraint*, which is
retried and resolves to the winner's row, rather than escaping as a 500. That
distinction matters: a unique violation on a business constraint is still an
error, and only the named ones are treated as a benign race.

## Why not a broker

Kafka or SQS would still require this table. The dual-write problem is between
the database and the broker, so a broker does not remove the outbox; it adds a
second hop after it. Until something outside this process needs to consume
events, the dispatcher delivers in-process and the table is the queue (ADR
0002). The messages are already in the right shape for an external consumer when
one appears.

## Consequences

Publication is asynchronous: a buyer's receipt e-mail is queued at commit, not
sent during checkout. That is correct — an SMTP timeout must never fail a
payment — but it means "sent" is eventual and the dispatcher's lag is an
operational metric that matters.

The dead-letter state is deliberately loud. A message that exhausts its attempts
is a bug or an outage, and both should be looked at by a person.
