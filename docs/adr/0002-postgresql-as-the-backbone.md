# 0002. PostgreSQL as queue, cache and search, not just storage

Status: Accepted
Date: 2026-09-11

## Context

The conventional starting architecture for a marketplace is PostgreSQL plus
Redis plus a message broker plus Elasticsearch plus an object store. Four of
those five are stateful services that must be deployed, monitored, patched,
backed up, capacity-planned and — this is the part that gets skipped —
reasoned about when they disagree with each other.

Every additional datastore introduces a consistency boundary. A job enqueued in
Redis after a Postgres commit is a job that can be lost. A search index updated
after a write is an index that can lie. A cache is a second source of truth that
is wrong by construction for some window. None of those problems are hard to
solve individually; all of them are expensive to solve *correctly*, and the cost
is paid forever.

## Decision

PostgreSQL 16 is the only stateful dependency. Object storage is the single
exception, because bytes genuinely do not belong in a database.

| Concern | Conventional choice | What is used here |
|---|---|---|
| Job queue | Redis / SQS / RabbitMQ | `jobs` table, `FOR UPDATE SKIP LOCKED` |
| Event publication | Kafka / SNS | `outbox_messages`, claimed the same way |
| Rate limiting | Redis counters | in-process GCRA, plus `rate_limit_allow()` for the distributed case |
| Full-text search | Elasticsearch | `tsvector` + GIN, trigram for fuzzy |
| Cache | Redis / memcached | none — indexed queries and rollups |
| Locks | Redis / etcd | `pg_advisory_xact_lock` |
| Scheduling | cron / Airflow | worker loop with a leader advisory lock |

The whole of delivery, settlement, audit and tax therefore commits or rolls back
as one unit with the business state that caused it.

## Why this is not a compromise

`SELECT … FOR UPDATE SKIP LOCKED` is not a poor imitation of a broker; it is the
same primitive brokers are built from, with transactional enrolment for free.
The measured load test drives 2,885 read requests/second and 53.9 completed
purchases/second on four shared cores while the database, the API, the worker
and a gateway simulator all compete for them. The bottleneck at that point is
Argon2id, deliberately.

The queue is also *inspectable*. "Which jobs failed and why" is a `SELECT`, not a
dashboard you have to have bought in advance.

## Consequences

The scaling ceiling is one PostgreSQL primary's write throughput. Read replicas,
partitioning of `audit_log`, `outbox_messages` and `journal_lines`, and a
read-path cache all remain available before that ceiling is reached; none of
them are needed to launch, and adding one early would have been a guess.

Search quality is tsvector-grade. For a catalogue of digital products with
curated tags, that is sufficient, and the curated taxonomy is doing more work
than the matcher is. If catalogue size ever makes it insufficient, the outbox
already carries the events an external index would consume, so the migration is
additive — that is why the outbox exists even though nothing outside the process
consumes it today.

## What would change this decision

A sustained write rate that a single primary cannot absorb, or a search
requirement (vector similarity over embeddings, faceting across tens of millions
of rows) that PostgreSQL genuinely cannot serve. Neither is a launch problem,
and pre-solving them would have cost the transactional guarantees above.
