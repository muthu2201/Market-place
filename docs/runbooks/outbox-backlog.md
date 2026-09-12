# Outbox backlog — SEV-2 or SEV-3

**Symptom:** dispatcher lag rising, or dead letters accumulating at
`GET /api/v1/admin/outbox`.

**What it means:** state changes committed, but the world has not been told.
Receipts, invoices and seller notifications are late or stuck. No money is wrong
— the outbox is downstream of the commit — but buyers and sellers are not being
informed, which becomes a support problem quickly.

## Triage

```sql
SELECT status, topic, count(*), min(created_at), max(attempts)
  FROM outbox_messages
 GROUP BY status, topic ORDER BY count DESC;
```

| Picture | Likely cause | Severity |
|---|---|---|
| `pending` growing, `attempts` low | The worker is not running, or is behind | SEV-2 |
| One topic failing, others fine | That consumer or its dependency is broken | SEV-3 |
| Everything failing | A shared dependency (SMTP, provider) is down | SEV-2 |
| `dead` growing | Attempts exhausted — a bug or a sustained outage | SEV-2 |

## If the worker is not running

Check it is alive and holding the leader lock:

```sql
SELECT pid, state, query FROM pg_stat_activity WHERE application_name LIKE '%worker%';
```

Starting a second worker is safe: dispatch uses `SKIP LOCKED`, and scheduled
tasks are behind a leader advisory lock, so nothing is duplicated.

## If one topic is failing

Read the error the dispatcher kept:

```sql
SELECT id, topic, attempts, last_error, created_at
  FROM outbox_messages
 WHERE status IN ('failed','dead') ORDER BY created_at DESC LIMIT 20;
```

Fix the consumer or its dependency, then replay:

```sql
-- Replay is the supported path; it resets attempts and re-queues.
SELECT outbox_replay(id) FROM outbox_messages WHERE status = 'dead' AND topic = $1;
```

Every consumer is idempotent, so replay is safe by construction: a receipt that
was in fact sent will not be sent twice, because the consumer de-duplicates.

## If ordering matters

Messages sharing an `ordering_key` are delivered in insertion order. A stuck
message blocks only its own key, never the queue. If one key is wedged, fix that
message — do not skip it, or two updates to the same order will be observed
backwards.

## Do not

- **Do not delete messages to clear the backlog.** A deleted outbox message is a
  notification the recipient will never get, with no record that it was owed.
- **Do not raise the attempt limit to make dead letters disappear.** The limit
  exists so a broken consumer surfaces.
