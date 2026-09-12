# Database failover — SEV-1

**Symptom:** `/readyz` failing across instances; connection errors in logs.

PostgreSQL is the only stateful dependency
(ADR [0002](../adr/0002-postgresql-as-the-backbone.md)), so this is a full
outage. The trade was made knowingly: one dependency means one point of failure,
against the transactional guarantees everything else relies on.

## First: is it the database or the path to it

```bash
psql "$DATABASE_URL" -c 'SELECT 1'        # from an application host
psql "$DATABASE_URL_DIRECT" -c 'SELECT 1' # bypassing the pooler, if any
```

| Result | Cause |
|---|---|
| Both fail, primary reachable by ping | The database is up but refusing — check `max_connections`, disk, or a stuck transaction |
| Both fail, primary unreachable | Host or network |
| Direct works, pooled fails | The pooler — restart it, do not fail over |

Failing over a healthy primary because the pooler died is the classic way to turn
a five-minute incident into a two-hour one.

## Connection exhaustion, not an outage

```sql
SELECT count(*), state FROM pg_stat_activity GROUP BY state;
SELECT pid, now() - xact_start AS age, state, left(query, 120)
  FROM pg_stat_activity
 WHERE xact_start < now() - INTERVAL '1 minute' ORDER BY age DESC;
```

A long-running transaction holding connections is far more common than a dead
primary. Terminate the offender before considering failover.

## Failing over

Only when the primary is genuinely gone:

1. **Confirm it is gone.** A split brain — two primaries accepting writes — is
   worse than downtime, and unrecoverable without manual reconciliation of the
   journal. Fence the old primary first.
2. Check replica lag before promoting:
   ```sql
   SELECT now() - pg_last_xact_replay_timestamp() AS lag;
   ```
   Any lag is data loss. Record the number — you will need it for the
   reconciliation.
3. Promote the replica.
4. Repoint the application and restart. Instances are stateless, so this is
   ordinary.
5. **Verify integrity before accepting traffic:**
   ```
   GET /internal/verify/trial-balance
   GET /internal/verify/audit-chain
   GET /internal/verify/consistency
   ```
   A promotion that lost transactions can leave an order paid with no ledger
   entry. Better to find that here than from a seller.

## After lag-related loss

Reconcile the window against the provider's records. The provider is the
external source of truth for what actually moved. Replay missing captures
through the normal path — the idempotency keys make replay safe — rather than
hand-posting to the ledger.

## Recovering the old primary

Never reattach it as a replica without rewinding it first (`pg_rewind` or a fresh
base backup). A former primary with divergent WAL that is reattached naively will
corrupt the timeline.

## Prevention

- Streaming replication with a promotable standby, and promotion rehearsed at
  least once in staging — a failover first performed during an incident is a
  procedure nobody has tested.
- PITR from WAL archives, with the restore tested, not assumed.
- Connection limits set so the application cannot exhaust the server.
- Alert on replica lag, not only on the primary being down.
