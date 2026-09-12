# Audit chain break — SEV-1, security

**Symptom:** `verify_audit_chain` raised, or
`GET /internal/verify/audit-chain` reports a break.

**What it means:** the hash chain over the audit log does not verify. Each entry
hashes its predecessor, so a break means an entry was **modified or deleted**
after it was written.

`UPDATE` and `DELETE` on the audit log raise an exception. Reaching this state
requires either direct database access with the trigger disabled, or a
compromise. **Treat it as a security incident until proven otherwise.**

## Do not

- **Do not rebuild the chain.** Recomputing the hashes makes the log verify
  again and destroys the evidence permanently. There is no undo.
- **Do not delete the broken entries.**
- **Do not restart anything** before snapshotting.

## Immediately

1. **Snapshot the database.** Before any query that could be mistaken for a
   write. This snapshot is evidence.

2. **Find the break point.**

   ```sql
   SELECT * FROM verify_audit_chain();   -- returns the first non-verifying chain_pos
   ```

3. **Look for a gap**, which indicates deletion rather than modification:

   ```sql
   SELECT chain_pos + 1 AS missing_from
     FROM audit_log a
    WHERE NOT EXISTS (SELECT 1 FROM audit_log b WHERE b.chain_pos = a.chain_pos + 1)
      AND chain_pos < (SELECT max(chain_pos) FROM audit_log);
   ```

4. **Establish who had access.** Database credentials in use, when they were last
   rotated, which hosts could reach the primary, and what the connection log
   shows around the break point's timestamp.

5. **Check the triggers**, exactly as in
   [ledger-imbalance.md](ledger-imbalance.md). A disabled `forbid_mutation` is
   the mechanism.

6. **Escalate.** This is a disclosure-relevant event if personal data or
   financial records were touched. Involve whoever owns that decision now, not
   after the technical investigation.

## Scope the damage

The break point bounds what is suspect. Entries before it are cryptographically
intact; entries after it are suspect only if the attacker continued.

Cross-check the audit log against the ledger for the affected window: the
journal is separately append-only, so an attacker who altered one and not the
other leaves a discrepancy that reconstructs what happened.

```sql
SELECT * FROM audit_log
 WHERE chain_pos BETWEEN $break - 50 AND $break + 50
 ORDER BY chain_pos;
```

## Recovery

1. Rotate every credential that could have been used: database, KEK, session and
   CSRF signing keys, provider API keys and webhook secrets.
2. Preserve the broken chain **as it is**. Start a new chain from a new genesis
   entry that records the incident, the break point and the snapshot's location.
   The history stays broken, visibly, because that is the truth.
3. Re-verify every ledger invariant over the affected window against the
   provider's statement.
4. Post-mortem: how did anything obtain write access to an append-only table.

## Note on a known false positive

Before migration `0012`, concurrent writers could fork the chain legitimately:
`BIGSERIAL` defaults are evaluated while the tuple is built, *before* the
`BEFORE` trigger fires, so rows took sequence numbers in one order and reached
the locked section in another. That is fixed — `chain_pos` is allocated from a
sequence inside the lock and verification walks `chain_pos`.

If you are running a build from before `0012`, confirm the migration is applied
before treating a break as an incident. On any current build, a break is real.
