# Ledger imbalance — SEV-1

**Symptom:** `verify_trial_balance` raised, or
`GET /internal/verify/trial-balance` shows a non-zero difference for a currency.

**What it means:** debits do not equal credits. A deferred constraint trigger
refuses unbalanced entries at commit, so this state should be unreachable.
Reaching it means something bypassed a constraint that should be impossible to
bypass.

**The amount does not determine severity.** One paise is the same finding as one
lakh: a control failed.

## Do not

- **Do not post a correcting entry to make it balance.** You would destroy the
  only evidence of how, and create a journal entry nobody can explain later.
- **Do not restart the application.** Nothing about this is transient.
- **Do not run a migration.** The schema is not the suspect until proven so.

## Immediately

1. **Snapshot.** Take a consistent backup *now*, before anything else changes.

   ```sql
   -- Note the exact moment and the extent of the imbalance.
   SELECT now(), * FROM ledger_trial_balance WHERE difference_minor <> 0;
   ```

2. **Bound it in time.** Find the first entry after which the difference appears:

   ```sql
   SELECT e.id, e.kind, e.occurred_at, e.reference_type, e.reference_id,
          sum(CASE WHEN l.direction = 'debit'  THEN l.amount_minor ELSE 0 END) AS dr,
          sum(CASE WHEN l.direction = 'credit' THEN l.amount_minor ELSE 0 END) AS cr
     FROM journal_entries e JOIN journal_lines l ON l.entry_id = e.id
    WHERE e.currency = $1
    GROUP BY e.id
   HAVING sum(CASE WHEN l.direction = 'debit' THEN l.amount_minor ELSE 0 END)
       <> sum(CASE WHEN l.direction = 'credit' THEN l.amount_minor ELSE 0 END)
    ORDER BY e.occurred_at;
   ```

   An entry listed here is individually unbalanced: the trigger did not fire for
   it. Note its `id` and `occurred_at`.

3. **Check whether the trigger still exists.**

   ```sql
   SELECT tgname, tgenabled FROM pg_trigger
    WHERE tgrelid = 'journal_lines'::regclass AND NOT tgisinternal;
   ```

   `tgenabled = 'D'` means someone disabled it. That is the answer, and it is a
   security incident — go to [audit-chain-break.md](audit-chain-break.md) for the
   evidence-handling posture.

4. **Check the audit log around that timestamp.** The chain will tell you whether
   the audit record itself is intact.

## Then

If no individual entry is unbalanced but the aggregate is, the rollup is the
suspect rather than the journal:

```sql
-- Recompute from the journal, ignoring the watermark entirely.
SELECT a.currency,
       sum(CASE WHEN l.direction = 'debit' THEN l.amount_minor ELSE -l.amount_minor END)
  FROM journal_lines l JOIN ledger_accounts a ON a.id = l.account_id
 GROUP BY a.currency;
```

If this nets to zero and the rolled-up view does not, the defect is in the
rollup, not in the money. That is still SEV-1 — a reporting layer that disagrees
with the journal has been telling someone the wrong thing — but no economic event
was lost.

## Recovery

Only after root cause is established and written down:

1. Fix the defect that allowed it, with a test that reproduces the original
   failure and then passes.
2. Post a compensating entry that **references the incident**, with a memo naming
   it. Never a silent adjustment.
3. Reconcile against the provider's own statement for the affected period. The
   provider is the external source of truth for what actually moved.
4. Write the post-mortem before closing. The question to answer is not "what was
   the amount" but "how did an entry reach the journal without balancing".
