# Runbooks

Procedures for the person on call. Each one states the symptom, the severity,
what to do first, and — for the two that matter most — what **not** to do.

| Runbook | Use when |
|---|---|
| [go-live-checklist.md](go-live-checklist.md) | Before the first real payment |
| [ledger-imbalance.md](ledger-imbalance.md) | `verify_trial_balance` raised |
| [audit-chain-break.md](audit-chain-break.md) | `verify_audit_chain` raised |
| [outbox-backlog.md](outbox-backlog.md) | Dispatcher lag or dead letters rising |
| [provider-outage.md](provider-outage.md) | The payment provider is failing |
| [key-rotation.md](key-rotation.md) | Rotating the KEK, or a suspected key compromise |
| [database-failover.md](database-failover.md) | The primary is unreachable |

## Severity

| Level | Meaning | Response |
|---|---|---|
| **SEV-1** | Money is wrong, or history was altered | Page immediately. Preserve evidence before anything else |
| **SEV-2** | Commerce is stopped or degraded | Page during business hours; escalate if sustained |
| **SEV-3** | A background process is behind | Ticket; watch the trend |

Ledger imbalance and audit-chain breaks are **always SEV-1** regardless of the
amount involved. The amount is not the signal — the fact that a constraint was
bypassed is.

## The two standing rules

**Preserve before you repair.** For any integrity finding, the evidence of *how*
is worth more than the speed of the fix. Snapshot first.

**Never make the ledger balance by hand.** If debits do not equal credits, a
constraint that should be impossible to bypass was bypassed. A manual correction
destroys the only record of how, and creates a journal entry nobody can explain
to an auditor.
