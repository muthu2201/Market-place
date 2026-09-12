# Failure modes

What breaks, what the system does about it, and how anyone finds out. A design
that only describes the happy path has not been designed.

## The governing posture

**Fail closed on money, fail open on convenience.** A payment that cannot be
verified is not honoured. A receipt that cannot be sent is retried forever. The
first protects correctness; the second protects the buyer from a transient SMTP
problem costing them their purchase.

## Dependency failures

### The payment provider is down

Checkout returns a problem document. No order advances past `pending`, because
an order only advances on a *verified capture* — never on a client assertion, a
timeout, or an optimistic assumption.

Orders left `pending` are released by `expire_stale_orders` after five minutes,
so nothing is stranded.

The dangerous case is the provider being down *after* taking the money. This is
why the webhook path exists independently of the browser callback: the buyer's
browser can close, crash or lose connectivity and the capture still lands when
the provider's webhook arrives. Both paths call the same `recordCapture` and
de-duplicate on the same key.

### The provider sends a webhook we cannot verify

Rejected with a 400, recorded, not processed. A signature failure is either a
misconfiguration or an attack, and neither is a reason to honour a payment.
Repeated failures are a paging condition, because a rotated secret nobody
deployed looks exactly like this.

### Object storage is unavailable

Existing presigned URLs keep working — they are served by R2, not by the
application. New grants fail with a problem document, and the buyer's
entitlement is untouched: they can retry. Browsing, purchasing and the ledger
are unaffected, because none of them touch storage.

### SMTP is unavailable

Mail queues in the database. `send_queued_mail` drains it every 15 seconds and
retries with backoff. Nothing in the purchase path blocks on mail — a receipt is
queued at commit, not sent during checkout, precisely so an SMTP timeout can
never fail a payment.

### PostgreSQL is unavailable

The system is down. This is the accepted consequence of
ADR [0002](../adr/0002-postgresql-as-the-backbone.md): one stateful dependency
means one single point of failure, traded against the consistency guarantees
that make everything else in this document simple.

Mitigations are operational rather than architectural — streaming replication
with a promotable standby, PITR from WAL archives, and a documented failover in
the runbooks. `/readyz` fails when the database is unreachable, so a load
balancer removes the instance rather than serving errors.

## Internal failures

### A transaction conflicts

`InTx` retries `40001` (serialization) and `40P01` (deadlock) with jittered
backoff, and retries `23505` on the named idempotency constraints so a
concurrent duplicate resolves to the winner's row.

Retries are bounded. Exhaustion is a 503, not an infinite loop, because a
request that cannot make progress must free its connection.

The jitter source is an `atomic.Uint64` splitmix64 — it was a plain shared
counter until the race detector found it.

### An outbox message keeps failing

Exponential backoff, then a dead-letter state with the last error kept. The
dispatcher moves on; `Replay` puts messages back after the cause is fixed.

Dead-lettering is deliberately loud. A message that exhausts its attempts is a
bug or an outage, and both should be looked at by a person rather than absorbed
silently.

### The trial balance does not net to zero

`verify_trial_balance` raises every five minutes. It **does not repair**.

A non-zero trial balance means something bypassed a constraint that should be
impossible to bypass. Automatic correction would destroy the evidence of how,
and the how is the entire value of the finding. This is an incident, not a
discrepancy.

### The audit chain does not verify

`verify_audit_chain` walks `chain_pos` hourly and detects both mutation and
deletion. A break means someone with database access modified history. The
runbook treats it as a security incident: preserve, do not repair.

### A worker dies mid-task

Every task is idempotent and every claim is transactional. An uncommitted claim
is released when the connection drops, and another worker takes the row. A
partially-completed task either committed — in which case it is done — or did
not, in which case it never happened.

### Two workers run the same scheduled task

They cannot. Scheduled tasks are behind a leader advisory lock; the dispatcher
does not need one because `SKIP LOCKED` makes concurrent dispatch safe by
construction.

## Business failures

### A buyer charges back after settlement release

Recorded as a receivable, offset against the seller's next release. No wallet
exists to go negative (ADR [0011](../adr/0011-settlement-holds-not-wallets.md)).

The residual risk — a chargeback against a seller with no subsequent sales — is
bounded, measurable from the ledger, and accepted.

### A seller disputes their settlement

The ledger answers it. Every component of every deduction is a posted line with a
memo, and `tax.Breakdown.Explain` narrates the computation in plain language. A
seller statement is produced *from* the journal, not assembled by application
logic that could disagree with it.

### A seller's asset turns out to be malware

The publish guard should have prevented it: no product publishes with an
unscanned or non-clean asset. If one is discovered afterwards, the product is
unpublished, grants are revoked, and affected buyers are identified from
`download_grants` — which is why every issuance is recorded even though the
bytes were served by R2.

### A buyer requests erasure while their orders are retained

Crypto-shredding. The DEK is destroyed, personal data becomes unreadable
everywhere including backups, and the financial records survive intact because
amounts, dates and invoice numbers are not personal data
(ADR [0008](../adr/0008-crypto-shredding-for-erasure.md)).

The erasure itself is recorded in the audit log: the fact that a person
exercised the right is a record that must be kept.

## Detection

| Signal | Source | Meaning |
|---|---|---|
| `/readyz` failing | api | Database unreachable — remove from the pool |
| Trial balance non-zero | `verify_trial_balance` | **Incident.** A constraint was bypassed |
| Audit chain broken | `verify_audit_chain` | **Security incident.** History was modified |
| Outbox dead letters rising | `/api/v1/admin/outbox` | A consumer is broken or a dependency is down |
| Dispatcher lag rising | metrics | The worker cannot keep up, or is not running |
| 5xx rate rising | metrics, by route | Anything |
| `23505` retries rising | metrics | Contention, or a client hammering an idempotent endpoint |
| Webhook signature failures | metrics | Misconfiguration or attack |
| Grievance SLA approaching | `grievance_sla_watch` | A statutory deadline is near |

Nine further checks are exposed at `/internal/verify/consistency` behind an
internal token: order totals against ledger postings, entitlements against paid
orders, grants against entitlements, settlement holds against releases, and so
on. They are the questions an auditor would ask, answered continuously instead
of once a year.

## What is deliberately not automated

- **Repairing a broken trial balance.** Preserve the evidence.
- **Repairing a broken audit chain.** Same, more so.
- **Refunding automatically on dispute.** A dispute is a decision, not an event.
- **Banning a seller on a provenance signal.** Advisory, never a gate
  (ADR [0010](../adr/0010-disclosure-first-provenance.md)).
- **Retrying a non-idempotent provider call.** The egress client retries only
  requests carrying an idempotency key.

Each of these is a case where automation would trade a recoverable problem for an
unrecoverable one.
