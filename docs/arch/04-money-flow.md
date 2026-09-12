# Money flow

Every rupee, from the buyer's card to the seller's bank, with the ledger posting
that records each movement. This is the document to read before touching
anything in `internal/modules/orders`.

The governing rule is
ADR [0003](../adr/0003-never-hold-customer-funds.md): **the platform is never in
the flow of funds**. Money sits at the provider, then moves to the seller. The
marketplace instructs and records.

## The worked example

A ₹1,000 listing. Seller is GST-registered in Tamil Nadu; the platform is in
Tamil Nadu, so the *commission* is an intra-state supply. The buyer is in
Karnataka, so the *product* supply is inter-state. Commission is 9%.

| # | Line | Amount | Basis |
|---|---|---|---|
| 1 | List price | ₹1,000.00 | Seller's price, tax-exclusive |
| 2 | IGST on the supply @18% | ₹180.00 | Inter-state, the seller's tax on their own supply |
| 3 | **Buyer pays** | **₹1,180.00** | 1 + 2 |
| 4 | Platform commission @9% | ₹90.00 | On the taxable value, never on the tax-inclusive total |
| 5 | GST on that commission @18% | ₹16.20 | The platform's own output tax on its service to the seller |
| 6 | TCS u/s 52 @1% | ₹10.00 | On net taxable value; **creditable to the seller** |
| 7 | TDS u/s 194-O @0.1% | ₹1.00 | On value excluding GST (CBDT Circular 17/2020); **creditable to the seller** |
| 8 | Processing fee @2% + GST | ₹23.60 + ₹4.25 | On the buyer total; borne per `PSP_FEE_BEARER`, here the platform |
| 9 | **Seller receives** | **₹1,062.80** | 3 − 4 − 5 − 6 − 7 |
| 10 | **Platform keeps** | **₹66.40** | Commission 4, less the processing cost it absorbed |

Line 4 is computed on the ₹1,000, not the ₹1,180: charging a percentage of the
GST would be charging the seller for the government's money.

Lines 6 and 7 are not platform revenue and not seller cost — they are the
seller's own tax, collected at source and creditable against their liability. The
seller statement says so in words on every line, because a deduction shown
without that sentence is how sellers conclude the platform charges 14%.

Line 2 likewise passes through: the seller owes that ₹180 to the government on
their own supply. Their economic position is ₹1,062.80 received, less ₹180 GST
payable, plus ₹11.00 of tax credits — against a ₹1,000 taxable value, with the
platform's ₹90 commission being the only amount the platform keeps.

Had the seller borne the processing cost instead, they would receive ₹1,034.95
and the platform would keep the full ₹90.00. Both figures are asserted in
`TestWorkedExampleMatchesDocs`, so this table cannot drift from the code.

`tax.Breakdown.Verify()` re-derives this and refuses a breakdown where
`SellerNet + Commission + CommissionGST + TCS + TDS` (plus the PSP fee when the
seller bears it) does not equal exactly what the buyer paid. A 200,000-iteration
randomised test asserts it over the whole input space.

## The purchase, end to end

```mermaid
sequenceDiagram
    participant B as Buyer
    participant API as api
    participant DB as PostgreSQL
    participant P as Provider
    participant W as worker
    participant S as Seller

    B->>API: POST /api/v1/checkout
    activate API
    Note over API: tax.Compute per line<br/>Breakdown.Verify()
    API->>DB: BEGIN · order + lines + outbox · COMMIT
    API-->>B: order, grand total
    deactivate API

    B->>API: POST /orders/{id}/payment
    API->>P: create payment (+ split where supported)
    P-->>API: provider order id
    API-->>B: checkout parameters

    B->>P: pays directly
    P-->>B: signed result

    par Browser callback
        B->>API: POST /orders/{id}/confirm
        API->>P: VerifyPayment (HMAC over order_id|payment_id)
    and Provider webhook
        P->>API: POST /webhooks/payments
        Note over API: HMAC over the exact raw body<br/>de-duplicated on (provider, event_id)
    end

    Note over API,DB: whichever arrives first runs recordCapture;<br/>the other is a no-op on the idempotency key
    API->>DB: BEGIN<br/>order → paid · ledger capture · ledger PSP fee<br/>entitlement · turnover delta · audit · outbox<br/>COMMIT

    W->>DB: dispatch outbox
    W->>S: sale notification, invoice

    Note over W: after the protection window
    W->>P: ReleaseSellerSettlement
    P->>S: settles directly
    W->>DB: ledger settlement release
```

Note what is inside the single `COMMIT` on capture: the order status, both ledger
entries, the buyer's entitlement, the turnover delta, the audit line and the
outbox messages. There is no instant at which the order is paid but the
entitlement does not exist, or the ledger is posted but the audit line is
missing.

## The postings

### Capture

Two entries, because they answer two different questions.

**Entry 1 — what the buyer paid and where it is owed** (idempotency key
`capture:{order}:{provider_payment_id}`):

```
DR  platform.clearing.{provider}    1,180.00   receivable from the PSP
  CR  seller.{id}.payable           1,062.80   owed to the seller
  CR  platform.income.commission       90.00   platform revenue
  CR  platform.payable.gst_output      16.20   GST on the commission, owed onward
  CR  platform.payable.tcs             10.00   TCS, owed onward
  CR  platform.payable.tds_194o         1.00   TDS, owed onward
                                   ─────────
                                    1,180.00   balanced
```

**Entry 2 — the processing cost**:

```
DR  platform.expense.psp_fee           23.60
DR  platform.input_credit.gst            4.25   recoverable input credit
  CR  platform.clearing.{provider}      27.85
```

Separating them matters: entry 1 is what the buyer paid, entry 2 is what it cost
to collect. Merged, neither reconciles cleanly against the provider's statement.

`platform.clearing.*` is an **asset** account — a receivable from the provider,
not cash the platform holds. The distinction is the entire regulatory position,
and it is visible in the chart of accounts.

Where the provider has not yet reported its fee, the configured blended rate is
used and reconciliation corrects the drift later — an estimate that is later
trued up, never a guess that is never revisited.

### Settlement release

After the protection window (`SETTLEMENT_HOLD_DAYS`, minimum 7, and production
configuration refuses less):

```
DR  seller.{id}.payable             1,062.80
  CR  platform.clearing.{provider}  1,062.80
```

The seller's payable is discharged and the provider's clearing balance falls,
because the provider has now moved the money. `ReleaseDueSettlements` skips any
order under dispute and records a reason for every deferral, so "where is my
money" is answered from data.

### Refund

A refund is a new entry, never a mutation. The journal is append-only —
`UPDATE` and `DELETE` raise an exception — so a correction is always a
compensating entry that references what it reverses:

```
DR  seller.{id}.payable                 ...   reverses the seller's share
DR  platform.income.commission          ...   reverses the commission
DR  platform.payable.gst_output         ...   reverses the output GST
  CR  platform.clearing.{provider}      ...   the provider returns the money
```

Whether the commission is refunded is policy; whether the entry balances is not.

### Chargeback after release

The one case where the money has already gone. No wallet exists to go negative
(ADR [0011](../adr/0011-settlement-holds-not-wallets.md)), so it is recorded as a
receivable and offset against the seller's *next* release:

```
DR  platform.expense.chargeback_loss    ...   recognised immediately
  CR  platform.clearing.{provider}      ...   the provider has debited us
```

then, at the next settlement, the seller's payable is reduced by the offset. No
debt collection, no negative balance, no concept of seller debt in the code.

## Where money is at every instant

| Order state | Buyer's money is | Ledger says |
|---|---|---|
| `pending` | With the buyer | Nothing posted |
| `paid` | At the provider | `clearing` debited; seller `payable` credited |
| `paid`, within the window | At the provider, transfer on hold | Unchanged — the hold is a provider fact |
| `complete`, released | With the seller | `payable` discharged, `clearing` reduced |
| `refunded` | Back with the buyer | Compensating entry |

The platform's own bank account (`platform.bank.operating`) appears only when the
provider settles the platform's *own* commission income. Buyer funds never touch
it, which is the property the whole design exists to preserve.

## The invariants, and who checks them

| Invariant | Enforced by | Checked by |
|---|---|---|
| Every entry balances | Deferred constraint trigger | `verify_trial_balance`, every 5 minutes |
| Journal is append-only | `forbid_mutation()` trigger on UPDATE/DELETE | A test that tries raw SQL and is refused |
| No cross-currency line | `CHECK` against account and entry currency | Type system, then the database |
| Buyer total = distribution | `tax.Breakdown.Verify()` | 200k-iteration randomised test |
| No rupee created or destroyed by allocation | `money.Allocate` largest-remainder | 70k-iteration property test |
| Capture posts exactly once | Unique idempotency key | 24-goroutine concurrent test |
| Trial balance nets to zero per currency | — | `verify_trial_balance` raises; it never repairs |

The last row is deliberate. A non-zero trial balance means something bypassed a
constraint that should be impossible to bypass. Silently correcting it would
destroy the evidence of how.
