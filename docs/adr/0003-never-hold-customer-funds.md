# 0003. The platform never holds customer funds

Status: Accepted
Date: 2026-09-11

## Context

The RBI (Regulation of Payment Aggregators) Directions, 2025 require a non-bank
payment aggregator to hold INR 15 crore of net worth at application, rising to
INR 25 crore by the end of the third financial year, to keep funds in escrow with
a scheduled commercial bank, and they explicitly bar a payment aggregator from
running a marketplace.

A bootstrapped platform meets none of those conditions and cannot. Any design in
which buyer money passes through an account the platform controls, even briefly,
even in a ledger column called "wallet", walks into that regime.

## Decision

Money moves directly from the buyer to the seller through a licensed provider's
split settlement. The platform is a facilitator: it instructs the split, it
records what happened, and it never takes custody.

Three rules follow, and they are enforced rather than documented:

1. **No wallet, no stored value, no internal balance a user can draw on.**
   `seller_ledger_account` accepts only `payable` and `reserve`; a test asserts
   that asking it for a `wallet` fails.
2. **No negative internal balance.** A refund or lost chargeback after
   settlement creates a `settlement_offset`, an ordinary trade receivable netted
   from the seller's next payout. A consistency check asserts no seller payable
   account is ever negative, and the load harness runs it after every run.
3. **Settlement is deferred, not held.** The seller's share stays with the
   provider through a protection window. Nothing is held because nothing has
   moved.

## Consequences

**This constrains the product, and that is the point.** The platform cannot
offer instant payouts, cannot let a seller "top up" a balance, and cannot net a
buyer's refund against a future purchase. Each of those is a feature request
that will be made, and the answer is no, with this record as the reason.

**Chargeback exposure is managed by timing rather than by custody.** The
protection window is sized against the card-network representment windows, which
tightened from 2026: Visa and Mastercard to 10-14 calendar days in India, RuPay
under NPCI's RGCS to seven working days. A rolling reserve withholds a further
percentage for longer. Both are seller-configurable and both are recorded in the
ledger as liabilities, because the money is still the seller's.

**The ledger exists anyway.** Not holding funds does not remove the need to know
exactly what is owed to whom; see ADR 0005.
