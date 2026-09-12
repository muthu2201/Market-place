# 0011. Settlement holds and offsets, never a wallet

Status: Accepted
Date: 2026-09-11

## Context

A marketplace needs an answer to: a buyer charges back three weeks after the
seller was paid. The money has left. Who absorbs it?

The common answer is a seller wallet. Sales credit it, payouts debit it, a
chargeback debits it, and the seller withdraws the balance. It is simple to
build and it is wrong on two counts.

**Regulatory**: a balance the platform owes a seller, funded by buyer payments,
is customer money held by the platform. Under the RBI PA Directions that is
payment-aggregation activity requiring escrow with a scheduled commercial bank
and a net worth the platform does not have (ADR 0003). A wallet is not a feature;
it is a licence application.

**Structural**: a wallet goes negative. A seller with a ₹0 balance and a ₹5,000
chargeback leaves a negative balance that is an unsecured receivable from someone
with no incentive to pay it, and the code now needs a concept of seller debt,
collections and write-offs.

## Decision

There is no wallet. Exposure is contained by **not moving the money yet**.

1. **Settlement hold.** The seller's share is transferred at the provider but
   marked `on_hold` for the protection window (`SETTLEMENT_HOLD_DAYS`, minimum 7,
   refused lower in production configuration). During the window the funds are at
   the provider, earmarked for the seller, not settled. A chargeback inside the
   window is netted against a transfer that has not happened, so there is nothing
   to claw back and no internal balance to go negative.
2. **Release, not withdrawal.** `ReleaseDueSettlements` releases transfers whose
   window has closed and whose orders are not under dispute. A seller does not
   withdraw a balance; a hold expires. Every deferral records a reason, so
   "where is my money" is answered from data rather than from code-reading.
3. **Offset against future settlement.** A chargeback landing after release is
   recorded in the ledger as a receivable and offset against the seller's next
   release. No debt collection, no negative balance — a reduction in a future
   payment that has not been made.
4. **Rolling reserve** for higher-risk sellers: a percentage of each sale held
   for longer, as a distinct ledger account rather than a wallet balance.

`seller_ledger_account` accepts only `payable` and `reserve` account types. A
`liability` account representing held customer funds is not creatable — the
constraint is in the schema, so the wallet cannot be added by accident during a
late-night feature.

## Consequences

Sellers wait. A seven-day minimum hold is a real disadvantage against a
competitor offering instant payout, and it will cost some sellers. It is also
exactly what the competitor offering instant payout is not disclosing about
their own regulatory position.

The mitigation is transparency, not speed: the hold, its length, its reason and
its expiry date are shown on the seller's dashboard from the moment of sale. A
known wait is tolerable; an unexplained one is not.

Established sellers can be moved to shorter windows as their chargeback history
justifies it, because the window is per-seller data rather than a constant.

The platform accepts residual risk on chargebacks arriving after release against
sellers with no subsequent sales. That risk is bounded, measurable from the
ledger, and small compared to the cost of holding customer funds.
