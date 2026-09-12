# 0015. A flat all-in commission with a published fee covenant

Status: Accepted
Date: 2026-09-11

## Context

The incumbent digital-goods marketplaces have converged on a pattern: a headline
rate, then payment processing on top, then a listing fee, then an offsite-ad fee
charged on sales the seller sourced themselves, then a currency-conversion
margin. The seller's effective rate is discoverable only after the fact, from a
statement.

The pattern is profitable and it is also the single most reliable source of
seller resentment in the category. Every platform that has raised fees or added a
mandatory charge has faced organised seller backlash, and the grievance is
rarely the level — it is that the terms changed after the seller had built a
business on the old ones.

That is an opening. A new marketplace cannot win on catalogue size or traffic.
It can win on being the one whose economics a seller can compute in advance.

## Decision

**A flat 9% all-in commission**, with payment-processing cost and statutory tax
itemised separately and passed through at cost. No listing fees, no mandatory
advertising charges, no currency margin beyond the provider's own.

The commission is the platform's entire revenue from a sale. Everything else on
the invoice is either the payment provider's or the government's, and is shown
as such.

**The fee covenant**, enforced in the schema rather than promised in copy:

- A seller is charged the schedule that was in force when they joined
  (`seller_fee_assignments`), for as long as they remain on it.
- A new schedule requires **90 days' notice**. `fee_schedules` carries a `CHECK`
  that `effective_from >= announced_at + INTERVAL '90 days'`. A schedule that
  violates the notice period **cannot be inserted**.
- Moving to a new schedule is opt-in (`opted_in`), which only ever happens when
  the new schedule is better.

Grandfathering is data. The covenant is a constraint. Neither is a marketing
claim, and neither can be quietly abandoned by a future operator without an
explicit, reviewable migration that deletes a named constraint — which is the
level of friction a promise like this deserves.

## The arithmetic

A ₹1,000 listing, sold intra-state by a GST-registered seller who bears the
processing cost. Every figure is asserted against the implementation by
`TestWorkedExampleMatchesDocs`:

| Line | Amount | Whose money it is |
|---|---|---|
| List price (taxable value) | ₹1,000.00 | The seller's price |
| GST on the supply @18% (CGST ₹90 + SGST ₹90) | ₹180.00 | The seller's tax, collected through us |
| **Buyer pays** | **₹1,180.00** | |
| Platform commission @9% of the taxable value | ₹90.00 | **Platform** — the only line that is ours |
| GST on that commission @18% | ₹16.20 | Government, on the platform's service |
| Payment processing @2% of the buyer total + GST | ₹23.60 + ₹4.25 | Provider, at cost |
| TCS u/s 52 @1% (CGST ₹5 + SGST ₹5) | ₹10.00 | Government — **creditable to the seller** |
| TDS u/s 194-O @0.1% | ₹1.00 | Government — **creditable to the seller** |
| **Seller receives** | **₹1,034.95** | |

The commission is charged on the ₹1,000, never on the ₹1,180. Taking a
percentage of the GST would be charging the seller for the government's money.

TCS and TDS are not costs. They are the seller's own tax, collected at source
and creditable against their liability — so the seller's position is ₹1,034.95
received, less the ₹180 GST they owe on their supply, plus ₹11.00 of credits.
Showing those two lines as deductions without that sentence is how sellers
conclude a platform charges 14%, so the seller statement says it in words on
every line.

Where the platform absorbs the processing cost instead, the seller receives
₹1,062.80 and the platform's ₹90.00 commission becomes ₹66.40 after the fee.

At 9%, the platform is below the effective all-in rate of every major incumbent
in this category, while every component above is verifiable by the seller from
their own records.

## Consequences

Margin is thin and depends on volume. The platform cannot buy growth with
subsidies it would later have to recover through fee increases, because the
covenant makes recovery slow and visible. That constraint is the point: it forces
the cost base to be genuinely low, which is what ADR 0002's single-datastore
architecture and ADR 0014's zero-egress delivery are for. The fee promise and the
infrastructure choices are the same decision seen from two directions.

If the rate ever proves unsustainable, the honest move is a new schedule with 90
days' notice applying to new sellers, with existing sellers grandfathered — which
is precisely what the mechanism above makes the *easiest* thing to do, and what
every platform that damaged its seller relationship chose not to do.
