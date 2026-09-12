# 0006. One payment port, three adapters

Status: Accepted
Date: 2026-09-11

## Context

Two constraints collide at launch.

The **regulatory** one: under the RBI (Regulation of Payment Aggregators)
Directions, 2025, a non-bank payment aggregator needs ₹15 crore of net worth at
application rising to ₹25 crore, must hold collections in an escrow account with
a scheduled commercial bank, and is barred from operating a marketplace. A
marketplace that routes buyer money through its own account and then pays
sellers is performing payment aggregation whether or not it calls itself a PA.
The platform must therefore never be in the flow of funds (ADR 0003).

The **commercial** one: the obvious way to stay out of the flow of funds is
Razorpay Route, which splits a payment at the provider and transfers the
seller's share directly. But Route activation requires evidenced domestic
turnover above ₹40 lakh (or ₹5 lakh export) in the current or preceding
financial year, supported by GSTR-3B filings. A pre-revenue platform cannot
activate it. The regulator-compliant design is not available on day one.

Designing for Route and bolting on a stopgap would have put the stopgap in the
business logic. Designing for the stopgap would have made Route a rewrite.

## Decision

A single `payments.Provider` port with three adapters behind it, selected once at
boot from validated configuration.

- **`bridge`** — launch. Collection through a single registered merchant
  account, with seller shares computed, ledgered and paid out on a separately
  reconciled cycle. Reports `SupportsSplit: false`, so any code path that
  requires a provider-side split fails at the port rather than silently doing
  something else.
- **`razorpay_route`** — the same Razorpay wire protocol with `transfers[]`
  attached to order creation, `on_hold` during the protection window, and
  provider-side settlement. Switching to it is a configuration change.
- **`mor`** — a merchant-of-record adapter (Paddle-shaped) for the case where
  the MoR takes on tax and chargeback liability. Signature verification uses the
  `ts=…;h1=…` scheme with a replay window rather than Razorpay's two schemes.

`Capabilities()` exists so callers branch on what a provider *can do*, never on
its name. `EvaluateRouteEligibility` encodes the turnover thresholds as code, so
"are we allowed to switch yet" is a query against the turnover rollup rather
than a note someone has to remember to read.

## Two signature schemes, deliberately not unified

Razorpay uses two different HMAC constructions and conflating them is a real
vulnerability:

- **Checkout callback**: `HMAC-SHA256(key_secret, order_id + "|" + payment_id)`.
- **Webhook**: `HMAC-SHA256(webhook_secret, exact raw request body)` — the raw
  bytes, before any JSON decode, because re-serialising changes them.

Different secrets, different payloads. The adapter keeps them apart, compares in
constant time, and the webhook handler reads the body once into a buffer so the
verified bytes and the parsed bytes are provably the same bytes.

## The outbound HTTP client is part of the security boundary

Every provider call goes through a client that refuses redirects, refuses to
connect to private, loopback, link-local or cloud-metadata addresses, caps
response bodies at 4 MB, and retries only requests that carry an idempotency
key. A payment provider integration is an SSRF primitive if it is written
carelessly; this one is the narrowest possible.

`PAYMENTS_ALLOW_LOOPBACK_PROVIDER` relaxes the address check for the gateway
simulator used in tests. Production configuration refuses to boot with it set.

## Consequences

Every order records which adapter handled it, so a provider migration is
auditable after the fact. The ledger's account structure is provider-neutral, so
a switch does not restate history.

The cost is that the port is the lowest common denominator of three providers:
capabilities only one of them has do not get first-class API surface. That is
the intended trade — a provider-specific feature that leaks into checkout is a
provider-specific migration later.
