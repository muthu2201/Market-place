# 0009. A published, reproducible ranking formula

Status: Accepted
Date: 2026-09-11

## Context

Three separate regimes ask the same question of a marketplace's listing order.

- **EU Regulation 2019/1150 (P2B), Article 5** requires the main parameters
  determining ranking, and the reasons for their relative importance, to be set
  out in the terms and conditions.
- **The Digital Services Act** adds transparency duties on recommender systems.
- **India's Consumer Protection (E-Commerce) Rules, 2020** prohibit manipulating
  search results and require disclosure of the parameters used to rank.

The usual response is a compliance document written after the fact, describing a
scoring service nobody outside the team can verify. That document is a liability:
it is either vague enough to be useless or specific enough to be wrong the next
time someone tunes a weight.

There is also a product problem. Pure reverse-chronological order fails in a
seller marketplace in four well-understood ways: relisting to bump, timing posts
for peak traffic, flooding the catalogue with near-identical items, and churning
listings so nothing established survives.

## Decision

The ranking formula is a pure function of stored, per-product inputs, published
verbatim on a public page, and versioned. `ranking.Published()` returns the exact
constants that page shows.

Each component exists to close one specific gaming behaviour:

| Component | Gaming behaviour it closes |
|---|---|
| Time decay with a 72-hour half-life | Timing a post for peak traffic — a genuine new listing stays visible for days |
| Bounded decay past `MaxAgeDays` | An established catalogue going permanently invisible, which is what makes relisting profitable |
| Per-seller exposure cap with basis-point decay beyond it | Flooding with volume |
| Score banding | Micro-optimisation: a one-point difference must not decide a page position |
| Published rotating shuffle seed within a band | A tie-break nobody can verify, which is indistinguishable from a thumb on the scale |

`Disclosure()` renders the parameters and their rationale as text, so the public
page and the code cannot drift: the page is generated from the same struct the
scorer uses.

Because the function is pure and the seed is published, any seller can recompute
their own position. "Why am I on page three" has an arithmetic answer.

## Turning a compliance obligation into an asset

Publishing the formula is required anyway. Publishing a formula that is
*reproducible* converts the obligation into three things a competitor who runs
an opaque scorer cannot offer: a seller can verify they were not demoted, the
platform can prove it did not manipulate results, and a regulator's question is
answered by pointing at a function rather than by an investigation.

## Consequences

Ranking cannot be quietly tuned. Changing a constant requires bumping
`FormulaVersion` and updating the public page, because sellers are entitled to
know the rules changed — which is precisely the discipline the regulation is
trying to impose, made structural rather than procedural.

Personalised ranking is ruled out for the default listing surface, since a
personalised order is not reproducible by the seller. Personalisation, if it
ever arrives, must be a separately-labelled surface, not the default.

The formula is also weaker than a learned ranker would be at pure relevance.
That is accepted: an unexplainable improvement in click-through is not worth the
three regulatory exposures it reopens.
