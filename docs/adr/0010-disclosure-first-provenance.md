# 0010. Disclosure-first provenance, never detector-only

Status: Accepted
Date: 2026-09-11

## Context

A digital-goods marketplace has to answer "where did this come from" — for
AI-generated content disclosure, for copyright complaints, and for plain
consumer protection. The tempting answer is an AI-detection model gating uploads.

AI detectors do not work well enough to be a gate. Published false-positive
rates on human-written and human-made work are high enough that a detector-only
policy guarantees wrongly accusing honest sellers, and detector outputs are not
explainable, so an accused seller cannot mount a defence. As generators improve,
the detector's accuracy decays while the accusation stays equally damaging. A
system whose worst error is "we banned an honest creator and cannot explain why"
is not a system that should be built.

## Decision

**Disclosure is mandatory and is the seller's declaration. Signals are
advisory and corroborate the declaration; they never replace it.**

Every product carries `ai_disclosure`, constrained to `no_ai`, `ai_assisted`,
`ai_generated` or `ai_generated_edited`. The database default is `undeclared`,
and a trigger refuses to publish an undeclared product. There is no path to a
live listing that skips the question.

Signals gathered per asset are all cheap, all advisory, and each stored as a
distinct fact rather than melted into one opaque number:

- **C2PA / Content Credentials** — presence, signature validity, issuer. A valid
  manifest is positive evidence, and its absence means nothing, because most
  honest tools do not emit one.
- **Generator hints** in metadata — weak, trivially stripped, useful only in
  aggregate.
- **Perceptual hash and SimHash** — near-duplicate detection. This catches actual
  resale of someone else's work, which is a far more common harm than undisclosed
  generation.
- **Presence of source project files** — a layered PSD, a Blender scene, a Figma
  file. Positive evidence of process, and the single hardest signal to fake.

These roll into a `provenance_score` used to **route** listings: high-confidence
items publish, ambiguous ones queue for human review. The score never
auto-rejects and is never shown to a buyer as a verdict.

## What is enforced versus what is advisory

Enforced, in the database: a published product must have at least one clean,
non-preview deliverable asset, no asset may be unscanned, and the disclosure may
not be `undeclared`. Those are the controls that stop "pay and receive nothing"
and "pay and receive malware", and they are triggers, not application code,
because a control that can be bypassed by a direct `INSERT` is not a control.

Advisory, in the application: everything about *how* the work was made.
Misdeclaration is handled as a trust-and-safety matter with evidence and an
appeal, the same way any other false statement by a seller is handled.

## Consequences

Sellers who lie will get away with it for a while. That is the accepted cost of
not falsely accusing sellers who told the truth, and the asymmetry is
deliberate: a missed undisclosed listing is recoverable, a wrongly banned creator
is not.

Buyers get a stated provenance and the evidence behind it, rather than a badge
whose meaning nobody can explain.

The perceptual-hash index does double duty as copyright-complaint tooling: "show
me every asset within Hamming distance 6 of this one" is an indexed query, which
is what makes a takedown investigation tractable.

## Implementation status

Implemented: the schema and publish-time triggers (`0005_catalog.sql`), and the
signal extractors in `internal/modules/provenance` — C2PA manifest extraction
with COSE_Sign1 verification, DCT perceptual hashing, SimHash over text and
code, metadata generator hints, source-project detection, and the routing model.

One boundary is drawn deliberately and stated wherever it surfaces. Three
questions about a Content Credentials manifest get three separate answers:

1. *Is it present?* Parsing alone.
2. *Is it intact?* The COSE signature verifies against the certificate inside
   the manifest, and the claim read out of it is the claim the signature
   covers. This is checked.
3. *Is the signer trustworthy?* **Not** checked here. That needs the C2PA trust
   list, which is a policy input rather than a parsing question, so the signer
   is recorded for a policy that owns the list to evaluate.

Conflating the second and third would be the easiest way to turn this feature
into a lie, and the reasons text says in words that a verified signature is not
a trusted one.

The moderation queue surfaces that consume this routing are the remaining work.
Until they land the routing is computed and stored but acted on manually, which
is more human review rather than less safety.
