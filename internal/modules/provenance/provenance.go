// Package provenance gathers evidence about where an uploaded asset came from.
//
// The governing rule, from ADR 0010: the seller's disclosure is the answer, and
// everything computed here is corroboration. Nothing in this package rejects a
// listing, and nothing in it is shown to a buyer as a verdict.
//
// That is not timidity. AI detectors have published false-positive rates high
// enough that a detector-gated marketplace is guaranteed to accuse honest
// creators, their outputs are not explainable so the accused cannot mount a
// defence, and their accuracy decays as generators improve while the accusation
// stays equally damaging. A missed undisclosed listing is recoverable; a
// wrongly banned creator is not. The asymmetry decides the design.
//
// What is computed here is deliberately the set of signals that are cheap,
// explainable, and individually meaningful:
//
//   - C2PA Content Credentials — presence, cryptographic integrity, and the
//     signer. Positive evidence when present; absence means nothing, because
//     most honest tools do not emit one.
//   - Generator hints in metadata — weak, trivially stripped, useful only in
//     aggregate.
//   - Perceptual hash — near-duplicate detection. This catches actual resale of
//     someone else's work, which is a far more common harm than undisclosed
//     generation.
//   - SimHash over text and code — the same, for non-image assets.
//   - Presence of source project files — positive evidence of process, and the
//     single hardest signal to fake.
//
// Each is stored as a distinct fact rather than melted into one opaque number,
// so a moderator reads evidence rather than a score.
package provenance

import (
	"fmt"
	"sort"
	"strings"
)

// Disclosure is the seller's declaration. It is mandatory: a database trigger
// refuses to publish a product that is still `undeclared`.
type Disclosure string

const (
	Undeclared        Disclosure = "undeclared"
	NoAI              Disclosure = "no_ai"
	AIAssisted        Disclosure = "ai_assisted"
	AIGenerated       Disclosure = "ai_generated"
	AIGeneratedEdited Disclosure = "ai_generated_edited"
)

// Valid reports whether d is one of the declared values, excluding the
// placeholder. It matches the ai_disclosure CHECK constraint.
func (d Disclosure) Valid() bool {
	switch d {
	case NoAI, AIAssisted, AIGenerated, AIGeneratedEdited:
		return true
	}
	return false
}

// DeclaresAI reports whether the seller said a generator was involved at all.
func (d Disclosure) DeclaresAI() bool {
	return d == AIAssisted || d == AIGenerated || d == AIGeneratedEdited
}

// Signals are the facts extracted from one asset's bytes. Every field is
// evidence; none is a conclusion.
type Signals struct {
	// C2PAPresent is true when a Content Credentials manifest was found.
	C2PAPresent bool
	// C2PAIntact is true when that manifest's signature verifies against the
	// certificate embedded in it, proving the manifest has not been altered
	// since signing. It does NOT mean the signer is trusted — see C2PAIssuer.
	C2PAIntact bool
	// C2PABindingValid is true when the manifest's hard binding matches the
	// actual bytes, proving the manifest describes THIS asset rather than
	// having been copied from another one.
	C2PABindingValid bool
	// C2PAIssuer is the signing certificate's subject, for a human or a trust
	// list to evaluate. A self-signed manifest is intact and worth nothing.
	C2PAIssuer string
	// C2PAGenerator is the claim_generator string: the tool that made the
	// assertion.
	C2PAGenerator string

	// GeneratorHint is a tool name found in metadata — EXIF Software, XMP
	// CreatorTool, a PNG tEXt key. Weak and trivially stripped.
	GeneratorHint string
	// GeneratorHintIndicatesAI is true when that hint names a known generator.
	GeneratorHintIndicatesAI bool

	// PerceptualHash is a 64-bit pHash for raster images, 0 when not computed.
	PerceptualHash uint64
	// SimHash is a 64-bit SimHash for text and code, 0 when not computed.
	SimHash uint64

	// HasSourceProject is true when the upload includes a layered or editable
	// project file alongside the deliverable.
	HasSourceProject bool
	// SourceProjectKinds names what was found, for the moderator's benefit.
	SourceProjectKinds []string

	// Notes records anything worth a human's attention that is not one of the
	// fields above, including extraction failures. An extraction that failed is
	// recorded, never silently treated as an absent signal.
	Notes []string
}

// Routing is what the platform does with an asset, and it is only ever about
// how much human attention the listing gets.
type Routing string

const (
	// RoutePublish means the evidence corroborates the declaration well enough
	// to publish without a person looking first.
	RoutePublish Routing = "publish"
	// RouteReview means a person should look before it goes live.
	RouteReview Routing = "review"
	// RoutePriorityReview means look sooner: the evidence and the declaration
	// disagree, or the work appears to be someone else's.
	RoutePriorityReview Routing = "priority_review"
)

// Assessment is the output: a score, a routing decision, and — the part that
// matters — the reasons, in words, in the order they weighed.
type Assessment struct {
	// Score is 0..100, higher meaning better-corroborated. It exists because
	// the schema stores one and because a queue needs a sort order. It is never
	// shown to a buyer and never, on its own, decides anything.
	Score int
	// Routing is the decision.
	Routing Routing
	// Reasons explain the score, strongest first. A moderator acts on these.
	Reasons []string
	// Conflicts are the specific disagreements between declaration and
	// evidence. A non-empty Conflicts is always at least RouteReview.
	Conflicts []string
}

// baseScore is where an asset starts: neutral. Evidence moves it in both
// directions, and an asset with no signals at all stays near the middle rather
// than being punished for the silence of honest tooling.
const baseScore = 50

type weighted struct {
	delta  int
	reason string
}

// Assess combines the declaration with the evidence.
//
// The weights below are stated as constants with the behaviour each is there to
// price, for the same reason the ranking formula is published: a number nobody
// can interrogate is indistinguishable from a thumb on the scale.
func Assess(d Disclosure, s Signals) Assessment {
	var a Assessment
	var items []weighted

	// ---- Positive evidence of process ------------------------------------
	switch {
	case s.C2PAPresent && s.C2PAIntact && s.C2PABindingValid:
		items = append(items, weighted{+25,
			"Content Credentials are present, cryptographically intact, and bound to these exact bytes" +
				issuerSuffix(s.C2PAIssuer)})
	case s.C2PAPresent && s.C2PAIntact:
		items = append(items, weighted{+10,
			"Content Credentials are present and intact, but their hard binding does not cover these bytes, " +
				"so the manifest may have been copied from another asset"})
	case s.C2PAPresent:
		items = append(items, weighted{-5,
			"Content Credentials are present but do not verify, which is worse than their absence: " +
				"an unaltered file would not carry a broken manifest"})
	}

	if s.HasSourceProject {
		items = append(items, weighted{+20,
			"the upload includes editable source (" + strings.Join(s.SourceProjectKinds, ", ") +
				"), which is the hardest evidence of process to fabricate"})
	}

	// ---- Corroboration of the declaration --------------------------------
	if s.GeneratorHintIndicatesAI {
		if d.DeclaresAI() {
			items = append(items, weighted{+10,
				"metadata names a generative tool (" + s.GeneratorHint +
					"), which agrees with the seller's declaration"})
		} else {
			c := "metadata names a generative tool (" + s.GeneratorHint +
				") but the seller declared no AI involvement"
			a.Conflicts = append(a.Conflicts, c)
			items = append(items, weighted{-30, c})
		}
	} else if s.GeneratorHint != "" {
		items = append(items, weighted{+5,
			"metadata names a conventional authoring tool (" + s.GeneratorHint + ")"})
	}

	if d.DeclaresAI() && s.HasSourceProject && d == AIGenerated {
		// Not a conflict, but worth a note: "purely generated" plus a layered
		// project usually means the seller under-declared their own editing.
		items = append(items, weighted{+5,
			"the seller declared fully generated work yet supplied editable source, " +
				"which usually means they understated their own contribution"})
	}

	// ---- Absence of evidence is not evidence -----------------------------
	if !s.C2PAPresent && s.GeneratorHint == "" && !s.HasSourceProject {
		items = append(items, weighted{0,
			"no provenance signals were found; this is the normal case for most honest tooling and is not itself a finding"})
	}

	for _, n := range s.Notes {
		items = append(items, weighted{0, n})
	}

	// ---- Score -----------------------------------------------------------
	score := baseScore
	for _, it := range items {
		score += it.delta
	}
	a.Score = clamp(score, 0, 100)

	// Reasons are ordered by how much each moved the score, so a moderator
	// reads the decisive evidence first rather than the first thing computed.
	sort.SliceStable(items, func(i, j int) bool { return abs(items[i].delta) > abs(items[j].delta) })
	for _, it := range items {
		a.Reasons = append(a.Reasons, it.reason)
	}

	// ---- Routing ----------------------------------------------------------
	//
	// Routing is not a threshold on the score alone. A conflict between what
	// the seller said and what the bytes say always reaches a person, however
	// well the asset scores otherwise.
	switch {
	case len(a.Conflicts) > 0:
		a.Routing = RoutePriorityReview
	case !d.Valid():
		a.Routing = RouteReview
		a.Reasons = append(a.Reasons, "the seller has not made a disclosure, which the database refuses to publish without")
	case a.Score >= 70:
		a.Routing = RoutePublish
	default:
		a.Routing = RouteReview
	}
	return a
}

// DuplicateVerdict describes how close two assets are.
type DuplicateVerdict struct {
	Distance int
	// NearDuplicate is true below the threshold at which two images are the
	// same work with different compression, cropping or a watermark.
	NearDuplicate bool
	Explanation   string
}

// NearDuplicateThreshold is the Hamming distance below which two perceptual
// hashes describe the same work.
//
// 10 is deliberately loose. The output is a moderation queue entry, not a
// takedown: a false positive costs a moderator thirty seconds, and a false
// negative means someone's work is resold on this platform. The queue is the
// cheaper side to be wrong on.
const NearDuplicateThreshold = 10

// CompareImages reports whether two perceptual hashes describe the same work.
func CompareImages(a, b uint64) DuplicateVerdict {
	if a == 0 || b == 0 {
		return DuplicateVerdict{Distance: -1,
			Explanation: "one of the assets has no perceptual hash, so no comparison was made"}
	}
	d := HammingDistance(a, b)
	v := DuplicateVerdict{Distance: d, NearDuplicate: d <= NearDuplicateThreshold}
	switch {
	case d == 0:
		v.Explanation = "the two images are perceptually identical"
	case v.NearDuplicate:
		v.Explanation = fmt.Sprintf(
			"the two images differ in %d of 64 perceptual bits, which is the range produced by re-compression, "+
				"cropping or a watermark rather than by independent creation", d)
	default:
		v.Explanation = fmt.Sprintf("the two images differ in %d of 64 perceptual bits and are not the same work", d)
	}
	return v
}

// HammingDistance counts differing bits.
func HammingDistance(a, b uint64) int {
	x := a ^ b
	n := 0
	for x != 0 {
		x &= x - 1
		n++
	}
	return n
}

func issuerSuffix(issuer string) string {
	if issuer == "" {
		return ""
	}
	return ", signed by " + issuer +
		" (whether that signer is trustworthy is a separate question this check does not answer)"
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
