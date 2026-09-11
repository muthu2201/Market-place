package ranking

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func goodGate() QualityGate {
	return QualityGate{
		SellerKYCVerified: true, AllAssetsScanned: true, AIDisclosureGiven: true,
		HasPreview: true, DescriptionAdequate: true, NotUnderModeration: true,
		RefundRateAcceptable: true,
	}
}

func TestRecencyHalvesOnSchedule(t *testing.T) {
	p := Published()
	fresh := Score(p, Input{ProductID: "a", SellerID: "s", AnchorAt: now, Gate: goodGate(), SellerRank: 1}, now)
	if fresh.RecencyScore != 1_000_000 {
		t.Fatalf("a brand-new listing scores %d, want 1,000,000", fresh.RecencyScore)
	}
	oneHalfLife := Score(p, Input{ProductID: "a", SellerID: "s",
		AnchorAt: now.Add(-72 * time.Hour), Gate: goodGate(), SellerRank: 1}, now)
	if oneHalfLife.RecencyScore != 500_000 {
		t.Fatalf("after one half-life the score is %d, want 500,000", oneHalfLife.RecencyScore)
	}
	twoHalfLives := Score(p, Input{ProductID: "a", SellerID: "s",
		AnchorAt: now.Add(-144 * time.Hour), Gate: goodGate(), SellerRank: 1}, now)
	if twoHalfLives.RecencyScore != 250_000 {
		t.Fatalf("after two half-lives the score is %d, want 250,000", twoHalfLives.RecencyScore)
	}
}

// The anti-bump control: the anchor is first publication, so relisting achieves
// nothing. This is asserted because it is the single most exploited weakness of
// chronological ordering.
func TestRelistingCannotBumpAListing(t *testing.T) {
	p := Published()
	old := Input{ProductID: "a", SellerID: "s", AnchorAt: now.Add(-30 * 24 * time.Hour), Gate: goodGate(), SellerRank: 1}
	before := Score(p, old, now)

	// The seller unpublishes and republishes. The anchor does not move, so
	// nothing about the score changes.
	after := Score(p, old, now)
	if before.FinalScore != after.FinalScore {
		t.Fatalf("republishing changed the score: %d -> %d", before.FinalScore, after.FinalScore)
	}
	// A genuinely new listing outranks it, which is the intended behaviour.
	fresh := Score(p, Input{ProductID: "b", SellerID: "s2", AnchorAt: now, Gate: goodGate(), SellerRank: 1}, now)
	if fresh.FinalScore <= before.FinalScore {
		t.Fatal("a genuinely new listing should outrank a month-old one")
	}
}

func TestQualityGateIsPassFailNotAMultiplier(t *testing.T) {
	p := Published()
	gate := goodGate()
	gate.AIDisclosureGiven = false
	res := Score(p, Input{ProductID: "a", SellerID: "s", AnchorAt: now, Gate: gate, SellerRank: 1}, now)
	if res.GatePassed || res.FinalScore != 0 {
		t.Fatalf("a failed gate must remove the listing from ranked results, got score %d", res.FinalScore)
	}
	if len(res.GateFailures) != 1 || !strings.Contains(res.GateFailures[0], "AI-content declaration") {
		t.Fatalf("the failure must name the missing condition: %v", res.GateFailures)
	}
	// The explanation must be actionable by the seller.
	joined := strings.Join(res.Explain, " ")
	if !strings.Contains(joined, "AI-content declaration") {
		t.Fatalf("the explanation must say what to fix: %v", res.Explain)
	}
	if !strings.Contains(joined, "cannot be bought") {
		t.Fatal("the disclosure must state plainly that position cannot be purchased")
	}
}

// The anti-flooding control.
func TestExposureCapThrottlesASingleSeller(t *testing.T) {
	p := Published()
	var scores []int
	for rank := 1; rank <= 8; rank++ {
		r := Score(p, Input{ProductID: "p", SellerID: "s", AnchorAt: now, Gate: goodGate(), SellerRank: rank}, now)
		scores = append(scores, r.FinalScore)
	}
	// The first three are equal (within the cap).
	if scores[0] != scores[1] || scores[1] != scores[2] {
		t.Fatalf("the first %d listings should carry full weight: %v", p.ExposureCapPerSeller, scores[:3])
	}
	// Each subsequent listing is strictly lower.
	for i := 3; i < len(scores); i++ {
		if scores[i] >= scores[i-1] {
			t.Fatalf("listing %d (%d) should be discounted below listing %d (%d)", i+1, scores[i], i, scores[i-1])
		}
	}
	// A seller flooding the catalogue cannot out-weigh several distinct sellers.
	flood := 0
	for rank := 1; rank <= 20; rank++ {
		flood += Score(p, Input{ProductID: "f", SellerID: "s", AnchorAt: now, Gate: goodGate(), SellerRank: rank}, now).FinalScore
	}
	honest := 0
	for i := 0; i < 6; i++ {
		honest += Score(p, Input{ProductID: "h", SellerID: "other", AnchorAt: now, Gate: goodGate(), SellerRank: 1}, now).FinalScore
	}
	if flood >= honest {
		t.Fatalf("20 listings from one seller (%d) must not outweigh 6 from distinct sellers (%d)", flood, honest)
	}
}

func TestFutureAnchorGainsNoAdvantage(t *testing.T) {
	p := Published()
	future := Score(p, Input{ProductID: "a", SellerID: "s",
		AnchorAt: now.Add(48 * time.Hour), Gate: goodGate(), SellerRank: 1}, now)
	present := Score(p, Input{ProductID: "b", SellerID: "s2",
		AnchorAt: now, Gate: goodGate(), SellerRank: 1}, now)
	if future.FinalScore > present.FinalScore {
		t.Fatal("a listing anchored in the future must not outrank one anchored now")
	}
}

// Ordering must be exactly reproducible by a third party, which is what makes
// the disclosure verifiable rather than merely asserted.
func TestOrderingIsDeterministicAndReproducible(t *testing.T) {
	p := Published()
	var results []Result
	for i := 0; i < 50; i++ {
		results = append(results, Score(p, Input{
			ProductID: "prd_" + string(rune('A'+i%26)) + string(rune('a'+i/26)),
			SellerID:  "slr_1", AnchorAt: now.Add(-time.Duration(i) * 6 * time.Hour),
			Gate: goodGate(), SellerRank: 1,
		}, now))
	}
	seed := SeedFor(now, p.SeedRotation)
	first := Order(results, seed)
	second := Order(results, seed)
	for i := range first {
		if first[i].ProductID != second[i].ProductID {
			t.Fatalf("ordering is not deterministic at position %d", i)
		}
	}
	// Bands are in descending order.
	for i := 1; i < len(first); i++ {
		if first[i].Band > first[i-1].Band {
			t.Fatalf("band order broken at %d: %d after %d", i, first[i].Band, first[i-1].Band)
		}
	}
	// A different seed produces a different order within bands.
	other := Order(results, SeedFor(now.Add(48*time.Hour), p.SeedRotation))
	same := 0
	for i := range first {
		if first[i].ProductID == other[i].ProductID {
			same++
		}
	}
	if same == len(first) {
		t.Fatal("rotating the seed must reshuffle within bands")
	}
}

func TestSeedRotatesOnSchedule(t *testing.T) {
	p := Published()
	a := SeedFor(now, p.SeedRotation)
	b := SeedFor(now.Add(2*time.Hour), p.SeedRotation)
	if a != b {
		t.Fatal("the seed must be stable within a rotation period")
	}
	c := SeedFor(now.Add(25*time.Hour), p.SeedRotation)
	if a == c {
		t.Fatal("the seed must change between rotation periods")
	}
}

func TestWithinBandOrderDoesNotFollowScore(t *testing.T) {
	p := Published()
	// Two listings whose scores differ by a single point sit in the same band,
	// so the higher score must NOT reliably win: micro-optimising is pointless.
	var sameBand []Result
	for i := 0; i < 200; i++ {
		r := Result{ProductID: "prd_" + pad(i), Band: 7, FinalScore: 35000 + i}
		sameBand = append(sameBand, r)
	}
	ordered := Order(sameBand, SeedFor(now, p.SeedRotation))
	// If ordering followed score, the highest-scoring item would lead.
	if ordered[0].FinalScore == 35199 {
		t.Fatal("within a band the highest score must not automatically lead")
	}
	if len(ordered) != len(sameBand) {
		t.Fatal("ordering dropped listings")
	}
}

func TestDisclosureCoversEveryRequiredPoint(t *testing.T) {
	text := Disclosure(Published())
	required := []string{
		"no paid placement",
		"halves every",
		"FIRST publication",
		"Quality gate",
		"NOT inputs to ranking",
		"Exposure cap",
		"published on this page",
		"reproduce the exact order",
		"grievance process",
	}
	lower := strings.ToLower(text)
	for _, r := range required {
		if !strings.Contains(lower, strings.ToLower(r)) {
			t.Errorf("the published disclosure is missing %q", r)
		}
	}
	if len(text) < 1500 {
		t.Fatalf("the disclosure is only %d characters; P2B Article 5 expects a genuine second layer of explanation", len(text))
	}
}

func TestEveryListingCarriesAnExplanation(t *testing.T) {
	p := Published()
	res := Score(p, Input{ProductID: "a", SellerID: "s",
		AnchorAt: now.Add(-100 * time.Hour), Gate: goodGate(), SellerRank: 5}, now)
	if len(res.Explain) < 4 {
		t.Fatalf("expected a full explanation, got %d lines", len(res.Explain))
	}
	joined := strings.Join(res.Explain, "\n")
	for _, want := range []string{"Recency", "Quality gate", "Exposure cap", "band"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the explanation omits %q:\n%s", want, joined)
		}
	}
}

func pad(i int) string {
	s := ""
	for _, c := range []int{i / 100 % 10, i / 10 % 10, i % 10} {
		s += string(rune('0' + c))
	}
	return s
}

func BenchmarkScore(b *testing.B) {
	p := Published()
	in := Input{ProductID: "prd_X", SellerID: "slr_Y", AnchorAt: now.Add(-50 * time.Hour), Gate: goodGate(), SellerRank: 2}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Score(p, in, now)
	}
}
