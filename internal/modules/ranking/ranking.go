// Package ranking implements the platform's published, deterministic listing
// order.
//
// The formula is public, the inputs are stored per product, and any listing's
// position can be explained to its seller in plain language. That is not
// decoration: EU Regulation 2019/1150 Article 5 requires disclosure of the main
// ranking parameters and the reasons for their relative importance, the DSA
// adds transparency duties, and India's Consumer Protection (E-Commerce) Rules
// 2020 prohibit manipulating search results. A formula you can publish is the
// cheapest way to satisfy all three at once.
//
// Pure reverse-chronological order fails in a seller marketplace, and the
// failures are well understood: relisting to bump, timing posts for peak
// traffic, flooding with volume, and churning listings so nothing established
// survives. Each component below exists to close one of those.
package ranking

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// FormulaVersion is published alongside the formula. Changing the constants
// below requires bumping it, because sellers are entitled to know that the
// rules changed.
const FormulaVersion = "v1"

// Parameters are the published constants. Every one is documented with the
// gaming behaviour it is there to prevent.
type Parameters struct {
	// HalfLifeHours controls time decay. A listing's recency score halves every
	// HalfLifeHours. Chosen so a genuinely new listing is visible for days, not
	// minutes, which removes the incentive to time a post for peak traffic.
	HalfLifeHours float64

	// MaxAgeDays bounds decay. Past this, recency contributes nothing and
	// ordering within the tail is by band and then by the published shuffle,
	// so an old catalogue does not become permanently invisible.
	MaxAgeDays float64

	// ExposureCapPerSeller is how many of a seller's listings receive full
	// exposure weight. Beyond it, each further listing is progressively
	// discounted. This is the anti-flooding control: publishing a hundred
	// near-identical items cannot crowd out everyone else.
	ExposureCapPerSeller int

	// ExposureDecayBps is the multiplicative discount applied per listing
	// beyond the cap, in basis points. 7000 means each additional listing is
	// weighted at 70% of the previous one.
	ExposureDecayBps int64

	// BandWidth groups scores into bands. Within a band, order is decided by a
	// published, rotating seed rather than by score, so a one-point difference
	// does not decide a page position and micro-optimisation is pointless.
	BandWidth int

	// SeedRotation is how often the shuffle seed changes. The seed itself is
	// published: a tie-break nobody can verify is indistinguishable from a
	// thumb on the scale.
	SeedRotation time.Duration
}

// Published returns the parameters in force. These exact values appear on the
// public "How ranking works" page.
func Published() Parameters {
	return Parameters{
		HalfLifeHours:        72,
		MaxAgeDays:           365,
		ExposureCapPerSeller: 3,
		ExposureDecayBps:     7000,
		BandWidth:            5000,
		SeedRotation:         24 * time.Hour,
	}
}

// QualityGate is a pass/fail set of objective conditions, deliberately NOT an
// engagement optimiser.
//
// Nothing here rewards popularity, and nothing here can be bought. A listing
// either meets the bar or it does not; there is no way to buy a higher
// position, which is the property the Consumer Protection rules care about.
type QualityGate struct {
	SellerKYCVerified   bool
	AllAssetsScanned    bool
	AIDisclosureGiven   bool
	HasPreview          bool
	DescriptionAdequate bool
	NotUnderModeration  bool
	// RefundRateAcceptable fails when a listing is refunded far more often than
	// the catalogue norm, which is an objective signal of misdescription rather
	// than a popularity measure.
	RefundRateAcceptable bool
}

// Failures lists the unmet conditions in the wording shown to the seller.
func (q QualityGate) Failures() []string {
	var out []string
	if !q.SellerKYCVerified {
		out = append(out, "seller identity is not yet verified")
	}
	if !q.AllAssetsScanned {
		out = append(out, "one or more files have not completed malware scanning")
	}
	if !q.AIDisclosureGiven {
		out = append(out, "the AI-content declaration is missing")
	}
	if !q.HasPreview {
		out = append(out, "the listing has no preview for buyers to inspect before purchase")
	}
	if !q.DescriptionAdequate {
		out = append(out, "the description is too short to tell a buyer what they are getting")
	}
	if !q.NotUnderModeration {
		out = append(out, "the listing is under moderation review")
	}
	if !q.RefundRateAcceptable {
		out = append(out, "this listing is refunded far more often than the catalogue norm")
	}
	return out
}

func (q QualityGate) Passed() bool { return len(q.Failures()) == 0 }

// Input is everything the formula reads about one listing.
type Input struct {
	ProductID string
	SellerID  string
	// AnchorAt is the FIRST publication time and never moves. Unpublishing and
	// republishing therefore buys no advantage, which removes bump spam.
	AnchorAt time.Time
	Gate     QualityGate
	// SellerRank is this listing's position among the seller's own listings,
	// newest first, starting at 1. It drives the exposure cap.
	SellerRank int
}

// Result is a scored listing with a complete explanation.
type Result struct {
	ProductID         string
	SellerID          string
	AgeHours          int
	RecencyScore      int
	GatePassed        bool
	GateFailures      []string
	ExposureRank      int
	ExposureFactorBps int64
	Band              int
	FinalScore        int
	ShuffleKey        uint64
	// Explain is the per-listing disclosure: why this listing sits where it
	// does, in language a seller can act on.
	Explain []string
}

// Score computes one listing's position inputs.
//
//	score = recency(age) x quality_gate x exposure_factor(seller_rank)
//
// recency is exponential decay with the published half-life; quality_gate is
// pass or fail, not a multiplier that can be nudged; exposure_factor throttles
// a single seller's simultaneous presence.
func Score(p Parameters, in Input, now time.Time) Result {
	res := Result{
		ProductID: in.ProductID, SellerID: in.SellerID,
		ExposureRank: in.SellerRank,
	}

	age := now.Sub(in.AnchorAt)
	if age < 0 {
		// A listing anchored in the future is treated as brand new rather than
		// given an advantage, which closes the clock-skew angle.
		age = 0
	}
	res.AgeHours = int(age.Hours())

	maxAge := time.Duration(p.MaxAgeDays) * 24 * time.Hour
	switch {
	case age >= maxAge:
		res.RecencyScore = 0
		res.Explain = append(res.Explain, fmt.Sprintf(
			"This listing is older than %.0f days, so recency no longer contributes to its position. Within that group, order is decided by the published daily shuffle.",
			p.MaxAgeDays))
	default:
		// 1_000_000 x 2^(-age/halfLife), computed in float only for the decay
		// curve itself and immediately truncated to an integer score, so
		// ordering is exactly reproducible by anyone following the published
		// formula.
		decay := math.Pow(2, -age.Hours()/p.HalfLifeHours)
		res.RecencyScore = int(math.Floor(decay * 1_000_000))
		res.Explain = append(res.Explain, fmt.Sprintf(
			"Recency: published %d hours ago, giving %d of 1,000,000. The score halves every %.0f hours and is measured from FIRST publication, so relisting does not reset it.",
			res.AgeHours, res.RecencyScore, p.HalfLifeHours))
	}

	res.GatePassed = in.Gate.Passed()
	res.GateFailures = in.Gate.Failures()
	if !res.GatePassed {
		res.FinalScore = 0
		res.ExposureFactorBps = 0
		res.Explain = append(res.Explain,
			"Quality gate: not met, so this listing does not appear in ranked results. Unmet conditions: "+
				strings.Join(res.GateFailures, "; ")+". The gate is a fixed checklist: a position here "+
				"cannot be bought, so fixing the conditions above is the only thing that changes this listing's placement.")
		return res
	}
	res.Explain = append(res.Explain,
		"Quality gate: met. The gate is a fixed checklist, not a popularity measure: a position here cannot be bought.")

	res.ExposureFactorBps = exposureFactor(p, in.SellerRank)
	if res.ExposureFactorBps < 10_000 {
		res.Explain = append(res.Explain, fmt.Sprintf(
			"Exposure cap: this is listing number %d from this seller. The first %d receive full weight; each further listing is weighted at %.0f%% of the one before, so this listing carries %.2f%%. This stops any one seller from filling the page.",
			in.SellerRank, p.ExposureCapPerSeller,
			float64(p.ExposureDecayBps)/100, float64(res.ExposureFactorBps)/100))
	} else {
		res.Explain = append(res.Explain, fmt.Sprintf(
			"Exposure cap: this is listing number %d from this seller, within the first %d, so it carries full weight.",
			in.SellerRank, p.ExposureCapPerSeller))
	}

	res.FinalScore = int(int64(res.RecencyScore) * res.ExposureFactorBps / 10_000)
	res.Band = res.FinalScore / p.BandWidth
	res.Explain = append(res.Explain, fmt.Sprintf(
		"Final score %d places this listing in band %d. Listings within a band are shuffled by a seed that rotates every %s and is published, so a one-point difference never decides a page position.",
		res.FinalScore, res.Band, p.SeedRotation))
	return res
}

// exposureFactor returns 10000 (full) for listings within the cap, then decays
// multiplicatively. Integer arithmetic throughout: the factor must be exactly
// reproducible from the published constants.
func exposureFactor(p Parameters, sellerRank int) int64 {
	if sellerRank <= p.ExposureCapPerSeller {
		return 10_000
	}
	factor := int64(10_000)
	for i := p.ExposureCapPerSeller; i < sellerRank; i++ {
		factor = factor * p.ExposureDecayBps / 10_000
		if factor == 0 {
			return 0
		}
	}
	return factor
}

// Order sorts scored listings: by band descending, then by the published
// shuffle within each band, then by product id as a final deterministic
// tie-break.
//
// The result is fully reproducible: anyone with the seed and the same inputs
// gets the same order, which is what makes the disclosure checkable rather than
// merely stated.
func Order(results []Result, seed uint64) []Result {
	out := make([]Result, len(results))
	copy(out, results)
	for i := range out {
		out[i].ShuffleKey = shuffleKey(seed, out[i].ProductID)
	}
	sort.SliceStable(out, func(i, j int) bool {
		switch {
		case out[i].Band != out[j].Band:
			return out[i].Band > out[j].Band
		case out[i].ShuffleKey != out[j].ShuffleKey:
			return out[i].ShuffleKey < out[j].ShuffleKey
		}
		return out[i].ProductID < out[j].ProductID
	})
	return out
}

// shuffleKey is a published mixing function: splitmix64 over the seed combined
// with the product id. It is specified rather than left to a library so a third
// party can reimplement it and verify our ordering.
func shuffleKey(seed uint64, productID string) uint64 {
	h := seed
	for i := 0; i < len(productID); i++ {
		h ^= uint64(productID[i])
		h *= 1099511628211 // FNV-1a prime
	}
	// splitmix64 finaliser, for avalanche.
	h += 0x9E3779B97F4A7C15
	z := h
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// SeedFor derives the shuffle seed for an instant. It is deterministic, so the
// public page can state today's seed and anyone can verify the order.
func SeedFor(t time.Time, rotation time.Duration) uint64 {
	if rotation <= 0 {
		rotation = 24 * time.Hour
	}
	period := t.UTC().Unix() / int64(rotation.Seconds())
	z := uint64(period) + 0x9E3779B97F4A7C15
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// Disclosure renders the full public explanation of the formula. It is served
// verbatim at /legal/ranking and is the P2B Article 5 artefact.
func Disclosure(p Parameters) string {
	var b strings.Builder
	b.WriteString("How listings are ordered (formula version " + FormulaVersion + ")\n\n")
	b.WriteString("Every listing's position is produced by a published formula from published inputs. " +
		"There is no paid placement on this marketplace, and no position can be bought, boosted or negotiated.\n\n")
	b.WriteString("  score = recency x quality_gate x exposure_factor\n\n")

	b.WriteString("1. Recency\n")
	fmt.Fprintf(&b, "   A listing starts at 1,000,000 points and halves every %.0f hours.\n", p.HalfLifeHours)
	b.WriteString("   Age is measured from FIRST publication and never resets. Unpublishing and\n")
	b.WriteString("   republishing a listing does not move it up, so there is nothing to gain from\n")
	b.WriteString("   relisting, and nothing to gain from posting at a particular time of day.\n")
	fmt.Fprintf(&b, "   After %.0f days recency contributes nothing and order within that group is\n", p.MaxAgeDays)
	b.WriteString("   decided by the published shuffle below.\n\n")

	b.WriteString("2. Quality gate (pass or fail)\n")
	b.WriteString("   A listing appears in ranked results only if all of the following hold:\n")
	b.WriteString("     - the seller's identity is verified;\n")
	b.WriteString("     - every file has completed malware scanning;\n")
	b.WriteString("     - the AI-content declaration has been given;\n")
	b.WriteString("     - a preview is available for buyers to inspect before purchase;\n")
	b.WriteString("     - the description is long enough to describe what is being sold;\n")
	b.WriteString("     - the listing is not under moderation review;\n")
	b.WriteString("     - the listing is not refunded far more often than the catalogue norm.\n")
	b.WriteString("   This is a checklist, not a score. Sales volume, ratings, revenue and advertising\n")
	b.WriteString("   spend are NOT inputs to ranking anywhere in this formula.\n\n")

	b.WriteString("3. Exposure cap\n")
	fmt.Fprintf(&b, "   A seller's %d most recent listings carry full weight. Each further listing is\n", p.ExposureCapPerSeller)
	fmt.Fprintf(&b, "   weighted at %.0f%% of the one before it. Publishing many near-identical listings\n", float64(p.ExposureDecayBps)/100)
	b.WriteString("   therefore cannot crowd others off the page.\n\n")

	b.WriteString("4. Bands and the published shuffle\n")
	fmt.Fprintf(&b, "   Scores are grouped into bands of %d points. Within a band, order is decided by a\n", p.BandWidth)
	fmt.Fprintf(&b, "   seed that rotates every %s and is published on this page. A one-point difference\n", p.SeedRotation)
	b.WriteString("   never decides a page position, so micro-optimising a listing achieves nothing.\n")
	b.WriteString("   Because the seed is published and the mixing function is specified, anyone can\n")
	b.WriteString("   reproduce the exact order we serve and check it for themselves.\n\n")

	b.WriteString("Buyers may also choose explicit sorts (newest, price, rating). Those replace this\n")
	b.WriteString("formula entirely and are applied exactly as named.\n\n")
	b.WriteString("If you believe a listing of yours is ranked wrongly, the per-listing explanation in\n")
	b.WriteString("your seller dashboard shows every input above for that listing, and our published\n")
	b.WriteString("grievance process is open to you at any time.\n")
	return b.String()
}
