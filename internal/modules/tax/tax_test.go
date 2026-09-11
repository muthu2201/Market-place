package tax

import (
	"math/rand"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/platform/money"
)

func inr(s string) money.Money {
	m, err := money.Parse(s, money.INR)
	if err != nil {
		panic(err)
	}
	return m
}

var now = time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)

func registeredSeller(state int) Seller {
	return Seller{
		GSTRegistered: true, GSTIN: "33AAACT2727Q1ZW", StateCode: state,
		HasPAN: true, ResidentIndividualOrHUF: false, Country: "IN",
	}
}

// The worked example from the blueprint's unit-economics section: a Rs 2,000
// sale, 9% commission, 18% GST, 1% TCS, 0.1% TDS.
func TestWorkedExampleIntraState(t *testing.T) {
	p := DefaultPolicy()
	s := registeredSeller(33)
	b := Buyer{Country: "IN", StateCode: 33}
	l := Line{ListPrice: inr("2000.00"), CommissionBps: 900, PSPFeeBps: 200, PSPFeeGSTBps: 1800}

	got, err := Compute(p, s, b, l, now)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}

	check := func(name string, have money.Money, want string) {
		t.Helper()
		if have.Decimal() != want {
			t.Errorf("%s = %s, want %s", name, have.Decimal(), want)
		}
	}
	if got.Supply != IntraState {
		t.Fatalf("supply = %s, want intra_state", got.Supply)
	}
	check("CGST", got.CGST, "180.00") // 9% of 2000
	check("SGST", got.SGST, "180.00") // 9% of 2000
	check("IGST", got.IGST, "0.00")
	check("tax total", got.TaxTotal, "360.00")
	check("buyer total", got.BuyerTotal, "2360.00")
	check("commission", got.Commission, "180.00")       // 9% of 2000
	check("commission GST", got.CommissionGST, "32.40") // 18% of 180
	check("TCS", got.TCS, "20.00")                      // 1% of 2000, split 10/10
	check("TCS CGST", got.TCSCGST, "10.00")
	check("TDS", got.TDS, "2.00")               // 0.1% of 2000
	check("PSP fee", got.PSPFee, "47.20")       // 2% of 2360
	check("PSP fee GST", got.PSPFeeGST, "8.50") // 18% of 47.20 = 8.496 -> 8.50
	// 2360.00 - 180.00 - 32.40 - 20.00 - 2.00
	check("seller net", got.SellerNet, "2125.60")
	// commission 180.00 less absorbed PSP fee 47.20
	check("platform margin", got.PlatformMargin, "132.80")
}

func TestInterStateUsesIGST(t *testing.T) {
	got, err := Compute(DefaultPolicy(), registeredSeller(33), Buyer{Country: "IN", StateCode: 29},
		Line{ListPrice: inr("2000.00"), CommissionBps: 900}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Supply != InterState {
		t.Fatalf("supply = %s", got.Supply)
	}
	if got.IGST.Decimal() != "360.00" || !got.CGST.IsZero() || !got.SGST.IsZero() {
		t.Fatalf("IGST=%s CGST=%s SGST=%s", got.IGST.Decimal(), got.CGST.Decimal(), got.SGST.Decimal())
	}
	if got.TCSIGST.Decimal() != "20.00" || !got.TCSCGST.IsZero() {
		t.Fatalf("TCS should be IGST-only inter-state, got igst=%s cgst=%s", got.TCSIGST.Decimal(), got.TCSCGST.Decimal())
	}
}

func TestUnregisteredSellerChargesNoGSTAndNoTCS(t *testing.T) {
	s := Seller{GSTRegistered: false, StateCode: 33, HasPAN: true, Country: "IN"}
	got, err := Compute(DefaultPolicy(), s, Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("500.00"), CommissionBps: 900}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Supply != Exempt {
		t.Fatalf("supply = %s, want exempt", got.Supply)
	}
	if !got.TaxTotal.IsZero() {
		t.Fatalf("an unregistered seller cannot charge GST, got %s", got.TaxTotal)
	}
	if !got.TCS.IsZero() {
		t.Fatalf("TCS must not be collected against a seller with no GSTIN, got %s", got.TCS)
	}
	if got.BuyerTotal.Decimal() != "500.00" {
		t.Fatalf("buyer total = %s, want 500.00", got.BuyerTotal.Decimal())
	}
	// Commission and its GST still apply: the platform IS registered.
	if got.Commission.Decimal() != "45.00" || got.CommissionGST.Decimal() != "8.10" {
		t.Fatalf("commission=%s gst=%s", got.Commission.Decimal(), got.CommissionGST.Decimal())
	}
	if got.SellerNet.Decimal() != "446.40" { // 500 - 45 - 8.10 - 0 - 0.50
		t.Fatalf("seller net = %s", got.SellerNet.Decimal())
	}
}

func TestExportOfServicesIsZeroRated(t *testing.T) {
	got, err := Compute(DefaultPolicy(), registeredSeller(33), Buyer{Country: "US"},
		Line{ListPrice: inr("2000.00"), CommissionBps: 900}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Supply != ExportOfServices {
		t.Fatalf("supply = %s", got.Supply)
	}
	if !got.TaxTotal.IsZero() {
		t.Fatalf("an export of services is zero-rated, got %s", got.TaxTotal)
	}
	if got.TCS.Decimal() != "20.00" {
		t.Fatalf("default policy collects TCS on exports, got %s", got.TCS.Decimal())
	}
	p := DefaultPolicy()
	p.CollectTCSOnExports = false
	got2, _ := Compute(p, registeredSeller(33), Buyer{Country: "US"},
		Line{ListPrice: inr("2000.00"), CommissionBps: 900}, now)
	if !got2.TCS.IsZero() {
		t.Fatalf("policy switch should suppress TCS on exports, got %s", got2.TCS)
	}
}

func TestTDS194OThresholdForResidentIndividual(t *testing.T) {
	p := DefaultPolicy()
	s := registeredSeller(33)
	s.ResidentIndividualOrHUF = true

	// Well inside the threshold: no deduction.
	s.FYGrossSupplyMinor = inr("100000.00").Minor()
	got, err := Compute(p, s, Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("2000.00"), CommissionBps: 900}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TDS.IsZero() {
		t.Fatalf("below threshold must not deduct, got %s (%s)", got.TDS, got.TDSReason)
	}

	// This sale crosses the threshold: deduction resumes.
	s.FYGrossSupplyMinor = inr("499000.00").Minor()
	got, err = Compute(p, s, Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("2000.00"), CommissionBps: 900}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.TDS.Decimal() != "2.00" {
		t.Fatalf("crossing the threshold must deduct 0.1%%, got %s (%s)", got.TDS.Decimal(), got.TDSReason)
	}

	// A company has no threshold at all.
	s2 := registeredSeller(33)
	s2.FYGrossSupplyMinor = 0
	got, _ = Compute(p, s2, Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("2000.00"), CommissionBps: 900}, now)
	if got.TDS.Decimal() != "2.00" {
		t.Fatalf("a company has no 194-O threshold, got %s", got.TDS.Decimal())
	}
}

func TestNoPANTriggersSection206AARate(t *testing.T) {
	s := registeredSeller(33)
	s.HasPAN = false
	got, err := Compute(DefaultPolicy(), s, Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("2000.00"), CommissionBps: 900}, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.TDS.Decimal() != "100.00" { // 5% of 2000
		t.Fatalf("no-PAN rate should be 5%%, got %s", got.TDS.Decimal())
	}
	if got.TDSBps != 500 {
		t.Fatalf("TDSBps = %d, want 500", got.TDSBps)
	}
}

func TestNonResidentSellerHasNo194O(t *testing.T) {
	s := registeredSeller(33)
	s.Country = "SG"
	got, err := Compute(DefaultPolicy(), s, Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("2000.00"), CommissionBps: 900}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TDS.IsZero() {
		t.Fatalf("194-O binds resident sellers, got %s", got.TDS)
	}
}

func TestSellerBearingPSPFeeChangesSettlementNotBuyerPrice(t *testing.T) {
	p := DefaultPolicy()
	p.PSPFeeBearer = "seller"
	l := Line{ListPrice: inr("2000.00"), CommissionBps: 900, PSPFeeBps: 200, PSPFeeGSTBps: 1800}
	got, err := Compute(p, registeredSeller(33), Buyer{Country: "IN", StateCode: 33}, l, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.BuyerTotal.Decimal() != "2360.00" {
		t.Fatalf("who bears the fee must not change what the buyer pays, got %s", got.BuyerTotal.Decimal())
	}
	// 2125.60 - 47.20 - 8.50
	if got.SellerNet.Decimal() != "2069.90" {
		t.Fatalf("seller net = %s, want 2069.90", got.SellerNet.Decimal())
	}
	if got.PlatformMargin.Decimal() != "180.00" {
		t.Fatalf("platform keeps the full commission when the seller bears the fee, got %s", got.PlatformMargin.Decimal())
	}
}

// A flat per-transaction fee is brutal on a low-priced product; a percentage is
// not. The blueprint's pricing argument is worth asserting so it cannot regress.
func TestLowTicketSaleStaysViable(t *testing.T) {
	got, err := Compute(DefaultPolicy(), registeredSeller(33), Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("50.00"), CommissionBps: 900, PSPFeeBps: 200, PSPFeeGSTBps: 1800}, now)
	if err != nil {
		t.Fatal(err)
	}
	// 59.00 - 4.50 - 0.81 - 0.50 - 0.05
	if got.SellerNet.Decimal() != "53.14" {
		t.Fatalf("seller net on a Rs 50 sale = %s, want 53.14", got.SellerNet.Decimal())
	}
	share := float64(got.SellerNet.Minor()) / float64(got.BuyerTotal.Minor())
	if share < 0.88 {
		t.Fatalf("seller keeps only %.1f%% of a small sale", share*100)
	}
}

// The invariant that matters most: across a large random sample, every paise the
// buyer paid is accounted for exactly once.
func TestConservationOverRandomisedSales(t *testing.T) {
	rng := rand.New(rand.NewSource(20260911))
	p := DefaultPolicy()
	for i := 0; i < 200000; i++ {
		price := rng.Int63n(5_000_000) // up to Rs 50,000
		s := Seller{
			GSTRegistered:           rng.Intn(2) == 0,
			GSTIN:                   "33AAACT2727Q1ZW",
			StateCode:               1 + rng.Intn(38),
			HasPAN:                  rng.Intn(10) > 0,
			ResidentIndividualOrHUF: rng.Intn(2) == 0,
			FYGrossSupplyMinor:      rng.Int63n(80_000_000),
			Country:                 "IN",
		}
		b := Buyer{Country: "IN", StateCode: 1 + rng.Intn(38)}
		if rng.Intn(8) == 0 {
			b = Buyer{Country: "US"}
		}
		bearer := "platform"
		if rng.Intn(2) == 0 {
			bearer = "seller"
		}
		pp := p
		pp.PSPFeeBearer = bearer

		l := Line{
			ListPrice:     money.MustNew(price, money.INR),
			CommissionBps: int64(rng.Intn(1500)),
			PSPFeeBps:     int64(rng.Intn(400)),
			PSPFeeGSTBps:  1800,
		}
		got, err := Compute(pp, s, b, l, now)
		if err != nil {
			t.Fatalf("iteration %d (price %d): %v", i, price, err)
		}
		// Verify already ran inside Compute; assert it independently too so a
		// future refactor that drops the internal call is caught here.
		if err := got.Verify(); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}

func TestNegativeSettlementIsRefused(t *testing.T) {
	// A commission of 100% plus GST and statutory deductions cannot be paid out
	// of the sale; the engine must refuse rather than emit a negative figure.
	_, err := Compute(DefaultPolicy(), registeredSeller(33), Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("100.00"), CommissionBps: 10000}, now)
	if err == nil {
		t.Fatal("expected refusal when deductions exceed the buyer payment")
	}
}

func TestPolicyValidation(t *testing.T) {
	bad := DefaultPolicy()
	bad.GSTBps = 1801 // odd: CGST and SGST could not be equal
	if _, err := Compute(bad, registeredSeller(33), Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("100.00"), CommissionBps: 900}, now); err == nil {
		t.Fatal("an odd GST rate must be rejected")
	}
	bad2 := DefaultPolicy()
	bad2.PSPFeeBearer = "buyer"
	if _, err := Compute(bad2, registeredSeller(33), Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("100.00"), CommissionBps: 900}, now); err == nil {
		t.Fatal("an unknown fee bearer must be rejected")
	}
}

func TestFinancialYearAndDueDates(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-09-11", "2026-04-01"},
		{"2026-04-01", "2026-04-01"},
		{"2026-03-31", "2025-04-01"},
		{"2026-01-15", "2025-04-01"},
	}
	for _, c := range cases {
		in, _ := time.Parse("2006-01-02", c.in)
		if got := FinancialYearStart(in).Format("2006-01-02"); got != c.want {
			t.Errorf("FinancialYearStart(%s) = %s, want %s", c.in, got, c.want)
		}
	}
	sep, _ := time.Parse("2006-01-02", "2026-09-01")
	if got := GSTR8DueDate(sep).Format("2006-01-02"); got != "2026-10-10" {
		t.Errorf("GSTR-8 due = %s, want 2026-10-10", got)
	}
	if got := TDSDepositDueDate(sep).Format("2006-01-02"); got != "2026-10-07" {
		t.Errorf("TDS due = %s, want 2026-10-07", got)
	}
	mar, _ := time.Parse("2006-01-02", "2026-03-01")
	if got := TDSDepositDueDate(mar).Format("2006-01-02"); got != "2026-04-30" {
		t.Errorf("March TDS due = %s, want 2026-04-30", got)
	}
}

func TestExplanationIsProduced(t *testing.T) {
	got, err := Compute(DefaultPolicy(), registeredSeller(33), Buyer{Country: "IN", StateCode: 33},
		Line{ListPrice: inr("2000.00"), CommissionBps: 900}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Explain) < 4 {
		t.Fatalf("expected a full explanation trace, got %d lines", len(got.Explain))
	}
	for _, line := range got.Explain {
		if len(line) < 10 {
			t.Fatalf("explanation line is not useful: %q", line)
		}
	}
}

func BenchmarkCompute(b *testing.B) {
	p := DefaultPolicy()
	s := registeredSeller(33)
	buyer := Buyer{Country: "IN", StateCode: 29}
	l := Line{ListPrice: inr("2499.00"), CommissionBps: 900, PSPFeeBps: 200, PSPFeeGSTBps: 1800}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Compute(p, s, buyer, l, now); err != nil {
			b.Fatal(err)
		}
	}
}
