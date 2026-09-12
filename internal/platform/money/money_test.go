package money

import (
	"math"
	"math/rand"
	"testing"
)

func TestParseDecimalRoundTrip(t *testing.T) {
	cases := []struct {
		in    string
		cur   Currency
		minor int64
		out   string
	}{
		{"0", INR, 0, "0.00"},
		{"1", INR, 100, "1.00"},
		{"0.01", INR, 1, "0.01"},
		{"1234.56", INR, 123456, "1234.56"},
		{"1,234.56", INR, 123456, "1234.56"},
		{"-0.07", INR, -7, "-0.07"},
		{"99999999.99", INR, 9999999999, "99999999.99"},
		{"500", JPY, 500, "500"},
		{"INR 250.00", INR, 25000, "250.00"},
	}
	for _, c := range cases {
		m, err := Parse(c.in, c.cur)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if m.Minor() != c.minor {
			t.Fatalf("Parse(%q) minor = %d, want %d", c.in, m.Minor(), c.minor)
		}
		if got := m.Decimal(); got != c.out {
			t.Fatalf("Decimal(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestParseRejectsExcessPrecision(t *testing.T) {
	if _, err := Parse("1.234", INR); err == nil {
		t.Fatal("expected rejection of sub-paise precision")
	}
	if _, err := Parse("12.5", JPY); err == nil {
		t.Fatal("expected rejection of fractional yen")
	}
	if _, err := Parse("abc", INR); err == nil {
		t.Fatal("expected rejection of non-numeric input")
	}
}

func TestCurrencyMismatchRefused(t *testing.T) {
	a := MustNew(100, INR)
	b := MustNew(100, USD)
	if _, err := a.Add(b); err == nil {
		t.Fatal("Add across currencies must fail")
	}
	if _, err := a.Sub(b); err == nil {
		t.Fatal("Sub across currencies must fail")
	}
	if _, err := a.Cmp(b); err == nil {
		t.Fatal("Cmp across currencies must fail")
	}
}

func TestOverflowRefused(t *testing.T) {
	max := MustNew(math.MaxInt64, INR)
	if _, err := max.Add(MustNew(1, INR)); err != ErrOverflow {
		t.Fatalf("want ErrOverflow, got %v", err)
	}
	min := MustNew(math.MinInt64, INR)
	if _, err := min.Sub(MustNew(1, INR)); err != ErrOverflow {
		t.Fatalf("want ErrOverflow, got %v", err)
	}
	if _, err := min.Neg(); err != ErrOverflow {
		t.Fatalf("negating MinInt64 must overflow, got %v", err)
	}
}

// A 128-bit intermediate must let us apply a rate to an amount whose naive
// product would overflow int64.
func TestMulRatioNoIntermediateOverflow(t *testing.T) {
	huge := MustNew(math.MaxInt64/2, INR)
	got, err := huge.ApplyBasisPoints(1800, HalfUp) // 18% GST
	if err != nil {
		t.Fatalf("ApplyBasisPoints on a huge amount: %v", err)
	}
	// (MaxInt64/2 * 1800) / 10000 == MaxInt64/2 * 0.18
	want := int64(830103483316929823) // exact: floor(4611686018427387903*1800/10000)=...822 rem 5400 -> half-up ...823
	if got.Minor() != want {
		t.Fatalf("got %d want %d", got.Minor(), want)
	}
}

func TestRoundingModes(t *testing.T) {
	// 2.5 paise cases: amount 5 * 1/2 = 2.5
	five := MustNew(5, INR)
	cases := []struct {
		mode Rounding
		want int64
	}{
		{HalfUp, 3},
		{HalfEven, 2}, // quotient 2 is even -> stays
		{Down, 2},
		{Up, 3},
	}
	for _, c := range cases {
		got, err := five.MulRatio(1, 2, c.mode)
		if err != nil {
			t.Fatal(err)
		}
		if got.Minor() != c.want {
			t.Fatalf("%s: got %d want %d", c.mode, got.Minor(), c.want)
		}
	}
	// Negative half-up rounds away from zero: -2.5 -> -3
	neg := MustNew(-5, INR)
	got, _ := neg.MulRatio(1, 2, HalfUp)
	if got.Minor() != -3 {
		t.Fatalf("negative HalfUp: got %d want -3", got.Minor())
	}
	gotD, _ := neg.MulRatio(1, 2, Down)
	if gotD.Minor() != -2 {
		t.Fatalf("negative Down: got %d want -2", gotD.Minor())
	}
}

func TestIndianTaxRatesAreExact(t *testing.T) {
	// A GST-inclusive style check on a round figure: 18% of 2000.00 = 360.00
	base := MustNew(200000, INR)
	gst, err := base.ApplyBasisPoints(1800, HalfUp)
	if err != nil {
		t.Fatal(err)
	}
	if gst.Decimal() != "360.00" {
		t.Fatalf("GST = %s, want 360.00", gst.Decimal())
	}
	// TCS 1% of 2000.00 = 20.00
	tcs, _ := base.ApplyBasisPoints(100, HalfUp)
	if tcs.Decimal() != "20.00" {
		t.Fatalf("TCS = %s, want 20.00", tcs.Decimal())
	}
	// TDS 0.1% of 2000.00 = 2.00
	tds, _ := base.ApplyBasisPoints(10, HalfUp)
	if tds.Decimal() != "2.00" {
		t.Fatalf("TDS = %s, want 2.00", tds.Decimal())
	}
	// TDS 0.1% of 499.00 = 0.499 -> 0.50 half-up
	odd := MustNew(49900, INR)
	tdsOdd, _ := odd.ApplyBasisPoints(10, HalfUp)
	if tdsOdd.Decimal() != "0.50" {
		t.Fatalf("TDS on 499.00 = %s, want 0.50", tdsOdd.Decimal())
	}
}

// Allocation must be conservative: the parts always sum back to the whole.
func TestAllocateConservesEveryMinorUnit(t *testing.T) {
	rng := rand.New(rand.NewSource(20260911))
	for i := 0; i < 20000; i++ {
		amount := rng.Int63n(10_000_000) - 5_000_000
		n := 1 + rng.Intn(6)
		weights := make([]int64, n)
		var any bool
		for j := range weights {
			weights[j] = rng.Int63n(1000)
			if weights[j] > 0 {
				any = true
			}
		}
		if !any {
			weights[0] = 1
		}
		m := MustNew(amount, INR)
		parts, err := m.Allocate(weights)
		if err != nil {
			t.Fatalf("allocate(%d, %v): %v", amount, weights, err)
		}
		var sum int64
		for _, p := range parts {
			if p.Currency() != INR {
				t.Fatal("allocation lost its currency")
			}
			sum += p.Minor()
		}
		if sum != amount {
			t.Fatalf("allocate(%d,%v) summed to %d", amount, weights, sum)
		}
	}
}

func TestAllocateSplitsClassicThreeWay(t *testing.T) {
	// 0.05 across three equal parts -> 2,2,1 (largest-remainder, no unit lost)
	parts, err := MustNew(5, INR).Allocate([]int64{1, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	got := []int64{parts[0].Minor(), parts[1].Minor(), parts[2].Minor()}
	total := got[0] + got[1] + got[2]
	if total != 5 {
		t.Fatalf("parts %v sum to %d, want 5", got, total)
	}
	for _, g := range got {
		if g < 1 || g > 2 {
			t.Fatalf("unbalanced allocation %v", got)
		}
	}
}

// Fuzz-style invariant: applying a rate then its complement never invents or
// destroys value beyond one minor unit of documented rounding drift.
func TestRateSplitDriftBounded(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 50000; i++ {
		amt := rng.Int63n(100_000_000)
		bps := rng.Int63n(10_001)
		m := MustNew(amt, INR)
		a, err := m.ApplyBasisPoints(bps, HalfUp)
		if err != nil {
			t.Fatal(err)
		}
		b, err := m.ApplyBasisPoints(10_000-bps, HalfUp)
		if err != nil {
			t.Fatal(err)
		}
		sum, _ := a.Add(b)
		diff := sum.Minor() - amt
		if diff < -1 || diff > 1 {
			t.Fatalf("amt=%d bps=%d drift=%d exceeds one minor unit", amt, bps, diff)
		}
	}
}

func TestJSONCarriesCurrency(t *testing.T) {
	b, err := MustNew(123456, INR).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"minor":123456,"currency":"INR","display":"1234.56"}`
	if string(b) != want {
		t.Fatalf("got %s want %s", b, want)
	}
}

func TestSumRequiresNonEmpty(t *testing.T) {
	if _, err := Sum(); err == nil {
		t.Fatal("Sum() of nothing has no currency and must fail")
	}
}

func BenchmarkApplyBasisPoints(b *testing.B) {
	m := MustNew(249900, INR)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := m.ApplyBasisPoints(1800, HalfUp); err != nil {
			b.Fatal(err)
		}
	}
}
