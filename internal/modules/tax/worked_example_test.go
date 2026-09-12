package tax_test

import (
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/modules/tax"
	"github.com/muthu2201/market-place/internal/platform/money"
)

// TestWorkedExampleMatchesDocs pins every figure quoted in the architecture
// documentation to the code that produces it.
//
// The worked examples in docs/arch/04-money-flow.md and
// docs/adr/0015-flat-all-in-commission.md are the first thing a seller, an
// auditor or a new engineer reads. A document that quietly disagrees with the
// implementation is worse than no document, so the numbers are asserted here
// and a change to either the policy constants or the computation fails this
// test until the documents are updated to match.
func TestWorkedExampleMatchesDocs(t *testing.T) {
	policy := tax.Policy{
		GSTBps: 1800, CommissionGSTBps: 1800, TCSBps: 100, TDSBps: 10,
		TDSNoPANBps: 500, TDSThresholdMinor: 500000 * 100, PlatformStateCode: 33,
		PlatformGSTIN: "33AAAAA0000A1Z5",
	}
	seller := tax.Seller{
		GSTRegistered: true, GSTIN: "33BBBBB1111B1Z5", StateCode: 33,
		HasPAN: true, Country: "IN", FYGrossSupplyMinor: 900000 * 100,
	}
	line := tax.Line{
		ListPrice: money.MustNew(1000_00, money.INR), CommissionBps: 900,
		PSPFeeBps: 200, PSPFeeGSTBps: 1800,
	}

	cases := []struct {
		name  string
		buyer tax.Buyer
		bears string

		supply                                    tax.SupplyKind
		cgst, sgst, igst, buyerTotal              string
		commission, commissionGST                 string
		tcs, tcsCGST, tcsSGST, tcsIGST, tds       string
		pspFee, pspFeeGST, sellerNet, platformNet string
	}{{
		// docs/arch/04-money-flow.md — the primary worked example.
		name:  "inter-state supply, platform bears the processing cost",
		buyer: tax.Buyer{Country: "IN", StateCode: 29}, bears: "platform",
		supply: tax.InterState,
		cgst:   "0.00", sgst: "0.00", igst: "180.00", buyerTotal: "1180.00",
		commission: "90.00", commissionGST: "16.20",
		tcs: "10.00", tcsCGST: "0.00", tcsSGST: "0.00", tcsIGST: "10.00", tds: "1.00",
		pspFee: "23.60", pspFeeGST: "4.25", sellerNet: "1062.80", platformNet: "66.40",
	}, {
		// docs/adr/0015-flat-all-in-commission.md — the seller-facing example.
		name:  "intra-state supply, seller bears the processing cost",
		buyer: tax.Buyer{Country: "IN", StateCode: 33}, bears: "seller",
		supply: tax.IntraState,
		cgst:   "90.00", sgst: "90.00", igst: "0.00", buyerTotal: "1180.00",
		commission: "90.00", commissionGST: "16.20",
		tcs: "10.00", tcsCGST: "5.00", tcsSGST: "5.00", tcsIGST: "0.00", tds: "1.00",
		pspFee: "23.60", pspFeeGST: "4.25", sellerNet: "1034.95", platformNet: "90.00",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := policy
			p.PSPFeeBearer = tc.bears

			b, err := tax.Compute(p, seller, tc.buyer, line, time.Now())
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if b.Supply != tc.supply {
				t.Errorf("supply = %q, documented %q", b.Supply, tc.supply)
			}
			for _, f := range []struct {
				label string
				got   money.Money
				want  string
			}{
				{"CGST", b.CGST, tc.cgst},
				{"SGST", b.SGST, tc.sgst},
				{"IGST", b.IGST, tc.igst},
				{"buyer total", b.BuyerTotal, tc.buyerTotal},
				{"commission", b.Commission, tc.commission},
				{"GST on commission", b.CommissionGST, tc.commissionGST},
				{"TCS", b.TCS, tc.tcs},
				{"TCS CGST", b.TCSCGST, tc.tcsCGST},
				{"TCS SGST", b.TCSSGST, tc.tcsSGST},
				{"TCS IGST", b.TCSIGST, tc.tcsIGST},
				{"TDS", b.TDS, tc.tds},
				{"processing fee", b.PSPFee, tc.pspFee},
				{"GST on processing fee", b.PSPFeeGST, tc.pspFeeGST},
				{"seller net", b.SellerNet, tc.sellerNet},
				{"platform margin", b.PlatformMargin, tc.platformNet},
			} {
				if got := f.got.Decimal(); got != f.want {
					t.Errorf("%s = %s, documented %s", f.label, got, f.want)
				}
			}
		})
	}
}
