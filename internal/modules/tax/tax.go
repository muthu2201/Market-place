// Package tax computes the Indian indirect- and direct-tax consequences of a
// marketplace sale.
//
// The platform is an electronic commerce operator (ECO). Three distinct levies
// touch one sale and they must never be netted against one another because they
// flow through different ledgers, different returns and different authorities:
//
//	GST (s.9 CGST/SGST/IGST) - on the SELLER's supply to the buyer, and
//	                           separately on the PLATFORM's commission to the seller.
//	TCS (s.52 CGST)          - 1%, COLLECTED by the ECO, reported in GSTR-8.
//	TDS (s.194-O IT Act)     - 0.1%, DEDUCTED by the ECO, deposited by challan.
//
// Every figure is produced by internal/platform/money, so no float is involved
// at any point and the components provably sum back to the buyer's total.
//
// This package encodes an engineering reading of the statute. It is not tax
// advice: the rates, thresholds and the export treatment are all configurable
// and must be confirmed with a chartered accountant before go-live. Where a
// reading is contestable, Policy carries the switch and the default is stated.
package tax

import (
	"errors"
	"fmt"
	"time"

	"github.com/muthu2201/market-place/internal/platform/money"
)

// Policy holds every rate and threshold. Nothing is hard-coded at a call site.
type Policy struct {
	// GSTBps is the rate on digital products, which are services. 1800 = 18%.
	GSTBps int64
	// CommissionGSTBps is the rate on the platform's own commission invoice.
	CommissionGSTBps int64
	// TCSBps is s.52 CGST. 100 = 1% (split 0.5/0.5 intra-state).
	TCSBps int64
	// TDSBps is s.194-O. 10 = 0.1% since 1 October 2024.
	TDSBps int64
	// TDSNoPANBps is the s.206AA rate where PAN is not furnished. 500 = 5%.
	TDSNoPANBps int64
	// TDSThresholdMinor is the s.194-O exemption ceiling for a resident
	// Individual/HUF seller, measured on gross supply for the financial year.
	TDSThresholdMinor int64
	// PlatformStateCode is the GST state code of the platform's registration.
	PlatformStateCode int

	// CollectTCSFromUnregisteredSellers, when false (the default), means no TCS
	// is collected from a seller who is below the registration threshold and is
	// therefore not GST-registered. Collecting TCS against a seller with no
	// GSTIN is precisely the pattern that GST-department analytics flags.
	CollectTCSFromUnregisteredSellers bool
	// CollectTCSOnExports, when true (the default), treats a zero-rated export
	// of services as a taxable supply for s.52 purposes and collects TCS on its
	// taxable value. This reading is contestable; confirm with a CA.
	CollectTCSOnExports bool
	// PlatformGSTIN is the platform's own GST registration.
	PlatformGSTIN string
	// PSPFeeBearer decides who absorbs payment-processing cost.
	// "platform" (the default) is what makes the headline commission genuinely
	// all-in; "seller" itemises it as a deduction instead.
	PSPFeeBearer string
}

// DefaultPolicy reflects the law as at the 2025-26 financial year.
func DefaultPolicy() Policy {
	return Policy{
		GSTBps:                            1800,
		CommissionGSTBps:                  1800,
		TCSBps:                            100,
		TDSBps:                            10,
		TDSNoPANBps:                       500,
		TDSThresholdMinor:                 500000 * 100, // Rs 5,00,000 in paise
		PlatformStateCode:                 33,           // Tamil Nadu
		CollectTCSFromUnregisteredSellers: false,
		CollectTCSOnExports:               true,
		PSPFeeBearer:                      "platform",
	}
}

func (p Policy) validate() error {
	switch {
	case p.GSTBps < 0 || p.GSTBps > 10000:
		return errors.New("tax: GSTBps out of range")
	case p.CommissionGSTBps < 0 || p.CommissionGSTBps > 10000:
		return errors.New("tax: CommissionGSTBps out of range")
	case p.TCSBps < 0 || p.TCSBps > 10000:
		return errors.New("tax: TCSBps out of range")
	case p.TDSBps < 0 || p.TDSBps > 10000:
		return errors.New("tax: TDSBps out of range")
	case p.TDSNoPANBps < 0 || p.TDSNoPANBps > 10000:
		return errors.New("tax: TDSNoPANBps out of range")
	case p.PlatformStateCode < 1 || p.PlatformStateCode > 99:
		return errors.New("tax: PlatformStateCode is not a valid GST state code")
	case p.PSPFeeBearer != "platform" && p.PSPFeeBearer != "seller":
		return errors.New(`tax: PSPFeeBearer must be "platform" or "seller"`)
	}
	// GST must be evenly splittable into CGST and SGST halves.
	if p.GSTBps%2 != 0 {
		return errors.New("tax: GSTBps must be even so CGST and SGST are equal")
	}
	if p.TCSBps%2 != 0 {
		return errors.New("tax: TCSBps must be even so the CGST and SGST components are equal")
	}
	return nil
}

// PlatformGSTIN is the platform's own registration, used on the commission
// invoice it raises to the seller.
func (p Policy) PlatformGSTINOrEmpty() string { return p.PlatformGSTIN }

// PlatformGSTIN is set by configuration; it is separate from the seller's.
// Declared on Policy so the orders module does not need a second config path.

// Seller describes the supplier for one line.
type Seller struct {
	GSTRegistered bool
	GSTIN         string
	StateCode     int
	HasPAN        bool
	// ResidentIndividualOrHUF decides whether the s.194-O threshold applies.
	// A company or a firm has no threshold.
	ResidentIndividualOrHUF bool
	// FYGrossSupplyMinor is the seller's gross supply through this platform so
	// far in the current financial year, excluding this sale.
	FYGrossSupplyMinor int64
	Country            string
}

// Buyer describes the recipient, which fixes the place of supply.
type Buyer struct {
	Country   string
	StateCode int
	GSTIN     string
	IsB2B     bool
}

// Line is one product sale to price.
type Line struct {
	// ListPrice is the seller's price, exclusive of tax. The buyer pays this
	// plus GST; the platform's commission is computed on this.
	ListPrice money.Money
	// CommissionBps is the seller's contracted rate, read from their fee
	// schedule assignment so that grandfathering is honoured.
	CommissionBps int64
	// PSPFeeBps and PSPFeeGSTBps let the caller attribute the actual provider
	// cost to the line. They do not change what the buyer or seller sees when
	// PSPFeeBearer is "platform"; they only feed the ledger and unit economics.
	PSPFeeBps    int64
	PSPFeeGSTBps int64
}

// SupplyKind classifies the place of supply, which decides the GST split.
type SupplyKind string

const (
	// IntraState: supplier and place of supply are in the same state. CGST+SGST.
	IntraState SupplyKind = "intra_state"
	// InterState: different states within India. IGST.
	InterState SupplyKind = "inter_state"
	// ExportOfServices: recipient outside India. Zero-rated under LUT/bond.
	ExportOfServices SupplyKind = "export_of_services"
	// Exempt: the seller is not GST-registered, so no GST is charged.
	Exempt SupplyKind = "exempt_unregistered_supplier"
)

// Breakdown is the complete, auditable decomposition of one line.
type Breakdown struct {
	Currency money.Currency
	Supply   SupplyKind

	// What the buyer is charged.
	ListPrice  money.Money
	CGST       money.Money
	SGST       money.Money
	IGST       money.Money
	TaxTotal   money.Money
	BuyerTotal money.Money
	GSTRateBps int64

	// What the platform takes.
	CommissionBps    int64
	Commission       money.Money
	CommissionGST    money.Money
	CommissionGSTBps int64

	// What the platform collects or deducts on behalf of an authority.
	TCSBps    int64
	TCSCGST   money.Money
	TCSSGST   money.Money
	TCSIGST   money.Money
	TCS       money.Money
	TDSBps    int64
	TDS       money.Money
	TDSReason string

	// Payment processing.
	PSPFee      money.Money
	PSPFeeGST   money.Money
	PSPFeeBorne string

	// What the seller receives.
	SellerNet money.Money

	// PlatformMargin is commission less the processing cost the platform
	// absorbs. It is the honest unit-economics figure, not the headline rate.
	PlatformMargin money.Money

	// Explain is a plain-language trace of every decision, rendered to the
	// seller in their statement and to the buyer on the invoice. Transparency
	// here is a Consumer Protection (E-Commerce) Rules obligation and also the
	// cheapest way to prevent support tickets.
	Explain []string
}

// Compute produces the breakdown for one line.
func Compute(p Policy, s Seller, b Buyer, l Line, at time.Time) (Breakdown, error) {
	var out Breakdown
	if err := p.validate(); err != nil {
		return out, err
	}
	if l.ListPrice.IsNegative() {
		return out, errors.New("tax: list price cannot be negative")
	}
	if l.CommissionBps < 0 || l.CommissionBps > 10000 {
		return out, fmt.Errorf("tax: commission %d bps is outside 0..10000", l.CommissionBps)
	}
	cur := l.ListPrice.Currency()
	zero := money.Zero(cur)

	out = Breakdown{
		Currency: cur, ListPrice: l.ListPrice,
		CGST: zero, SGST: zero, IGST: zero, TaxTotal: zero, BuyerTotal: l.ListPrice,
		Commission: zero, CommissionGST: zero,
		TCS: zero, TCSCGST: zero, TCSSGST: zero, TCSIGST: zero, TDS: zero,
		PSPFee: zero, PSPFeeGST: zero, SellerNet: zero, PlatformMargin: zero,
		CommissionBps: l.CommissionBps, CommissionGSTBps: p.CommissionGSTBps,
		PSPFeeBorne: p.PSPFeeBearer,
	}

	// ---- 1. Place of supply -------------------------------------------------
	out.Supply = classify(p, s, b)

	// ---- 2. GST on the seller's supply -------------------------------------
	switch out.Supply {
	case Exempt:
		out.GSTRateBps = 0
		out.Explain = append(out.Explain,
			"No GST was charged on this supply: the seller is below the GST registration threshold for services and is not registered, so they cannot and do not collect GST.")
	case ExportOfServices:
		out.GSTRateBps = 0
		out.Explain = append(out.Explain,
			"This is a zero-rated export of services: the recipient is outside India, so GST is charged at 0% under a letter of undertaking.")
	case IntraState:
		half := p.GSTBps / 2
		cgst, err := l.ListPrice.ApplyBasisPoints(half, money.HalfUp)
		if err != nil {
			return out, fmt.Errorf("tax: CGST: %w", err)
		}
		// CGST and SGST are each computed at half the rate and are equal by
		// construction, which is how a GST invoice is actually drawn. Rounding
		// each component separately can differ by one paise from rounding the
		// combined rate; the component figures are the ones that are filed.
		out.CGST, out.SGST = cgst, cgst
		out.GSTRateBps = p.GSTBps
		out.Explain = append(out.Explain, fmt.Sprintf(
			"The seller and the place of supply are both in state %d, so GST is split as CGST %s + SGST %s at %.2f%% each.",
			//archcheck:allow money is never a float -- renders a RATE as human-readable text; the amounts themselves are money.Money integers.
			s.StateCode, cgst.Decimal(), cgst.Decimal(), float64(half)/100))
	case InterState:
		igst, err := l.ListPrice.ApplyBasisPoints(p.GSTBps, money.HalfUp)
		if err != nil {
			return out, fmt.Errorf("tax: IGST: %w", err)
		}
		out.IGST = igst
		out.GSTRateBps = p.GSTBps
		out.Explain = append(out.Explain, fmt.Sprintf(
			"The seller is in state %d and the place of supply is state %d, so IGST applies at %.2f%%.",
			//archcheck:allow money is never a float -- renders a RATE as text.
			s.StateCode, b.StateCode, float64(p.GSTBps)/100))
	}

	taxTotal, err := money.Sum(out.CGST, out.SGST, out.IGST)
	if err != nil {
		return out, err
	}
	out.TaxTotal = taxTotal
	if out.BuyerTotal, err = l.ListPrice.Add(taxTotal); err != nil {
		return out, fmt.Errorf("tax: buyer total: %w", err)
	}

	// ---- 3. Platform commission and GST on it ------------------------------
	// The commission is computed on the taxable value, never on the
	// tax-inclusive total: charging a percentage of the GST would be charging
	// the seller for the government's money.
	if out.Commission, err = l.ListPrice.ApplyBasisPoints(l.CommissionBps, money.HalfUp); err != nil {
		return out, fmt.Errorf("tax: commission: %w", err)
	}
	if out.CommissionGST, err = out.Commission.ApplyBasisPoints(p.CommissionGSTBps, money.HalfUp); err != nil {
		return out, fmt.Errorf("tax: commission GST: %w", err)
	}
	out.Explain = append(out.Explain, fmt.Sprintf(
		"Platform commission is %.2f%% of the %s taxable value: %s, plus %.2f%% GST on that commission: %s.",
		//archcheck:allow money is never a float -- renders RATES as text; every amount above is a money.Money integer.
		float64(l.CommissionBps)/100, l.ListPrice.Decimal(), out.Commission.Decimal(),
		float64(p.CommissionGSTBps)/100, out.CommissionGST.Decimal()))

	// ---- 4. TCS under s.52 CGST --------------------------------------------
	collectTCS := true
	switch {
	case !s.GSTRegistered && !p.CollectTCSFromUnregisteredSellers:
		collectTCS = false
		out.Explain = append(out.Explain,
			"No TCS was collected under section 52: the seller is not GST-registered, and collecting TCS against a supplier with no GSTIN cannot be reported in GSTR-8.")
	case out.Supply == ExportOfServices && !p.CollectTCSOnExports:
		collectTCS = false
		out.Explain = append(out.Explain, "No TCS was collected: this is an export of services and the configured policy excludes exports.")
	}
	if collectTCS && p.TCSBps > 0 {
		if out.Supply == IntraState {
			half := p.TCSBps / 2
			c, err := l.ListPrice.ApplyBasisPoints(half, money.HalfUp)
			if err != nil {
				return out, fmt.Errorf("tax: TCS: %w", err)
			}
			out.TCSCGST, out.TCSSGST = c, c
		} else {
			i, err := l.ListPrice.ApplyBasisPoints(p.TCSBps, money.HalfUp)
			if err != nil {
				return out, fmt.Errorf("tax: TCS: %w", err)
			}
			out.TCSIGST = i
		}
		if out.TCS, err = money.Sum(out.TCSCGST, out.TCSSGST, out.TCSIGST); err != nil {
			return out, err
		}
		out.TCSBps = p.TCSBps
		out.Explain = append(out.Explain, fmt.Sprintf(
			"TCS of %.2f%% (%s) was collected under section 52 of the CGST Act on the net taxable value and will be reported in GSTR-8 against GSTIN %s.",
			//archcheck:allow money is never a float -- renders a RATE as text.
			float64(p.TCSBps)/100, out.TCS.Decimal(), s.GSTIN))
	}

	// ---- 5. TDS under s.194-O ----------------------------------------------
	// CBDT Circular 17/2020: where GST is indicated separately, s.194-O applies
	// to the value excluding GST. Our list price is already tax-exclusive.
	tdsRate := p.TDSBps
	switch {
	case s.Country != "" && s.Country != "IN":
		tdsRate = 0
		out.TDSReason = "seller is not resident in India; section 194-O does not apply"
	case !s.HasPAN:
		tdsRate = p.TDSNoPANBps
		//archcheck:allow money is never a float -- renders a RATE as text.
		out.TDSReason = fmt.Sprintf("PAN not furnished, so the higher rate under section 206AA applies (%.2f%%)", float64(tdsRate)/100)
	case s.ResidentIndividualOrHUF && belowThreshold(s.FYGrossSupplyMinor, l.ListPrice.Minor(), p.TDSThresholdMinor):
		tdsRate = 0
		out.TDSReason = fmt.Sprintf(
			"resident individual/HUF whose gross supply for the financial year (%s including this sale) remains within the section 194-O threshold",
			money.MustNew(s.FYGrossSupplyMinor+l.ListPrice.Minor(), cur).Decimal())
	default:
		//archcheck:allow money is never a float -- renders a RATE as text.
		out.TDSReason = fmt.Sprintf("section 194-O applies at %.2f%%", float64(tdsRate)/100)
	}
	if tdsRate > 0 {
		if out.TDS, err = l.ListPrice.ApplyBasisPoints(tdsRate, money.HalfUp); err != nil {
			return out, fmt.Errorf("tax: TDS: %w", err)
		}
		out.TDSBps = tdsRate
	}
	out.Explain = append(out.Explain, "TDS under section 194-O: "+out.TDS.Decimal()+" ("+out.TDSReason+").")

	// ---- 6. Payment processing cost ----------------------------------------
	if out.PSPFee, err = out.BuyerTotal.ApplyBasisPoints(l.PSPFeeBps, money.HalfUp); err != nil {
		return out, fmt.Errorf("tax: PSP fee: %w", err)
	}
	if out.PSPFeeGST, err = out.PSPFee.ApplyBasisPoints(l.PSPFeeGSTBps, money.HalfUp); err != nil {
		return out, fmt.Errorf("tax: PSP fee GST: %w", err)
	}

	// ---- 7. Settlement -----------------------------------------------------
	// The seller receives the whole buyer payment less what the platform keeps
	// and what the platform must remit onward. The GST element flows to the
	// seller because it is the seller who owes it to the government.
	net := out.BuyerTotal
	for _, d := range []money.Money{out.Commission, out.CommissionGST, out.TCS, out.TDS} {
		if net, err = net.Sub(d); err != nil {
			return out, fmt.Errorf("tax: settlement: %w", err)
		}
	}
	if p.PSPFeeBearer == "seller" {
		if net, err = net.Sub(out.PSPFee); err != nil {
			return out, fmt.Errorf("tax: settlement psp: %w", err)
		}
		if net, err = net.Sub(out.PSPFeeGST); err != nil {
			return out, fmt.Errorf("tax: settlement psp gst: %w", err)
		}
		out.Explain = append(out.Explain, "Payment-processing cost of "+out.PSPFee.Decimal()+" plus GST was deducted from the settlement.")
	} else {
		out.Explain = append(out.Explain,
			"Payment-processing cost of "+out.PSPFee.Decimal()+" plus GST was absorbed by the platform out of its commission and is shown for transparency only.")
	}
	if net.IsNegative() {
		return out, fmt.Errorf("tax: deductions exceed the buyer payment; settlement would be %s", net.String())
	}
	out.SellerNet = net

	margin := out.Commission
	if p.PSPFeeBearer == "platform" {
		if margin, err = margin.Sub(out.PSPFee); err != nil {
			return out, err
		}
	}
	out.PlatformMargin = margin

	out.Explain = append(out.Explain, fmt.Sprintf(
		"Settlement to the seller: %s (buyer paid %s, less commission %s, GST on commission %s, TCS %s and TDS %s).",
		out.SellerNet.Decimal(), out.BuyerTotal.Decimal(), out.Commission.Decimal(),
		out.CommissionGST.Decimal(), out.TCS.Decimal(), out.TDS.Decimal()))

	if err := out.Verify(); err != nil {
		return out, err
	}
	return out, nil
}

// Verify re-checks the arithmetic invariants. Compute always runs it, so a
// breakdown that escapes this package has already proved itself.
func (b Breakdown) Verify() error {
	taxSum, err := money.Sum(b.CGST, b.SGST, b.IGST)
	if err != nil {
		return err
	}
	if !taxSum.Equal(b.TaxTotal) {
		return fmt.Errorf("tax: components %s do not sum to tax total %s", taxSum, b.TaxTotal)
	}
	gross, err := b.ListPrice.Add(b.TaxTotal)
	if err != nil {
		return err
	}
	if !gross.Equal(b.BuyerTotal) {
		return fmt.Errorf("tax: list %s + tax %s <> buyer total %s", b.ListPrice, b.TaxTotal, b.BuyerTotal)
	}

	// Conservation: nothing the buyer paid may vanish, and nothing may be
	// invented. This is the invariant the whole ledger depends on.
	distributed, err := money.Sum(b.SellerNet, b.Commission, b.CommissionGST, b.TCS, b.TDS)
	if err != nil {
		return err
	}
	if b.PSPFeeBorne == "seller" {
		if distributed, err = money.Sum(distributed, b.PSPFee, b.PSPFeeGST); err != nil {
			return err
		}
	}
	if !distributed.Equal(b.BuyerTotal) {
		return fmt.Errorf("tax: distribution %s does not reconcile to buyer total %s", distributed, b.BuyerTotal)
	}

	if b.CGST.Minor() != b.SGST.Minor() {
		return fmt.Errorf("tax: CGST %s and SGST %s must be equal", b.CGST, b.SGST)
	}
	if b.IGST.IsPositive() && (b.CGST.IsPositive() || b.SGST.IsPositive()) {
		return errors.New("tax: IGST and CGST/SGST are mutually exclusive")
	}
	if b.TCSIGST.IsPositive() && (b.TCSCGST.IsPositive() || b.TCSSGST.IsPositive()) {
		return errors.New("tax: TCS IGST and TCS CGST/SGST are mutually exclusive")
	}
	for _, m := range []money.Money{b.ListPrice, b.CGST, b.SGST, b.IGST, b.TaxTotal, b.BuyerTotal,
		b.Commission, b.CommissionGST, b.TCS, b.TDS, b.PSPFee, b.PSPFeeGST, b.SellerNet} {
		if m.IsNegative() {
			return fmt.Errorf("tax: %s is negative", m)
		}
		if m.Currency() != b.Currency {
			return fmt.Errorf("tax: %s is not in %s", m, b.Currency)
		}
	}
	return nil
}

func classify(p Policy, s Seller, b Buyer) SupplyKind {
	if !s.GSTRegistered {
		return Exempt
	}
	buyerCountry := b.Country
	if buyerCountry == "" {
		buyerCountry = "IN"
	}
	if buyerCountry != "IN" {
		return ExportOfServices
	}
	// Place of supply for an online service supplied to an unregistered person
	// is the recipient's location; to a registered person it is their location
	// too. Either way it is the buyer's state.
	if s.StateCode > 0 && b.StateCode > 0 && s.StateCode == b.StateCode {
		return IntraState
	}
	return InterState
}

func belowThreshold(fySoFar, thisSale, threshold int64) bool {
	// Guard the addition: a corrupt running total must not wrap into "below".
	if fySoFar < 0 || thisSale < 0 {
		return false
	}
	if fySoFar > threshold {
		return false
	}
	return fySoFar+thisSale <= threshold
}

// FinancialYearStart returns 1 April of the Indian financial year containing t.
func FinancialYearStart(t time.Time) time.Time {
	t = t.UTC()
	y := t.Year()
	if t.Month() < time.April {
		y--
	}
	return time.Date(y, time.April, 1, 0, 0, 0, 0, time.UTC)
}

// GSTR8DueDate returns the filing deadline for a TCS month: the 10th of the
// following month.
func GSTR8DueDate(periodMonth time.Time) time.Time {
	m := time.Date(periodMonth.Year(), periodMonth.Month(), 1, 0, 0, 0, 0, time.UTC)
	return m.AddDate(0, 1, 9)
}

// TDSDepositDueDate returns the s.194-O deposit deadline: the 7th of the
// following month, except for March which is deposited by 30 April.
func TDSDepositDueDate(periodMonth time.Time) time.Time {
	m := time.Date(periodMonth.Year(), periodMonth.Month(), 1, 0, 0, 0, 0, time.UTC)
	if m.Month() == time.March {
		return time.Date(m.Year(), time.April, 30, 0, 0, 0, 0, time.UTC)
	}
	return m.AddDate(0, 1, 6)
}
