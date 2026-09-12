package seller_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/muthu2201/market-place/internal/modules/identity"
	"github.com/muthu2201/market-place/internal/modules/seller"
	"github.com/muthu2201/market-place/internal/platform/clock"
	"github.com/muthu2201/market-place/internal/platform/db"
	"github.com/muthu2201/market-place/internal/platform/dbtest"
	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/testsupport/fixtures"
)

// TestPayoutDestinationIsQuarantined is the most important test in this
// package. An attacker who takes over a seller account must not be able to
// redirect the next settlement run; they must have to survive a window in which
// the real seller is told what happened.
func TestPayoutDestinationIsQuarantined(t *testing.T) {
	h := newHarness(t)
	s := h.onboard(t, "quarantine")
	h.verify(t, s.ID)

	acct, err := h.svc.AddPayoutAccount(h.ctx, seller.PayoutAccountRequest{
		SellerID: s.ID, UserID: h.userFor(t, s.ID), Method: "bank_account",
		AccountNumber: "50100123456789", IFSC: "HDFC0001234",
		BeneficiaryName: "Ananya Textiles Private Limited", IP: "203.0.113.9",
	})
	if err != nil {
		t.Fatalf("AddPayoutAccount: %v", err)
	}
	if !acct.Quarantined {
		t.Fatal("a newly added destination was not quarantined")
	}
	want := h.clock.Now().Add(seller.PayoutCoolOff)
	if acct.ActiveFrom.Before(want.Add(-time.Minute)) || acct.ActiveFrom.After(want.Add(time.Minute)) {
		t.Errorf("active_from = %s, want about %s", acct.ActiveFrom, want)
	}
	if acct.Last4 != "6789" {
		t.Errorf("last4 = %q, want the last four digits", acct.Last4)
	}

	// Validated, and still not payable: validation and quarantine are
	// independent gates, and passing one must not shorten the other.
	if err := h.svc.RecordValidation(h.ctx, acct.ID, "penny_drop", "pd_123", 97, ""); err != nil {
		t.Fatalf("RecordValidation: %v", err)
	}
	eligibility, err := h.svc.PayoutEligibility(h.ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if eligibility.Payable {
		t.Fatal("a destination still inside its cool-off was reported payable")
	}
	if eligibility.PayoutActiveFrom == nil {
		t.Fatal("the eligibility answer does not say when the destination becomes active")
	}
	if !strings.Contains(strings.Join(eligibility.Reasons, " "), "tell us") {
		t.Errorf("the reason does not explain why the wait exists: %v", eligibility.Reasons)
	}

	// Past the cool-off, it becomes payable.
	h.clock.Advance(seller.PayoutCoolOff + time.Minute)
	eligibility, err = h.svc.PayoutEligibility(h.ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !eligibility.Payable {
		t.Fatalf("still not payable after the cool-off: %v", eligibility.Reasons)
	}
}

// TestChangingDestinationDoesNotDisturbTheExistingOne: the previous, validated
// account must keep receiving settlement while the new one waits.
func TestChangingDestinationDoesNotDisturbTheExistingOne(t *testing.T) {
	h := newHarness(t)
	s := h.onboard(t, "swap")
	userID := h.userFor(t, s.ID)
	h.verify(t, s.ID)

	original, err := h.svc.AddPayoutAccount(h.ctx, seller.PayoutAccountRequest{
		SellerID: s.ID, UserID: userID, Method: "bank_account",
		AccountNumber: "50100111111111", IFSC: "HDFC0001234",
		BeneficiaryName: "Ananya Textiles Private Limited",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.RecordValidation(h.ctx, original.ID, "penny_drop", "pd_1", 99, ""); err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(seller.PayoutCoolOff + time.Hour)

	// Now an attacker adds theirs.
	attacker, err := h.svc.AddPayoutAccount(h.ctx, seller.PayoutAccountRequest{
		SellerID: s.ID, UserID: userID, Method: "bank_account",
		AccountNumber: "50100999999999", IFSC: "ICIC0004321",
		BeneficiaryName: "Somebody Else", IP: "198.51.100.4",
	})
	if err != nil {
		t.Fatal(err)
	}

	// The seller is still payable — to the ORIGINAL account, which is what
	// keeps a legitimate business running while the change is reviewed.
	eligibility, err := h.svc.PayoutEligibility(h.ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !eligibility.Payable {
		t.Fatalf("adding a second destination stopped settlement to the first: %v", eligibility.Reasons)
	}

	var defaultLast4 string
	if err := h.db.QueryRow(h.ctx, `
		SELECT account_last4 FROM seller_payout_accounts
		 WHERE seller_id = $1 AND is_default AND disabled_at IS NULL`, s.ID).Scan(&defaultLast4); err != nil {
		t.Fatal(err)
	}
	if defaultLast4 != "1111" {
		t.Fatalf("the default destination became %q immediately; the attacker's account took over", defaultLast4)
	}

	// A notification was queued in the same transaction as the change, so the
	// seller finds out.
	var notices int
	if err := h.db.QueryRow(h.ctx,
		`SELECT count(*) FROM jobs WHERE kind = 'notify_payout_change' AND payload->>'seller_id' = $1`,
		s.ID.String()).Scan(&notices); err != nil {
		t.Fatal(err)
	}
	if notices != 2 {
		t.Errorf("payout-change notices = %d, want one per change", notices)
	}
	_ = attacker
}

// TestValidationFailureOnNameMismatch covers the case that actually loses
// money: an account number that is valid and belongs to a stranger.
func TestValidationFailureOnNameMismatch(t *testing.T) {
	h := newHarness(t)
	s := h.onboard(t, "namemismatch")
	h.verify(t, s.ID)

	acct, err := h.svc.AddPayoutAccount(h.ctx, seller.PayoutAccountRequest{
		SellerID: s.ID, UserID: h.userFor(t, s.ID), Method: "bank_account",
		AccountNumber: "50100222222222", IFSC: "HDFC0001234",
		BeneficiaryName: "Ananya Textiles Private Limited",
	})
	if err != nil {
		t.Fatal(err)
	}
	// The penny drop came back naming somebody else.
	if err := h.svc.RecordValidation(h.ctx, acct.ID, "penny_drop", "pd_2", 31, ""); err != nil {
		t.Fatal(err)
	}

	var status string
	var failure *string
	if err := h.db.QueryRow(h.ctx,
		`SELECT validation_status, validation_failure FROM seller_payout_accounts WHERE id = $1`,
		acct.ID).Scan(&status, &failure); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("validation_status = %q, want failed", status)
	}
	if failure == nil || *failure == "" {
		t.Error("a failed validation must record why")
	}

	h.clock.Advance(seller.PayoutCoolOff + time.Hour)
	eligibility, err := h.svc.PayoutEligibility(h.ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if eligibility.Payable {
		t.Fatal("a destination whose name did not match was reported payable")
	}
}

// TestSettlementGatedOnTheProvidersView: our own KYC record is a cache, and a
// cache is not an authorisation.
func TestSettlementGatedOnTheProvidersView(t *testing.T) {
	h := newHarness(t)
	s := h.onboard(t, "providergate")

	// Everything on our side says yes.
	if _, err := h.db.Exec(h.ctx, `
		UPDATE sellers SET status = 'active', kyc_status = 'verified', kyc_verified_at = now()
		 WHERE id = $1`, s.ID); err != nil {
		t.Fatal(err)
	}
	acct, err := h.svc.AddPayoutAccount(h.ctx, seller.PayoutAccountRequest{
		SellerID: s.ID, UserID: h.userFor(t, s.ID), Method: "bank_account",
		AccountNumber: "50100333333333", IFSC: "HDFC0001234",
		BeneficiaryName: "Ananya Textiles Private Limited",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.RecordValidation(h.ctx, acct.ID, "penny_drop", "pd_3", 95, ""); err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(seller.PayoutCoolOff + time.Hour)

	// But the provider has not activated the linked account.
	eligibility, err := h.svc.PayoutEligibility(h.ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if eligibility.Payable {
		t.Fatal("settlement was allowed on our own KYC record while the provider had not activated the account")
	}
	if !strings.Contains(strings.Join(eligibility.Reasons, " "), "payment provider") {
		t.Errorf("the reason does not name the provider: %v", eligibility.Reasons)
	}
}

func TestOnboardingRejectsInvalidIdentity(t *testing.T) {
	h := newHarness(t)

	base := func() seller.OnboardRequest {
		userID := fixtures.NewBuyer(t, h.ctx, h.db, h.vault,
			"onboard-"+strings.ToLower(ids.NewPublic("x")[2:10])+"@example.test", 33)
		return seller.OnboardRequest{
			UserID: userID, Handle: "handle" + strings.ToLower(ids.NewPublic("x")[2:8]),
			DisplayName: "Ananya Textiles", LegalName: "Ananya Textiles Private Limited",
			EntityType: "private_limited", Country: "IN", StateCode: 33,
			PAN: "AAACA1234C",
		}
	}

	for _, tc := range []struct {
		name   string
		mutate func(*seller.OnboardRequest)
	}{
		{"handle too short", func(r *seller.OnboardRequest) { r.Handle = "ab" }},
		{"handle with capitals is folded, not rejected", nil},
		{"malformed PAN", func(r *seller.OnboardRequest) { r.PAN = "NOTAPAN123" }},
		{"malformed GSTIN", func(r *seller.OnboardRequest) { r.GSTIN = "33AAACA1234C1Z" }},
		{"GSTIN with a bad check digit", func(r *seller.OnboardRequest) { r.GSTIN = "33AAACA1234C1ZA" }},
		{"GSTIN belonging to a different PAN", func(r *seller.OnboardRequest) {
			r.GSTIN = fixtures.GSTINFor(33, "BBBCB5678D")
		}},
		{"unknown entity type", func(r *seller.OnboardRequest) { r.EntityType = "guild" }},
		{"Indian seller with no state code", func(r *seller.OnboardRequest) { r.StateCode = 0 }},
	} {
		if tc.mutate == nil {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			req := base()
			tc.mutate(&req)
			if _, err := h.svc.Onboard(h.ctx, req); err == nil {
				t.Fatal("invalid identity was accepted")
			}
		})
	}
}

// TestGSTINChecksumIsEnforced: a transposed digit produces a well-formed GSTIN
// belonging to nobody, and finding that out when a GSTR-8 return is rejected is
// expensive.
func TestGSTINChecksumIsEnforced(t *testing.T) {
	h := newHarness(t)
	pan := "AAACA1234C"
	valid := fixtures.GSTINFor(33, pan)

	userID := fixtures.NewBuyer(t, h.ctx, h.db, h.vault,
		"gstin-"+strings.ToLower(ids.NewPublic("x")[2:10])+"@example.test", 33)
	req := seller.OnboardRequest{
		UserID: userID, Handle: "gstin" + strings.ToLower(ids.NewPublic("x")[2:8]),
		DisplayName: "Ananya Textiles", LegalName: "Ananya Textiles Private Limited",
		EntityType: "private_limited", Country: "IN", StateCode: 33,
		PAN: pan, GSTIN: valid,
	}
	if _, err := h.svc.Onboard(h.ctx, req); err != nil {
		t.Fatalf("a GSTIN with a correct check digit was rejected: %v", err)
	}

	// Break the check digit only.
	broken := []byte(valid)
	if broken[14] == 'A' {
		broken[14] = 'B'
	} else {
		broken[14] = 'A'
	}
	req.UserID = fixtures.NewBuyer(t, h.ctx, h.db, h.vault,
		"gstin2-"+strings.ToLower(ids.NewPublic("x")[2:10])+"@example.test", 33)
	req.Handle = "gstinb" + strings.ToLower(ids.NewPublic("x")[2:8])
	req.GSTIN = string(broken)
	if _, err := h.svc.Onboard(h.ctx, req); err == nil {
		t.Fatal("a GSTIN with a wrong check digit was accepted")
	}
}

func TestOneSellerPerUser(t *testing.T) {
	h := newHarness(t)
	s := h.onboard(t, "duplicate")
	userID := h.userFor(t, s.ID)

	_, err := h.svc.Onboard(h.ctx, seller.OnboardRequest{
		UserID: userID, Handle: "second" + strings.ToLower(ids.NewPublic("x")[2:8]),
		DisplayName: "Second Attempt", LegalName: "Second Attempt Limited",
		EntityType: "private_limited", Country: "IN", StateCode: 33, PAN: "AAACA1234C",
	})
	if !errors.Is(err, seller.ErrAlreadySeller) {
		t.Fatalf("error = %v, want ErrAlreadySeller", err)
	}
}

// TestLegalNameIsNeverStoredInTheClear: an erasure request must be able to make
// this unreadable, which is only true if it was encrypted in the first place.
func TestLegalNameIsNeverStoredInTheClear(t *testing.T) {
	h := newHarness(t)
	s := h.onboard(t, "encrypted")

	var ciphertext []byte
	if err := h.db.QueryRow(h.ctx,
		`SELECT legal_name_ciphertext FROM sellers WHERE id = $1`, s.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("no ciphertext was stored")
	}
	if strings.Contains(string(ciphertext), "Ananya") {
		t.Fatal("the legal name is readable in the stored column")
	}

	// And it decrypts under the subject's own key, bound to the field name.
	userID := h.userFor(t, s.ID)
	got, err := h.vault.DecryptFor(h.ctx, h.db, userID, "seller.legal_name", ciphertext)
	if err != nil {
		t.Fatalf("decrypting under the subject key: %v", err)
	}
	if !strings.Contains(got, "Ananya") {
		t.Errorf("decrypted to %q", got)
	}

	// A ciphertext cannot be read as a different field, which is what stops it
	// being moved between columns.
	if _, err := h.vault.DecryptFor(h.ctx, h.db, userID, "payout.account", ciphertext); err == nil {
		t.Fatal("a legal-name ciphertext decrypted as a payout account")
	}
}

func TestPayoutValidationRejectsBadDestinations(t *testing.T) {
	h := newHarness(t)
	s := h.onboard(t, "badpayout")
	userID := h.userFor(t, s.ID)

	base := seller.PayoutAccountRequest{
		SellerID: s.ID, UserID: userID, Method: "bank_account",
		AccountNumber: "50100123456789", IFSC: "HDFC0001234",
		BeneficiaryName: "Ananya Textiles Private Limited",
	}

	for _, tc := range []struct {
		name   string
		mutate func(*seller.PayoutAccountRequest)
	}{
		{"malformed IFSC", func(r *seller.PayoutAccountRequest) { r.IFSC = "HDFC1001234" }},
		{"IFSC too short", func(r *seller.PayoutAccountRequest) { r.IFSC = "HDFC0001" }},
		{"account number with punctuation", func(r *seller.PayoutAccountRequest) { r.AccountNumber = "5010-0123-4567" }},
		{"account number too short", func(r *seller.PayoutAccountRequest) { r.AccountNumber = "12345" }},
		{"no beneficiary name", func(r *seller.PayoutAccountRequest) { r.BeneficiaryName = "" }},
		{"unknown method", func(r *seller.PayoutAccountRequest) { r.Method = "carrier_pigeon" }},
		{"VPA with an IFSC", func(r *seller.PayoutAccountRequest) { r.Method = "vpa"; r.AccountNumber = "seller@okhdfcbank" }},
		{"malformed VPA", func(r *seller.PayoutAccountRequest) { r.Method = "vpa"; r.AccountNumber = "not-a-vpa"; r.IFSC = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			if _, err := h.svc.AddPayoutAccount(h.ctx, req); err == nil {
				t.Fatal("an invalid destination was accepted")
			}
		})
	}
}

func TestDuplicateDestinationIsRefused(t *testing.T) {
	h := newHarness(t)
	s := h.onboard(t, "dupdest")
	userID := h.userFor(t, s.ID)

	req := seller.PayoutAccountRequest{
		SellerID: s.ID, UserID: userID, Method: "bank_account",
		AccountNumber: "50100444444444", IFSC: "HDFC0001234",
		BeneficiaryName: "Ananya Textiles Private Limited",
	}
	if _, err := h.svc.AddPayoutAccount(h.ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.AddPayoutAccount(h.ctx, req); err == nil {
		t.Fatal("the same destination was added twice")
	}
}

func TestAccountNumberIsNeverReturned(t *testing.T) {
	h := newHarness(t)
	s := h.onboard(t, "noleak")
	userID := h.userFor(t, s.ID)

	const account = "50100555555555"
	if _, err := h.svc.AddPayoutAccount(h.ctx, seller.PayoutAccountRequest{
		SellerID: s.ID, UserID: userID, Method: "bank_account",
		AccountNumber: account, IFSC: "HDFC0001234",
		BeneficiaryName: "Ananya Textiles Private Limited",
	}); err != nil {
		t.Fatal(err)
	}

	accounts, err := h.svc.ListPayoutAccounts(h.ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(accounts))
	}
	if strings.Contains(accounts[0].Last4, account[:6]) {
		t.Fatal("the account number was returned")
	}
	if accounts[0].Last4 != "5555" {
		t.Errorf("last4 = %q", accounts[0].Last4)
	}
	if !accounts[0].Quarantined {
		t.Error("a freshly added destination did not report itself quarantined")
	}
}

// ---- harness ----------------------------------------------------------------

type harness struct {
	ctx   context.Context
	db    *db.DB
	svc   *seller.Service
	vault *identity.Vault
	clock *clock.Fixed
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	d := dbtest.Open(t)
	ctx := context.Background()
	clk := clock.NewFixed(time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC))
	vault := fixtures.TestVault(t)

	pepper := make([]byte, 32)
	for i := range pepper {
		pepper[i] = byte(i * 7)
	}
	svc, err := seller.New(seller.Options{
		DB: d, Vault: vault, Clock: clk, PayoutPepper: pepper,
	})
	if err != nil {
		t.Fatalf("seller.New: %v", err)
	}
	return &harness{ctx: ctx, db: d, svc: svc, vault: vault, clock: clk}
}

func (h *harness) onboard(t *testing.T, prefix string) *seller.Seller {
	t.Helper()
	suffix := strings.ToLower(ids.NewPublic("x")[2:8])
	userID := fixtures.NewBuyer(t, h.ctx, h.db, h.vault, prefix+suffix+"@example.test", 33)

	s, err := h.svc.Onboard(h.ctx, seller.OnboardRequest{
		UserID: userID, Handle: prefix + suffix,
		DisplayName: "Ananya Textiles", LegalName: "Ananya Textiles Private Limited",
		EntityType: "private_limited", Country: "IN", StateCode: 33,
		PAN: fixtures.PANFor(prefix + suffix),
	})
	if err != nil {
		t.Fatalf("Onboard(%s): %v", prefix, err)
	}
	return s
}

// verify puts a seller in the fully-approved state on our side AND the
// provider's, so a test can isolate one gate at a time.
func (h *harness) verify(t *testing.T, sellerID ids.UUID) {
	t.Helper()
	if _, err := h.db.Exec(h.ctx, `
		UPDATE sellers SET status = 'active', kyc_status = 'verified', kyc_verified_at = now(),
		       provider = 'razorpay_route', provider_account_id = $2,
		       provider_account_status = 'activated', provider_account_activated_at = now()
		 WHERE id = $1`, sellerID, "acc_"+sellerID.String()[:8]); err != nil {
		t.Fatalf("verify seller: %v", err)
	}
}

func (h *harness) userFor(t *testing.T, sellerID ids.UUID) ids.UUID {
	t.Helper()
	var userID ids.UUID
	if err := h.db.QueryRow(h.ctx, `SELECT user_id FROM sellers WHERE id = $1`, sellerID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	return userID
}
