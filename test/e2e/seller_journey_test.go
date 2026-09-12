package e2e

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/muthu2201/market-place/internal/platform/ids"
	"github.com/muthu2201/market-place/internal/testsupport/fixtures"
)

// TestSellerJourney walks the whole seller path over real HTTP: register,
// become a seller, draft a listing, price it, upload a file, watch it scan, add
// a payout destination, and publish.
//
// Every request goes through the full middleware chain — CSRF, rate limiting,
// authentication, role checks — because that chain is where a surprising number
// of access-control mistakes live, and a test that called the services directly
// would exercise none of it.
func TestSellerJourney(t *testing.T) {
	e := newEnv(t)
	c := e.newClient()

	const email = "seller-journey@example.test"
	const password = "correct-horse-battery-staple-42"
	c.register(email, password)
	c.mustOK(c.login(email, password), "login")

	// --- the seller surface refuses a buyer ---------------------------------
	//
	// Before onboarding, the role is absent and every seller endpoint must
	// refuse. Checking this first means the later successes prove the role
	// actually gates something.
	for _, path := range []string{
		"POST /api/v1/seller/products",
		"GET /api/v1/seller/payouts",
		"POST /api/v1/seller/payouts/accounts",
	} {
		method, p, _ := strings.Cut(path, " ")
		if r := c.do(method, p, map[string]any{}, nil); r.Status != 403 {
			t.Fatalf("%s before onboarding: status %d, want 403", path, r.Status)
		}
	}

	// --- onboard -------------------------------------------------------------
	handle := "journey" + strings.ToLower(ids.NewPublic("x")[2:8])
	pan := fixtures.PANFor(handle)

	var onboard struct {
		SellerID  string `json:"seller_id"`
		Status    string `json:"status"`
		KYCStatus string `json:"kyc_status"`
	}
	r := c.do("POST", "/api/v1/seller/onboard", map[string]any{
		"handle": handle, "display_name": "Journey Studio",
		"legal_name": "Journey Studio Private Limited", "entity_type": "private_limited",
		"country": "IN", "state_code": 33, "pan": pan,
		"gstin": fixtures.GSTINFor(33, pan),
	}, &onboard)
	c.mustOK(r, "onboard")
	if onboard.Status != "pending" || onboard.KYCStatus != "unverified" {
		t.Fatalf("a new seller started at status=%q kyc=%q, want pending/unverified",
			onboard.Status, onboard.KYCStatus)
	}

	// The role arrives with onboarding, so the seller surface opens immediately
	// even though nothing can be sold yet.
	sellerID := e.sellerIDForHandle(t, handle)

	// --- draft ---------------------------------------------------------------
	categoryPublicID := e.categoryPublicID(t)
	var draft struct {
		ProductID string `json:"product_id"`
		Status    string `json:"status"`
	}
	r = c.do("POST", "/api/v1/seller/products", map[string]any{
		"category_id":   categoryPublicID,
		"title":         "Eight Hand-Drawn Map Brushes",
		"summary":       "Eight brushes for drawing fantasy coastlines and terrain.",
		"description":   "Drawn on paper, scanned at 1200dpi and cleaned up by hand.",
		"delivery_type": "download", "license_type": "commercial",
		"license_terms": "Use in commercial work. Do not resell the brushes themselves.",
		"ai_disclosure": "no_ai",
		"tags":          []string{"brushes", "cartography", "hand-drawn"},
	}, &draft)
	c.mustOK(r, "draft product")
	if draft.Status != "draft" {
		t.Fatalf("status = %q, want draft", draft.Status)
	}

	// --- readiness says everything that is missing, at once ------------------
	var readiness struct {
		Ready    bool `json:"ready"`
		Blockers []struct {
			Code    string `json:"code"`
			Detail  string `json:"detail"`
			Fixable bool   `json:"you_can_fix_this"`
		} `json:"blockers"`
	}
	r = c.do("GET", "/api/v1/seller/products/"+draft.ProductID+"/readiness", nil, &readiness)
	c.mustOK(r, "readiness")
	if readiness.Ready {
		t.Fatal("an empty draft reported ready")
	}
	codes := map[string]bool{}
	for _, b := range readiness.Blockers {
		codes[b.Code] = true
		if b.Detail == "" {
			t.Errorf("blocker %q has no explanation", b.Code)
		}
	}
	for _, want := range []string{"no_deliverable_asset", "no_priced_variant", "seller_not_verified"} {
		if !codes[want] {
			t.Errorf("blocker %q missing", want)
		}
	}
	// The seller cannot fix verification themselves, and the response says so
	// rather than telling them to try.
	for _, b := range readiness.Blockers {
		if b.Code == "seller_not_verified" && b.Fixable {
			t.Error("verification was reported as something the seller can fix")
		}
	}

	// --- price it -------------------------------------------------------------
	r = c.do("POST", "/api/v1/seller/products/"+draft.ProductID+"/variants", map[string]any{
		"name": "Full set", "price_minor": 149900, "currency": "INR",
	}, nil)
	c.mustOK(r, "add variant")

	// --- upload ---------------------------------------------------------------
	var ticket struct {
		UploadID string `json:"upload_id"`
		Direct   bool   `json:"direct"`
		MaxBytes int64  `json:"max_bytes"`
	}
	content := []byte("PK\x03\x04" + strings.Repeat("brush data ", 500))
	r = c.do("POST", "/api/v1/seller/products/"+draft.ProductID+"/uploads", map[string]any{
		"filename": "map-brushes.zip", "content_type": "application/zip",
		"size_bytes": len(content),
	}, &ticket)
	c.mustOK(r, "request upload")
	if ticket.UploadID == "" {
		t.Fatal("no upload id was issued")
	}

	// The filesystem adapter cannot presign, so the bytes go where the API's
	// streaming fallback would put them: the quarantine prefix.
	quarantine := "quarantine/" + sellerID.String() + "/" + ticket.UploadID
	if _, err := e.store.Put(e.ctx(), putRequest(quarantine, content)); err != nil {
		t.Fatalf("storing the upload: %v", err)
	}

	var asset struct {
		AssetID    string `json:"asset_id"`
		SHA256     string `json:"sha256"`
		ScanStatus string `json:"scan_status"`
		SizeBytes  int64  `json:"size_bytes"`
	}
	r = c.do("POST", "/api/v1/seller/products/"+draft.ProductID+"/assets", map[string]any{
		"upload_id": ticket.UploadID, "filename": "map-brushes.zip",
		"content_type": "application/zip",
	}, &asset)
	c.mustOK(r, "finalise upload")
	if asset.ScanStatus != "pending" {
		t.Fatalf("scan_status = %q, want pending", asset.ScanStatus)
	}
	if asset.SizeBytes != int64(len(content)) {
		t.Errorf("size = %d, uploaded %d", asset.SizeBytes, len(content))
	}
	if asset.SHA256 == "" {
		t.Error("no checksum was returned; a buyer has nothing to verify against")
	}

	// An unscanned asset's object key must resolve to nothing. This is the
	// property that makes serving one impossible rather than merely forbidden.
	var objectKey string
	if err := e.app.DB.QueryRow(e.ctx(),
		`SELECT object_key FROM product_assets WHERE public_id = $1`, asset.AssetID).Scan(&objectKey); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Stat(e.ctx(), objectKey); err == nil {
		t.Fatal("an object exists at the deliverable key of an unscanned asset")
	}

	// Publishing is refused while the file is unscanned.
	if r := c.do("POST", "/api/v1/seller/products/"+draft.ProductID+"/publish", nil, nil); r.Status != 409 {
		t.Fatalf("publish with an unscanned file: status %d, want 409", r.Status)
	}

	// --- the worker scans it ---------------------------------------------------
	scansBefore := e.clamd.Scans()
	if err := e.app.Catalog.ScanAsset(e.ctx(), asset.AssetID); err != nil {
		t.Fatalf("ScanAsset: %v", err)
	}
	if e.clamd.Scans() != scansBefore+1 {
		t.Fatal("the scanner was never reached; the asset was passed without being examined")
	}
	if !bytes.Equal(e.clamd.LastBytes(), content) {
		t.Fatalf("the scanner examined %d bytes, the seller uploaded %d — a framing bug would "+
			"mean scanning something other than what the buyer downloads",
			len(e.clamd.LastBytes()), len(content))
	}
	body, info, err := e.store.Get(e.ctx(), objectKey)
	if err != nil {
		t.Fatalf("a scanned-clean asset was not promoted to its deliverable key: %v", err)
	}
	got := new(bytes.Buffer)
	if _, err := got.ReadFrom(body); err != nil {
		t.Fatal(err)
	}
	_ = body.Close()
	if !bytes.Equal(got.Bytes(), content) {
		t.Fatalf("the promoted object is %d bytes, uploaded %d", info.Size, len(content))
	}

	// --- payout destination, and its quarantine --------------------------------
	var payout struct {
		Last4       string `json:"last4"`
		Quarantined bool   `json:"quarantined"`
		Note        string `json:"note"`
	}
	r = c.do("POST", "/api/v1/seller/payouts/accounts", map[string]any{
		"method": "bank_account", "account_number": "50100987654321",
		"ifsc": "HDFC0001234", "beneficiary_name": "Journey Studio Private Limited",
	}, &payout)
	c.mustOK(r, "add payout account")
	if !payout.Quarantined {
		t.Fatal("a new payout destination was not quarantined")
	}
	if payout.Last4 != "4321" {
		t.Errorf("last4 = %q", payout.Last4)
	}
	if !strings.Contains(payout.Note, "48 hours") {
		t.Errorf("the response does not tell the seller about the wait: %q", payout.Note)
	}

	var payoutStatus struct {
		Payable  bool     `json:"payable"`
		Reasons  []string `json:"reasons"`
		Accounts []struct {
			Last4       string `json:"last4"`
			Quarantined bool   `json:"quarantined"`
		} `json:"accounts"`
	}
	r = c.do("GET", "/api/v1/seller/payouts", nil, &payoutStatus)
	c.mustOK(r, "payout status")
	if payoutStatus.Payable {
		t.Fatal("an unverified seller with a quarantined destination was reported payable")
	}
	if len(payoutStatus.Accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(payoutStatus.Accounts))
	}
	// The account number itself must never come back.
	if strings.Contains(string(r.Body), "50100987654321") {
		t.Fatal("the payout response contains the account number")
	}

	// --- verification, then publish --------------------------------------------
	e.verifySeller(t, sellerID)

	r = c.do("GET", "/api/v1/seller/products/"+draft.ProductID+"/readiness", nil, &readiness)
	c.mustOK(r, "readiness after verification")
	if !readiness.Ready {
		t.Fatalf("still blocked after satisfying everything: %+v", readiness.Blockers)
	}

	r = c.do("POST", "/api/v1/seller/products/"+draft.ProductID+"/publish", nil, nil)
	c.mustOK(r, "publish")

	// --- and it is now visible to a buyer ---------------------------------------
	buyer := e.newClient()
	var listing struct {
		Products []struct {
			ID           string `json:"id"`
			Title        string `json:"title"`
			AIDisclosure string `json:"ai_disclosure"`
		} `json:"products"`
		RankingDisclosureURL string `json:"ranking_disclosure_url"`
	}
	r = buyer.do("GET", "/api/v1/catalog/products", nil, &listing)
	buyer.mustOK(r, "public listing")

	var found bool
	for _, p := range listing.Products {
		if p.ID == draft.ProductID {
			found = true
			if p.AIDisclosure != "no_ai" {
				t.Errorf("the published disclosure is %q, want the seller's declaration", p.AIDisclosure)
			}
		}
	}
	if !found {
		t.Fatal("a published product did not appear in the public catalogue")
	}
	if listing.RankingDisclosureURL != "/legal/ranking" {
		t.Errorf("ranking disclosure URL = %q", listing.RankingDisclosureURL)
	}
}

// TestSellerCannotTouchAnotherSellersListing: ownership is part of every query,
// and a product belonging to someone else must be indistinguishable from one
// that does not exist.
func TestSellerCannotTouchAnotherSellersListing(t *testing.T) {
	e := newEnv(t)

	owner := e.onboardedSeller(t, "owner")
	intruder := e.onboardedSeller(t, "intruder")

	var draft struct {
		ProductID string `json:"product_id"`
	}
	r := owner.do("POST", "/api/v1/seller/products", map[string]any{
		"category_id":   e.categoryPublicID(t),
		"title":         "The Owner's Private Draft",
		"summary":       "A draft that belongs to exactly one seller.",
		"description":   "Nobody else should be able to see or change this.",
		"delivery_type": "download", "license_type": "commercial",
		"license_terms": "Commercial use permitted.", "ai_disclosure": "no_ai",
	}, &draft)
	owner.mustOK(r, "draft")

	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/seller/products/" + draft.ProductID + "/readiness", nil},
		{"POST", "/api/v1/seller/products/" + draft.ProductID + "/publish", nil},
		{"POST", "/api/v1/seller/products/" + draft.ProductID + "/unpublish", nil},
		{"POST", "/api/v1/seller/products/" + draft.ProductID + "/variants",
			map[string]any{"name": "Cheap", "price_minor": 1}},
		{"POST", "/api/v1/seller/products/" + draft.ProductID + "/uploads",
			map[string]any{"filename": "x.zip", "content_type": "application/zip", "size_bytes": 10}},
		{"PUT", "/api/v1/seller/products/" + draft.ProductID + "/tags",
			map[string]any{"tags": []string{"hijacked"}}},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			r := intruder.do(tc.method, tc.path, tc.body, nil)
			if r.Status != 404 {
				t.Fatalf("status %d, want 404 — another seller's product must be indistinguishable from a missing one", r.Status)
			}
		})
	}
}

// TestOnboardingIsRefusedTwice: one seller per account.
func TestOnboardingIsRefusedTwice(t *testing.T) {
	e := newEnv(t)
	c := e.onboardedSeller(t, "twice")

	handle := "second" + strings.ToLower(ids.NewPublic("x")[2:8])
	r := c.do("POST", "/api/v1/seller/onboard", map[string]any{
		"handle": handle, "display_name": "Second Attempt",
		"legal_name": "Second Attempt Private Limited", "entity_type": "private_limited",
		"country": "IN", "state_code": 33, "pan": fixtures.PANFor(handle),
	}, nil)
	if r.Status != 409 {
		t.Fatalf("second onboarding: status %d, want 409", r.Status)
	}
}

// ---- helpers ----------------------------------------------------------------

func (e *env) ctx() context.Context { return context.Background() }

func (e *env) categoryPublicID(t *testing.T) string {
	t.Helper()
	id := fixtures.Category(t, e.ctx(), e.app.DB)
	var publicID string
	if err := e.app.DB.QueryRow(e.ctx(),
		`SELECT public_id FROM categories WHERE id = $1`, id).Scan(&publicID); err != nil {
		t.Fatal(err)
	}
	return publicID
}

func (e *env) sellerIDForHandle(t *testing.T, handle string) ids.UUID {
	t.Helper()
	var id ids.UUID
	if err := e.app.DB.QueryRow(e.ctx(),
		`SELECT id FROM sellers WHERE handle = $1`, handle).Scan(&id); err != nil {
		t.Fatalf("seller %q not found: %v", handle, err)
	}
	return id
}

// verifySeller puts a seller in the fully approved state on our side AND the
// provider's, the way a completed verification would.
func (e *env) verifySeller(t *testing.T, sellerID ids.UUID) {
	t.Helper()
	if _, err := e.app.DB.Exec(e.ctx(), `
		UPDATE sellers SET status = 'active', kyc_status = 'verified', kyc_verified_at = now(),
		       provider = 'bridge', provider_account_id = $2,
		       provider_account_status = 'activated', provider_account_activated_at = now()
		 WHERE id = $1`, sellerID, "acc_"+sellerID.String()[:8]); err != nil {
		t.Fatalf("verifying the seller: %v", err)
	}
}

// onboardedSeller returns a logged-in client that is already a seller.
func (e *env) onboardedSeller(t *testing.T, prefix string) *client {
	t.Helper()
	suffix := strings.ToLower(ids.NewPublic("x")[2:8])
	c := e.newClient()
	email := prefix + suffix + "@example.test"
	const password = "correct-horse-battery-staple-42"
	c.register(email, password)
	c.mustOK(c.login(email, password), "login "+prefix)

	handle := prefix + suffix
	pan := fixtures.PANFor(handle)
	c.mustOK(c.do("POST", "/api/v1/seller/onboard", map[string]any{
		"handle": handle, "display_name": prefix + " studio",
		"legal_name": prefix + " Studio Private Limited", "entity_type": "private_limited",
		"country": "IN", "state_code": 33, "pan": pan,
	}, nil), "onboard "+prefix)
	return c
}
